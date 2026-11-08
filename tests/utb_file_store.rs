//! The optional file adapter: the store contract, the lock protocol, atomic replacement.
#![cfg(feature = "file-cache")]

use std::fs;
use std::future::Future;
use std::path::PathBuf;
use std::pin::pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use unicity_token::api::bft::trust_base_cache::*;
use unicity_token::api::bft::trust_base_file_store::FileStore;
use unicity_token::api::NetworkId;

static VT: RawWakerVTable = RawWakerVTable::new(
    |_| RawWaker::new(std::ptr::null(), &VT),
    |_| {},
    |_| {},
    |_| {},
);

fn block_on<F: Future>(f: F) -> F::Output {
    let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VT)) };
    let mut cx = Context::from_waker(&waker);
    let mut f = pin!(f);
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

static N: AtomicUsize = AtomicUsize::new(0);

struct Dir(PathBuf);

impl Dir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "utb-file-store-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&p);
        Dir(p)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn key() -> StoreKey {
    StoreKey::new(NetworkId::new(7).unwrap(), &[9; 32], "test")
}

fn names(d: &Dir) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(&d.0)
        .map(|r| {
            r.map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

#[test]
fn read_write_roundtrip_with_revisions() {
    let d = Dir::new();
    let s = FileStore::new(&d.0);
    assert_eq!(block_on(s.read(&key(), 1024)), Ok(StoreRead::Absent));
    let r = block_on(s.compare_and_swap(&key(), None, b"one")).unwrap();
    assert_eq!(r, StoreCas::Written(Revision::of(b"one")));
    assert_eq!(
        block_on(s.read(&key(), 1024)),
        Ok(StoreRead::Present {
            revision: Revision::of(b"one"),
            bytes: b"one".to_vec()
        })
    );
    // a stale expectation changes nothing
    assert_eq!(
        block_on(s.compare_and_swap(&key(), None, b"two")),
        Ok(StoreCas::Changed)
    );
    assert_eq!(
        block_on(s.compare_and_swap(&key(), Some(&Revision::of(b"zzz")), b"two")),
        Ok(StoreCas::Changed)
    );
    assert_eq!(
        block_on(s.compare_and_swap(&key(), Some(&Revision::of(b"one")), b"two")),
        Ok(StoreCas::Written(Revision::of(b"two")))
    );
    // ABA is harmless for this contract: identical bytes, identical token
    assert_eq!(
        block_on(s.compare_and_swap(&key(), Some(&Revision::of(b"two")), b"one")),
        Ok(StoreCas::Written(Revision::of(b"one")))
    );
    assert_eq!(
        block_on(s.compare_and_swap(&key(), Some(&Revision::of(b"one")), b"x")),
        Ok(StoreCas::Written(Revision::of(b"x")))
    );
    // no temporary file or lock is left behind
    assert_eq!(names(&d).len(), 1, "{:?}", names(&d));
}

#[test]
fn the_read_budget_is_enforced_before_reading() {
    let d = Dir::new();
    let s = FileStore::new(&d.0);
    block_on(s.compare_and_swap(&key(), None, &[7u8; 100])).unwrap();
    assert_eq!(block_on(s.read(&key(), 99)), Err(StoreError::TooLarge));
    assert!(block_on(s.read(&key(), 100)).is_ok());
}

#[test]
fn a_held_lock_is_busy_at_once_and_is_never_stolen() {
    let d = Dir::new();
    let s = FileStore::new(&d.0);
    block_on(s.compare_and_swap(&key(), None, b"old")).unwrap();
    // a crash-left (or foreign) lock
    fs::create_dir(s.lock_path(&key())).unwrap();
    assert_eq!(
        block_on(s.compare_and_swap(&key(), Some(&Revision::of(b"old")), b"new")),
        Err(StoreError::Busy)
    );
    assert_eq!(
        block_on(s.compare_and_swap(&key(), Some(&Revision::of(b"old")), b"new")),
        Err(StoreError::Busy)
    );
    assert!(
        s.lock_path(&key()).exists(),
        "the store does not remove a lock it did not take"
    );
    // readers need no lock, and still see the old complete bytes
    assert_eq!(
        block_on(s.read(&key(), 16)),
        Ok(StoreRead::Present {
            revision: Revision::of(b"old"),
            bytes: b"old".to_vec()
        })
    );
    // the app's maintenance action
    fs::remove_dir(s.lock_path(&key())).unwrap();
    assert!(matches!(
        block_on(s.compare_and_swap(&key(), Some(&Revision::of(b"old")), b"new")),
        Ok(StoreCas::Written(_))
    ));
}

#[test]
fn an_orphan_temporary_file_is_ignored_and_the_old_bytes_stand() {
    let d = Dir::new();
    let s = FileStore::new(&d.0);
    block_on(s.compare_and_swap(&key(), None, b"old")).unwrap();
    // a writer that died after writing its temporary file, before the rename
    let stem = s
        .file_path(&key())
        .file_stem()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    fs::write(d.0.join(format!("{stem}.tmp-1-1")), b"half-written").unwrap();
    assert_eq!(
        block_on(s.read(&key(), 16)),
        Ok(StoreRead::Present {
            revision: Revision::of(b"old"),
            bytes: b"old".to_vec()
        })
    );
    // an orphan with the very name the next writer would pick (same pid, fresh counter) must
    // not fail the write, and the orphans are cleaned up under the lock
    fs::write(
        d.0.join(format!("{stem}.tmp-{}-0", std::process::id())),
        b"half",
    )
    .unwrap();
    assert!(matches!(
        block_on(s.compare_and_swap(&key(), Some(&Revision::of(b"old")), b"new")),
        Ok(StoreCas::Written(_))
    ));
    assert_eq!(names(&d).len(), 1, "{:?}", names(&d));
}

#[cfg(unix)]
#[test]
fn a_permission_failure_is_typed_and_leaves_nothing_behind() {
    use std::os::unix::fs::PermissionsExt;
    let d = Dir::new();
    let s = FileStore::new(&d.0);
    block_on(s.compare_and_swap(&key(), None, b"old")).unwrap();
    fs::set_permissions(&d.0, fs::Permissions::from_mode(0o555)).unwrap();
    let r = block_on(s.compare_and_swap(&key(), Some(&Revision::of(b"old")), b"new"));
    let writable = fs::write(d.0.join("probe"), b"x").is_ok(); // running as root ignores modes
    fs::set_permissions(&d.0, fs::Permissions::from_mode(0o755)).unwrap();
    if writable {
        let _ = fs::remove_file(d.0.join("probe"));
        return;
    }
    assert_eq!(r, Err(StoreError::Permission));
    assert_eq!(names(&d).len(), 1, "{:?}", names(&d));
    assert_eq!(
        block_on(s.read(&key(), 16)),
        Ok(StoreRead::Present {
            revision: Revision::of(b"old"),
            bytes: b"old".to_vec()
        })
    );
}

#[test]
fn concurrent_writers_never_lose_an_update() {
    // 4 threads x 25 increments of a shared counter, every change a compare-and-swap; Busy and
    // Changed are retried. A lost update would leave the counter below 100.
    let d = Dir::new();
    let s = FileStore::new(&d.0);
    block_on(s.compare_and_swap(&key(), None, &0u64.to_be_bytes())).unwrap();
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let s = s.clone();
            std::thread::spawn(move || {
                for _ in 0..25 {
                    let mut spins = 0u32;
                    loop {
                        spins += 1;
                        assert!(spins < 200_000, "stuck: a lock was never released");
                        let StoreRead::Present { revision, bytes } =
                            block_on(s.read(&key(), 64)).unwrap()
                        else {
                            panic!()
                        };
                        let v = u64::from_be_bytes(bytes.try_into().unwrap()) + 1;
                        match block_on(s.compare_and_swap(
                            &key(),
                            Some(&revision),
                            &v.to_be_bytes(),
                        )) {
                            Ok(StoreCas::Written(_)) => break,
                            Ok(StoreCas::Changed) | Err(StoreError::Busy) => {
                                std::thread::yield_now()
                            }
                            Err(e) => panic!("{e:?}"),
                        }
                    }
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    let StoreRead::Present { bytes, .. } = block_on(s.read(&key(), 64)).unwrap() else {
        panic!()
    };
    assert_eq!(u64::from_be_bytes(bytes.try_into().unwrap()), 100);
    assert_eq!(names(&d).len(), 1, "{:?}", names(&d));
}

#[test]
fn the_filename_never_carries_the_namespace() {
    let d = Dir::new();
    let s = FileStore::new(&d.0);
    let k = StoreKey::new(NetworkId::new(7).unwrap(), &[9; 32], "..-weird namespace");
    let p = s.file_path(&k);
    assert_eq!(p.parent().unwrap(), d.0.as_path());
    assert!(!p.to_string_lossy().contains("weird"));
}

#[test]
fn a_session_over_the_file_store_saves_and_reloads_with_strict_revalidation() {
    use serde_json::Value;
    use unicity_token::api::bft::{TrustBaseEntry, TrustBaseHistory};
    let v: Value = serde_json::from_str(include_str!("vectors/utb-cache/v1/vectors.json")).unwrap();
    let find = |sec: &str, name: &str| -> Value {
        v[sec]
            .as_array()
            .unwrap()
            .iter()
            .find(|x| x["name"] == name)
            .unwrap()
            .clone()
    };
    let unhex = |x: &Value| hex::decode(x.as_str().unwrap()).unwrap();
    let p = find("pins", "A1-3");
    let id = |k: &str| -> [u8; 32] { unhex(&p[k]).try_into().unwrap() };
    let ep = |k: &str| p[k].as_str().unwrap().parse::<u64>().unwrap();
    let pin = PinSpec {
        network_id: NetworkId::new(7).unwrap(),
        genesis_epoch: ep("genesisEpoch"),
        genesis_entry_id: id("genesisEntryId"),
        pinned_epoch: ep("pinnedEpoch"),
        pinned_entry_id: id("pinnedEntryId"),
        bundle_sha256: id("bundleSha256"),
        bundle: unhex(&p["bundle"]),
    };
    let auth = || Authority::Custom {
        namespace: "test".into(),
        pin: pin.clone(),
    };
    let d = Dir::new();
    let store = FileStore::new(&d.0);
    let open = || {
        block_on(Session::open(
            pin.network_id,
            auth(),
            store.clone(),
            SessionOptions::default(),
        ))
        .unwrap()
    };
    let (mut s, diags) = open();
    assert!(diags.is_empty());
    for n in ["A4", "A5"] {
        let e = TrustBaseEntry::from_cbor(&unhex(&find("entries", n)["hex"])).unwrap();
        s.append(e).unwrap();
    }
    assert!(matches!(
        block_on(s.flush()),
        Flush::Saved { wrote: true, .. }
    ));
    let (s2, diags) = open();
    assert!(diags.is_empty());
    assert_eq!(s2.history().unwrap().latest().epoch, 5);
    // a bit flipped on disk is reverified, rejected, and the embedded history stands
    let path = store.file_path(s.key());
    let mut bytes = fs::read(&path).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x55;
    fs::write(&path, &bytes).unwrap();
    let (s3, diags) = open();
    assert_eq!(
        diags,
        vec![Diagnostic::CacheRejected(CacheReject::Malformed)]
    );
    assert_eq!(s3.history().unwrap().latest().epoch, 3);
    assert!(TrustBaseHistory::from_bundle(&bytes, None).is_err());
}
