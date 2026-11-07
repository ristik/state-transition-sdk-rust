//! The shared maximum-size entry (bft-go-base 81ee667, `tests/vectors/trust-base-v2-max`) through the cache: the per-entry budget, a session that
//! appends and flushes it, and a store that holds exactly the shared bundle.
#![cfg(feature = "std")]

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use serde_json::Value;
use unicity_token::api::bft::trust_base_cache::*;
use unicity_token::api::bft::trust_base_history::BundleLimits;
use unicity_token::api::bft::{Appended, HistoryError, TrustBaseEntry, TrustBaseHistory};
use unicity_token::api::NetworkId;

fn block_on<F: Future>(f: F) -> F::Output {
    fn clone(_: *const ()) -> RawWaker {
        RawWaker::new(std::ptr::null(), &VT)
    }
    fn noop(_: *const ()) {}
    static VT: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
    let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VT)) };
    let mut cx = Context::from_waker(&waker);
    let mut f = pin!(f);
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

fn fixture() -> Value {
    serde_json::from_slice(include_bytes!("vectors/trust-base-v2-max/max-entry.json")).unwrap()
}

fn hx(v: &Value, key: &str) -> Vec<u8> {
    hex::decode(v[key].as_str().unwrap()).unwrap()
}

fn net(v: &Value) -> NetworkId {
    NetworkId::new(v["network"].as_u64().unwrap() as u16).unwrap()
}

#[test]
fn the_per_entry_budget_is_the_cap_not_a_reason_to_prune() {
    let v = fixture();
    let bundle = hx(&v, "bundle");
    let pin: [u8; 32] = hx(&v, "genesisId").try_into().unwrap();
    let entry_len = hx(&v, "entry").len();
    let at = |max_entry_bytes| BundleLimits {
        max_entry_bytes,
        ..BundleLimits::default()
    };
    assert!(TrustBaseHistory::from_bundle_with(&bundle, Some(pin), &at(entry_len)).is_ok());
    assert!(matches!(
        TrustBaseHistory::from_bundle_with(&bundle, Some(pin), &at(entry_len - 1)),
        Err(HistoryError::Budget(_))
    ));
    // the default budget is the 128 KiB cap, which the largest entry is well inside
    assert_eq!(BundleLimits::default().max_entry_bytes, 128 * 1024);
}

#[test]
fn a_session_appends_flushes_and_reopens_the_largest_entry() {
    let v = fixture();
    let genesis_only = {
        let g = TrustBaseEntry::from_cbor(&hx(&v, "genesis")).unwrap();
        TrustBaseHistory::from_genesis(g, None).unwrap().to_bundle()
    };
    let entry = TrustBaseEntry::from_cbor(&hx(&v, "entry")).unwrap();
    let store = MemoryStore::new();
    let open = |limits: BundleLimits| {
        block_on(Session::open_in(
            &[],
            net(&v),
            Authority::local(&genesis_only).unwrap(),
            &store,
            SessionOptions {
                limits,
                ..SessionOptions::default()
            },
        ))
    };
    let (mut s, _) = open(BundleLimits::default()).unwrap();
    assert_eq!(s.append(entry), Ok(Appended::Added));
    assert!(matches!(
        block_on(s.flush()),
        Flush::Saved { wrote: true, .. }
    ));
    // the store holds exactly the shared two-entry bundle
    assert_eq!(store.get(s.key()), Some(hx(&v, "bundle")));
    drop(s);

    // reopened: the cache extends the embedded genesis, nothing to save
    let (s, d) = open(BundleLimits::default()).unwrap();
    assert!(d.is_empty());
    assert_eq!(s.history().unwrap().latest().epoch, 2);
    assert!(!s.is_dirty());
    drop(s);

    // a budget below the entry makes the stored cache an oversize rejection, never a rewrite
    let small = BundleLimits {
        max_entry_bytes: 90_000,
        ..BundleLimits::default()
    };
    let (s, d) = open(small).unwrap();
    assert_eq!(d, vec![Diagnostic::CacheRejected(CacheReject::Oversize)]);
    assert_eq!(s.history().unwrap().latest().epoch, 1);
}
