//! The fetch loop (`trust_base_update`) over scripted sources whose pages are the shared GetTrustBase vectors (bft-core 5d9a8eaa), and
//! verify-update-retry. The entries are the three of `tests/vectors/trust-base-v2`: epoch 1 is the genesis, epochs 2 and 3 are signed by
//! members a, b, c.
#![cfg(all(feature = "std", feature = "client"))]

use std::cell::{Cell, RefCell};

use serde_json::Value;
use unicity_token::api::bft::trust_base_range::TrustBaseRange;
use unicity_token::api::bft::trust_base_range::{TrustBaseStatus, PAGE_LIMITS};
use unicity_token::api::bft::trust_base_update::{
    update, verify_with_update, Snapshot, SourceError, TrustBaseRequest, TrustBaseSource,
    UpdateCause, UpdateFailure, UpdateOptions,
};
use unicity_token::api::bft::{TrustBaseEntry, TrustBaseHistory, UnicitySeal};
use unicity_token::api::NetworkId;
use unicity_token::crypto::signer::{Secp256k1Signer, Signer};
use unicity_token::verify::{SealAuthenticator, SealSession, VerificationError};

fn gtb() -> Value {
    serde_json::from_str(include_str!("vectors/gettrustbase/vectors.json")).unwrap()
}

fn tbv2() -> Value {
    serde_json::from_str(include_str!("vectors/trust-base-v2/vectors.json")).unwrap()
}

fn case(prefix: &str) -> Vec<u8> {
    let v = gtb();
    let c = v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"].as_str().unwrap().starts_with(prefix))
        .unwrap_or_else(|| panic!("no case {prefix}"));
    hex::decode(c["hex"].as_str().unwrap()).unwrap()
}

fn entry(name: &str) -> TrustBaseEntry {
    let v = tbv2();
    let e = v["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == name)
        .unwrap();
    TrustBaseEntry::from_cbor(&hex::decode(e["hex"].as_str().unwrap()).unwrap()).unwrap()
}

fn genesis_only() -> TrustBaseHistory {
    TrustBaseHistory::from_genesis(entry("genesis"), None).unwrap()
}

fn net() -> NetworkId {
    NetworkId::new(gtb()["network"].as_u64().unwrap() as u16).unwrap()
}

/// A source whose answer is a function of the request; every request is recorded.
struct Script<F: Fn(usize, &TrustBaseRequest) -> Result<Vec<u8>, SourceError>> {
    answer: F,
    seen: RefCell<Vec<TrustBaseRequest>>,
}

impl<F: Fn(usize, &TrustBaseRequest) -> Result<Vec<u8>, SourceError>> Script<F> {
    fn new(answer: F) -> Self {
        Script {
            answer,
            seen: RefCell::new(Vec::new()),
        }
    }
    fn count(&self) -> usize {
        self.seen.borrow().len()
    }
}

impl<F: Fn(usize, &TrustBaseRequest) -> Result<Vec<u8>, SourceError>> TrustBaseSource
    for Script<F>
{
    fn get_trust_base_page(&self, request: &TrustBaseRequest) -> Result<Vec<u8>, SourceError> {
        let i = self.seen.borrow().len();
        self.seen.borrow_mut().push(request.clone());
        (self.answer)(i, request)
    }
}

fn fixed(
    bytes: Vec<u8>,
) -> Script<impl Fn(usize, &TrustBaseRequest) -> Result<Vec<u8>, SourceError>> {
    Script::new(move |_, _| Ok(bytes.clone()))
}

fn down() -> Script<impl Fn(usize, &TrustBaseRequest) -> Result<Vec<u8>, SourceError>> {
    Script::new(|_, _| Err(SourceError("connection refused".into())))
}

fn src(s: &dyn TrustBaseSource) -> &dyn TrustBaseSource {
    s
}

const NOTHING_NEWER: &str = "status 3 NotYetAvailable: from 4 is past the tip";
const LAGGING: &str = "status 3 NotYetAvailable: a lagging peer";

#[test]
fn a_range_from_the_next_epoch_is_appended_and_authenticated() {
    let mut h = genesis_only();
    let s = fixed(case("range from epoch 2 to the tip"));
    let n = update(&mut h, &[src(&s)], &UpdateOptions::default()).unwrap();
    assert_eq!(n, 2);
    assert_eq!(h.latest().epoch, 3);
    let r = s.seen.borrow()[0].clone();
    assert_eq!(
        (r.from_epoch, r.max_entries, r.network_id, r.snapshot),
        (2, 64, net(), None)
    );
}

#[test]
fn a_paged_range_follows_the_cursor_and_echoes_the_snapshot() {
    let mut h = genesis_only();
    let page1 = case("page 2 starting mid-history");
    let page2 = case("page 2, the last page");
    let end_id = TrustBaseRange::decode(&page1, &PAGE_LIMITS, net())
        .unwrap()
        .end_entry_id
        .unwrap();
    let s = Script::new(move |i, _| Ok(if i == 0 { page1.clone() } else { page2.clone() }));
    assert_eq!(update(&mut h, &[src(&s)], &UpdateOptions::default()), Ok(2));
    assert_eq!(h.latest().epoch, 3);
    let seen = s.seen.borrow();
    assert_eq!(seen.len(), 2);
    assert_eq!((seen[0].from_epoch, seen[0].snapshot), (2, None));
    assert_eq!(
        (seen[1].from_epoch, seen[1].snapshot),
        (
            3,
            Some(Snapshot {
                end: 3,
                entry_id: end_id
            })
        )
    );
}

#[test]
fn nothing_newer_is_a_result_only_when_every_source_says_it() {
    // every source: current, zero appended
    let mut h = TrustBaseHistory::from_genesis(entry("genesis"), None).unwrap();
    h.append(entry("epoch2-signed-abc")).unwrap();
    h.append(entry("epoch3-signed-abc")).unwrap();
    let a = fixed(case(NOTHING_NEWER));
    let b = fixed(case(NOTHING_NEWER));
    assert_eq!(
        update(&mut h, &[src(&a), src(&b)], &UpdateOptions::default()),
        Ok(0)
    );
    assert_eq!((a.count(), b.count()), (1, 1));

    // one says current, the other is down: not current
    let down = down();
    let e = update(&mut h, &[src(&a), src(&down)], &UpdateOptions::default()).unwrap_err();
    assert_eq!(e.failure, UpdateFailure::NoneServed);
    assert_eq!(e.appended, 0);
}

#[test]
fn a_lagging_source_does_not_end_the_update_and_the_next_one_serves() {
    let mut h = genesis_only();
    let lag = fixed(case(LAGGING));
    let good = fixed(case("range from epoch 2 to the tip"));
    assert_eq!(
        update(&mut h, &[src(&lag), src(&good)], &UpdateOptions::default()),
        Ok(2)
    );
    assert_eq!(h.latest().epoch, 3);
}

#[test]
fn a_hostile_status_is_final_for_the_call_but_busy_is_asked_again() {
    let calls = Cell::new(0);
    let opts = UpdateOptions {
        pause: Some(&|ms| {
            assert_eq!(ms, 200);
            calls.set(calls.get() + 1);
        }),
        ..UpdateOptions::default()
    };
    // history mismatch: final, not asked in the second round
    let mut h = genesis_only();
    let mismatch = fixed(case("status 4 (HistoryMismatch), nothing else"));
    let e = update(&mut h, &[src(&mismatch)], &opts).unwrap_err();
    assert_eq!(mismatch.count(), 1);
    assert_eq!(
        e.causes,
        vec![UpdateCause::Status {
            source: 0,
            status: TrustBaseStatus::HistoryMismatch
        }]
    );
    // busy: asked again after the pause
    calls.set(0);
    let busy = fixed(case("status 6 (Busy), nothing else"));
    let e = update(&mut h, &[src(&busy)], &opts).unwrap_err();
    assert_eq!(busy.count(), 2);
    assert_eq!(calls.get(), 1, "one pause between the two rounds");
    assert_eq!(e.failure, UpdateFailure::NoneServed);
}

/// The page "range from epoch 2 to the tip" with a bit flipped in the signature of its entry `epoch`.
fn damaged_page(epoch: u64) -> Vec<u8> {
    let bytes = case("range from epoch 2 to the tip");
    let page = TrustBaseRange::decode(&bytes, &PAGE_LIMITS, net()).unwrap();
    let e = page.entries.iter().find(|e| e.epoch == epoch).unwrap();
    let sig = e.signatures.as_ref().unwrap()[0].1.clone();
    let at = bytes
        .windows(sig.len())
        .position(|w| w == sig.as_slice())
        .unwrap();
    let mut bad = bytes.clone();
    bad[at + 10] ^= 1;
    bad
}

#[test]
fn an_entry_the_history_refuses_keeps_the_authenticated_prefix_and_the_next_source_continues() {
    let mut h = genesis_only();
    let bad = fixed(damaged_page(3)); // epoch 2 is good, epoch 3's signature is not
    let e = update(&mut h, &[src(&bad)], &UpdateOptions::default()).unwrap_err();
    assert_eq!(e.failure, UpdateFailure::NoneServed);
    assert_eq!(e.appended, 1, "the prefix is kept");
    assert_eq!(h.latest().epoch, 2);
    assert!(matches!(
        e.causes[0],
        UpdateCause::Refused { source: 0, .. }
    ));

    // with a good second source, one call ends with everything
    let mut h = genesis_only();
    let bad = Script::new(|_, r| {
        Ok(if r.from_epoch == 2 {
            damaged_page(3)
        } else {
            case("range of the tip entry only")
        })
    });
    let good = Script::new(|_, r| {
        Ok(if r.from_epoch == 3 {
            case("range of the tip entry only")
        } else {
            case("range from epoch 2 to the tip")
        })
    });
    assert_eq!(
        update(&mut h, &[src(&bad), src(&good)], &UpdateOptions::default()),
        Ok(2)
    );
    assert_eq!(h.latest().epoch, 3);
    // the second source was asked from the epoch after the held prefix, with no stale snapshot
    let r = good.seen.borrow()[0].clone();
    assert_eq!((r.from_epoch, r.snapshot), (3, None));
}

#[test]
fn a_page_that_does_not_continue_the_range_is_skipped() {
    let mut h = genesis_only();
    // asked from 2, the source answers a page that starts at 3
    let wrong = fixed(case("range of the tip entry only"));
    let e = update(&mut h, &[src(&wrong)], &UpdateOptions::default()).unwrap_err();
    assert!(e
        .causes
        .iter()
        .all(|c| matches!(c, UpdateCause::NotContinuing { source: 0 })));
    assert_eq!(h.latest().epoch, 1);
}

/// A hand-built OK page (the shared vectors have no pair of pages whose announced ends differ).
fn page(from: u64, end: u64, end_id: [u8; 32], entries: &[&str], next: Option<u64>) -> Vec<u8> {
    let raw: Vec<Vec<u8>> = entries.iter().map(|n| entry(n).to_cbor()).collect();
    page_raw(from, end, end_id, &raw, next)
}

fn page_raw(from: u64, end: u64, end_id: [u8; 32], raw: &[Vec<u8>], next: Option<u64>) -> Vec<u8> {
    use unicity_token::cbor::{
        encode_array, encode_byte_string, encode_null, encode_tag, encode_uint,
    };
    let refs: Vec<&[u8]> = raw.iter().map(Vec::as_slice).collect();
    encode_tag(
        39015,
        &encode_array(&[
            &encode_uint(1),
            &encode_uint(u64::from(net().id())),
            &encode_uint(0),
            &encode_uint(from),
            &encode_uint(end),
            &encode_byte_string(&end_id),
            &encode_array(&refs),
            &next.map_or_else(encode_null, encode_uint),
        ]),
    )
}

/// The entry `name` with a bit flipped in its first signature: it decodes, it does not verify.
fn damaged_entry(name: &str) -> Vec<u8> {
    let e = entry(name);
    let bytes = e.to_cbor();
    let sig = e.signatures.as_ref().unwrap()[0].1.clone();
    let at = bytes
        .windows(sig.len())
        .position(|w| w == sig.as_slice())
        .unwrap();
    let mut bad = bytes;
    bad[at + 10] ^= 1;
    bad
}

#[test]
fn a_refused_entry_in_the_middle_of_a_paged_range_drops_the_snapshot_for_the_next_source() {
    let mut h = genesis_only();
    // source 0: page 1 is good and announces end 4; page 2 (from 3) carries a damaged entry
    let p1 = page(2, 4, [8; 32], &["epoch2-signed-abc"], Some(3));
    let p2 = page_raw(
        3,
        4,
        [8; 32],
        &[damaged_entry("epoch3-signed-abc")],
        Some(4),
    );
    let a = Script::new(move |i, _| Ok(if i == 0 { p1.clone() } else { p2.clone() }));
    let b = fixed(case("range of the tip entry only"));
    assert_eq!(
        update(&mut h, &[src(&a), src(&b)], &UpdateOptions::default()),
        Ok(2)
    );
    assert_eq!(h.latest().epoch, 3);
    // source 1 is asked from the epoch after the held prefix and with no snapshot of source 0's announcement
    let first = b.seen.borrow()[0].clone();
    assert_eq!((first.from_epoch, first.snapshot), (3, None));
}

#[test]
fn a_frozen_snapshot_is_checked_on_the_later_pages() {
    // page 1 (from 2, entry 2, cursor 3) announces end 4 with id X; page 2 (from 3, entry 3, cursor 4) then announces end 4 with id Y or end 5
    for (end2, id2, what) in [
        (4u64, [9u8; 32], "another end id"),
        (5, [8u8; 32], "another end epoch"),
    ] {
        let mut h = genesis_only();
        let p1 = page(2, 4, [8; 32], &["epoch2-signed-abc"], Some(3));
        let p2 = page(3, end2, id2, &["epoch3-signed-abc"], Some(4));
        let s = Script::new(move |i, _| Ok(if i == 0 { p1.clone() } else { p2.clone() }));
        let e = update(
            &mut h,
            &[src(&s)],
            &UpdateOptions {
                rounds: 1,
                ..UpdateOptions::default()
            },
        )
        .unwrap_err();
        assert_eq!(
            e.causes,
            vec![UpdateCause::NotContinuing { source: 0 }],
            "{what}"
        );
        // the authenticated entry of page 1 is kept; page 2 was not applied
        assert_eq!((e.appended, h.latest().epoch), (1, 2), "{what}");
        // the second request echoed page 1's announcement
        assert_eq!(
            s.seen.borrow()[1].snapshot,
            Some(Snapshot {
                end: 4,
                entry_id: [8; 32]
            })
        );
    }
    // the same announcement on both pages is followed to the end of the cursor chain: page 2 identical, page 3 the tip
    let mut h = genesis_only();
    let p1 = page(2, 4, [8; 32], &["epoch2-signed-abc"], Some(3));
    let p2 = page(3, 4, [8; 32], &["epoch3-signed-abc"], Some(4));
    let s = Script::new(move |i, _| Ok(if i == 0 { p1.clone() } else { p2.clone() }));
    // page 3 does not exist: the source is asked from 4 and has nothing; with a snapshot a status-3 page is not "current"
    let e = update(
        &mut h,
        &[src(&s)],
        &UpdateOptions {
            rounds: 1,
            ..UpdateOptions::default()
        },
    )
    .unwrap_err();
    assert_eq!(e.appended, 2);
    assert_eq!(h.latest().epoch, 3);
}

/// A hand-built page of a status other than OK (advisory `from` and `end`, no entries, no cursor).
fn status_page(status: u64, from: u64, end: u64) -> Vec<u8> {
    use unicity_token::cbor::{encode_array, encode_null, encode_tag, encode_uint};
    encode_tag(
        39015,
        &encode_array(&[
            &encode_uint(1),
            &encode_uint(u64::from(net().id())),
            &encode_uint(status),
            &encode_uint(from),
            &encode_uint(end),
            &encode_null(),
            &encode_array(&[]),
            &encode_null(),
        ]),
    )
}

#[test]
fn nothing_newer_means_a_tip_below_the_requested_epoch_and_only_without_a_snapshot() {
    let one_round = UpdateOptions {
        rounds: 1,
        ..UpdateOptions::default()
    };
    // a tip equal to the requested epoch is not "nothing newer": the source has that epoch and did not serve it
    let mut h = genesis_only();
    let s = fixed(status_page(3, 2, 2));
    let e = update(&mut h, &[src(&s)], &one_round).unwrap_err();
    assert_eq!(
        e.causes,
        vec![UpdateCause::Status {
            source: 0,
            status: TrustBaseStatus::NotYetAvailable
        }]
    );
    // a tip below it is
    let s = fixed(status_page(3, 2, 1));
    assert_eq!(update(&mut h, &[src(&s)], &one_round), Ok(0));

    // in the middle of a paged range (a snapshot is frozen) the same answer is not "current"
    let mut h = genesis_only();
    let p1 = page(2, 4, [8; 32], &["epoch2-signed-abc"], Some(3));
    let lag = status_page(3, 3, 2);
    let s = Script::new(move |i, _| Ok(if i == 0 { p1.clone() } else { lag.clone() }));
    let e = update(&mut h, &[src(&s)], &one_round).unwrap_err();
    assert_eq!(e.appended, 1);
    assert_eq!(
        e.causes,
        vec![UpdateCause::Status {
            source: 0,
            status: TrustBaseStatus::NotYetAvailable
        }]
    );
}

#[test]
fn unavailable_is_asked_again_like_busy() {
    let mut h = genesis_only();
    let s = fixed(case("status 7 (Unavailable), nothing else"));
    let e = update(&mut h, &[src(&s)], &UpdateOptions::default()).unwrap_err();
    assert_eq!(s.count(), 2);
    assert_eq!(e.failure, UpdateFailure::NoneServed);
}

#[test]
fn an_honest_source_refusing_a_fake_snapshot_is_asked_again_without_it() {
    // page 1 (from some hostile source or a stale one) announces end 4 with a fake id; the echo is refused as another history; the same source
    // then serves from the tip without a snapshot
    let mut h = genesis_only();
    let p1 = page(2, 4, [8; 32], &["epoch2-signed-abc"], Some(3));
    let mismatch = case("status 4 (HistoryMismatch), nothing else");
    let tip = case("range of the tip entry only");
    let s = Script::new(move |i, r| {
        Ok(match i {
            0 => p1.clone(),
            _ if r.snapshot.is_some() => mismatch.clone(),
            _ => tip.clone(),
        })
    });
    let one_round = UpdateOptions {
        rounds: 1,
        ..UpdateOptions::default()
    };
    assert_eq!(update(&mut h, &[src(&s)], &one_round), Ok(2));
    assert_eq!(h.latest().epoch, 3);
    let seen = s.seen.borrow();
    assert_eq!(seen.len(), 3);
    assert_eq!(seen[0].snapshot, None);
    assert!(seen[1].snapshot.is_some());
    assert_eq!((seen[2].from_epoch, seen[2].snapshot), (3, None));
    drop(seen);

    // control: a mismatch without a snapshot is still final (one request, then no more)
    let mut h = genesis_only();
    let s = fixed(case("status 4 (HistoryMismatch), nothing else"));
    let e = update(&mut h, &[src(&s)], &UpdateOptions::default()).unwrap_err();
    assert_eq!(s.count(), 1);
    assert_eq!(e.failure, UpdateFailure::NoneServed);
}

#[test]
fn no_source_and_cancellation() {
    let mut h = genesis_only();
    let e = update(&mut h, &[], &UpdateOptions::default()).unwrap_err();
    assert_eq!(e.failure, UpdateFailure::NoSource);

    let s = fixed(case("range from epoch 2 to the tip"));
    let stop = Cell::new(false);
    let cancelled = || stop.get();
    let opts = UpdateOptions {
        cancelled: Some(&cancelled),
        ..UpdateOptions::default()
    };
    stop.set(true);
    let e = update(&mut h, &[src(&s)], &opts).unwrap_err();
    assert_eq!(
        (e.failure, e.appended, s.count()),
        (UpdateFailure::Cancelled, 0, 0)
    );
}

// ---- verify-update-retry ------------------------------------------------------------------------------------------

fn signer(node: &str) -> Secp256k1Signer {
    let i = (node.as_bytes()[0] - b'a') + 1;
    Secp256k1Signer::from_bytes(&[i; 32]).unwrap()
}

fn seal(epoch: u64, round: u64, signers: &[&str]) -> UnicitySeal {
    let mut s = UnicitySeal {
        network_id: net(),
        root_chain_round_number: round,
        epoch,
        timestamp: 1_731_504_000,
        previous_hash: None,
        hash: vec![7; 32],
        signatures: Vec::new(),
    };
    let digest = s.calculate_hash();
    s.signatures = signers
        .iter()
        .map(|n| (n.to_string(), signer(n).sign(&digest).encode().to_vec()))
        .collect();
    s
}

fn check(h: &TrustBaseHistory, s: &UnicitySeal) -> Result<(), VerificationError> {
    SealSession::new(h).authenticate_seal(s)
}

#[test]
fn verify_with_update_fetches_only_for_the_missing_entry_and_retries_once() {
    let opts = UpdateOptions::default();
    let s2 = seal(2, 150, &["a", "b", "c"]);

    // verifies at once: the sources are not asked
    let mut h = genesis_only();
    let src_ok = fixed(case("range from epoch 2 to the tip"));
    let ok1 = seal(1, 50, &["a", "b", "c"]);
    assert_eq!(
        verify_with_update(&mut h, &[src(&src_ok)], &opts, |h| check(h, &ok1)),
        Ok(Ok(()))
    );
    assert_eq!(src_ok.count(), 0);

    // another failure is returned as it is, no fetch can help it
    let weak = seal(1, 50, &["a", "b"]);
    assert_eq!(
        verify_with_update(&mut h, &[src(&src_ok)], &opts, |h| check(h, &weak)),
        Ok(Err(VerificationError::QuorumNotMet))
    );
    assert_eq!(src_ok.count(), 0);

    // the missing entry: one update, one retry
    let runs = Cell::new(0);
    let r = verify_with_update(&mut h, &[src(&src_ok)], &opts, |h| {
        runs.set(runs.get() + 1);
        check(h, &s2)
    });
    assert_eq!(r, Ok(Ok(())));
    assert_eq!((runs.get(), src_ok.count(), h.latest().epoch), (2, 1, 3));

    // nothing newer: the first result stands (and verify ran once)
    let mut cur = genesis_only();
    let nothing = fixed(case(LAGGING));
    let s9 = seal(9, 900, &["a", "b", "c"]);
    let runs = Cell::new(0);
    // epoch 9 is missing; the only source says it has nothing from epoch 2 either (lagging at 1 < 2)
    let r = verify_with_update(&mut cur, &[src(&nothing)], &opts, |h| {
        runs.set(runs.get() + 1);
        check(h, &s9)
    });
    assert_eq!(
        r,
        Ok(Err(VerificationError::UnknownTrustEpoch { epoch: 9 }))
    );
    assert_eq!(runs.get(), 1);

    // an update that failed without helping is the outer error
    let mut cur = genesis_only();
    let dead = down();
    let r = verify_with_update(&mut cur, &[src(&dead)], &opts, |h| check(h, &s2));
    assert_eq!(r.unwrap_err().failure, UpdateFailure::NoneServed);
}

#[test]
fn a_later_page_failing_after_the_needed_entry_arrived_still_verifies() {
    let opts = UpdateOptions::default();
    let s2 = seal(2, 150, &["a", "b", "c"]);
    let mut h = genesis_only();
    let bad = fixed(damaged_page(3)); // epoch 2 arrives, epoch 3 is refused
    let r = verify_with_update(&mut h, &[src(&bad)], &opts, |h| check(h, &s2));
    assert_eq!(
        r,
        Ok(Ok(())),
        "the held prefix makes the verification possible"
    );
    assert_eq!(h.latest().epoch, 2);

    // ... but epoch 3's seal still lacks its entry: the update error surfaces
    let s3 = seal(3, 250, &["a", "b", "c"]);
    let mut h = genesis_only();
    let r = verify_with_update(&mut h, &[src(&bad)], &opts, |h| check(h, &s3));
    let e = r.unwrap_err();
    assert_eq!((e.failure, e.appended), (UpdateFailure::NoneServed, 1));
}
