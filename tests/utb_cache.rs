//! The Trust Base cache against the shared vectors (`tests/vectors/utb-cache/v1/vectors.json`)
//! and the store/session behaviours that need a scripted store.
//!
//! The vectors are generated from this file (`UTB_CACHE_UPDATE_VECTORS=1 cargo test --test
//! utb_cache`) from unsigned test keys (member i signs with 32 bytes of value i); every expected
//! outcome is written literally in `generate()`, never computed by the implementation under test.
#![cfg(all(feature = "std", feature = "client"))]

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use num_bigint::BigUint;
use serde_json::{json, Value};
use unicity_token::api::bft::trust_base_cache::*;
use unicity_token::api::bft::trust_base_history::BundleLimits;
use unicity_token::api::bft::{
    Appended, HistoryError, TrustBaseEntry, TrustBaseHistory, TrustBaseMember,
};
use unicity_token::api::NetworkId;
use unicity_token::cbor::{encode_array, encode_byte_string, encode_null, encode_tag, encode_uint};
use unicity_token::crypto::hash::sha256;
use unicity_token::crypto::signer::{Secp256k1Signer, Signer};

const VECTORS: &str = include_str!("vectors/utb-cache/v1/vectors.json");
const VECTORS_PATH: &str = "tests/vectors/utb-cache/v1/vectors.json";

// ---------------------------------------------------------------- helpers

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

fn signer(id: &str) -> Secp256k1Signer {
    let i = id.as_bytes()[0] - b'a' + 1;
    Secp256k1Signer::from_bytes(&[i; 32]).unwrap()
}

fn net(n: u16) -> NetworkId {
    NetworkId::new(n).unwrap()
}

fn members(ids: &[&str]) -> Vec<TrustBaseMember> {
    ids.iter()
        .map(|i| TrustBaseMember::new(*i, signer(i).public_key(), 1))
        .collect()
}

fn genesis(n: u16, ids: &[&str]) -> TrustBaseEntry {
    TrustBaseEntry::genesis(net(n), 1, 1, members(ids))
}

/// A successor of `prev` with the given committee, start offset and tag byte (state hash),
/// signed by `signers` of the predecessor's committee.
fn succ(
    prev: &TrustBaseEntry,
    ids: &[&str],
    bump: u64,
    tag: u8,
    signers: &[&str],
) -> TrustBaseEntry {
    let ms = members(ids);
    let total = ms.iter().map(|m| m.weight).sum::<u64>();
    let mut e = TrustBaseEntry::new(
        prev.network_id,
        prev.epoch + 1,
        prev.epoch_start + bump,
        ms,
        TrustBaseEntry::threshold_for(total).unwrap(),
        Some(vec![tag; 32]),
        None,
        prev.entry_id(),
    );
    for s in signers {
        e.sign(s, &signer(s));
    }
    e
}

fn mutate_sig(e: &TrustBaseEntry, who: &str, f: impl Fn(&mut [u8])) -> TrustBaseEntry {
    let mut e = e.clone();
    let sigs = e.signatures.as_mut().unwrap();
    let s = sigs.iter_mut().find(|(i, _)| i == who).unwrap();
    f(&mut s.1);
    e
}

fn high_s(sig: &mut [u8]) {
    let n = BigUint::parse_bytes(
        b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        16,
    )
    .unwrap();
    let s = BigUint::from_bytes_be(&sig[32..64]);
    let mut t = (n - s).to_bytes_be();
    while t.len() < 32 {
        t.insert(0, 0);
    }
    sig[32..64].copy_from_slice(&t);
    sig[64] ^= 1;
}

fn bundle_of(entries: &[&TrustBaseEntry]) -> Vec<u8> {
    let raw: Vec<Vec<u8>> = entries.iter().map(|e| e.to_cbor()).collect();
    raw_bundle(
        39015,
        entries[0].network_id.id().into(),
        entries[0].epoch,
        entries[entries.len() - 1].epoch,
        Some(entries[entries.len() - 1].entry_id()),
        &raw,
    )
}

fn raw_bundle(
    tag: u64,
    network: u64,
    from: u64,
    end: u64,
    end_id: Option<[u8; 32]>,
    items: &[Vec<u8>],
) -> Vec<u8> {
    let refs: Vec<&[u8]> = items.iter().map(Vec::as_slice).collect();
    let id = end_id.map_or_else(encode_null, |i| encode_byte_string(&i));
    let inner = encode_array(&[
        &encode_uint(1),
        &encode_uint(network),
        &encode_uint(0),
        &encode_uint(from),
        &encode_uint(end),
        &id,
        &encode_array(&refs),
        &encode_null(),
    ]);
    encode_tag(tag, &inner)
}

fn hx(b: &[u8]) -> String {
    hex::encode(b)
}

fn pin_of(entries: &[&TrustBaseEntry]) -> PinSpec {
    let bundle = bundle_of(entries);
    let last = entries[entries.len() - 1];
    PinSpec {
        network_id: last.network_id,
        genesis_epoch: entries[0].epoch,
        genesis_entry_id: entries[0].entry_id(),
        pinned_epoch: last.epoch,
        pinned_entry_id: last.entry_id(),
        bundle_sha256: sha256(&bundle).data().try_into().unwrap(),
        bundle,
    }
}

fn pin_json(p: &PinSpec) -> Value {
    json!({
        "network": p.network_id.id(),
        "genesisEpoch": p.genesis_epoch.to_string(),
        "genesisEntryId": hx(&p.genesis_entry_id),
        "pinnedEpoch": p.pinned_epoch.to_string(),
        "pinnedEntryId": hx(&p.pinned_entry_id),
        "bundleSha256": hx(&p.bundle_sha256),
        "bundle": hx(&p.bundle),
    })
}

fn pin_from(v: &Value) -> PinSpec {
    let id = |k: &str| -> [u8; 32] {
        hex::decode(v[k].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    };
    let epoch = |k: &str| v[k].as_str().unwrap().parse::<u64>().unwrap();
    PinSpec {
        network_id: net(v["network"].as_u64().unwrap() as u16),
        genesis_epoch: epoch("genesisEpoch"),
        genesis_entry_id: id("genesisEntryId"),
        pinned_epoch: epoch("pinnedEpoch"),
        pinned_entry_id: id("pinnedEntryId"),
        bundle_sha256: id("bundleSha256"),
        bundle: hex::decode(v["bundle"].as_str().unwrap()).unwrap(),
    }
}

// ---------------------------------------------------------------- the generator

struct World {
    a: Vec<TrustBaseEntry>, // a[0] = epoch 1 .. a[5] = epoch 6
    a3w: TrustBaseEntry,
    a3hs: TrustBaseEntry,
    a3bad: TrustBaseEntry,
    a2bad: TrustBaseEntry,
    f3: TrustBaseEntry,
    f4: TrustBaseEntry,
    f4bad: TrustBaseEntry,
    f3bad: TrustBaseEntry,
    g: Vec<TrustBaseEntry>,
    n8: Vec<TrustBaseEntry>,
}

fn world() -> World {
    let abcd = ["a", "b", "c", "d"];
    let abce = ["a", "b", "c", "e"];
    let a1 = genesis(7, &abcd);
    let a2 = succ(&a1, &abcd, 100, 2, &["a", "b", "c"]);
    let a3 = succ(&a2, &abcd, 100, 3, &["a", "b", "c"]);
    // epoch 4 rotates the committee (d out, e in), signed by the old committee
    let a4 = succ(&a3, &abce, 100, 4, &["a", "b", "c"]);
    let a5 = succ(&a4, &abce, 100, 5, &["a", "b", "e"]);
    let a6 = succ(&a5, &abce, 100, 6, &["a", "c", "e"]);
    let a3w = succ(&a2, &abcd, 100, 3, &["a", "b", "d"]);
    assert_eq!(a3w.entry_id(), a3.entry_id());
    let a3hs = mutate_sig(&a3, "c", high_s);
    let a3bad = mutate_sig(&succ(&a2, &abcd, 100, 3, &["a", "b", "c", "d"]), "d", |s| {
        s[5] ^= 1
    });
    let a2bad = mutate_sig(&succ(&a1, &abcd, 100, 2, &["a", "b", "c", "d"]), "d", |s| {
        s[5] ^= 1
    });
    let f3 = succ(&a2, &abcd, 101, 33, &["a", "b", "c"]);
    let f4 = succ(&a3, &abce, 101, 44, &["a", "b", "c"]);
    let f4bad = mutate_sig(
        &succ(&a3, &abce, 101, 44, &["a", "b", "c", "d"]),
        "d",
        |s| s[5] ^= 1,
    );
    let f3bad = mutate_sig(
        &succ(&a2, &abcd, 101, 33, &["a", "b", "c", "d"]),
        "d",
        |s| s[5] ^= 1,
    );
    let g1 = genesis(7, &["a", "b", "c"]);
    let g2 = succ(&g1, &["a", "b", "c"], 100, 2, &["a", "b", "c"]);
    let g3 = succ(&g2, &["a", "b", "c"], 100, 3, &["a", "b", "c"]);
    let m1 = genesis(8, &abcd);
    let m2 = succ(&m1, &abcd, 100, 2, &["a", "b", "c"]);
    let m3 = succ(&m2, &abcd, 100, 3, &["a", "b", "c"]);
    World {
        a: vec![a1, a2, a3, a4, a5, a6],
        a3w,
        a3hs,
        a3bad,
        a2bad,
        f3,
        f4,
        f4bad,
        f3bad,
        g: vec![g1, g2, g3],
        n8: vec![m1, m2, m3],
    }
}

fn generate() -> Value {
    let w = world();
    let a = &w.a;
    let entries: Vec<(&str, &TrustBaseEntry)> = vec![
        ("A1", &a[0]),
        ("A2", &a[1]),
        ("A3", &a[2]),
        ("A4", &a[3]),
        ("A5", &a[4]),
        ("A6", &a[5]),
        ("A3-witness-abd", &w.a3w),
        ("A3-high-s", &w.a3hs),
        ("A3-bad-extra-signature", &w.a3bad),
        ("A2-bad-extra-signature", &w.a2bad),
        ("F3", &w.f3),
        ("F4", &w.f4),
        ("F4-bad-extra-signature", &w.f4bad),
        ("F3-bad-extra-signature", &w.f3bad),
        ("G1", &w.g[0]),
        ("G2", &w.g[1]),
        ("G3", &w.g[2]),
        ("N8-1", &w.n8[0]),
        ("N8-2", &w.n8[1]),
        ("N8-3", &w.n8[2]),
    ];
    let entries_json: Vec<Value> = entries
        .iter()
        .map(|(n, e)| json!({"name": n, "hex": hx(&e.to_cbor()), "entryId": hx(&e.entry_id()), "epoch": e.epoch.to_string(), "network": e.network_id.id()}))
        .collect();

    // noncanonical entry: the network id 7 in a two-byte form
    let mut nc = a[1].to_cbor();
    assert_eq!(&nc[..5], &[0xd9, 0x98, 0x58, 0x8a, 0x02]);
    assert_eq!(nc[5], 0x07);
    nc.splice(5..6, [0x18, 0x07]);

    let mut bundles: Vec<(String, Vec<u8>, Vec<[u8; 32]>)> = Vec::new();
    let mut add =
        |name: &str, b: Vec<u8>, ids: Vec<[u8; 32]>| bundles.push((name.to_string(), b, ids));
    let ids = |es: &[&TrustBaseEntry]| es.iter().map(|e| e.entry_id()).collect::<Vec<_>>();
    let a1_2 = [&a[0], &a[1]];
    let a1_3 = [&a[0], &a[1], &a[2]];
    let a1_4 = [&a[0], &a[1], &a[2], &a[3]];
    let a1_5 = [&a[0], &a[1], &a[2], &a[3], &a[4]];
    let a1_6 = [&a[0], &a[1], &a[2], &a[3], &a[4], &a[5]];
    add("A1", bundle_of(&[&a[0]]), ids(&[&a[0]]));
    add("A1-2", bundle_of(&a1_2), ids(&a1_2));
    add("A1-3", bundle_of(&a1_3), ids(&a1_3));
    add("A1-4", bundle_of(&a1_4), ids(&a1_4));
    add("A1-5", bundle_of(&a1_5), ids(&a1_5));
    add("A1-6", bundle_of(&a1_6), ids(&a1_6));
    let a1_3w = [&a[0], &a[1], &w.a3w];
    add("A1-3-witness-abd", bundle_of(&a1_3w), ids(&a1_3w));
    let a1_4w = [&a[0], &a[1], &w.a3w, &a[3]];
    add("A1-4-witness-abd", bundle_of(&a1_4w), ids(&a1_4w));
    let f_4 = [&a[0], &a[1], &a[2], &w.f4];
    add("F1-4", bundle_of(&f_4), ids(&f_4));
    let f_3 = [&a[0], &a[1], &w.f3];
    add("F1-3", bundle_of(&f_3), ids(&f_3));
    let g1_3 = [&w.g[0], &w.g[1], &w.g[2]];
    add("G1-3", bundle_of(&g1_3), ids(&g1_3));
    let n8 = [&w.n8[0], &w.n8[1], &w.n8[2]];
    add("N8-1-3", bundle_of(&n8), ids(&n8));
    let bad3 = [&a[0], &a[1], &w.a3bad];
    add("A1-3-bad-extra-signature", bundle_of(&bad3), ids(&bad3));
    let bad2 = [&a[0], &w.a2bad, &a[2]];
    add(
        "A1-3-bad-extra-signature-epoch2",
        bundle_of(&bad2),
        ids(&bad2),
    );
    let hs3 = [&a[0], &a[1], &w.a3hs];
    add("A1-3-high-s", bundle_of(&hs3), ids(&hs3));
    let good3 = bundle_of(&a1_3);
    add("truncated", good3[..good3.len() - 7].to_vec(), vec![]);
    let mut corrupt = good3.clone();
    let mid = corrupt.len() / 2;
    corrupt[mid] ^= 0x55;
    add("corrupt", corrupt, vec![]);
    let items: Vec<Vec<u8>> = a1_3.iter().map(|e| e.to_cbor()).collect();
    add(
        "wrong-tag",
        raw_bundle(39016, 7, 1, 3, Some(a[2].entry_id()), &items),
        vec![],
    );
    add(
        "wrong-network-header",
        raw_bundle(39015, 8, 1, 3, Some(a[2].entry_id()), &items),
        vec![],
    );
    add(
        "wrong-from-epoch",
        raw_bundle(39015, 7, 2, 3, Some(a[2].entry_id()), &items),
        vec![],
    );
    add(
        "wrong-end-epoch",
        raw_bundle(39015, 7, 1, 4, Some(a[2].entry_id()), &items),
        vec![],
    );
    add("null-tip", raw_bundle(39015, 7, 1, 3, None, &items), vec![]);
    add(
        "wrong-tip-id",
        raw_bundle(39015, 7, 1, 3, Some(a[1].entry_id()), &items),
        vec![],
    );
    let dup = vec![items[0].clone(), items[1].clone(), items[1].clone()];
    add(
        "duplicate",
        raw_bundle(39015, 7, 1, 3, Some(a[1].entry_id()), &dup),
        vec![],
    );
    let gap = vec![items[0].clone(), a[2].to_cbor()];
    add(
        "gap",
        raw_bundle(39015, 7, 1, 3, Some(a[2].entry_id()), &gap),
        vec![],
    );
    let ncb = vec![items[0].clone(), nc.clone(), items[2].clone()];
    add(
        "noncanonical-entry",
        raw_bundle(39015, 7, 1, 3, Some(a[2].entry_id()), &ncb),
        vec![],
    );
    add("empty-bytes", vec![], vec![]);
    let bundles_json: Vec<Value> = bundles
        .iter()
        .map(|(n, b, ids)| json!({"name": n, "hex": hx(b), "entryIds": ids.iter().map(|i| hx(i)).collect::<Vec<_>>()}))
        .collect();

    // pins
    let mut pins: Vec<Value> = Vec::new();
    for (name, es) in [
        ("A1-3", a1_3.to_vec()),
        ("A1-5", a1_5.to_vec()),
        ("A1", vec![&a[0]]),
        ("A1-6", a1_6.to_vec()),
        ("G1-3", g1_3.to_vec()),
    ] {
        let mut j = pin_json(&pin_of(&es));
        j["name"] = json!(name);
        j["valid"] = json!(true);
        pins.push(j);
    }
    let mut invalid = |name: &str, mut p: PinSpec, edit: &dyn Fn(&mut PinSpec)| {
        edit(&mut p);
        let mut j = pin_json(&p);
        j["name"] = json!(name);
        j["valid"] = json!(false);
        j["error"] = json!("ReleasePinInvalid");
        pins.push(j);
    };
    invalid("bad-sha", pin_of(&a1_3), &|p| p.bundle_sha256[0] ^= 1);
    invalid("wrong-tip-id", pin_of(&a1_3), &|p| {
        p.pinned_entry_id[0] ^= 1
    });
    invalid("wrong-genesis-id", pin_of(&a1_3), &|p| {
        p.genesis_entry_id[0] ^= 1
    });
    invalid("epoch-mismatch", pin_of(&a1_3), &|p| p.pinned_epoch = 4);
    invalid("genesis-epoch-mismatch", pin_of(&a1_3), &|p| {
        p.genesis_epoch = 2
    });
    invalid("network-mismatch", pin_of(&a1_3), &|p| {
        p.network_id = net(8)
    });
    invalid("tip-short-of-bundle", pin_of(&a1_3), &|p| {
        let b = bundle_of(&a1_4);
        p.bundle_sha256 = sha256(&b).data().try_into().unwrap();
        p.bundle = b;
    });
    let badpin = bundle_of(&bad3);
    invalid("bad-predecessor-signature", pin_of(&a1_3), &|p| {
        p.bundle = badpin.clone();
        p.bundle_sha256 = sha256(&badpin).data().try_into().unwrap();
        p.pinned_entry_id = bad3[2].entry_id();
    });
    let highs = bundle_of(&hs3);
    invalid("high-s-signature", pin_of(&a1_3), &|p| {
        p.bundle = highs.clone();
        p.bundle_sha256 = sha256(&highs).data().try_into().unwrap();
    });
    let nullp = raw_bundle(39015, 7, 1, 3, None, &items);
    invalid("null-tip-bundle", pin_of(&a1_3), &|p| {
        p.bundle = nullp.clone();
        p.bundle_sha256 = sha256(&nullp).data().try_into().unwrap();
    });

    // open cases: (name, pin, cache, store, tipEpoch, tipEntry, diagnostics, flushNeeded)
    let tip = |h: &[&TrustBaseEntry]| {
        let e = h[h.len() - 1];
        (e.epoch.to_string(), hx(&e.entry_id()))
    };
    let open_cell = std::cell::RefCell::new(Vec::<Value>::new());
    #[allow(clippy::too_many_arguments)]
    let oc_full = |name: &str,
                   pin: &str,
                   cache: Value,
                   store: Value,
                   limits: Value,
                   t: (String, String),
                   diag: &[&str],
                   flush: bool| {
        open_cell.borrow_mut().push(json!({
            "name": name, "pin": pin, "cache": cache, "store": store, "limits": limits,
            "expect": {"tipEpoch": t.0, "tipEntryId": t.1, "diagnostics": diag, "flushNeeded": flush}
        }));
    };
    let oc =
        |name: &str,
         pin: &str,
         cache: Value,
         store: Value,
         t: (String, String),
         diag: &[&str],
         flush: bool| { oc_full(name, pin, cache, store, Value::Null, t, diag, flush) };
    let a15_len = bundle_of(&a1_5).len();
    let cb = |n: &str| json!({"bundle": n});
    let none = Value::Null;
    oc(
        "absent",
        "A1-3",
        none.clone(),
        none.clone(),
        tip(&a1_3),
        &[],
        false,
    );
    oc(
        "equal",
        "A1-3",
        cb("A1-3"),
        none.clone(),
        tip(&a1_3),
        &[],
        false,
    );
    oc(
        "shorter",
        "A1-3",
        cb("A1-2"),
        none.clone(),
        tip(&a1_3),
        &[],
        true,
    );
    oc(
        "genesis-only",
        "A1-3",
        cb("A1"),
        none.clone(),
        tip(&a1_3),
        &[],
        true,
    );
    oc(
        "older-sdk-longer-kept",
        "A1-3",
        cb("A1-5"),
        none.clone(),
        tip(&a1_5),
        &[],
        false,
    );
    oc(
        "older-sdk-longest-kept",
        "A1-3",
        cb("A1-6"),
        none.clone(),
        tip(&a1_6[..]),
        &[],
        false,
    );
    oc(
        "pin-bump-extends-cache",
        "A1-5",
        cb("A1-3"),
        none.clone(),
        tip(&a1_5),
        &[],
        true,
    );
    oc(
        "pin-bump-equal",
        "A1-5",
        cb("A1-5"),
        none.clone(),
        tip(&a1_5),
        &[],
        false,
    );
    oc(
        "pin-bump-longer-cache",
        "A1-5",
        cb("A1-6"),
        none.clone(),
        tip(&a1_6[..]),
        &[],
        false,
    );
    oc(
        "divergent-cache-loses-to-newer-pin",
        "A1-5",
        cb("F1-4"),
        none.clone(),
        tip(&a1_5),
        &["CacheRejected:pinMismatch"],
        false,
    );
    oc(
        "divergent-before-pin",
        "A1-3",
        cb("F1-3"),
        none.clone(),
        tip(&a1_3),
        &["CacheRejected:pinMismatch"],
        false,
    );
    oc(
        "longer-cache-on-another-post-pin-branch-is-held",
        "A1-3",
        cb("F1-4"),
        none.clone(),
        tip(&[&a[0], &a[1], &a[2], &w.f4]),
        &[],
        false,
    );
    oc(
        "same-id-other-witness",
        "A1-3",
        cb("A1-3-witness-abd"),
        none.clone(),
        tip(&a1_3),
        &[],
        false,
    );
    oc(
        "other-genesis",
        "A1-3",
        cb("G1-3"),
        none.clone(),
        tip(&a1_3),
        &["CacheRejected:wrongGenesis"],
        false,
    );
    oc(
        "other-network",
        "A1-3",
        cb("N8-1-3"),
        none.clone(),
        tip(&a1_3),
        &["CacheRejected:wrongNetwork"],
        false,
    );
    for (case, name) in [
        ("truncated", "truncated"),
        ("corrupt", "corrupt"),
        ("wrong-tag", "wrong-tag"),
        ("wrong-from-epoch", "wrong-from-epoch"),
        ("wrong-end-epoch", "wrong-end-epoch"),
        ("null-tip", "null-tip"),
        ("wrong-tip-id", "wrong-tip-id"),
        ("duplicate", "duplicate"),
        ("gap", "gap"),
        ("noncanonical-entry", "noncanonical-entry"),
        ("bad-extra-signature", "A1-3-bad-extra-signature"),
        (
            "bad-extra-signature-epoch2",
            "A1-3-bad-extra-signature-epoch2",
        ),
        ("high-s", "A1-3-high-s"),
        ("empty-bytes", "empty-bytes"),
    ] {
        oc(
            case,
            "A1-3",
            cb(name),
            none.clone(),
            tip(&a1_3),
            &["CacheRejected:malformed"],
            false,
        );
    }
    oc(
        "wrong-network-header",
        "A1-3",
        cb("wrong-network-header"),
        none.clone(),
        tip(&a1_3),
        &["CacheRejected:wrongNetwork"],
        false,
    );
    oc(
        "store-unreadable",
        "A1-3",
        none.clone(),
        json!("unreadable"),
        tip(&a1_3),
        &["CacheUnavailable"],
        false,
    );
    oc(
        "store-oversize",
        "A1-3",
        none.clone(),
        json!("oversize"),
        tip(&a1_3),
        &["CacheRejected:oversize"],
        false,
    );

    // budgets: a valid longer history over the budget is oversize, not malformed
    let lim = |entries: Option<usize>, bytes: Option<usize>| json!({"maxEntries": entries, "maxBundleBytes": bytes, "maxEntryBytes": Option::<usize>::None});
    let max_entry = a1_3.iter().map(|e| e.to_cbor().len()).max().unwrap();
    let elim = |n: usize| json!({"maxEntries": Option::<usize>::None, "maxBundleBytes": Option::<usize>::None, "maxEntryBytes": n});
    let ig = || json!("ignoresBudget");
    oc_full(
        "over-entry-budget",
        "A1-3",
        cb("A1-5"),
        none.clone(),
        lim(Some(4), None),
        tip(&a1_3),
        &["CacheRejected:oversize"],
        false,
    );
    oc_full(
        "over-byte-budget-store-does-not-enforce",
        "A1-3",
        cb("A1-5"),
        ig(),
        lim(None, Some(a15_len - 1)),
        tip(&a1_3),
        &["CacheRejected:oversize"],
        false,
    );
    oc_full(
        "at-the-entry-budget",
        "A1-3",
        cb("A1-5"),
        none.clone(),
        lim(Some(5), None),
        tip(&a1_5),
        &[],
        false,
    );
    oc_full(
        "at-the-byte-budget",
        "A1-3",
        cb("A1-5"),
        ig(),
        lim(None, Some(a15_len)),
        tip(&a1_5),
        &[],
        false,
    );
    // per-entry budget: the genesis-only pin fits (a genesis carries no signatures), the cache's
    // successors do not
    assert!(a[0].to_cbor().len() < max_entry);
    oc_full(
        "over-entry-bytes-budget",
        "A1",
        cb("A1-3"),
        none.clone(),
        elim(max_entry - 1),
        tip(&[&a[0]]),
        &["CacheRejected:oversize"],
        false,
    );
    oc_full(
        "at-the-entry-bytes-budget",
        "A1",
        cb("A1-3"),
        none.clone(),
        elim(max_entry),
        tip(&a1_3),
        &[],
        false,
    );
    oc(
        "longer-cache-keeps-the-embedded-witnesses",
        "A1-3",
        cb("A1-4-witness-abd"),
        none.clone(),
        tip(&a1_4),
        &[],
        false,
    );
    oc(
        "longer-cache-other-witness-on-the-last-pinned-entry-only",
        "A1-3",
        cb("A1-4"),
        none.clone(),
        tip(&a1_4),
        &[],
        false,
    );
    let mut open = open_cell.into_inner();
    // the session exports the embedded witnesses followed by the cache's later entries
    for o in open.iter_mut() {
        let name = o["name"].as_str().unwrap().to_string();
        let export = match name.as_str() {
            "longer-cache-keeps-the-embedded-witnesses" => "A1-4",
            "longer-cache-other-witness-on-the-last-pinned-entry-only" => "A1-4",
            "older-sdk-longer-kept" => "A1-5",
            "same-id-other-witness" => "A1-3",
            _ => continue,
        };
        o["expect"]["exportBundle"] = json!(export);
    }

    // flush cases: open, offer each entry, flush once, compare the stored bytes
    let mut flush = Vec::new();
    #[allow(clippy::too_many_arguments)]
    let mut fc = |name: &str,
                  pin: &str,
                  cache: Value,
                  limits: Value,
                  store: Value,
                  offers: &[&str],
                  result: &str,
                  stored: &str| {
        flush.push(json!({
            "name": name, "pin": pin, "cache": cache, "limits": limits, "store": store, "offers": offers,
            "expect": {"result": result, "stored": stored}
        }));
    };
    let nl = json!({"maxEntries": null, "maxBundleBytes": null});
    let el = elim(max_entry - 1);
    let l4 = json!({"maxEntries": 4, "maxBundleBytes": null});
    let lb = json!({"maxEntries": null, "maxBundleBytes": a15_len - 1});
    let ig = json!("ignoresBudget");
    // blocker 1: a valid history over the budget is never rewritten shorter
    fc(
        "oversize-entries-is-not-rewritten",
        "A1-3",
        cb("A1-5"),
        l4.clone(),
        none.clone(),
        &[],
        "pending:Oversize",
        "unchanged",
    );
    fc(
        "oversize-entries-is-not-rewritten-when-dirty",
        "A1-3",
        cb("A1-5"),
        l4,
        none.clone(),
        &["A4"],
        "pending:Oversize",
        "unchanged",
    );
    fc(
        "oversize-bytes-is-not-rewritten",
        "A1-3",
        cb("A1-5"),
        lb,
        ig,
        &["A4"],
        "pending:Oversize",
        "unchanged",
    );
    fc(
        "oversize-entry-bytes-is-not-rewritten",
        "A1",
        cb("A1-3"),
        el,
        none.clone(),
        &[],
        "pending:Oversize",
        "unchanged",
    );
    // blocker 2: an authenticated chain diverging before or at the checkpoint is not overwritten
    fc(
        "fork-before-the-pin-is-not-overwritten",
        "A1-3",
        cb("F1-3"),
        nl.clone(),
        none.clone(),
        &[],
        "pending:PinMismatch",
        "unchanged",
    );
    fc(
        "fork-before-the-pin-is-not-overwritten-when-dirty",
        "A1-3",
        cb("F1-3"),
        nl.clone(),
        none.clone(),
        &["A4"],
        "pending:PinMismatch",
        "unchanged",
    );
    fc(
        "fork-below-a-newer-pin-is-not-overwritten",
        "A1-5",
        cb("F1-4"),
        nl.clone(),
        none.clone(),
        &[],
        "pending:PinMismatch",
        "unchanged",
    );
    // damaged or foreign caches are replaced at the observed revision
    fc(
        "malformed-is-replaced",
        "A1-3",
        cb("corrupt"),
        nl.clone(),
        none.clone(),
        &["A4"],
        "saved:wrote",
        "A1-4",
    );
    fc(
        "malformed-is-replaced-even-when-clean",
        "A1-3",
        cb("truncated"),
        nl.clone(),
        none.clone(),
        &[],
        "saved:wrote",
        "A1-3",
    );
    fc(
        "other-genesis-is-replaced",
        "A1-3",
        cb("G1-3"),
        nl.clone(),
        none.clone(),
        &["A4"],
        "saved:wrote",
        "A1-4",
    );
    fc(
        "other-network-is-replaced",
        "A1-3",
        cb("N8-1-3"),
        nl.clone(),
        none.clone(),
        &["A4"],
        "saved:wrote",
        "A1-4",
    );
    // ordinary saves
    fc(
        "shorter-cache-is-upgraded",
        "A1-3",
        cb("A1-2"),
        nl.clone(),
        none.clone(),
        &[],
        "saved:wrote",
        "A1-3",
    );
    fc(
        "longer-cache-is-kept",
        "A1-3",
        cb("A1-5"),
        nl.clone(),
        none.clone(),
        &[],
        "saved:noop",
        "unchanged",
    );
    fc(
        "equal-cache-other-witness-is-not-rewritten",
        "A1-3",
        cb("A1-3-witness-abd"),
        nl.clone(),
        none.clone(),
        &[],
        "saved:noop",
        "unchanged",
    );
    fc(
        "absent-and-clean-writes-nothing",
        "A1-3",
        none.clone(),
        nl.clone(),
        none.clone(),
        &[],
        "saved:noop",
        "absent",
    );
    fc(
        "absent-then-append-writes-the-bundle",
        "A1-3",
        none.clone(),
        nl.clone(),
        none.clone(),
        &["A4", "A5"],
        "saved:wrote",
        "A1-5",
    );
    fc(
        "store-suffix-is-imported-not-lost",
        "A1-3",
        cb("A1-4"),
        nl.clone(),
        none.clone(),
        &["A4"],
        "saved:noop",
        "unchanged",
    );
    // a conflicted session never writes, whatever the store holds
    fc(
        "conflicted-session-never-flushes-empty-store",
        "A1-3",
        none.clone(),
        nl.clone(),
        none.clone(),
        &["A4", "F4"],
        "pending:HistoryConflicted",
        "absent",
    );
    fc(
        "conflicted-session-never-flushes-over-a-cache",
        "A1-3",
        cb("A1-3"),
        nl.clone(),
        none.clone(),
        &["A4", "F4"],
        "pending:HistoryConflicted",
        "unchanged",
    );
    fc(
        "stored-fork-after-the-pin-latches-and-stays",
        "A1-3",
        cb("A1-4"),
        nl.clone(),
        none.clone(),
        &["F4"],
        "pending:HistoryConflicted",
        "unchanged",
    );

    // a clean flush does not read the store: a longer suffix that appeared after open is neither
    // imported nor written over
    flush.push(json!({
        "name": "clean-flush-does-not-read", "pin": "A1-3", "cache": cb("A1-3"), "limits": nl.clone(),
        "store": none, "storeAfterOpen": cb("A1-5"), "offers": Vec::<&str>::new(),
        "expect": {"result": "saved:noop", "stored": "unchanged", "tipEpoch": "3"}
    }));
    flush.push(json!({
        "name": "clean-flush-does-not-detect-a-stored-fork", "pin": "A1-3", "cache": cb("A1-4"), "limits": nl.clone(),
        "store": none, "storeAfterOpen": cb("F1-4"), "offers": Vec::<&str>::new(),
        "expect": {"result": "saved:noop", "stored": "unchanged", "tipEpoch": "4"}
    }));
    flush.push(json!({
        "name": "damage-between-open-and-flush-is-reported", "pin": "A1-3", "cache": cb("A1-3"),
        "limits": nl.clone(), "store": none, "storeAfterOpen": cb("corrupt"), "offers": ["A4"],
        "expect": {"result": "saved:wrote", "stored": "A1-4"}
    }));
    for f in flush.iter_mut() {
        let diags: &[&str] = match f["name"].as_str().unwrap() {
            "malformed-is-replaced"
            | "malformed-is-replaced-even-when-clean"
            | "damage-between-open-and-flush-is-reported" => &["CacheRejected:malformed"],
            "other-genesis-is-replaced" => &["CacheRejected:wrongGenesis"],
            "other-network-is-replaced" => &["CacheRejected:wrongNetwork"],
            _ => &[],
        };
        f["expect"]["diagnostics"] = json!(diags);
    }

    // offer cases
    let mut offer = Vec::new();
    let mut of = |name: &str,
                  pin: &str,
                  cache: Value,
                  offers: &[&str],
                  results: &[&str],
                  conflicted: bool,
                  tip_epoch: &str| {
        offer.push(json!({
            "name": name, "pin": pin, "cache": cache, "offers": offers,
            "expect": {"results": results, "conflicted": conflicted, "tipEpoch": tip_epoch}
        }));
    };
    of(
        "extend",
        "A1-3",
        none.clone(),
        &["A4", "A5"],
        &["appended", "appended"],
        false,
        "5",
    );
    of(
        "repeat-and-other-witness",
        "A1-3",
        none.clone(),
        &["A3", "A3-witness-abd", "A2"],
        &["noop", "noop", "noop"],
        false,
        "3",
    );
    of(
        "gap",
        "A1-3",
        none.clone(),
        &["A5"],
        &["refused:gap"],
        false,
        "3",
    );
    of(
        "wrong-network",
        "A1-3",
        none.clone(),
        &["N8-1"],
        &["refused:network"],
        false,
        "3",
    );
    of(
        "post-pin-fork-latches",
        "A1-3",
        none.clone(),
        &["A4", "F4", "A5", "@verify"],
        &[
            "appended",
            "Conflict",
            "HistoryConflicted",
            "HistoryConflicted",
        ],
        true,
        "4",
    );
    of(
        "post-pin-fork-latches-with-longer-cache",
        "A1-3",
        cb("A1-4"),
        &["F4", "@verify"],
        &["Conflict", "HistoryConflicted"],
        true,
        "4",
    );
    of(
        "pinned-prefix-mismatch-does-not-latch",
        "A1-3",
        none.clone(),
        &["F3", "A4", "@verify"],
        &["PinMismatch", "appended", "ok"],
        false,
        "4",
    );
    of(
        "pinned-checkpoint-fork-in-cache-chain",
        "A1-5",
        none.clone(),
        &["F4", "A6"],
        &["PinMismatch", "appended"],
        false,
        "6",
    );
    of(
        "bad-signature-fork-does-not-latch",
        "A1-3",
        none.clone(),
        &["A4", "F4-bad-extra-signature", "A5", "@verify"],
        &["appended", "refused:signature", "appended", "ok"],
        false,
        "5",
    );
    of(
        "bad-signature-at-next-epoch",
        "A1-3",
        none.clone(),
        &["A3-bad-extra-signature", "A4"],
        &["refused:signature", "appended"],
        false,
        "4",
    );
    of(
        "pinned-prefix-fork-with-a-bad-witness-is-a-signature-refusal",
        "A1-3",
        none.clone(),
        &["F3-bad-extra-signature", "@verify", "A4"],
        &["refused:signature", "ok", "appended"],
        false,
        "4",
    );
    of(
        "high-s-witness-is-refused",
        "A1-3",
        none.clone(),
        &["A3-high-s"],
        &["refused:signature"],
        false,
        "3",
    );

    let key = |network: u16, genesis: &[u8; 32], ns: &str| {
        json!({"network": network, "genesisEntryId": hx(genesis), "namespace": ns,
               "key": format!("utb/v1/{}/{}/{}", network, hx(genesis), ns)})
    };
    let keys = vec![
        key(7, &a[0].entry_id(), "public"),
        key(7, &a[0].entry_id(), "test-a"),
        key(7, &w.g[0].entry_id(), "test-a"),
        key(8, &w.n8[0].entry_id(), "public"),
    ];
    let revisions = vec![
        json!({"hex": "", "revision": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}),
        json!({"hex": "616263", "revision": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}),
    ];

    json!({
        "spec": [
            "Shared UTB cache vectors (design: briefs/utb-cache-design.md). Generated by sdk-rust tests/utb_cache.rs from unsigned test keys: member i signs with 32 bytes of value i (members a..e).",
            "Epochs are decimal strings; bytes are lowercase hex. Networks 7 and 8 are private test ids; every authority here is a custom/test namespace.",
            "Bundles are tag 39015, version 1, status 0, a non-null endEntryId, no continuation.",
            "A1..A6 is one chain (epoch 4 rotates d out and e in); A3-witness-abd is A3 with another valid witness (same EntryID); F3 forks A2, F4 forks A3, both validly signed.",
            "pins: valid pins verify; the invalid ones are ReleasePinInvalid. open: a session is opened over the pin and the cache (store: null, 'unreadable' = I/O error on read, 'oversize' = value over the budget); the expectation holds after open, nothing is written on open; flushNeeded means the merged history differs from the cache.",
            "offer: entries by name, in order, offered to the session; '@verify' asks for the history view. results: appended | noop | (a same-EntryID entry with a bad witness is refused:signature) | refused:<signature|chain|invalid|encoding|gap|network|beforeGenesis> | PinMismatch | Conflict (authenticated fork after the checkpoint; latches) | HistoryConflicted | ok.",
            "flush: open, optionally replace the store content with storeAfterOpen, offer each entry in order, flush once, then compare the stored bytes ('unchanged' = as before, 'absent' = nothing stored, else a bundle name). result: saved:wrote | saved:noop | pending:<PinMismatch|Oversize|HistoryConflicted>. A valid history over the budget (oversize) and an authenticated chain diverging at or before the checkpoint (pinMismatch) are never overwritten; a malformed cache, another network or another genesis is replaced at its observed revision; a conflicted session never writes; a clean session (nothing dirty, no damaged cache to replace, no blocked cache) flushes without reading the store, so it neither imports nor detects what changed after open (optional expect.tipEpoch). expect.diagnostics: what the flush result reports (a cache found damaged, foreign or of another network at flush is replaced and reported once, whether it was damaged at open or after it). open expect.exportBundle (optional): the session's exported bundle is that named bundle byte for byte: a longer cache extends the embedded history, so the embedded witnesses stay (the first held). casAttempts: compare-and-swap writes per flush (the first plus three retries). Optional limits {maxEntries, maxBundleBytes} (null = default) apply to the session; store 'ignoresBudget' serves the bytes without enforcing the byte budget.",
            "key: 'utb/v1/<network decimal>/<genesisEntryId hex>/<namespace>'. revision: lowercase hex SHA-256 of the stored bytes."
        ],
        "limits": {"maxBundleBytes": 16777216, "maxEntries": 4096, "maxEntryBytes": 65536, "casAttempts": 4},
        "entries": entries_json,
        "bundles": bundles_json,
        "pins": pins,
        "open": open,
        "flush": flush,
        "offer": offer,
        "key": keys,
        "revision": revisions,
    })
}

#[test]
fn vectors_are_current() {
    let want = generate();
    if std::env::var("UTB_CACHE_UPDATE_VECTORS").is_ok() {
        std::fs::create_dir_all("tests/vectors/utb-cache/v1").unwrap();
        std::fs::write(
            VECTORS_PATH,
            serde_json::to_string_pretty(&want).unwrap() + "\n",
        )
        .unwrap();
        return;
    }
    let have: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(have, want, "regenerate with UTB_CACHE_UPDATE_VECTORS=1");
}

// ---------------------------------------------------------------- the runner

#[derive(Clone, Copy)]
enum Fault {
    Unreadable,
    Oversize,
}

struct IgnoreBudget<'a>(&'a MemoryStore);

impl TrustBaseStore for IgnoreBudget<'_> {
    async fn read(&self, k: &StoreKey, _: usize) -> Result<StoreRead, StoreError> {
        self.0.read(k, usize::MAX).await
    }
    async fn compare_and_swap(
        &self,
        k: &StoreKey,
        e: Option<&Revision>,
        b: &[u8],
    ) -> Result<StoreCas, StoreError> {
        self.0.compare_and_swap(k, e, b).await
    }
}

fn options_of(c: &Value) -> SessionOptions {
    let mut o = SessionOptions::default();
    if let Some(n) = c["limits"]["maxEntries"].as_u64() {
        o.limits.max_entries = n as usize;
    }
    if let Some(n) = c["limits"]["maxEntryBytes"].as_u64() {
        o.limits.max_entry_bytes = n as usize;
    }
    if let Some(n) = c["limits"]["maxBundleBytes"].as_u64() {
        o.limits.max_bytes = n as usize;
    }
    o
}

struct FaultStore<'a>(&'a MemoryStore, Fault);

impl TrustBaseStore for FaultStore<'_> {
    async fn read(&self, _: &StoreKey, _: usize) -> Result<StoreRead, StoreError> {
        Err(match self.1 {
            Fault::Unreadable => StoreError::Io("injected".into()),
            Fault::Oversize => StoreError::TooLarge,
        })
    }
    async fn compare_and_swap(
        &self,
        k: &StoreKey,
        e: Option<&Revision>,
        b: &[u8],
    ) -> Result<StoreCas, StoreError> {
        self.0.compare_and_swap(k, e, b).await
    }
}

fn unhex(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

struct Fx {
    v: Value,
}

impl Fx {
    fn named(&self, section: &str, name: &str) -> &Value {
        self.v[section]
            .as_array()
            .unwrap()
            .iter()
            .find(|x| x["name"] == name)
            .unwrap_or_else(|| panic!("{section} {name}"))
    }
    fn pin(&self, name: &str) -> PinSpec {
        pin_from(self.named("pins", name))
    }
    fn bundle(&self, name: &str) -> Vec<u8> {
        unhex(&self.named("bundles", name)["hex"])
    }
    fn entry(&self, name: &str) -> TrustBaseEntry {
        TrustBaseEntry::from_cbor(&unhex(&self.named("entries", name)["hex"])).unwrap()
    }
    fn cache_bytes(&self, c: &Value) -> Option<Vec<u8>> {
        if c.is_null() {
            None
        } else if let Some(n) = c.get("bundle") {
            Some(self.bundle(n.as_str().unwrap()))
        } else {
            Some(unhex(&c["hex"]))
        }
    }
}

fn authority(pin: &PinSpec) -> Authority {
    Authority::Custom {
        namespace: "test".into(),
        pin: pin.clone(),
    }
}

fn diag_name(d: &Diagnostic) -> String {
    match d {
        Diagnostic::CacheRejected(r) => format!(
            "CacheRejected:{}",
            match r {
                CacheReject::Malformed => "malformed",
                CacheReject::WrongNetwork => "wrongNetwork",
                CacheReject::WrongGenesis => "wrongGenesis",
                CacheReject::PinMismatch => "pinMismatch",
                CacheReject::Oversize => "oversize",
            }
        ),
        Diagnostic::CacheUnavailable(_) => "CacheUnavailable".into(),
    }
}

fn flush_diags(f: &Flush) -> Vec<String> {
    match f {
        Flush::Saved { diagnostics, .. } => diagnostics.iter().map(diag_name).collect(),
        Flush::Pending(_) => vec![],
    }
}

fn flush_name(f: Flush) -> String {
    match f {
        Flush::Saved { wrote: true, .. } => "saved:wrote".into(),
        Flush::Saved { wrote: false, .. } => "saved:noop".into(),
        Flush::Pending(CacheError::Rejected(CacheReject::PinMismatch)) => {
            "pending:PinMismatch".into()
        }
        Flush::Pending(CacheError::Rejected(CacheReject::Oversize)) => "pending:Oversize".into(),
        Flush::Pending(CacheError::HistoryConflicted) => "pending:HistoryConflicted".into(),
        Flush::Pending(e) => format!("pending:other:{e}"),
    }
}

fn refusal_class(e: &HistoryError) -> String {
    use unicity_token::api::bft::TrustBaseError as T;
    match e {
        HistoryError::Entry(T::Signature(_)) => "refused:signature",
        HistoryError::Entry(T::Chain(_)) => "refused:chain",
        HistoryError::Entry(T::Invalid(_)) => "refused:invalid",
        HistoryError::Entry(_) => "refused:encoding",
        HistoryError::Gap { .. } => "refused:gap",
        HistoryError::WrongNetwork => "refused:network",
        HistoryError::BeforeGenesis => "refused:beforeGenesis",
        _ => "refused:other",
    }
    .into()
}

#[test]
fn the_shared_vectors_hold() {
    let fx = Fx {
        v: serde_json::from_str(VECTORS).unwrap(),
    };
    // bundles re-encode byte for byte
    for b in fx.v["bundles"].as_array().unwrap() {
        if b["entryIds"].as_array().unwrap().is_empty() {
            continue;
        }
        let bytes = unhex(&b["hex"]);
        if let Ok(h) = TrustBaseHistory::from_bundle(&bytes, None) {
            assert_eq!(h.to_bundle(), bytes, "{}", b["name"]);
            let ids: Vec<String> = h.entries().iter().map(|e| hx(&e.entry_id())).collect();
            let want: Vec<String> = b["entryIds"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap().into())
                .collect();
            assert_eq!(ids, want, "{}", b["name"]);
        }
    }
    // pins
    for p in fx.v["pins"].as_array().unwrap() {
        let spec = pin_from(p);
        let r = spec.verify(&BundleLimits::default());
        assert_eq!(
            r.is_ok(),
            p["valid"].as_bool().unwrap(),
            "pin {}: {r:?}",
            p["name"]
        );
        if let Err(e) = r {
            assert!(
                matches!(e, CacheError::ReleasePinInvalid(_)),
                "pin {}",
                p["name"]
            );
            assert_eq!(p["error"], "ReleasePinInvalid");
            let o = block_on(Session::open(
                spec.network_id,
                authority(&spec),
                MemoryStore::new(),
                SessionOptions::default(),
            ));
            assert!(
                matches!(o, Err(CacheError::ReleasePinInvalid(_))),
                "open {}",
                p["name"]
            );
        }
    }
    // keys and revisions
    for k in fx.v["key"].as_array().unwrap() {
        let id: [u8; 32] = unhex(&k["genesisEntryId"]).try_into().unwrap();
        let key = StoreKey::new(
            net(k["network"].as_u64().unwrap() as u16),
            &id,
            k["namespace"].as_str().unwrap(),
        );
        assert_eq!(key.0, k["key"].as_str().unwrap());
    }
    for r in fx.v["revision"].as_array().unwrap() {
        assert_eq!(
            hx(&Revision::of(&unhex(&r["hex"])).0),
            r["revision"].as_str().unwrap()
        );
    }
    // open
    for c in fx.v["open"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let pin = fx.pin(c["pin"].as_str().unwrap());
        let store = MemoryStore::new();
        let key = StoreKey::new(pin.network_id, &pin.genesis_entry_id, "test");
        if let Some(b) = fx.cache_bytes(&c["cache"]) {
            store.put(&key, &b);
        }
        let before = store.get(&key);
        let o = options_of(c);
        let opened = match c["store"].as_str() {
            Some("unreadable") => block_on(Session::open(
                pin.network_id,
                authority(&pin),
                FaultStore(&store, Fault::Unreadable),
                o,
            ))
            .map(|(s, d)| (s.history().unwrap().clone(), s.is_dirty(), d)),
            Some("oversize") => block_on(Session::open(
                pin.network_id,
                authority(&pin),
                FaultStore(&store, Fault::Oversize),
                o,
            ))
            .map(|(s, d)| (s.history().unwrap().clone(), s.is_dirty(), d)),
            Some("ignoresBudget") => block_on(Session::open(
                pin.network_id,
                authority(&pin),
                IgnoreBudget(&store),
                o,
            ))
            .map(|(s, d)| (s.history().unwrap().clone(), s.is_dirty(), d)),
            _ => block_on(Session::open(pin.network_id, authority(&pin), &store, o))
                .map(|(s, d)| (s.history().unwrap().clone(), s.is_dirty(), d)),
        };
        let (h, dirty, diags) = opened.unwrap_or_else(|e| panic!("{name}: {e}"));
        let e = &c["expect"];
        assert_eq!(
            h.latest().epoch.to_string(),
            e["tipEpoch"].as_str().unwrap(),
            "{name}"
        );
        assert_eq!(
            hx(&h.latest().entry_id()),
            e["tipEntryId"].as_str().unwrap(),
            "{name}"
        );
        let got: Vec<String> = diags.iter().map(diag_name).collect();
        let want: Vec<String> = e["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().into())
            .collect();
        assert_eq!(got, want, "{name}");
        assert_eq!(dirty, e["flushNeeded"].as_bool().unwrap(), "{name}");
        if let Some(b) = e["exportBundle"].as_str() {
            assert_eq!(h.to_bundle(), fx.bundle(b), "{name}: exported bytes");
        }
        assert_eq!(store.get(&key), before, "{name}: open writes nothing");
    }
    // flush
    for c in fx.v["flush"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let pin = fx.pin(c["pin"].as_str().unwrap());
        let store = MemoryStore::new();
        let key = StoreKey::new(pin.network_id, &pin.genesis_entry_id, "test");
        if let Some(b) = fx.cache_bytes(&c["cache"]) {
            store.put(&key, &b);
        }
        let o = options_of(c);
        let ib = IgnoreBudget(&store);
        macro_rules! run {
            ($st:expr) => {{
                let (mut s, _) =
                    block_on(Session::open(pin.network_id, authority(&pin), $st, o)).unwrap();
                if let Some(b) = fx.cache_bytes(&c["storeAfterOpen"]) {
                    store.put(&key, &b);
                }
                for n in c["offers"].as_array().unwrap() {
                    let _ = s.append(fx.entry(n.as_str().unwrap()));
                }
                let before = store.get(&key);
                let fl = block_on(s.flush());
                let diags = flush_diags(&fl);
                let r = flush_name(fl);
                let tip = TrustBaseHistory::from_bundle(&s.export_bundle(), None)
                    .unwrap()
                    .latest()
                    .epoch;
                (r, before, tip, diags)
            }};
        }
        let (result, before, tip, diags) = if c["store"].as_str() == Some("ignoresBudget") {
            run!(&ib)
        } else {
            run!(&store)
        };
        assert_eq!(result, c["expect"]["result"].as_str().unwrap(), "{name}");
        let want: Vec<String> = c["expect"]["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().into())
            .collect();
        assert_eq!(diags, want, "{name}: flush diagnostics");
        if let Some(t) = c["expect"]["tipEpoch"].as_str() {
            assert_eq!(tip.to_string(), t, "{name}");
        }
        let after = store.get(&key);
        match c["expect"]["stored"].as_str().unwrap() {
            "unchanged" => assert_eq!(after, before, "{name}"),
            "absent" => assert_eq!(after, None, "{name}"),
            b => assert_eq!(after, Some(fx.bundle(b)), "{name}"),
        }
    }
    // offer
    for c in fx.v["offer"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let pin = fx.pin(c["pin"].as_str().unwrap());
        let store = MemoryStore::new();
        let key = StoreKey::new(pin.network_id, &pin.genesis_entry_id, "test");
        if let Some(b) = fx.cache_bytes(&c["cache"]) {
            store.put(&key, &b);
        }
        let (mut s, _) = block_on(Session::open(
            pin.network_id,
            authority(&pin),
            &store,
            SessionOptions::default(),
        ))
        .unwrap();
        let mut got = Vec::new();
        for o in c["offers"].as_array().unwrap() {
            let o = o.as_str().unwrap();
            if o == "@verify" {
                got.push(match s.history() {
                    Ok(_) => "ok".to_string(),
                    Err(SessionError::HistoryConflicted) => "HistoryConflicted".into(),
                    Err(e) => panic!("{e}"),
                });
                continue;
            }
            got.push(match s.append(fx.entry(o)) {
                Ok(Appended::Added) => "appended".into(),
                Ok(Appended::AlreadyHeld) => "noop".into(),
                Err(SessionError::Conflict(ev)) => {
                    assert!(ev.held_entry_id != ev.offered_entry_id);
                    "Conflict".into()
                }
                Err(SessionError::HistoryConflicted) => "HistoryConflicted".into(),
                Err(SessionError::PinMismatch) => "PinMismatch".into(),
                Err(SessionError::Refused(e)) => refusal_class(&e),
                Err(e) => panic!("{e}"),
            });
        }
        let want: Vec<String> = c["expect"]["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| {
                x.as_str()
                    .unwrap()
                    .replace("noop-checked", "refused:signature")
            })
            .collect();
        assert_eq!(got, want, "{name}");
        assert_eq!(
            s.conflict().is_some(),
            c["expect"]["conflicted"].as_bool().unwrap(),
            "{name}"
        );
        if let Some(ev) = s.conflict() {
            assert!(!ev.held_bytes.is_empty() && !ev.offered_bytes.is_empty());
        }
        let tip = TrustBaseHistory::from_bundle(&s.export_bundle(), None)
            .unwrap()
            .latest()
            .epoch;
        assert_eq!(
            tip.to_string(),
            c["expect"]["tipEpoch"].as_str().unwrap(),
            "{name}"
        );
    }
}

// ---------------------------------------------------------------- store and session behaviour

use std::cell::{Cell, RefCell};

enum CasMode {
    Real,
    AlwaysChanged,
    Fail(StoreError),
    /// a competing writer stores these bytes just before the first compare-and-swap
    RaceOnce(Option<Vec<u8>>),
}

struct Script<'a> {
    inner: &'a MemoryStore,
    key: StoreKey,
    reads: Cell<usize>,
    cas: Cell<usize>,
    mode: RefCell<CasMode>,
    read_error: RefCell<Option<StoreError>>,
}

impl<'a> Script<'a> {
    fn new(inner: &'a MemoryStore, key: StoreKey) -> Self {
        Script {
            inner,
            key,
            reads: Cell::new(0),
            cas: Cell::new(0),
            mode: RefCell::new(CasMode::Real),
            read_error: RefCell::new(None),
        }
    }
}

impl TrustBaseStore for &Script<'_> {
    async fn read(&self, k: &StoreKey, max: usize) -> Result<StoreRead, StoreError> {
        self.reads.set(self.reads.get() + 1);
        if let Some(e) = self.read_error.borrow().clone() {
            return Err(e);
        }
        self.inner.read(k, max).await
    }
    async fn compare_and_swap(
        &self,
        k: &StoreKey,
        e: Option<&Revision>,
        b: &[u8],
    ) -> Result<StoreCas, StoreError> {
        self.cas.set(self.cas.get() + 1);
        match &mut *self.mode.borrow_mut() {
            CasMode::Real => {}
            CasMode::AlwaysChanged => return Ok(StoreCas::Changed),
            CasMode::Fail(err) => return Err(err.clone()),
            CasMode::RaceOnce(bytes) => {
                if let Some(x) = bytes.take() {
                    self.inner.put(&self.key, &x);
                }
            }
        }
        self.inner.compare_and_swap(k, e, b).await
    }
}

struct Fix {
    w: World,
}

impl Fix {
    fn new() -> Self {
        Fix { w: world() }
    }
    fn a(&self, from: usize, to: usize) -> Vec<&TrustBaseEntry> {
        self.w.a[from..to].iter().collect()
    }
    fn pin(&self, to: usize) -> PinSpec {
        pin_of(&self.a(0, to))
    }
    fn bytes(&self, to: usize) -> Vec<u8> {
        bundle_of(&self.a(0, to))
    }
    fn key(&self, pin: &PinSpec) -> StoreKey {
        StoreKey::new(pin.network_id, &pin.genesis_entry_id, "test")
    }
}

fn open_on<S: TrustBaseStore>(pin: &PinSpec, store: S) -> (Session<S>, Vec<Diagnostic>) {
    block_on(Session::open(
        pin.network_id,
        authority(pin),
        store,
        SessionOptions::default(),
    ))
    .unwrap()
}

fn tip_of(bytes: &[u8]) -> u64 {
    TrustBaseHistory::from_bundle(bytes, None)
        .unwrap()
        .latest()
        .epoch
}

#[test]
fn a_flush_writes_one_complete_bundle_and_a_second_flush_writes_nothing() {
    let f = Fix::new();
    let pin = f.pin(3);
    let store = MemoryStore::new();
    let (mut s, _) = open_on(&pin, &store);
    // nothing of ours beyond the pin: nothing to save
    assert_eq!(
        block_on(s.flush()),
        Flush::Saved {
            wrote: false,
            diagnostics: vec![]
        }
    );
    assert_eq!(store.get(&f.key(&pin)), None);
    s.append(f.w.a[3].clone()).unwrap();
    assert!(s.is_dirty());
    assert_eq!(
        block_on(s.flush()),
        Flush::Saved {
            wrote: true,
            diagnostics: vec![]
        }
    );
    assert!(!s.is_dirty());
    assert_eq!(
        store.get(&f.key(&pin)).unwrap(),
        f.bytes(4),
        "one complete canonical bundle"
    );
    assert_eq!(
        block_on(s.flush()),
        Flush::Saved {
            wrote: false,
            diagnostics: vec![]
        }
    );
}

#[test]
fn two_writers_with_compatible_histories_lose_no_suffix() {
    let f = Fix::new();
    let pin = f.pin(3);
    let store = MemoryStore::new();
    let (mut s1, _) = open_on(&pin, &store);
    let (mut s2, _) = open_on(&pin, &store);
    s1.append(f.w.a[3].clone()).unwrap();
    assert!(matches!(
        block_on(s1.flush()),
        Flush::Saved { wrote: true, .. }
    ));
    s2.append(f.w.a[3].clone()).unwrap();
    s2.append(f.w.a[4].clone()).unwrap();
    assert!(matches!(
        block_on(s2.flush()),
        Flush::Saved { wrote: true, .. }
    ));
    // a clean session does not reread the store: it writes nothing and imports nothing
    assert!(matches!(
        block_on(s1.flush()),
        Flush::Saved { wrote: false, .. }
    ));
    assert_eq!(s1.history().unwrap().latest().epoch, 4);
    // the shorter writer learns an entry of its own, rereads, imports the longer stored
    // history and writes nothing
    s1.append(f.w.a[4].clone()).unwrap();
    assert!(matches!(
        block_on(s1.flush()),
        Flush::Saved { wrote: false, .. }
    ));
    assert_eq!(s1.history().unwrap().latest().epoch, 5);
    assert_eq!(store.get(&f.key(&pin)).unwrap(), f.bytes(5));
}

#[test]
fn competing_valid_branches_are_never_selected_by_length_or_order() {
    let f = Fix::new();
    let pin = f.pin(3);
    let store = MemoryStore::new();
    let (mut s1, _) = open_on(&pin, &store);
    let (mut s2, _) = open_on(&pin, &store);
    s1.append(f.w.a[3].clone()).unwrap();
    s1.append(f.w.a[4].clone()).unwrap();
    assert!(matches!(
        block_on(s1.flush()),
        Flush::Saved { wrote: true, .. }
    ));
    let stored = store.get(&f.key(&pin)).unwrap();
    s2.append(f.w.f4.clone()).unwrap();
    assert_eq!(
        block_on(s2.flush()),
        Flush::Pending(CacheError::HistoryConflicted)
    );
    assert!(
        s2.conflict().is_some(),
        "the stored fork latches the session"
    );
    assert_eq!(
        store.get(&f.key(&pin)).unwrap(),
        stored,
        "the held bytes are untouched"
    );
    assert!(s2.is_dirty());
    assert!(matches!(s2.history(), Err(SessionError::HistoryConflicted)));
}

#[test]
fn a_stale_revision_is_reread_validated_and_merged() {
    let f = Fix::new();
    let pin = f.pin(3);
    let store = MemoryStore::new();
    let script = Script::new(&store, f.key(&pin));
    let (mut s, _) = open_on(&pin, &script);
    script.reads.set(0);
    s.append(f.w.a[3].clone()).unwrap();
    // a competing writer lands A1-5 between our read and our swap
    *script.mode.borrow_mut() = CasMode::RaceOnce(Some(f.bytes(5)));
    let r = block_on(s.flush());
    assert!(matches!(r, Flush::Saved { wrote: false, .. }), "{r:?}");
    assert_eq!(script.cas.get(), 1);
    assert_eq!(script.reads.get(), 2);
    assert_eq!(s.history().unwrap().latest().epoch, 5, "imported by append");
    assert_eq!(store.get(&f.key(&pin)).unwrap(), f.bytes(5));
}

#[test]
fn contention_is_retried_three_times_then_pending_and_the_session_stays_dirty() {
    let f = Fix::new();
    let pin = f.pin(3);
    let store = MemoryStore::new();
    let script = Script::new(&store, f.key(&pin));
    let (mut s, _) = open_on(&pin, &script);
    script.reads.set(0);
    s.append(f.w.a[3].clone()).unwrap();
    *script.mode.borrow_mut() = CasMode::AlwaysChanged;
    assert_eq!(block_on(s.flush()), Flush::Pending(CacheError::Contended));
    assert_eq!((script.reads.get(), script.cas.get()), (4, 4));
    assert!(s.is_dirty());
    assert_eq!(
        s.history().unwrap().latest().epoch,
        4,
        "verified history is not undone"
    );
    *script.mode.borrow_mut() = CasMode::Real;
    assert!(matches!(
        block_on(s.flush()),
        Flush::Saved { wrote: true, .. }
    ));
}

#[test]
fn a_failed_save_is_reported_separately_and_the_dirty_state_survives() {
    let f = Fix::new();
    let pin = f.pin(3);
    let store = MemoryStore::new();
    let script = Script::new(&store, f.key(&pin));
    let (mut s, _) = open_on(&pin, &script);
    s.append(f.w.a[3].clone()).unwrap();
    for e in [
        StoreError::Quota,
        StoreError::Permission,
        StoreError::Io("disk".into()),
        StoreError::Busy,
    ] {
        *script.mode.borrow_mut() = CasMode::Fail(e.clone());
        assert_eq!(
            block_on(s.flush()),
            Flush::Pending(CacheError::Unavailable(e))
        );
        assert!(s.is_dirty());
        assert_eq!(store.get(&f.key(&pin)), None);
    }
    *script.mode.borrow_mut() = CasMode::Real;
    assert!(matches!(
        block_on(s.flush()),
        Flush::Saved { wrote: true, .. }
    ));
}

#[test]
fn a_damaged_cache_is_reported_then_replaced_only_against_its_exact_revision() {
    let f = Fix::new();
    let pin = f.pin(3);
    let store = MemoryStore::new();
    let key = f.key(&pin);
    store.put(&key, b"garbage");
    let script = Script::new(&store, key.clone());
    let (mut s, d) = open_on(&pin, &script);
    assert_eq!(d, vec![Diagnostic::CacheRejected(CacheReject::Malformed)]);
    assert_eq!(store.get(&key).unwrap(), b"garbage", "open does not repair");
    s.append(f.w.a[3].clone()).unwrap();
    let r = block_on(s.flush());
    assert_eq!(
        r,
        Flush::Saved {
            wrote: true,
            diagnostics: vec![Diagnostic::CacheRejected(CacheReject::Malformed)]
        }
    );
    assert_eq!(store.get(&key).unwrap(), f.bytes(4));

    // the repair loses a race against a writer that stored a longer valid history
    let store = MemoryStore::new();
    store.put(&key, b"garbage");
    let script = Script::new(&store, key.clone());
    let (mut s, _) = open_on(&pin, &script);
    s.append(f.w.a[3].clone()).unwrap();
    *script.mode.borrow_mut() = CasMode::RaceOnce(Some(f.bytes(5)));
    block_on(s.flush());
    assert_eq!(
        store.get(&key).unwrap(),
        f.bytes(5),
        "the racing valid history is never overwritten"
    );
    assert_eq!(s.history().unwrap().latest().epoch, 5);
}

#[test]
fn a_rejection_is_reported_once_across_retries() {
    let f = Fix::new();
    let pin = f.pin(3);
    let store = MemoryStore::new();
    let key = f.key(&pin);
    store.put(&key, b"garbage");
    let script = Script::new(&store, key.clone());
    let (mut s, _) = open_on(&pin, &script);
    s.append(f.w.a[3].clone()).unwrap();
    // another damaged value lands before our swap: the retry rejects again
    *script.mode.borrow_mut() = CasMode::RaceOnce(Some(b"more garbage".to_vec()));
    assert_eq!(
        block_on(s.flush()),
        Flush::Saved {
            wrote: true,
            diagnostics: vec![Diagnostic::CacheRejected(CacheReject::Malformed)]
        }
    );
    assert_eq!(script.cas.get(), 2);
    assert_eq!(store.get(&key).unwrap(), f.bytes(4));
}

#[test]
fn a_read_failure_cannot_authorize_a_replacement() {
    let f = Fix::new();
    let pin = f.pin(3);
    let store = MemoryStore::new();
    let key = f.key(&pin);
    store.put(&key, &f.bytes(3));
    let script = Script::new(&store, key.clone());
    let (mut s, _) = open_on(&pin, &script);
    s.append(f.w.a[3].clone()).unwrap();
    for e in [StoreError::TooLarge, StoreError::Io("x".into())] {
        *script.read_error.borrow_mut() = Some(e.clone());
        assert_eq!(
            block_on(s.flush()),
            Flush::Pending(CacheError::Unavailable(e))
        );
    }
    assert_eq!(script.cas.get(), 0);
    assert_eq!(store.get(&key).unwrap(), f.bytes(3));
}

#[test]
fn limits_are_checked_before_decoding_and_before_signature_work() {
    let f = Fix::new();
    let pin = f.pin(3);
    let store = MemoryStore::new();
    let key = f.key(&pin);
    store.put(&key, &f.bytes(5));
    // a byte budget below the stored size: the store refuses the read
    let tight = SessionOptions {
        limits: BundleLimits {
            max_bytes: f.bytes(3).len(),
            ..BundleLimits::default()
        },
        ..SessionOptions::default()
    };
    let (_, d) = block_on(Session::open(
        pin.network_id,
        authority(&pin),
        &store,
        tight,
    ))
    .unwrap();
    assert_eq!(d, vec![Diagnostic::CacheRejected(CacheReject::Oversize)]);
    // an entry-count budget below the cache's
    let few = SessionOptions {
        limits: BundleLimits {
            max_entries: 4,
            ..BundleLimits::default()
        },
        ..SessionOptions::default()
    };
    let (s, d) = block_on(Session::open(pin.network_id, authority(&pin), &store, few)).unwrap();
    assert_eq!(d, vec![Diagnostic::CacheRejected(CacheReject::Oversize)]);
    assert_eq!(s.history().unwrap().latest().epoch, 3);
    // the embedded asset has to fit the budget too: fatal, no cache rescues it
    let tiny = SessionOptions {
        limits: BundleLimits {
            max_entries: 2,
            ..BundleLimits::default()
        },
        ..SessionOptions::default()
    };
    let r = block_on(Session::open(pin.network_id, authority(&pin), &store, tiny));
    assert!(matches!(r, Err(CacheError::ReleasePinInvalid(_))));
}

#[test]
fn yielding_between_entries_does_not_change_the_result() {
    let f = Fix::new();
    let pin = f.pin(3);
    let store = MemoryStore::new();
    store.put(&f.key(&pin), &f.bytes(6));
    struct Counting<F>(F, usize);
    impl<F: Future + Unpin> Future for Counting<F> {
        type Output = F::Output;
        fn poll(mut self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
            let r = std::pin::Pin::new(&mut self.0).poll(cx);
            if r.is_pending() {
                self.1 += 1;
            }
            r
        }
    }
    let opts = SessionOptions {
        yield_every: 1,
        ..SessionOptions::default()
    };
    let fut = Box::pin(Session::open(pin.network_id, authority(&pin), &store, opts));
    let mut c = Counting(fut, 0);
    let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &NOOP_VT)) };
    let mut cx = Context::from_waker(&waker);
    let (s, _) = loop {
        if let Poll::Ready(r) = std::pin::Pin::new(&mut c).poll(&mut cx) {
            break r.unwrap();
        }
    };
    assert!(c.1 >= 5, "yielded {} times", c.1);
    assert_eq!(s.history().unwrap().latest().epoch, 6);
}

static NOOP_VT: RawWakerVTable = RawWakerVTable::new(
    |_| RawWaker::new(std::ptr::null(), &NOOP_VT),
    |_| {},
    |_| {},
    |_| {},
);

#[test]
fn merging_a_fetched_bundle_keeps_a_verified_prefix_and_a_fork_latches() {
    let f = Fix::new();
    let pin = f.pin(3);
    let store = MemoryStore::new();
    let (mut s, _) = open_on(&pin, &store);
    assert_eq!(block_on(s.merge_bundle(&f.bytes(5))).unwrap(), 2);
    assert!(s.is_dirty());
    // a malformed page changes nothing and does not latch
    let mut bad = f.bytes(6);
    let n = bad.len();
    bad[n - 9] ^= 1;
    assert!(matches!(
        block_on(s.merge_bundle(&bad)),
        Err(SessionError::Refused(_))
    ));
    assert!(s.conflict().is_none());
    let w = &f.w;
    let forked = bundle_of(&[&w.a[0], &w.a[1], &w.a[2], &w.f4]);
    assert!(matches!(
        block_on(s.merge_bundle(&forked)),
        Err(SessionError::Conflict(_))
    ));
    // F4 is at epoch 4, after the pin (3): authenticated fork
    assert!(s.conflict().is_some());
    assert!(matches!(
        block_on(s.merge_bundle(&f.bytes(6))),
        Err(SessionError::HistoryConflicted)
    ));
    assert_eq!(
        tip_of(&s.export_bundle()),
        5,
        "evidence and export stay available"
    );
}

fn row(pin: &PinSpec) -> ReleasePinRow {
    ReleasePinRow {
        network_id: pin.network_id.id(),
        genesis_epoch: pin.genesis_epoch,
        genesis_entry_id: pin.genesis_entry_id,
        pinned_epoch: pin.pinned_epoch,
        pinned_entry_id: pin.pinned_entry_id,
        bundle: Box::leak(pin.bundle.clone().into_boxed_slice()),
        bundle_sha256: pin.bundle_sha256,
    }
}

#[test]
fn authorities_release_override_and_custom() {
    let f = Fix::new();
    let w = &f.w;
    let table = [row(&f.pin(3))];
    let n7 = net(7);
    let open = |auth: Authority, network: NetworkId, table: &[ReleasePinRow]| {
        block_on(Session::open_in(
            table,
            network,
            auth,
            MemoryStore::new(),
            SessionOptions::default(),
        ))
        .map(|(s, _)| s.key().0.clone())
    };
    // unknown network, and no TOFU for a network without a row
    assert_eq!(
        open(Authority::Release, n7, &[]),
        Err(CacheError::UnknownNetwork)
    );
    assert_eq!(
        open(Authority::ReleaseOverride(f.pin(5)), n7, &[]),
        Err(CacheError::UnknownNetwork)
    );
    assert_eq!(
        open(Authority::Release, net(8), &table),
        Err(CacheError::UnknownNetwork)
    );
    // the release row lives in the public namespace
    let k = open(Authority::Release, n7, &table).unwrap();
    assert!(k.ends_with("/public"), "{k}");
    // a newer pin extending the lineage, an equal one
    assert!(open(Authority::ReleaseOverride(f.pin(5)), n7, &table).is_ok());
    assert!(open(Authority::ReleaseOverride(f.pin(3)), n7, &table).is_ok());
    // older, forked, other-genesis overrides fail
    assert_eq!(
        open(Authority::ReleaseOverride(f.pin(2)), n7, &table),
        Err(CacheError::PinMismatch)
    );
    let forked = pin_of(&[
        &w.a[0],
        &w.a[1],
        &w.f3,
        &succ(&w.f3, &["a", "b", "c", "d"], 100, 9, &["a", "b", "c"]),
    ]);
    assert_eq!(
        open(Authority::ReleaseOverride(forked), n7, &table),
        Err(CacheError::PinMismatch)
    );
    let other = pin_of(&[&w.g[0], &w.g[1], &w.g[2]]);
    assert_eq!(
        open(Authority::ReleaseOverride(other.clone()), n7, &table),
        Err(CacheError::PinMismatch)
    );
    // custom: never the public namespace, own storage key
    let custom = |ns: &str| Authority::Custom {
        namespace: ns.into(),
        pin: other.clone(),
    };
    assert_eq!(
        open(custom("public"), n7, &table),
        Err(CacheError::PinMismatch)
    );
    assert_eq!(open(custom(""), n7, &table), Err(CacheError::PinMismatch));
    assert_eq!(
        open(custom("a/b"), n7, &table),
        Err(CacheError::PinMismatch)
    );
    let ka = open(custom("test-a"), n7, &table).unwrap();
    let kb = open(custom("test-b"), n7, &table).unwrap();
    assert_ne!(ka, kb);
    assert!(!ka.ends_with("/public"));
    // an override that is itself invalid is fatal
    let mut bad = f.pin(5);
    bad.bundle_sha256[0] ^= 1;
    assert!(matches!(
        open(Authority::ReleaseOverride(bad), n7, &table),
        Err(CacheError::ReleasePinInvalid(_))
    ));
    // the shipped release table is empty until the owner approves a public pin
    assert!(RELEASE_PINS.is_empty());
}

#[test]
fn a_pin_bump_is_discovered_by_the_same_key() {
    let f = Fix::new();
    let (p3, p5) = (f.pin(3), f.pin(5));
    assert_eq!(
        f.key(&p3),
        f.key(&p5),
        "the key is network + genesis + namespace, never the tip"
    );
}

#[test]
fn different_witnesses_of_one_entry_are_not_a_conflict_and_the_first_is_kept() {
    let f = Fix::new();
    let pin = f.pin(3);
    let store = MemoryStore::new();
    let (mut s, _) = open_on(&pin, &store);
    let held = s.history().unwrap().get(3).unwrap().to_cbor();
    assert_eq!(s.append(f.w.a3w.clone()), Ok(Appended::AlreadyHeld));
    assert_eq!(s.history().unwrap().get(3).unwrap().to_cbor(), held);
    assert!(!s.is_dirty());
}
