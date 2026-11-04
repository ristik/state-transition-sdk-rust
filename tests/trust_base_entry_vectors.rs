//! The shared Unicity Trust Base v2 vectors (tests/vectors/trust-base-v2, from bft-go-base) against the entry codec:
//! byte-exact encoding, identity (entry id over the unsigned bytes), strict decoding, successor and weighted-quorum verification.
#![cfg(feature = "std")]

use serde_json::Value;
use unicity_token::api::bft::{TrustBaseEntry, TrustBaseError};

fn vectors() -> Value {
    serde_json::from_str(include_str!("vectors/trust-base-v2/vectors.json")).expect("vectors.json")
}

fn unhex(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string")).expect("hex")
}

fn entry(v: &Value, name: &str) -> (TrustBaseEntry, Value) {
    let e = v["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == name)
        .unwrap_or_else(|| panic!("no entry {name}"));
    (TrustBaseEntry::from_cbor(&unhex(&e["hex"])).expect(name), e.clone())
}

#[test]
fn entries_round_trip_with_the_reference_bytes_and_identity() {
    let v = vectors();
    let all = v["entries"].as_array().unwrap();
    assert!(all.len() >= 5);
    for e in all {
        let name = e["name"].as_str().unwrap();
        let bytes = unhex(&e["hex"]);
        let parsed = TrustBaseEntry::from_cbor(&bytes).expect(name);
        assert_eq!(parsed.to_cbor(), bytes, "{name}: re-encoding");
        assert_eq!(parsed.sig_bytes(), unhex(&e["sigBytes"]), "{name}: sig bytes");
        assert_eq!(parsed.entry_id().to_vec(), unhex(&e["entryId"]), "{name}: entry id");
    }
}

#[test]
fn two_signature_subsets_of_one_entry_have_one_identity() {
    let v = vectors();
    let (abc, _) = entry(&v, "epoch2-signed-abc");
    let (abd, _) = entry(&v, "epoch2-signed-abd");
    assert_ne!(abc.to_cbor(), abd.to_cbor());
    assert_eq!(abc.entry_id(), abd.entry_id());
}

#[test]
fn decode_accept_and_reject_cases() {
    let v = vectors();
    let cases = v["decode"].as_array().unwrap();
    assert!(cases.len() >= 14);
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let r = TrustBaseEntry::from_cbor(&unhex(&c["hex"]));
        if c["valid"].as_bool().unwrap() {
            assert!(r.is_ok(), "{name}: {r:?}");
            continue;
        }
        match (c["errorClass"].as_str().unwrap(), r) {
            ("encoding", Err(TrustBaseError::Encoding(_))) => {}
            ("invalid", Err(TrustBaseError::Invalid(_))) => {}
            (class, other) => panic!("{name}: expected {class}, got {other:?}"),
        }
    }
}

#[test]
fn successors_verify_against_their_predecessor() {
    let v = vectors();
    let (g, _) = entry(&v, "genesis");
    let (e2, _) = entry(&v, "epoch2-signed-abc");
    let (e2_abd, _) = entry(&v, "epoch2-signed-abd");
    let (e3, _) = entry(&v, "epoch3-signed-abc");
    g.verify_genesis().unwrap();
    e2.verify_successor(&g).unwrap();
    e2_abd.verify_successor(&g).unwrap();
    e3.verify_successor(&e2).unwrap();
    assert!(matches!(e2.verify_genesis(), Err(TrustBaseError::Invalid(_))));
    assert!(matches!(g.verify_successor(&g), Err(TrustBaseError::Chain(_))));
    // wrong predecessor: epoch 3 does not extend the genesis
    assert!(matches!(e3.verify_successor(&g), Err(TrustBaseError::Chain(_))));
}

#[test]
fn weighted_quorum_counts_weight_not_signers() {
    let v = vectors();
    let (committee, _) = entry(&v, "weighted-genesis-5-1-1-1");
    let (genesis, _) = entry(&v, "genesis");
    let cases = v["weightedQuorum"].as_array().unwrap();
    assert_eq!(cases.len(), 4);
    for c in cases {
        let name = c["name"].as_str().unwrap();
        // the successor is built on the plain genesis; the committee that signs is the weighted one
        let succ = TrustBaseEntry::from_cbor(&unhex(&c["entry"])).expect(name);
        assert_eq!(succ.previous_entry_id, committee.entry_id(), "{name}: links to the weighted committee");
        let r = succ.verify_successor(&committee);
        if c["valid"].as_bool().unwrap() {
            r.unwrap_or_else(|e| panic!("{name}: {e}"));
        } else {
            assert!(matches!(r, Err(TrustBaseError::Signature(_))), "{name}: {r:?}");
        }
        // it is not a successor of an unrelated entry
        assert!(succ.verify_successor(&genesis).is_err(), "{name}");
    }
}

/// Each chain rule alone: the entry is the vectors' epoch 2 with one field changed, so only that rule can refuse it.
/// (Chain rules are checked before signatures, so a mutated field never reaches the signature check.)
#[test]
fn each_chain_rule_refuses_alone() {
    let v = vectors();
    let (g, _) = entry(&v, "genesis");
    let (e2, _) = entry(&v, "epoch2-signed-abc");
    let chain = |name: &str, f: &dyn Fn(&mut TrustBaseEntry)| {
        let mut m = e2.clone();
        f(&mut m);
        match m.verify_successor(&g) {
            Err(TrustBaseError::Chain(_)) => {}
            other => panic!("{name}: expected a chain error, got {other:?}"),
        }
    };
    chain("other network", &|m| {
        m.network_id = unicity_token::api::NetworkId::new(6).unwrap();
    });
    chain("epoch gap", &|m| m.epoch = 3);
    chain("epoch repeated", &|m| m.epoch = 1);
    chain("epoch start does not increase", &|m| m.epoch_start = g.epoch_start);
    chain("wrong predecessor", &|m| m.previous_entry_id = [9; 32]);
}

#[test]
fn structure_rules_refuse_alone() {
    let v = vectors();
    let (g, _) = entry(&v, "genesis");
    let invalid = |name: &str, f: &dyn Fn(&mut TrustBaseEntry)| {
        let mut m = g.clone();
        f(&mut m);
        assert!(matches!(m.validate(), Err(TrustBaseError::Invalid(_))), "{name}");
    };
    invalid("shared signing key", &|m| {
        m.members[1].signing_key = m.members[0].signing_key.clone();
    });
    invalid("unsorted members", &|m| m.members.swap(0, 1));
    invalid("zero weight", &|m| m.members[0].weight = 0);
    invalid("no members", &|m| m.members.clear());
    invalid("wrong threshold", &|m| m.quorum_threshold = 2);
}
