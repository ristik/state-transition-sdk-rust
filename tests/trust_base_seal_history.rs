//! Seal verification against a trust base history: the entry of the seal's own epoch is the authority, the quorum is by weight, a missing entry is the
//! typed retryable error. The members' keys are the shared vectors' (member i signs with the 32 bytes of value i).
#![cfg(all(feature = "std", feature = "client"))]

use serde_json::Value;
use unicity_token::api::bft::{TrustBaseEntry, TrustBaseHistory, UnicitySeal};
use unicity_token::crypto::signer::{Secp256k1Signer, Signer};
use unicity_token::verify::{SealAuthenticator, SealSession, VerificationError};

fn vectors() -> Value {
    serde_json::from_str(include_str!("vectors/trust-base-v2/vectors.json")).unwrap()
}

fn entry(v: &Value, name: &str) -> TrustBaseEntry {
    let e = v["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == name)
        .unwrap();
    TrustBaseEntry::from_cbor(&hex::decode(e["hex"].as_str().unwrap()).unwrap()).unwrap()
}

/// genesis (epoch 1, from round 1), epoch 2 (from round 101), epoch 3 (from round 201); members a..d, weight 1
fn chain(upto: u64) -> TrustBaseHistory {
    let v = vectors();
    let mut h = TrustBaseHistory::from_genesis(entry(&v, "genesis"), None).unwrap();
    if upto >= 2 {
        h.append(entry(&v, "epoch2-signed-abc")).unwrap();
    }
    if upto >= 3 {
        h.append(entry(&v, "epoch3-signed-abc")).unwrap();
    }
    h
}

fn signer(node: &str) -> Secp256k1Signer {
    let i = (node.as_bytes()[0] - b'a') + 1;
    Secp256k1Signer::from_bytes(&[i; 32]).unwrap()
}

fn seal(network: u16, epoch: u64, round: u64, signers: &[&str]) -> UnicitySeal {
    let mut s = UnicitySeal {
        network_id: unicity_token::api::NetworkId::new(network).unwrap(),
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
fn each_epoch_is_judged_by_its_own_entry() {
    let h = chain(3);
    assert_eq!(check(&h, &seal(5, 1, 50, &["a", "b", "c"])), Ok(()));
    assert_eq!(check(&h, &seal(5, 2, 150, &["a", "b", "c"])), Ok(()));
    assert_eq!(check(&h, &seal(5, 3, 250, &["b", "c", "d"])), Ok(()));
}

#[test]
fn a_missing_entry_is_the_typed_retryable_error_and_appending_it_fixes_it() {
    let mut h = chain(2);
    let s3 = seal(5, 3, 250, &["a", "b", "c"]);
    assert_eq!(
        check(&h, &s3),
        Err(VerificationError::UnknownTrustEpoch { epoch: 3 })
    );
    // an epoch before the genesis is not "missing": no fetch can supply it, so it is a final failure
    assert_eq!(
        check(&h, &seal(5, 0, 50, &["a", "b", "c"])),
        Err(VerificationError::SealBeforeEpochStart)
    );
    h.append(entry(&vectors(), "epoch3-signed-abc")).unwrap();
    assert_eq!(check(&h, &s3), Ok(()));
}

#[test]
fn the_seal_round_has_to_lie_inside_its_epoch() {
    let h = chain(3);
    assert_eq!(
        check(&h, &seal(5, 2, 100, &["a", "b", "c"])),
        Err(VerificationError::SealBeforeEpochStart)
    );
    assert_eq!(check(&h, &seal(5, 2, 101, &["a", "b", "c"])), Ok(()));
    assert_eq!(check(&h, &seal(5, 1, 100, &["a", "b", "c"])), Ok(()));
    // epoch 2 began at round 101: no epoch-1 seal from there on
    assert_eq!(
        check(&h, &seal(5, 1, 101, &["a", "b", "c"])),
        Err(VerificationError::SealEpochMismatch)
    );
    // the latest epoch has no end yet
    assert_eq!(check(&h, &seal(5, 3, 1_000_000, &["a", "b", "c"])), Ok(()));
}

#[test]
fn another_network_is_refused() {
    let h = chain(1);
    assert_eq!(
        check(&h, &seal(6, 1, 50, &["a", "b", "c"])),
        Err(VerificationError::SealNetworkMismatch)
    );
}

#[test]
fn the_upstream_signature_rule_is_unchanged() {
    let h = chain(1);
    // a quorum of three of four
    assert_eq!(
        check(&h, &seal(5, 1, 50, &["a", "b"])),
        Err(VerificationError::QuorumNotMet)
    );
    // unknown signers and bad extras count zero, and do not break a quorum that is there
    let mut s = seal(5, 1, 50, &["a", "b", "c"]);
    s.signatures.push(("z".into(), s.signatures[0].1.clone()));
    s.signatures.push(("d".into(), vec![1, 2, 3]));
    assert_eq!(check(&h, &s), Ok(()));
    // ... and are not a quorum by themselves
    let mut s = seal(5, 1, 50, &["a", "b"]);
    s.signatures.push(("z".into(), s.signatures[0].1.clone()));
    s.signatures.push(("d".into(), vec![1, 2, 3]));
    assert_eq!(check(&h, &s), Err(VerificationError::QuorumNotMet));
    // the 64-byte compact form is not a seal signature
    let mut s = seal(5, 1, 50, &["a", "b", "c"]);
    s.signatures[2].1.truncate(64);
    assert_eq!(check(&h, &s), Err(VerificationError::QuorumNotMet));
    // a signature of another member under a member's name counts zero
    let mut s = seal(5, 1, 50, &["a", "b", "c"]);
    s.signatures[2].0 = "d".into();
    assert_eq!(check(&h, &s), Err(VerificationError::QuorumNotMet));
    // one member's signature repeated under two names is one vote at most
    let mut s = seal(5, 1, 50, &["a", "b"]);
    s.signatures.push(("c".into(), s.signatures[0].1.clone()));
    assert_eq!(check(&h, &s), Err(VerificationError::QuorumNotMet));
}

#[test]
fn the_quorum_is_by_weight() {
    // members a=5, b=1, c=1, d=1 (total 8, threshold 6)
    let v = vectors();
    let h = TrustBaseHistory::from_genesis(entry(&v, "weighted-genesis-5-1-1-1"), None).unwrap();
    assert_eq!(
        check(&h, &seal(5, 1, 50, &["a"])),
        Err(VerificationError::QuorumNotMet),
        "weight 5 of 6"
    );
    assert_eq!(
        check(&h, &seal(5, 1, 50, &["b", "c", "d"])),
        Err(VerificationError::QuorumNotMet),
        "three of four members, weight 3"
    );
    assert_eq!(check(&h, &seal(5, 1, 50, &["a", "b"])), Ok(()), "weight 6");
    assert_eq!(check(&h, &seal(5, 1, 50, &["a", "b", "c", "d"])), Ok(()));
}

#[test]
fn a_verdict_is_not_reused_across_histories() {
    // the same session type, another history: a seal that passed under one authority is checked again under the other
    let h = chain(1);
    let w = TrustBaseHistory::from_genesis(entry(&vectors(), "weighted-genesis-5-1-1-1"), None)
        .unwrap();
    let s = seal(5, 1, 50, &["b", "c", "d"]);
    assert_eq!(check(&h, &s), Ok(()));
    assert_eq!(check(&w, &s), Err(VerificationError::QuorumNotMet));
}

/// Epoch 1: members a, b, c, d. Epoch 2: members e, f, g (a new committee, signed in by a, b, c). Keys: member x signs with the byte `x - 'a' + 1`.
fn changing_committee() -> TrustBaseHistory {
    use unicity_token::api::bft::TrustBaseMember;
    let net = unicity_token::api::NetworkId::new(5).unwrap();
    let member = |n: &str| TrustBaseMember::new(n, signer(n).public_key(), 1);
    let g = TrustBaseEntry::genesis(net, 1, 1, ["a", "b", "c", "d"].map(member).to_vec());
    let mut e2 = TrustBaseEntry::new(
        net,
        2,
        101,
        ["e", "f", "g"].map(member).to_vec(),
        TrustBaseEntry::threshold_for(3).unwrap(),
        None,
        None,
        g.entry_id(),
    );
    for n in ["a", "b", "c"] {
        e2.sign(n, &signer(n));
    }
    let mut h = TrustBaseHistory::from_genesis(g, None).unwrap();
    h.append(e2).unwrap();
    h
}

#[test]
fn a_seal_is_judged_by_the_committee_of_its_own_epoch() {
    let h = changing_committee();
    assert_eq!(check(&h, &seal(5, 1, 50, &["a", "b", "c"])), Ok(()));
    assert_eq!(
        check(&h, &seal(5, 1, 50, &["e", "f", "g"])),
        Err(VerificationError::QuorumNotMet),
        "epoch 1 is not signed by epoch 2's members"
    );
    assert_eq!(check(&h, &seal(5, 2, 150, &["e", "f", "g"])), Ok(()));
    assert_eq!(
        check(&h, &seal(5, 2, 150, &["a", "b", "c"])),
        Err(VerificationError::QuorumNotMet),
        "epoch 2 is not signed by epoch 1's members"
    );
}

#[test]
fn a_malformed_seal_is_refused_before_any_signature_work() {
    let h = chain(1);
    let mut s = seal(5, 1, 50, &["a", "b", "c"]);
    s.signatures.clear();
    assert_eq!(check(&h, &s), Err(VerificationError::SealMalformed));
    let mut s = seal(5, 1, 50, &["a", "b", "c"]);
    s.timestamp = 1;
    assert_eq!(check(&h, &s), Err(VerificationError::SealMalformed));
    assert_eq!(
        check(&h, &seal(5, 1, 0, &["a", "b", "c"])),
        Err(VerificationError::SealMalformed)
    );
}

/// The proof verifiers authenticate a certificate's seal through `verify_quorum`, not `authenticate_seal`: the same entry, interval and error rules apply.
#[test]
fn the_quorum_entry_point_applies_the_same_epoch_rules() {
    let h = chain(2);
    let q = |s: &UnicitySeal| SealSession::new(&h).verify_quorum(s);
    assert_eq!(q(&seal(5, 2, 150, &["a", "b", "c"])), Ok(()));
    assert_eq!(
        q(&seal(5, 3, 250, &["a", "b", "c"])),
        Err(VerificationError::UnknownTrustEpoch { epoch: 3 })
    );
    assert_eq!(
        q(&seal(5, 2, 100, &["a", "b", "c"])),
        Err(VerificationError::SealBeforeEpochStart)
    );
    assert_eq!(
        q(&seal(5, 1, 101, &["a", "b", "c"])),
        Err(VerificationError::SealEpochMismatch)
    );
}
