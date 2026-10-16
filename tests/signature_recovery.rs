//! Strict recoverable-signature rule (arch-o3 §4) against the shared fixtures of
//! bft-go-base (`tests/vectors/o3-signature-recovery/v1/vectors.json`, byte-identical):
//! exactly 65 bytes `r||s||v`, low-S, `v` in 0..3, and the key recovered with `v` must
//! equal the trusted key. A nonconforming signature contributes zero votes.
#![cfg(feature = "std")]

use unicity_token::api::bft::root_trust_base::RootTrustBaseNodeInfo;
use unicity_token::api::bft::{RootTrustBase, UnicitySeal};
use unicity_token::api::NetworkId;
use unicity_token::cbor::Decoder;
use unicity_token::crypto::signature::{PublicKey, Signature};
use unicity_token::verify::{SealSession, VerificationError};

const VECTORS: &str = include_str!("vectors/o3-signature-recovery/v1/vectors.json");

fn fixtures() -> serde_json::Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn key(hex_key: &str) -> PublicKey {
    PublicKey::from_bytes(&hex::decode(hex_key).unwrap()).unwrap()
}

/// The verifier's verdict on one wire signature: decode (exactly 65 bytes, v in 0..3)
/// then recovery-bound verification.
fn accepts(wire: &[u8], digest: &[u8], trusted: &PublicKey) -> bool {
    Signature::decode(wire).is_ok_and(|s| s.verify(digest, trusted))
}

#[test]
fn primitive_vectors_agree_with_the_reference() {
    let f = fixtures();
    let p = &f["primitive"];
    let trusted = key(p["publicKeyCompressed"].as_str().unwrap());
    let digest = hex::decode(p["messageHashSha256"].as_str().unwrap()).unwrap();
    let vectors = p["vectors"].as_array().unwrap();
    assert!(vectors.len() >= 20);
    let mut accepted = 0;
    for v in vectors {
        let name = v["name"].as_str().unwrap();
        let wire = hex::decode(v["signature"].as_str().unwrap()).unwrap();
        let expect = v["accept"].as_bool().unwrap();
        assert_eq!(accepts(&wire, &digest, &trusted), expect, "{name}");
        accepted += usize::from(expect);
    }
    assert_eq!(accepted, 1, "only the signer's own encoding conforms");

    // every v in 0..3 on the valid (r, s): exactly the producing recovery id verifies,
    // including the in-range values 2 and 3 and xor-1
    let valid = hex::decode(vectors[0]["signature"].as_str().unwrap()).unwrap();
    let produced = valid[64];
    for v in 0..=3u8 {
        let mut w = valid.clone();
        w[64] = v;
        assert_eq!(accepts(&w, &digest, &trusted), v == produced, "v={v}");
    }
    // nothing outside 0..3 even decodes
    for v in 4..=255u8 {
        let mut w = valid.clone();
        w[64] = v;
        assert!(Signature::decode(&w).is_err(), "v={v}");
    }
}

#[test]
fn seal_quorum_vectors_count_only_conforming_signatures() {
    let f = fixtures();
    let s = &f["seal"];
    let nodes = s["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| RootTrustBaseNodeInfo {
            node_id: n["id"].as_str().unwrap().to_string(),
            signing_key: key(n["publicKeyCompressed"].as_str().unwrap()),
            stake: n["stake"].as_u64().unwrap(),
        })
        .collect();
    assert_eq!(s["networkId"].as_u64(), Some(3));
    let tb = RootTrustBase::new(
        1,
        NetworkId::LOCAL,
        s["epoch"].as_u64().unwrap(),
        0,
        nodes,
        s["quorumThreshold"].as_u64().unwrap(),
    );
    let cases = s["cases"].as_array().unwrap();
    assert!(cases.len() >= 9);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let bytes = hex::decode(case["sealCbor"].as_str().unwrap()).unwrap();
        // surplus malformed signatures (compact 64 bytes) make the wire decode fail in the
        // Rust codec; that is a rejection of the whole seal here, never an acceptance
        let verdict = UnicitySeal::from_cbor(Decoder::new(&bytes))
            .ok()
            .map(|seal| SealSession::new(&tb).verify_quorum(&seal));
        let accepted = matches!(verdict, Some(Ok(())));
        let expect = case["accept"].as_bool().unwrap();
        if expect {
            assert!(accepted, "{name}: {verdict:?}");
        } else {
            assert!(!accepted, "{name}: {verdict:?}");
            if let Some(Err(e)) = verdict {
                assert_eq!(e, VerificationError::QuorumNotMet, "{name}");
            }
        }
    }
}

#[cfg(feature = "client")]
mod generated {
    use super::*;
    use unicity_token::crypto::signer::{Secp256k1Signer, Signer};

    fn signers() -> Vec<Secp256k1Signer> {
        (1..=4u8)
            .map(|i| Secp256k1Signer::from_bytes(&[i; 32]).unwrap())
            .collect()
    }

    fn setup(signers: &[Secp256k1Signer]) -> (RootTrustBase, UnicitySeal) {
        let tb = RootTrustBase::new(
            1,
            NetworkId::LOCAL,
            1,
            1,
            signers
                .iter()
                .enumerate()
                .map(|(i, s)| RootTrustBaseNodeInfo {
                    node_id: format!("n{i}"),
                    signing_key: s.public_key(),
                    stake: 1,
                })
                .collect(),
            3,
        );
        let mut seal = UnicitySeal {
            network_id: NetworkId::LOCAL,
            root_chain_round_number: 5,
            epoch: 1,
            timestamp: 1_731_504_000,
            previous_hash: None,
            hash: vec![7; 32],
            signatures: Vec::new(),
        };
        let digest = seal.calculate_hash();
        seal.signatures = signers
            .iter()
            .enumerate()
            .map(|(i, s)| (format!("n{i}"), s.sign(&digest).encode().to_vec()))
            .collect();
        (tb, seal)
    }

    fn with_v_xor(seal: &UnicitySeal, nodes: &[usize]) -> UnicitySeal {
        let mut s = seal.clone();
        for &i in nodes {
            s.signatures[i].1[64] ^= 1;
        }
        s
    }

    /// A bad recovery id contributes zero votes; surplus invalid signatures are tolerated
    /// while enough conforming ones remain; the changed witness never reuses a verdict.
    #[test]
    fn a_mutated_recovery_id_contributes_no_vote_and_no_cached_verdict() {
        let signers = signers();
        let (tb, seal) = setup(&signers);
        let mut session = SealSession::new(&tb);
        assert_eq!(session.verify_quorum(&seal), Ok(()));
        assert_eq!(session.stats().quorum_checks, 1);

        // one flipped: three conforming votes remain (a different witness: re-verified)
        let one = with_v_xor(&seal, &[0]);
        assert_eq!(session.verify_quorum(&one), Ok(()));
        assert_eq!(session.stats().quorum_checks, 2);
        // two flipped: only two votes
        let two = with_v_xor(&seal, &[0, 1]);
        assert_eq!(
            session.verify_quorum(&two),
            Err(VerificationError::QuorumNotMet)
        );
        // the original is still a hit, and the failed mutation was not remembered
        assert_eq!(session.verify_quorum(&seal), Ok(()));
        assert_eq!(
            session.verify_quorum(&two),
            Err(VerificationError::QuorumNotMet)
        );
        assert_eq!(session.stats().quorum_checks, 4);

        // exactly three signers, one with a flipped v: the quorum is lost
        let mut three = seal.clone();
        three.signatures.truncate(3);
        let three_flipped = with_v_xor(&three, &[2]);
        let mut fresh = SealSession::new(&tb);
        assert_eq!(fresh.verify_quorum(&three), Ok(()));
        assert_eq!(
            fresh.verify_quorum(&three_flipped),
            Err(VerificationError::QuorumNotMet)
        );
        // every in-range v other than the producing one fails for a single signer too
        for v in 0..=3u8 {
            let mut s = three.clone();
            s.signatures[0].1[64] = v;
            let ok = SealSession::new(&tb).verify_quorum(&s).is_ok();
            assert_eq!(ok, v == three.signatures[0].1[64], "v={v}");
        }
    }
}
