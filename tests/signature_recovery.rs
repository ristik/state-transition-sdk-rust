//! Strict recoverable-signature rule (arch-o3 §4) against the shared fixtures of
//! bft-go-base (`tests/vectors/o3-signature-recovery/v1/vectors.json`, byte-identical):
//! exactly 65 bytes `r||s||v`, low-S, `v` in 0..3, and the key recovered with `v` must
//! equal the trusted key. Trust base entries use this rule; unicity seals use the native one.
#![cfg(feature = "std")]

use unicity_token::crypto::signature::{PublicKey, Signature};

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

/// Single-pass recover-and-compare cases: valid 2/3 accepted, wrong branch, `r + n >= p`,
/// decompression failure, recovered identity, zero and `>= n` digests (reduced mod n).
#[test]
fn recovery_vectors_agree_with_the_reference() {
    let f = fixtures();
    let cases = f["recovery"].as_array().unwrap();
    assert!(cases.len() >= 18);
    let mut accepted = 0;
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let trusted = key(case["publicKeyCompressed"].as_str().unwrap());
        let digest = hex::decode(case["digest"].as_str().unwrap()).unwrap();
        let wire = hex::decode(case["signature"].as_str().unwrap()).unwrap();
        let expect = case["accept"].as_bool().unwrap();
        assert_eq!(accepts(&wire, &digest, &trusted), expect, "{name}");
        accepted += usize::from(expect);
    }
    assert!(
        accepted >= 7,
        "valid 2/3 and reduced-digest cases are accepted"
    );
}
