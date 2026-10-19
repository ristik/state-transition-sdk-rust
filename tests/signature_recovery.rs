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

/// The native seal-signature rule (bridge verifier, bft-core `b1ref`), as opposed to the strict
/// recoverable rule above that trust base entries use: 64 bytes, or 65 with a recovery byte of
/// 0/1 that is otherwise ignored; low-S; plain ECDSA against the listed key. The seal level
/// is covered by the shared B1 vectors (`b1_seal_vectors.rs`).
#[cfg(feature = "client")]
mod native_seal_rule {
    use unicity_token::crypto::hash::sha256;
    use unicity_token::crypto::signature::{verify_seal_signature, SealSignatureError};
    use unicity_token::crypto::signer::{Secp256k1Signer, Signer};

    #[test]
    fn forms_and_ranges() {
        let signer = Secp256k1Signer::from_bytes(&[7; 32]).unwrap();
        let other = Secp256k1Signer::from_bytes(&[8; 32]).unwrap();
        let digest = sha256(b"a seal");
        let d = digest.data();
        let wire = signer.sign(&digest).encode().to_vec();
        let key = signer.public_key();

        assert_eq!(verify_seal_signature(&wire, d, &key), Ok(()));
        assert_eq!(
            verify_seal_signature(&wire[..64], d, &key),
            Ok(()),
            "compact form"
        );
        let mut flipped = wire.clone();
        flipped[64] ^= 1;
        assert_eq!(
            verify_seal_signature(&flipped, d, &key),
            Ok(()),
            "the recovery byte is ignored"
        );
        let mut v2 = wire.clone();
        v2[64] = 2;
        assert_eq!(
            verify_seal_signature(&v2, d, &key),
            Err(SealSignatureError::Format)
        );
        let mut v27 = wire.clone();
        v27[64] = 27;
        assert_eq!(
            verify_seal_signature(&v27, d, &key),
            Err(SealSignatureError::Format)
        );
        assert_eq!(
            verify_seal_signature(&wire[..63], d, &key),
            Err(SealSignatureError::Format)
        );
        let mut long = wire.clone();
        long.push(0);
        assert_eq!(
            verify_seal_signature(&long, d, &key),
            Err(SealSignatureError::Format)
        );
        assert_eq!(
            verify_seal_signature(&[], d, &key),
            Err(SealSignatureError::Format)
        );

        // a high-s copy of a valid signature (s' = n - s) is valid ECDSA but not canonical
        const N: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x41,
        ];
        let mut high = wire.clone();
        let mut borrow = 0i32;
        for i in (0..32).rev() {
            let d = i32::from(N[i]) - i32::from(wire[32 + i]) - borrow;
            borrow = i32::from(d < 0);
            high[32 + i] = (d + 256) as u8;
        }
        assert_ne!(high[32..64], wire[32..64]);
        assert_eq!(
            verify_seal_signature(&high, d, &key),
            Err(SealSignatureError::Range),
            "high-s"
        );
        assert_eq!(
            verify_seal_signature(&high[..64], d, &key),
            Err(SealSignatureError::Range)
        );

        // r = 0 and s = 0 are out of range
        let mut zero_r = wire.clone();
        zero_r[..32].fill(0);
        assert_eq!(
            verify_seal_signature(&zero_r, d, &key),
            Err(SealSignatureError::Range)
        );
        let mut zero_s = wire.clone();
        zero_s[32..64].fill(0);
        assert_eq!(
            verify_seal_signature(&zero_s, d, &key),
            Err(SealSignatureError::Range)
        );

        // valid and well-formed, but not this key's signature of this digest
        assert_eq!(
            verify_seal_signature(&wire, d, &other.public_key()),
            Err(SealSignatureError::Invalid)
        );
        assert_eq!(
            verify_seal_signature(&wire, sha256(b"another").data(), &key),
            Err(SealSignatureError::Invalid)
        );
    }
}
