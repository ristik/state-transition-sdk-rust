//! secp256k1 public keys and recoverable signatures.
//!
//! Wire signature = 65 bytes: `r(32) || s(32) || recovery(1)`. Public keys are
//! 33-byte compressed SEC1 points. Signatures are over a *raw 32-byte digest*
//! (no extra prehash). Verification enforces **low-`s`** (BIP-0062 canonical
//! form) so a malleated high-`s` copy of a valid signature is rejected, and the
//! recovery id is bound to the trusted key (see [`Signature::verify`]).

use alloc::vec::Vec;

use k256::ecdsa::{RecoveryId, Signature as K256Signature, VerifyingKey};
use k256::elliptic_curve::bigint::{CheckedAdd, Encoding};
use k256::elliptic_curve::group::Group;
use k256::elliptic_curve::ops::{LinearCombination, Reduce};
use k256::elliptic_curve::point::DecompressPoint;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::subtle::Choice;
use k256::elliptic_curve::Curve;
use k256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar, Secp256k1, U256};

use crate::cbor::{encode_byte_string, Decoder};
use crate::error::Error;

/// A compressed secp256k1 public key (33 bytes).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PublicKey {
    bytes: [u8; 33],
}

impl PublicKey {
    /// Validate and wrap 33 compressed SEC1 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let arr: [u8; 33] = bytes.try_into().map_err(|_| Error::InvalidLength {
            what: "secp256k1 public key",
            expected: 33,
            actual: bytes.len(),
        })?;
        // Reject non-points and the uncompressed/identity encodings.
        VerifyingKey::from_sec1_bytes(&arr).map_err(|_| Error::Crypto("invalid public key"))?;
        Ok(PublicKey { bytes: arr })
    }

    /// The 33 compressed bytes.
    pub fn as_bytes(&self) -> &[u8; 33] {
        &self.bytes
    }
}

impl core::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PublicKey({})", hex::encode(self.bytes))
    }
}

/// Why a native (B1) unicity-seal signature did not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealSignatureError {
    /// Not 64 bytes, or 65 bytes whose recovery byte is not 0 or 1.
    Format,
    /// `r` or `s` outside `1..n`, or `s` above `n/2`.
    Range,
    /// Well-formed, but not a valid ECDSA signature of the digest by the key.
    Invalid,
}

/// Verify a unicity-seal signature by the native (B1) rule: 64 bytes `r||s`, or 65 bytes whose
/// last byte is 0 or 1 and is otherwise ignored; `1 <= r < n`, `1 <= s <= n/2`; plain ECDSA of
/// the 32-byte `digest` against the listed `key` (no key recovery, so the recovery byte is not
/// a signature field). This is the rule of the bridge verifier and of bft-core's `b1ref`; the
/// trust base entries themselves use [`Signature::verify`] (65 bytes, recovery-bound).
pub fn verify_seal_signature(
    wire: &[u8],
    digest: &[u8],
    key: &PublicKey,
) -> Result<(), SealSignatureError> {
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    let compact = match wire.len() {
        64 => wire,
        65 if wire[64] <= 1 => &wire[..64],
        _ => return Err(SealSignatureError::Format),
    };
    let sig = K256Signature::from_slice(compact).map_err(|_| SealSignatureError::Range)?;
    if sig.normalize_s().is_some() {
        return Err(SealSignatureError::Range);
    }
    let vk =
        VerifyingKey::from_sec1_bytes(key.as_bytes()).map_err(|_| SealSignatureError::Invalid)?;
    vk.verify_prehash(digest, &sig)
        .map_err(|_| SealSignatureError::Invalid)
}

/// A recoverable secp256k1 signature.
#[derive(Clone, PartialEq, Eq)]
pub struct Signature {
    /// Compact `r || s` (64 bytes).
    bytes: [u8; 64],
    /// Recovery id (0..=3).
    recovery: u8,
}

impl Signature {
    /// Construct from compact bytes and a recovery id.
    pub fn new(bytes: [u8; 64], recovery: u8) -> Result<Self, Error> {
        RecoveryId::from_byte(recovery).ok_or(Error::Crypto("invalid recovery id"))?;
        Ok(Signature { bytes, recovery })
    }

    /// Decode from the 65-byte wire form `r || s || recovery`.
    pub fn decode(input: &[u8]) -> Result<Self, Error> {
        if input.len() != 65 {
            return Err(Error::InvalidLength {
                what: "signature",
                expected: 65,
                actual: input.len(),
            });
        }
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(&input[..64]);
        Signature::new(bytes, input[64])
    }

    /// Decode from a CBOR byte string (65 bytes).
    pub fn from_cbor(d: Decoder<'_>) -> Result<Self, Error> {
        Signature::decode(d.bytes_value()?)
    }

    /// The compact `r || s` bytes.
    pub fn compact(&self) -> &[u8; 64] {
        &self.bytes
    }

    /// The recovery id.
    pub fn recovery(&self) -> u8 {
        self.recovery
    }

    /// The 65-byte wire encoding.
    pub fn encode(&self) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(&self.bytes);
        out[64] = self.recovery;
        out
    }

    /// CBOR byte string of the 65-byte encoding.
    pub fn to_cbor(&self) -> Vec<u8> {
        encode_byte_string(&self.encode())
    }

    /// Parse `r || s` into a k256 signature, enforcing low-`s`.
    fn canonical(&self) -> Result<K256Signature, Error> {
        let sig = K256Signature::from_slice(&self.bytes)
            .map_err(|_| Error::Crypto("malformed signature scalars"))?;
        // normalize_s() returns Some(..) iff s was high (non-canonical).
        if sig.normalize_s().is_some() {
            return Err(Error::Crypto("non-canonical high-s signature"));
        }
        Ok(sig)
    }

    /// Verify this signature over `digest` against `public_key`: recover the key
    /// the signature selects and require it to be the trusted one - one recovery,
    /// no separate ECDSA verification.
    ///
    /// `Q' = r^-1 (s R - z G)` with `R` lifted from `x = r + (v >> 1) n` and parity
    /// `v & 1`. Equality `Q' == Q` implies `s R = z G + r Q`, i.e. ordinary ECDSA
    /// validity **and** the selected recovery branch, so the 65-byte witness has
    /// no malleable byte (a range check on `v` alone would not do: `v ^ 1` stays
    /// in range and recovers another key). Returns `false` for any failure.
    pub fn verify(&self, digest: &[u8], public_key: &PublicKey) -> bool {
        // compare compressed encodings: the recovered point is already affine and
        // the trusted key keeps its encoding, so nothing is re-parsed
        match self.recover_point(digest) {
            Ok(q) => q.to_encoded_point(true).as_bytes() == public_key.as_bytes().as_slice(),
            Err(_) => false,
        }
    }

    /// Recover the signer's public key from `digest` (ecrecover semantics; the
    /// caller decides whether it is the key it trusts).
    pub fn recover(&self, digest: &[u8]) -> Result<PublicKey, Error> {
        let q = self.recover_point(digest)?;
        PublicKey::from_bytes(q.to_encoded_point(true).as_bytes())
    }

    /// The single recovery calculation (checks in order): the 32-byte digest;
    /// `1 <= r, s < n` and low-`s` (no reduction of received scalars); `v` in
    /// `0..=3`; `r + n < p` for `v & 2` (checked addition); decompression of `R`
    /// (on-curve, requested parity); scalar coefficients first, then one two-term
    /// linear combination `a R + b G` with `a = s r^-1`, `b = -z r^-1`; rejection
    /// of the identity.
    fn recover_point(&self, digest: &[u8]) -> Result<AffinePoint, Error> {
        let bad = |m| Error::Crypto(m);
        let digest: &[u8; 32] = digest
            .try_into()
            .map_err(|_| bad("digest must be 32 bytes"))?;
        let sig = self.canonical()?;
        let (r, s) = sig.split_scalars();
        if self.recovery > 3 {
            return Err(bad("invalid recovery id"));
        }

        let mut x = FieldBytes::from(r.to_bytes());
        if self.recovery & 2 != 0 {
            let lifted = Option::<U256>::from(
                U256::from_be_slice(&x).checked_add(&<Secp256k1 as Curve>::ORDER),
            )
            .ok_or(bad("recovery lift overflows"))?;
            x = FieldBytes::from(lifted.to_be_bytes());
        }
        // not a canonical field element (x >= p) or not on the curve: no such point
        let big_r = Option::<AffinePoint>::from(AffinePoint::decompress(
            &x,
            Choice::from(self.recovery & 1),
        ))
        .ok_or(bad("key recovery failed"))?;

        let z = <Scalar as Reduce<U256>>::reduce_bytes(&FieldBytes::from(*digest));
        let t = Option::<Scalar>::from(r.invert()).ok_or(bad("key recovery failed"))?;
        let a = *s * t;
        let b = -(z * t);
        let q = ProjectivePoint::lincomb(
            &ProjectivePoint::from(big_r),
            &a,
            &<ProjectivePoint as Group>::generator(),
            &b,
        );
        if bool::from(q.is_identity()) {
            return Err(bad("key recovery failed"));
        }
        Ok(q.to_affine())
    }
}

impl core::fmt::Debug for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Signature({}, recovery={})",
            hex::encode(self.bytes),
            self.recovery
        )
    }
}

#[cfg(all(test, feature = "client"))]
mod recovery_tests {
    use super::*;
    use crate::crypto::hash::sha256;
    use crate::crypto::signer::{Secp256k1Signer, Signer};

    fn sig_from(r: &[u8; 32], s: &[u8; 32], v: u8) -> Signature {
        let mut c = [0u8; 64];
        c[..32].copy_from_slice(r);
        c[32..].copy_from_slice(s);
        Signature::new(c, v).unwrap()
    }

    fn be(n: u64) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[24..].copy_from_slice(&n.to_be_bytes());
        b
    }

    /// Test-only reference: ordinary verification plus recovery with the library's own
    /// recover-then-verify (never used in production code).
    fn reference_accepts(sig: &Signature, digest: &[u8], pk: &PublicKey) -> bool {
        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        let Ok(k) = K256Signature::from_slice(sig.compact()) else {
            return false;
        };
        if k.normalize_s().is_some() {
            return false;
        }
        let Some(rid) = RecoveryId::from_byte(sig.recovery()) else {
            return false;
        };
        let vk = VerifyingKey::from_sec1_bytes(pk.as_bytes()).unwrap();
        vk.verify_prehash(digest, &k).is_ok()
            && VerifyingKey::recover_from_prehash(digest, &k, rid).is_ok_and(|r| r == vk)
    }

    #[test]
    fn single_pass_agrees_with_the_reference_on_valid_and_mutated_signatures() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        };
        for i in 0..40u8 {
            let mut sk = [0u8; 32];
            sk[..8].copy_from_slice(&next().to_le_bytes());
            sk[31] = i + 1;
            let signer = Secp256k1Signer::from_bytes(&sk).unwrap();
            let pk = signer.public_key();
            let mut d = [0u8; 32];
            for c in d.chunks_mut(8) {
                c.copy_from_slice(&next().to_le_bytes());
            }
            let digest = crate::crypto::hash::DataHash::new(
                crate::crypto::hash::HashAlgorithm::Sha256,
                d.to_vec(),
            )
            .unwrap();
            let sig = signer.sign(&digest);
            for v in 0..=3u8 {
                let c = Signature::new(*sig.compact(), v).unwrap();
                assert_eq!(c.verify(&d, &pk), reference_accepts(&c, &d, &pk), "v={v}");
            }
            // a flipped bit anywhere in r || s, a wrong digest, a wrong key
            for bit in [0usize, 7, 100, 255, 256, 300, 511] {
                let mut bytes = *sig.compact();
                bytes[bit / 8] ^= 1 << (bit % 8);
                let m = Signature::new(bytes, sig.recovery()).unwrap();
                assert_eq!(
                    m.verify(&d, &pk),
                    reference_accepts(&m, &d, &pk),
                    "bit {bit}"
                );
                assert!(!m.verify(&d, &pk), "bit {bit}");
            }
            let mut other = d;
            other[0] ^= 1;
            assert!(!sig.verify(&other, &pk));
            let wrong = Secp256k1Signer::from_bytes(&[9; 32]).unwrap().public_key();
            assert!(!sig.verify(&d, &wrong));
        }
    }

    /// Message representative: zero and values >= n are valid digests (reduced mod n);
    /// only the length is checked.
    #[test]
    fn digests_are_reduced_modulo_n_and_must_be_32_bytes() {
        let signer = Secp256k1Signer::from_bytes(&[5; 32]).unwrap();
        let pk = signer.public_key();
        for d in [[0u8; 32], [0xff; 32], {
            // n itself: reduces to zero
            let mut n = [0u8; 32];
            n.copy_from_slice(
                &hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
                    .unwrap(),
            );
            n
        }] {
            let hash = crate::crypto::hash::DataHash::new(
                crate::crypto::hash::HashAlgorithm::Sha256,
                d.to_vec(),
            )
            .unwrap();
            let sig = signer.sign(&hash);
            assert!(sig.verify(&d, &pk), "{}", hex::encode(d));
            assert_eq!(sig.verify(&d, &pk), reference_accepts(&sig, &d, &pk));
        }
        let sig = signer.sign(&sha256(b"x"));
        let digest = sha256(b"x");
        assert!(sig.verify(digest.data(), &pk));
        assert!(!sig.verify(&digest.data()[..31], &pk));
        let mut long = digest.data().to_vec();
        long.push(0);
        assert!(!sig.verify(&long, &pk));
        assert!(!sig.verify(&[], &pk));
    }

    /// Recovery IDs 2 and 3 are accepted when they are the right branch: the
    /// primitive inputs r = 2, s = 1, z = 0 lift to x = r + n (constructed expected
    /// keys; noble 2.2.0 gives the same points).
    #[test]
    fn recovery_ids_two_and_three_are_accepted_when_valid() {
        let zero = [0u8; 32];
        let r = be(2);
        let s = be(1);
        let k2 = Signature::new(
            {
                let mut c = [0u8; 64];
                c[..32].copy_from_slice(&r);
                c[32..].copy_from_slice(&s);
                c
            },
            2,
        )
        .unwrap();
        let k3 = Signature::new(*k2.compact(), 3).unwrap();
        let q2 = k2.recover(&zero).unwrap();
        let q3 = k3.recover(&zero).unwrap();
        assert_eq!(
            hex::encode(q2.as_bytes()),
            "02ad802f2145df548ce1fc418b851cb32669c5a6bb939e6caf744de90310f8f1ff"
        );
        assert_eq!(
            hex::encode(q3.as_bytes()),
            "03ad802f2145df548ce1fc418b851cb32669c5a6bb939e6caf744de90310f8f1ff"
        );
        // verification against each constructed key accepts exactly that branch
        assert!(k2.verify(&zero, &q2) && k3.verify(&zero, &q3));
        assert!(!k2.verify(&zero, &q3) && !k3.verify(&zero, &q2));
        assert!(reference_accepts(&k2, &zero, &q2) && reference_accepts(&k3, &zero, &q3));
        // the same r, s with v = 0 / 1 recover other keys (or none)
        for v in [0u8, 1] {
            let c = Signature::new(*k2.compact(), v).unwrap();
            assert!(!c.verify(&zero, &q2) && !c.verify(&zero, &q3));
        }
    }

    #[test]
    fn invalid_recovery_inputs_are_rejected_without_panics() {
        let zero = [0u8; 32];
        let pk = Secp256k1Signer::from_bytes(&[5; 32]).unwrap().public_key();
        let n = hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
            .unwrap();
        let mut n_minus_1 = [0u8; 32];
        n_minus_1.copy_from_slice(&n);
        n_minus_1[31] -= 1;
        let mut p_minus_n = [0u8; 32];
        p_minus_n.copy_from_slice(
            &hex::decode("000000000000000000000000000000014551231950b75fc4402da1722fc9baee")
                .unwrap(),
        );
        let one = be(1);
        // r + n overflows 2^256 (r = n - 1) or reaches p (r = p - n): no lift for v & 2
        for r in [n_minus_1, p_minus_n] {
            for v in [2u8, 3] {
                let sig = sig_from(&r, &one, v);
                assert!(sig.recover(&zero).is_err());
                assert!(!sig.verify(&zero, &pk));
            }
        }
        // zero and out-of-range scalars, high-s: not signatures at all
        let mut nn = [0u8; 32];
        nn.copy_from_slice(&n);
        for (r, s) in [
            (be(0), one),
            (one, be(0)),
            (nn, one),
            (one, nn),
            (one, n_minus_1),
        ] {
            for v in 0..=3u8 {
                let sig = sig_from(&r, &s, v);
                assert!(!sig.verify(&zero, &pk));
                assert!(sig.recover(&zero).is_err());
            }
        }
        // x without a curve point: a small r that is not an x-coordinate
        let mut failures = 0;
        for x in 1..40u64 {
            if sig_from(&be(x), &one, 0).recover(&zero).is_err() {
                failures += 1;
            }
        }
        assert!(failures > 5, "about half of all x have no point");
    }

    /// A recovery that lands on the identity (sR = zG) is rejected.
    #[test]
    fn a_recovered_identity_is_rejected() {
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        // R = 7G, r = x(R), s = 1, z = 7: Q' = r^-1 (R - 7G) = O
        let big_r = (k256::ProjectivePoint::GENERATOR * Scalar::from(7u64)).to_affine();
        let enc = big_r.to_encoded_point(true);
        let parity = enc.as_bytes()[0] & 1;
        let mut x = [0u8; 32];
        x.copy_from_slice(&enc.as_bytes()[1..]);
        let z = be(7);
        let sig = sig_from(&x, &be(1), parity);
        assert!(sig.recover(&z).is_err());
        let any = Secp256k1Signer::from_bytes(&[5; 32]).unwrap().public_key();
        assert!(!sig.verify(&z, &any));
    }

    /// Cost probe (run with `--ignored --nocapture`): per-verification time of the
    /// quorum hot path.
    #[test]
    #[ignore]
    fn verify_cost() {
        let signer = Secp256k1Signer::from_bytes(&[7; 32]).unwrap();
        let digest = sha256(b"o3");
        let sig = signer.sign(&digest);
        let pk = signer.public_key();
        let n = 300;
        let time = |name: &str, f: &dyn Fn()| {
            let t = std::time::Instant::now();
            for _ in 0..n {
                f();
            }
            println!("{name}: {:?} per call", t.elapsed() / n);
        };
        // the pre-O3 check: ECDSA verification against the trusted key, v ignored
        time("old (verify_prehash only)", &|| {
            use k256::ecdsa::signature::hazmat::PrehashVerifier;
            let vk = VerifyingKey::from_sec1_bytes(pk.as_bytes()).unwrap();
            let k = sig.canonical().unwrap();
            assert!(vk.verify_prehash(digest.data(), &k).is_ok());
        });
        // the library's recover_from_prehash (recover-then-verify on the host)
        time("library recover_from_prehash + compare", &|| {
            let k = sig.canonical().unwrap();
            let rid = RecoveryId::from_byte(sig.recovery()).unwrap();
            let vk = VerifyingKey::recover_from_prehash(digest.data(), &k, rid).unwrap();
            assert_eq!(vk.to_encoded_point(true).as_bytes(), pk.as_bytes());
        });
        time("verify (single-pass recover and compare)", &|| {
            assert!(sig.verify(digest.data(), &pk));
        });
    }

    #[test]
    fn only_the_recovery_id_that_recovers_the_signer_verifies() {
        let signer = Secp256k1Signer::from_bytes(&[7; 32]).unwrap();
        let other = Secp256k1Signer::from_bytes(&[8; 32]).unwrap();
        let digest = sha256(b"o3");
        let sig = signer.sign(&digest);
        let pk = signer.public_key();
        assert!(sig.verify(digest.data(), &pk));
        assert!(!sig.verify(digest.data(), &other.public_key()));
        for v in 0..=3u8 {
            let variant = Signature::new(*sig.compact(), v).unwrap();
            assert_eq!(
                variant.verify(digest.data(), &pk),
                v == sig.recovery(),
                "v={v}"
            );
        }
        // xor-1 stays in range and recovers another key (or none)
        let flipped = Signature::new(*sig.compact(), sig.recovery() ^ 1).unwrap();
        assert!(!flipped.verify(digest.data(), &pk));
        // a high-s copy with the matching parity flip is valid ECDSA but not canonical
        // (covered by the shared fixtures); a wrong digest never verifies
        assert!(!sig.verify(sha256(b"other").data(), &pk));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_recovery_id_during_decode() {
        let mut encoded = [0u8; 65];
        encoded[64] = 0xff;
        assert!(matches!(
            Signature::decode(&encoded),
            Err(Error::Crypto("invalid recovery id"))
        ));
    }
}
