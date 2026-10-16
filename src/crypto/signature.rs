//! secp256k1 public keys and recoverable signatures.
//!
//! Wire signature = 65 bytes: `r(32) || s(32) || recovery(1)`. Public keys are
//! 33-byte compressed SEC1 points. Signatures are over a *raw 32-byte digest*
//! (no extra prehash). Verification enforces **low-`s`** (BIP-0062 canonical
//! form) so a malleated high-`s` copy of a valid signature is rejected, and the
//! recovery id is bound to the trusted key (see [`Signature::verify`]).

use alloc::vec::Vec;

use k256::ecdsa::{RecoveryId, Signature as K256Signature, VerifyingKey};

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

    /// Verify this signature over `digest` against `public_key`, **binding the
    /// recovery id**: the key recovered from `(digest, r, s, v)` must equal
    /// `public_key`. A signature whose `r || s` verifies but whose `v` selects another
    /// recovery branch (or an out of range one, which can not be constructed) is
    /// refused, so the 65-byte witness has no malleable byte. A range check on `v`
    /// would not be enough: `v ^ 1` stays in range and recovers another key.
    ///
    /// Returns `false` for any failure, including a non-canonical high-`s` encoding.
    /// (Recovering the trusted key implies the ECDSA equation holds for it.)
    pub fn verify(&self, digest: &[u8], public_key: &PublicKey) -> bool {
        match self.recover(digest) {
            Ok(recovered) => recovered == *public_key,
            Err(_) => false,
        }
    }

    /// Recover the signer's public key from `digest` using the recovery id.
    pub fn recover(&self, digest: &[u8]) -> Result<PublicKey, Error> {
        let sig = self.canonical()?;
        let rid =
            RecoveryId::from_byte(self.recovery).ok_or(Error::Crypto("invalid recovery id"))?;
        let vk = VerifyingKey::recover_from_prehash(digest, &sig, rid)
            .map_err(|_| Error::Crypto("key recovery failed"))?;
        let enc = vk.to_encoded_point(true);
        PublicKey::from_bytes(enc.as_bytes())
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
