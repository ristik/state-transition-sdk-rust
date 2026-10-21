//! Non-inclusion certificate for the Unicity radix sparse Merkle tree.
//!
//! The public type is relation-specific even though inclusion and
//! non-inclusion use the same private path-folding primitive.  A non-empty
//! certificate authenticates the terminal leaf reached by key-directed descent;
//! that terminal must have a different key from the requested state id.

use alloc::vec::Vec;

use crate::api::{StateId, AGGREGATION_TREE_VALUE_SIZE};
use crate::crypto::hash::DataHash;
use crate::error::Error;
use crate::radix::fold_certificate_path;
use crate::verify::VerificationError;

const BITMAP_SIZE: usize = 32;
const HASH_SIZE: usize = 32;
const TERMINAL_KEY_SIZE: usize = 32;

/// An authenticated proof that one state id is absent from an SMT root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonInclusionCertificate {
    body: Option<Body>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Body {
    bitmap: [u8; BITMAP_SIZE],
    siblings: Vec<[u8; HASH_SIZE]>,
    terminal_key: [u8; TERMINAL_KEY_SIZE],
    terminal_value: [u8; AGGREGATION_TREE_VALUE_SIZE],
}

/// How a state id relates to an authenticated non-inclusion path (see
/// [`NonInclusionCertificate::relation_to_trusted_root`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathRelation {
    /// The authenticated terminal leaf is a different key: the state is absent in that tree.
    Absent,
    /// The authenticated terminal leaf is the queried key: the state is present.
    Present,
}

impl NonInclusionCertificate {
    /// Construct the distinguished certificate for an empty tree.
    pub fn empty_tree() -> Self {
        Self { body: None }
    }

    /// Construct a non-empty certificate from its typed components.
    ///
    /// Siblings are ordered root-to-leaf and their count must equal the bitmap
    /// population count. The fixed terminal-value width is a Unicity profile
    /// restriction; the generic RSMT format permits arbitrary byte strings.
    pub fn from_parts(
        bitmap: [u8; BITMAP_SIZE],
        siblings: Vec<[u8; HASH_SIZE]>,
        terminal_key: [u8; TERMINAL_KEY_SIZE],
        terminal_value: [u8; AGGREGATION_TREE_VALUE_SIZE],
    ) -> Result<Self, Error> {
        let expected = bitmap.iter().map(|byte| byte.count_ones()).sum::<u32>() as usize;
        if siblings.len() != expected {
            return Err(Error::InvalidLength {
                what: "NonInclusionCertificate siblings",
                expected,
                actual: siblings.len(),
            });
        }
        Ok(Self {
            body: Some(Body {
                bitmap,
                siblings,
                terminal_key,
                terminal_value,
            }),
        })
    }

    /// Decode the canonical raw-byte representation.
    ///
    /// The empty byte string is the distinguished certificate for an empty
    /// tree.  Otherwise the format is
    /// `bitmap[32] || siblings[n][32] || terminalKey[32] || terminalValue[32]`,
    /// where `n` is the bitmap population count.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Ok(Self::empty_tree());
        }
        if bytes.len() < BITMAP_SIZE {
            return Err(Error::InvalidLength {
                what: "NonInclusionCertificate bitmap",
                expected: BITMAP_SIZE,
                actual: bytes.len(),
            });
        }

        let mut bitmap = [0u8; BITMAP_SIZE];
        bitmap.copy_from_slice(&bytes[..BITMAP_SIZE]);
        let sibling_count = bitmap.iter().map(|byte| byte.count_ones()).sum::<u32>() as usize;
        let terminal_offset = BITMAP_SIZE
            .checked_add(sibling_count * HASH_SIZE)
            .and_then(|size| size.checked_add(TERMINAL_KEY_SIZE))
            .ok_or(Error::OutOfRange(
                "NonInclusionCertificate encoded length overflow",
            ))?;
        if bytes.len() < terminal_offset {
            return Err(Error::InvalidLength {
                what: "NonInclusionCertificate",
                expected: terminal_offset + AGGREGATION_TREE_VALUE_SIZE,
                actual: bytes.len(),
            });
        }
        let terminal_value_size = bytes.len() - terminal_offset;
        if terminal_value_size != AGGREGATION_TREE_VALUE_SIZE {
            return Err(Error::InvalidLength {
                what: "Unicity aggregation-tree terminal value",
                expected: AGGREGATION_TREE_VALUE_SIZE,
                actual: terminal_value_size,
            });
        }
        let expected = terminal_offset + AGGREGATION_TREE_VALUE_SIZE;

        let siblings_end = BITMAP_SIZE + sibling_count * HASH_SIZE;
        let mut siblings = Vec::with_capacity(sibling_count);
        for chunk in bytes[BITMAP_SIZE..siblings_end].chunks_exact(HASH_SIZE) {
            let mut sibling = [0u8; HASH_SIZE];
            sibling.copy_from_slice(chunk);
            siblings.push(sibling);
        }
        let terminal_key: [u8; TERMINAL_KEY_SIZE] = bytes
            [siblings_end..siblings_end + TERMINAL_KEY_SIZE]
            .try_into()
            .expect("length checked");
        let terminal_value: [u8; AGGREGATION_TREE_VALUE_SIZE] = bytes
            [siblings_end + TERMINAL_KEY_SIZE..expected]
            .try_into()
            .expect("length checked");

        Self::from_parts(bitmap, siblings, terminal_key, terminal_value)
    }

    /// Encode to the canonical raw-byte representation.
    pub fn encode(&self) -> Vec<u8> {
        let Some(body) = &self.body else {
            return Vec::new();
        };
        let mut bytes = Vec::with_capacity(
            BITMAP_SIZE
                + body.siblings.len() * HASH_SIZE
                + TERMINAL_KEY_SIZE
                + AGGREGATION_TREE_VALUE_SIZE,
        );
        bytes.extend_from_slice(&body.bitmap);
        for sibling in &body.siblings {
            bytes.extend_from_slice(sibling);
        }
        bytes.extend_from_slice(&body.terminal_key);
        bytes.extend_from_slice(&body.terminal_value);
        bytes
    }

    /// Whether this is the distinguished certificate for an empty tree.
    pub fn is_empty_tree(&self) -> bool {
        self.body.is_none()
    }

    /// The authenticated terminal key, or `None` for an empty-tree certificate.
    ///
    /// Treat this as untrusted data until certificate or proof verification has
    /// succeeded.
    pub fn terminal_key(&self) -> Option<&[u8; TERMINAL_KEY_SIZE]> {
        self.body.as_ref().map(|body| &body.terminal_key)
    }

    /// The authenticated terminal value, or `None` for an empty-tree certificate.
    ///
    /// Treat this as untrusted data until certificate or proof verification has
    /// succeeded.
    pub fn terminal_value(&self) -> Option<&[u8; AGGREGATION_TREE_VALUE_SIZE]> {
        self.body.as_ref().map(|body| &body.terminal_value)
    }

    /// Classify the relation of `target` to the authenticated path, against a root the caller
    /// **already trusts** (`None` is the certified empty tree). It is not certificate
    /// authentication and exposes no snapshot: use
    /// [`NonInclusionProof::verify_at_snapshot`](crate::api::NonInclusionProof::verify_at_snapshot)
    /// when the root still needs BFT-certificate authentication.
    ///
    /// **Non-inclusion proves absence only at the authenticated snapshot returned by verification.
    /// It does not prove absence now, continuous absence, or that a token can be spent. Compare the
    /// snapshot’s network and root round (or its certified seal timestamp under your application's
    /// time policy) with an independently trusted requirement. The seal timestamp is a
    /// consensus-certified time, not proof of real-time freshness. Do not use unverified response
    /// metadata for this check.**
    pub fn relation_to_trusted_root(
        &self,
        target: &StateId,
        trusted_root: Option<&DataHash>,
    ) -> Result<PathRelation, VerificationError> {
        if !self.authenticates(target, trusted_root) {
            return Err(VerificationError::NonInclusionCertificateInvalid);
        }
        Ok(if self.terminal_matches(target) {
            PathRelation::Present
        } else {
            PathRelation::Absent
        })
    }

    pub(crate) fn authenticates(&self, target: &StateId, expected_root: Option<&DataHash>) -> bool {
        match (&self.body, expected_root) {
            (None, None) => true,
            (None, Some(_)) | (Some(_), None) => false,
            (Some(body), Some(root)) => fold_certificate_path(
                &body.bitmap,
                &body.siblings,
                target.bytes(),
                &body.terminal_key,
                &body.terminal_value,
            )
            .is_some_and(|calculated| &calculated == root),
        }
    }

    pub(crate) fn terminal_matches(&self, target: &StateId) -> bool {
        self.body
            .as_ref()
            .is_some_and(|body| &body.terminal_key == target.bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::{encode_byte_string, Decoder};
    use crate::crypto::hash::{DataHasher, HashAlgorithm};
    use alloc::vec;
    use hex_literal::hex;

    fn state_id(bytes: [u8; 32]) -> StateId {
        StateId::from_cbor(Decoder::new(&encode_byte_string(&bytes))).unwrap()
    }

    fn leaf_root(key: &[u8; 32], value: &[u8; 32]) -> DataHash {
        DataHasher::new(HashAlgorithm::Sha256)
            .expect("sha256")
            .update(&[0x00])
            .update(key)
            .update(value)
            .finalize()
    }

    #[test]
    fn empty_certificate_only_verifies_empty_root() {
        let certificate = NonInclusionCertificate::empty_tree();
        let target = state_id([7u8; 32]);
        assert!(certificate.is_empty_tree());
        assert_eq!(
            certificate.relation_to_trusted_root(&target, None),
            Ok(PathRelation::Absent)
        );
        assert_eq!(
            certificate.relation_to_trusted_root(&target, Some(&leaf_root(&[1; 32], &[2; 32]))),
            Err(VerificationError::NonInclusionCertificateInvalid)
        );
        assert!(certificate.encode().is_empty());
    }

    #[test]
    fn singleton_terminal_proves_another_key_absent() {
        let terminal_key = [1u8; 32];
        let terminal_value = [2u8; 32];
        let certificate = NonInclusionCertificate::from_parts(
            [0u8; BITMAP_SIZE],
            vec![],
            terminal_key,
            terminal_value,
        )
        .unwrap();
        let mut encoded = vec![0u8; BITMAP_SIZE];
        encoded.extend_from_slice(&terminal_key);
        encoded.extend_from_slice(&terminal_value);
        let root = leaf_root(&terminal_key, &terminal_value);

        assert_eq!(
            certificate.relation_to_trusted_root(&state_id([3u8; 32]), Some(&root)),
            Ok(PathRelation::Absent)
        );
        assert_eq!(
            certificate.relation_to_trusted_root(&state_id(terminal_key), Some(&root)),
            Ok(PathRelation::Present)
        );
        assert_eq!(certificate.terminal_key(), Some(&terminal_key));
        assert_eq!(certificate.terminal_value(), Some(&terminal_value));
        assert_eq!(certificate.encode(), encoded);
    }

    #[test]
    fn branch_choice_is_bound_to_target() {
        let left_key = [0u8; 32];
        let mut right_key = [0u8; 32];
        right_key[0] = 0x80;
        let left_value = [1u8; 32];
        let right_value = [2u8; 32];
        let left_hash = leaf_root(&left_key, &left_value);
        let right_hash = leaf_root(&right_key, &right_value);
        let root = DataHasher::new(HashAlgorithm::Sha256)
            .expect("sha256")
            .update(&[0x01, 0])
            .update(&[0u8; 32])
            .update(left_hash.data())
            .update(right_hash.data())
            .finalize();

        let mut bitmap = [0u8; BITMAP_SIZE];
        bitmap[0] = 0x80;
        let certificate = NonInclusionCertificate::from_parts(
            bitmap,
            vec![right_hash.data().try_into().expect("SHA-256 length")],
            left_key,
            left_value,
        )
        .unwrap();

        let mut target_left = [0u8; 32];
        target_left[31] = 1;
        assert_eq!(
            certificate.relation_to_trusted_root(&state_id(target_left), Some(&root)),
            Ok(PathRelation::Absent)
        );

        let mut target_right = [0u8; 32];
        target_right[0] = 0x80;
        target_right[31] = 1;
        assert_eq!(
            certificate.relation_to_trusted_root(&state_id(target_right), Some(&root)),
            Err(VerificationError::NonInclusionCertificateInvalid)
        );
    }

    #[test]
    fn decoder_rejects_wrong_terminal_or_sibling_lengths() {
        let mut bitmap = [0u8; BITMAP_SIZE];
        bitmap[0] = 0x80;
        assert!(NonInclusionCertificate::from_parts(
            bitmap,
            vec![],
            [1u8; 32],
            [2u8; AGGREGATION_TREE_VALUE_SIZE],
        )
        .is_err());

        assert!(NonInclusionCertificate::decode(&[0u8; 32]).is_err());

        let mut one_sibling_without_terminal = vec![0u8; 64];
        one_sibling_without_terminal[0] = 0x80;
        assert!(NonInclusionCertificate::decode(&one_sibling_without_terminal).is_err());

        let mut valid_singleton = vec![0u8; 96];
        valid_singleton.push(0);
        assert!(NonInclusionCertificate::decode(&valid_singleton).is_err());
    }

    #[test]
    fn rugregator_two_leaf_golden_vector_verifies() {
        // Generated independently by rugregator's rsmt implementation for
        // leaves 00..00 -> 01..01 and 80..00 -> 02..02, queried at 01..00.
        let certificate = NonInclusionCertificate::decode(&hex!(
            "8000000000000000000000000000000000000000000000000000000000000000d79ae116bb8c8604819adc35c2a71b7c3acf89cd1be8a382fbedbd6905ac20e700000000000000000000000000000000000000000000000000000000000000000101010101010101010101010101010101010101010101010101010101010101"
        ))
        .unwrap();
        let root = DataHash::new(
            HashAlgorithm::Sha256,
            hex!("5158a5f4029511f5312b7a147c9da48b9281322d1b893a10a25b2c17e2197a53"),
        )
        .unwrap();
        let mut target = [0u8; 32];
        target[0] = 0x01;

        assert_eq!(
            certificate.relation_to_trusted_root(&state_id(target), Some(&root)),
            Ok(PathRelation::Absent)
        );
    }
}
