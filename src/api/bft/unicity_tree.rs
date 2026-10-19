//! Unicity tree certificate (CBOR tag 39004) and its hash steps.

use alloc::vec::Vec;

use crate::cbor::{
    encode_array, encode_byte_string, encode_null, encode_tag, encode_uint, Decoder,
};
use crate::crypto::hash::{sha256, DataHash, DataHasher, HashAlgorithm};
use crate::error::Error;

/// CBOR tag for [`UnicityTreeCertificate`].
pub const UNICITY_TREE_CERTIFICATE_TAG: u64 = 39004;
/// The most steps a unicity tree path may have (the native bound).
pub const MAX_UNICITY_TREE_STEPS: usize = 32;
const VERSION: u64 = 1;

/// A single step on the path from the partition leaf to the unicity-tree root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashStep {
    /// The sibling node's key.
    pub key: u32,
    /// The sibling node's hash.
    pub hash: Vec<u8>,
}

impl HashStep {
    fn from_cbor(d: Decoder<'_>) -> Result<Self, Error> {
        let items = d.array(Some(2))?;
        Ok(HashStep {
            key: u32::try_from(items[0].uint()?)
                .map_err(|_| Error::OutOfRange("unicity tree step key exceeds 32 bits"))?,
            hash: items[1].bytes_value()?.to_vec(),
        })
    }

    fn to_cbor(&self) -> Vec<u8> {
        encode_array(&[
            &encode_uint(self.key as u64),
            &encode_byte_string(&self.hash),
        ])
    }
}

/// Proof folding the shard-tree root up to the unicity-tree root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnicityTreeCertificate {
    /// Partition identifier (the leaf key).
    pub partition_identifier: u32,
    /// Steps up to the root.
    pub steps: Vec<HashStep>,
    /// The list was `null` on the wire (an empty path collection written by a native encoder).
    /// Kept so that re-encoding reproduces the exact bytes; it has no meaning for verification.
    pub empty_as_null: bool,
}

impl UnicityTreeCertificate {
    /// Decode from CBOR (tagged).
    pub fn from_cbor(d: Decoder<'_>) -> Result<Self, Error> {
        let inner = d.expect_tag(UNICITY_TREE_CERTIFICATE_TAG)?;
        let items = inner.array(Some(3))?;
        if items[0].uint()? != VERSION {
            return Err(Error::UnexpectedValue(
                "unsupported UnicityTreeCertificate version",
            ));
        }
        let partition_identifier = u32::try_from(items[1].uint()?)
            .map_err(|_| Error::OutOfRange("partition identifier exceeds 32 bits"))?;
        // an empty path collection is `null` or an empty array on the native wire: zero steps
        let mut steps = Vec::new();
        let empty_as_null = items[2].is_null();
        if !empty_as_null {
            let encoded = items[2].array(None)?;
            if encoded.len() > MAX_UNICITY_TREE_STEPS {
                return Err(Error::OutOfRange("too many unicity tree steps"));
            }
            for s in encoded {
                steps.push(HashStep::from_cbor(s)?);
            }
        }
        Ok(UnicityTreeCertificate {
            partition_identifier,
            steps,
            empty_as_null,
        })
    }

    /// Fold the shard-tree root of this partition up the steps to the
    /// unicity-tree root (the value the unicity seal commits to).
    pub fn compute_root_hash(&self, shard_tree_root: &[u8]) -> DataHash {
        let key = self.partition_identifier.to_be_bytes();

        let unicity_tree_hash = sha256(&encode_byte_string(shard_tree_root));
        // LEAF
        let mut result = DataHasher::new(HashAlgorithm::Sha256)
            .expect("sha256")
            .update(&encode_byte_string(&[0x01]))
            .update(&encode_byte_string(&key))
            .update(&encode_byte_string(unicity_tree_hash.data()))
            .finalize();

        for step in &self.steps {
            let step_key = step.key.to_be_bytes();
            let h = DataHasher::new(HashAlgorithm::Sha256)
                .expect("sha256")
                .update(&encode_byte_string(&[0x00])) // NODE
                .update(&encode_byte_string(&step_key));
            result = if key[..] > step_key[..] {
                h.update(&encode_byte_string(&step.hash))
                    .update(&encode_byte_string(result.data()))
            } else {
                h.update(&encode_byte_string(result.data()))
                    .update(&encode_byte_string(&step.hash))
            }
            .finalize();
        }
        result
    }

    /// Encode to CBOR (tagged).
    pub fn to_cbor(&self) -> Vec<u8> {
        let steps: Vec<Vec<u8>> = self.steps.iter().map(|s| s.to_cbor()).collect();
        let step_refs: Vec<&[u8]> = steps.iter().map(|v| v.as_slice()).collect();
        encode_tag(
            UNICITY_TREE_CERTIFICATE_TAG,
            &encode_array(&[
                &encode_uint(VERSION),
                &encode_uint(self.partition_identifier as u64),
                &if self.empty_as_null && step_refs.is_empty() {
                    encode_null()
                } else {
                    encode_array(&step_refs)
                },
            ]),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_partition_and_step_keys_above_u32() {
        let oversized = encode_uint(u32::MAX as u64 + 1);
        let certificate = encode_tag(
            UNICITY_TREE_CERTIFICATE_TAG,
            &encode_array(&[&encode_uint(VERSION), &oversized, &encode_array(&[])]),
        );
        assert!(UnicityTreeCertificate::from_cbor(Decoder::new(&certificate)).is_err());

        let step = encode_array(&[&oversized, &encode_byte_string(&[0u8; 32])]);
        let certificate = encode_tag(
            UNICITY_TREE_CERTIFICATE_TAG,
            &encode_array(&[
                &encode_uint(VERSION),
                &encode_uint(1),
                &encode_array(&[&step]),
            ]),
        );
        assert!(UnicityTreeCertificate::from_cbor(Decoder::new(&certificate)).is_err());
    }
}
