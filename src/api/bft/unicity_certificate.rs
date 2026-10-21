//! Unicity certificate (CBOR tag 39001) and the root-hash recomputations used
//! to tie an input record back to the signed unicity seal.

use alloc::vec::Vec;

use super::input_record::InputRecord;
use super::shard_tree::ShardTreeCertificate;
use super::unicity_seal::UnicitySeal;
use super::unicity_tree::UnicityTreeCertificate;
use crate::cbor::{
    encode_array, encode_byte_string, encode_nullable, encode_tag, encode_uint, Decoder,
};
use crate::crypto::hash::{DataHash, DataHasher, HashAlgorithm};
use crate::error::Error;

/// CBOR tag for [`UnicityCertificate`].
pub const UNICITY_CERTIFICATE_TAG: u64 = 39001;
const VERSION: u64 = 1;

/// A unicity certificate: input record + shard/unicity tree proofs + the signed
/// seal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnicityCertificate {
    /// The per-block input record (its `hash` is the certified state-tree root).
    pub input_record: InputRecord,
    /// Optional technical record hash.
    pub technical_record_hash: Option<Vec<u8>>,
    /// Shard configuration hash.
    pub shard_configuration_hash: Vec<u8>,
    /// Shard tree proof.
    pub shard_tree_certificate: ShardTreeCertificate,
    /// Unicity tree proof.
    pub unicity_tree_certificate: UnicityTreeCertificate,
    /// The signed seal.
    pub unicity_seal: UnicitySeal,
}

impl UnicityCertificate {
    /// Decode from CBOR (tagged).
    pub fn from_cbor(d: Decoder<'_>) -> Result<Self, Error> {
        let inner = d.expect_tag(UNICITY_CERTIFICATE_TAG)?;
        let items = inner.array(Some(7))?;
        if items[0].uint()? != VERSION {
            return Err(Error::UnexpectedValue(
                "unsupported UnicityCertificate version",
            ));
        }
        Ok(UnicityCertificate {
            input_record: InputRecord::from_cbor(items[1])?,
            technical_record_hash: items[2]
                .nullable(|x| x.bytes_value().map(|b| b.to_vec()).map_err(Into::into))?,
            shard_configuration_hash: items[3].bytes_value()?.to_vec(),
            shard_tree_certificate: ShardTreeCertificate::from_cbor(items[4])?,
            unicity_tree_certificate: UnicityTreeCertificate::from_cbor(items[5])?,
            unicity_seal: UnicitySeal::from_cbor(items[6])?,
        })
    }

    /// Encode to CBOR (tagged).
    pub fn to_cbor(&self) -> Vec<u8> {
        encode_tag(
            UNICITY_CERTIFICATE_TAG,
            &encode_array(&[
                &encode_uint(VERSION),
                &self.input_record.to_cbor(),
                &encode_nullable(self.technical_record_hash.as_ref(), |v| {
                    encode_byte_string(v)
                }),
                &encode_byte_string(&self.shard_configuration_hash),
                &self.shard_tree_certificate.to_cbor(),
                &self.unicity_tree_certificate.to_cbor(),
                &self.unicity_seal.to_cbor(),
            ]),
        )
    }

    /// The body rules of bft-go-base's `UnicityCertificate.IsValid` that do not depend on the
    /// caller's expectations: the input record's conditional rules (outside round 0 the summary
    /// value is present and the timestamp assigned; the block hash is empty exactly when the
    /// state hash is unchanged) and a 32-byte technical record hash. A null summary value is
    /// legal at round 0, and so is a null hash. `Err` names the violated rule.
    pub fn check_body(&self) -> Result<(), &'static str> {
        let ir = &self.input_record;
        if ir.round_number != 0 {
            if ir.summary_value.is_none() {
                return Err("summary value is nil");
            }
            if ir.timestamp == 0 {
                return Err("timestamp is unassigned");
            }
        }
        // Go compares with bytes.Equal and tests len(), so null and empty are the same here.
        let empty: &[u8] = &[];
        let same_state =
            ir.previous_hash.as_deref().unwrap_or(empty) == ir.hash.as_deref().unwrap_or(empty);
        let block_hash_empty = ir.block_hash.as_deref().map_or(true, <[u8]>::is_empty);
        if same_state && !block_hash_empty {
            return Err("state hash didn't change but block hash is not nil");
        }
        if !same_state && block_hash_empty {
            return Err("block hash is nil but state hash changed");
        }
        if self.technical_record_hash.as_ref().map(Vec::len) != Some(32) {
            return Err("technical record hash must be 32 bytes");
        }
        Ok(())
    }

    /// Recompute the shard-tree root hash from the input record and shard proof.
    pub fn shard_tree_root_hash(&self) -> Result<DataHash, Error> {
        let mut root = DataHasher::new(HashAlgorithm::Sha256)
            .expect("sha256")
            .update(&self.input_record.to_cbor())
            .update(&encode_nullable(self.technical_record_hash.as_ref(), |v| {
                encode_byte_string(v)
            }))
            .update(&encode_byte_string(&self.shard_configuration_hash))
            .finalize();

        let shard = &self.shard_tree_certificate.shard;
        let siblings = &self.shard_tree_certificate.sibling_hash_list;
        if siblings.len() != shard.length() {
            return Err(Error::UnexpectedValue(
                "shard sibling count differs from shard bit length",
            ));
        }
        for (i, sibling) in siblings.iter().enumerate() {
            let bit_index = shard
                .length()
                .checked_sub(i + 1)
                .ok_or(Error::OutOfRange("invalid shard sibling index"))?;
            let is_right = shard.get_bit(bit_index)? == 1;
            let h = DataHasher::new(HashAlgorithm::Sha256).expect("sha256");
            root = if is_right {
                h.update(&encode_byte_string(sibling))
                    .update(&encode_byte_string(root.data()))
            } else {
                h.update(&encode_byte_string(root.data()))
                    .update(&encode_byte_string(sibling))
            }
            .finalize();
        }
        Ok(root)
    }

    /// Recompute the unicity-tree root hash (which must equal the seal hash).
    pub fn computed_seal_hash(&self) -> Result<DataHash, Error> {
        let shard_root = self.shard_tree_root_hash()?;
        Ok(self
            .unicity_tree_certificate
            .compute_root_hash(shard_root.data()))
    }
}
