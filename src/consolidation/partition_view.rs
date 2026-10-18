//! The `PartitionViewV1` value, its strict codec and bound checks.
//!
//! Wire: an untagged, definite-length array
//! `[1, partitionId, [[shardId, inputRecord, trHash, shardConfHash], ...]]`
//! where `shardId` is the end-marker bit string as a byte string, `inputRecord`
//! the embedded tag-39002 native record and the hashes byte strings.

use alloc::vec::Vec;

use super::error::PartitionViewError;
use crate::api::bft::input_record::INPUT_RECORD_TAG;
use crate::api::bft::{InputRecord, ShardId};
use crate::cbor::{
    encode_array, encode_byte_string, encode_nullable, encode_tag, encode_uint, DecodeLimits,
    Decoder,
};

/// The only supported partition view version.
pub const PARTITION_VIEW_VERSION: u64 = 1;
/// Maximum number of shards in a view.
pub const MAX_PARTITION_VIEW_LEAVES: usize = 8;
/// Maximum size of an encoded view.
pub const MAX_PARTITION_VIEW_BYTES: usize = 16 * 1024;
/// Maximum shard id length in bits.
pub const MAX_PARTITION_VIEW_SHARD_ID_BITS: usize = 256;
/// Maximum size of one encoded input record.
pub const MAX_PARTITION_VIEW_IR_BYTES: usize = 1024;
/// Maximum size of an input record's summary value.
pub const MAX_PARTITION_VIEW_SUMMARY_VALUE_BYTES: usize = 256;

const HASH_LEN: usize = 32;

// array(3) > leaves > leaf > tag > input record > its items
const DECODE_LIMITS: DecodeLimits = DecodeLimits {
    max_input_bytes: MAX_PARTITION_VIEW_BYTES,
    max_nesting_depth: 5,
    max_collection_items: 16,
    max_total_items: 192,
};

/// A native input record exactly as carried by a view.
///
/// Unlike [`InputRecord`] it keeps the CBOR distinction between an absent
/// (`null`) and an empty byte string for **every** byte field, because the leaf
/// hash covers the exact encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionViewInputRecord {
    /// Shard round number.
    pub round_number: u64,
    /// Shard epoch.
    pub epoch: u64,
    /// Previously certified state hash.
    pub previous_hash: Option<Vec<u8>>,
    /// Certified state hash.
    pub hash: Option<Vec<u8>>,
    /// Summary value.
    pub summary_value: Option<Vec<u8>>,
    /// Reference time.
    pub timestamp: u64,
    /// Block hash.
    pub block_hash: Option<Vec<u8>>,
    /// Sum of earned fees.
    pub sum_of_earned_fees: u64,
    /// Executed transactions hash.
    pub executed_transactions_hash: Option<Vec<u8>>,
}

impl PartitionViewInputRecord {
    /// The view representation of an ordinary input record.
    pub fn from_input_record(ir: &InputRecord) -> Self {
        Self {
            round_number: ir.round_number,
            epoch: ir.epoch,
            previous_hash: ir.previous_hash.clone(),
            hash: ir.hash.clone(),
            summary_value: ir.summary_value.clone(),
            timestamp: ir.timestamp,
            block_hash: ir.block_hash.clone(),
            sum_of_earned_fees: ir.sum_of_earned_fees,
            executed_transactions_hash: ir.executed_transactions_hash.clone(),
        }
    }

    /// The ordinary input record (every nullable field is preserved as such).
    pub fn to_input_record(&self) -> InputRecord {
        InputRecord {
            round_number: self.round_number,
            epoch: self.epoch,
            previous_hash: self.previous_hash.clone(),
            hash: self.hash.clone(),
            summary_value: self.summary_value.clone(),
            timestamp: self.timestamp,
            block_hash: self.block_hash.clone(),
            sum_of_earned_fees: self.sum_of_earned_fees,
            executed_transactions_hash: self.executed_transactions_hash.clone(),
        }
    }

    fn from_cbor(d: Decoder<'_>) -> Result<Self, PartitionViewError> {
        let inner = d.expect_tag(INPUT_RECORD_TAG)?;
        let items = inner.array(Some(10))?;
        if items[0].uint()? != 1 {
            return Err(PartitionViewError::Bounds(
                "unsupported input record version",
            ));
        }
        let opt = |d: Decoder<'_>| {
            d.nullable(|x| x.bytes_value().map(|b| b.to_vec()).map_err(Into::into))
        };
        Ok(Self {
            round_number: items[1].uint()?,
            epoch: items[2].uint()?,
            previous_hash: opt(items[3])?,
            hash: opt(items[4])?,
            summary_value: opt(items[5])?,
            timestamp: items[6].uint()?,
            block_hash: opt(items[7])?,
            sum_of_earned_fees: items[8].uint()?,
            executed_transactions_hash: opt(items[9])?,
        })
    }

    /// Encode as the tagged native input record.
    pub fn to_cbor(&self) -> Vec<u8> {
        let bs = |v: &Vec<u8>| encode_byte_string(v);
        encode_tag(
            INPUT_RECORD_TAG,
            &encode_array(&[
                &encode_uint(1),
                &encode_uint(self.round_number),
                &encode_uint(self.epoch),
                &encode_nullable(self.previous_hash.as_ref(), bs),
                &encode_nullable(self.hash.as_ref(), bs),
                &encode_nullable(self.summary_value.as_ref(), bs),
                &encode_uint(self.timestamp),
                &encode_nullable(self.block_hash.as_ref(), bs),
                &encode_uint(self.sum_of_earned_fees),
                &encode_nullable(self.executed_transactions_hash.as_ref(), bs),
            ]),
        )
    }

    /// Native validity of the record (as the reference `InputRecord.IsValid`)
    /// plus the consolidation admission bounds.
    fn check(&self) -> Result<(), PartitionViewError> {
        if self.round_number != 0 {
            if self.summary_value.is_none() {
                return Err(PartitionViewError::Bounds(
                    "input record: summary value is nil",
                ));
            }
            if self.timestamp == 0 {
                return Err(PartitionViewError::Bounds(
                    "input record: timestamp is unassigned",
                ));
            }
        }
        let bytes = |o: &Option<Vec<u8>>| o.as_deref().unwrap_or(&[]).to_vec();
        let same_state = bytes(&self.previous_hash) == bytes(&self.hash);
        let nil_block_hash = self.block_hash.as_deref().map_or(true, <[u8]>::is_empty);
        if same_state && !nil_block_hash {
            return Err(PartitionViewError::Bounds(
                "input record: state hash didn't change but block hash is not nil",
            ));
        }
        if !same_state && nil_block_hash {
            return Err(PartitionViewError::Bounds(
                "input record: block hash is nil but state hash changed",
            ));
        }
        if self.summary_value.as_ref().map_or(0, Vec::len) > MAX_PARTITION_VIEW_SUMMARY_VALUE_BYTES
        {
            return Err(PartitionViewError::Bounds("summary value is too long"));
        }
        for h in [
            &self.hash,
            &self.previous_hash,
            &self.block_hash,
            &self.executed_transactions_hash,
        ] {
            // absent/empty (initial or unchanged state) or a full hash
            if h.as_ref()
                .is_some_and(|h| !h.is_empty() && h.len() != HASH_LEN)
            {
                return Err(PartitionViewError::Bounds(
                    "input record hash must be empty or 32 bytes",
                ));
            }
        }
        if self.to_cbor().len() > MAX_PARTITION_VIEW_IR_BYTES {
            return Err(PartitionViewError::Bounds("input record is too large"));
        }
        Ok(())
    }
}

/// One shard's leaf of the view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionViewLeaf {
    /// The shard.
    pub shard_id: ShardId,
    /// The shard's input record.
    pub input_record: PartitionViewInputRecord,
    /// Hash of the shard's technical record (32 bytes).
    pub tr_hash: Vec<u8>,
    /// Hash of the shard configuration (32 bytes).
    pub shard_conf_hash: Vec<u8>,
}

impl PartitionViewLeaf {
    fn check(&self) -> Result<(), PartitionViewError> {
        if self.shard_id.length() > MAX_PARTITION_VIEW_SHARD_ID_BITS {
            return Err(PartitionViewError::Bounds("shard id is too long"));
        }
        self.input_record.check()?;
        if self.tr_hash.len() != HASH_LEN {
            return Err(PartitionViewError::Bounds("TRHash must be 32 bytes"));
        }
        if self.shard_conf_hash.len() != HASH_LEN {
            return Err(PartitionViewError::Bounds("ShardConfHash must be 32 bytes"));
        }
        Ok(())
    }

    fn to_cbor(&self) -> Vec<u8> {
        encode_array(&[
            &encode_byte_string(&self.shard_id.encode()),
            &self.input_record.to_cbor(),
            &encode_byte_string(&self.tr_hash),
            &encode_byte_string(&self.shard_conf_hash),
        ])
    }

    fn from_cbor(d: Decoder<'_>) -> Result<Self, PartitionViewError> {
        let items = d.array(Some(4))?;
        Ok(Self {
            shard_id: ShardId::decode(items[0].bytes_value()?)?,
            input_record: PartitionViewInputRecord::from_cbor(items[1])?,
            tr_hash: items[2].bytes_value()?.to_vec(),
            shard_conf_hash: items[3].bytes_value()?.to_vec(),
        })
    }

    /// `H(inputRecord, trHash, shardConfHash)`, the native shard tree leaf.
    pub(crate) fn leaf_hash(&self) -> Vec<u8> {
        use crate::crypto::hash::{DataHasher, HashAlgorithm};
        DataHasher::new(HashAlgorithm::Sha256)
            .expect("sha256")
            .update(&self.input_record.to_cbor())
            .update(&encode_byte_string(&self.tr_hash))
            .update(&encode_byte_string(&self.shard_conf_hash))
            .finalize()
            .data()
            .to_vec()
    }
}

/// The complete leaf vector of one partition under a single unicity seal
/// (version 1; the version is implicit and never defaulted on decode).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionView {
    /// The partition (non-zero).
    pub partition_id: u32,
    /// The leaves, in canonical shard order.
    pub leaves: Vec<PartitionViewLeaf>,
}

impl PartitionView {
    /// Check the structural bounds that do not need a topology.
    pub fn check_bounds(&self) -> Result<(), PartitionViewError> {
        if self.partition_id == 0 {
            return Err(PartitionViewError::Bounds("partition ID is zero"));
        }
        let n = self.leaves.len();
        if !(1..=MAX_PARTITION_VIEW_LEAVES).contains(&n) {
            return Err(PartitionViewError::Bounds("leaf count must be 1..=8"));
        }
        self.leaves.iter().try_for_each(PartitionViewLeaf::check)
    }

    /// Encode the view; it must satisfy the bounds.
    pub fn to_cbor(&self) -> Result<Vec<u8>, PartitionViewError> {
        self.check_bounds()?;
        let leaves: Vec<Vec<u8>> = self.leaves.iter().map(PartitionViewLeaf::to_cbor).collect();
        let leaf_refs: Vec<&[u8]> = leaves.iter().map(Vec::as_slice).collect();
        let data = encode_array(&[
            &encode_uint(PARTITION_VIEW_VERSION),
            &encode_uint(u64::from(self.partition_id)),
            &encode_array(&leaf_refs),
        ]);
        if data.len() > MAX_PARTITION_VIEW_BYTES {
            return Err(PartitionViewError::TooLarge {
                limit: MAX_PARTITION_VIEW_BYTES,
                actual: data.len(),
            });
        }
        Ok(data)
    }

    /// Strictly decode a view: bounded input size and nesting, exact array
    /// lengths, definite lengths only, no trailing bytes, explicit version 1,
    /// all bounds, and the encoding must be the canonical one.
    pub fn from_cbor(data: &[u8]) -> Result<Self, PartitionViewError> {
        if data.len() > MAX_PARTITION_VIEW_BYTES {
            return Err(PartitionViewError::TooLarge {
                limit: MAX_PARTITION_VIEW_BYTES,
                actual: data.len(),
            });
        }
        let top = Decoder::with_limits(data, DECODE_LIMITS);
        let items = top.array(Some(3))?;
        let version = items[0].uint()?;
        if version != PARTITION_VIEW_VERSION {
            return Err(PartitionViewError::UnsupportedVersion(version));
        }
        let partition_id = u32::try_from(items[1].uint()?)
            .map_err(|_| PartitionViewError::Bounds("partition ID exceeds 32 bits"))?;
        let mut leaves = Vec::new();
        for leaf in items[2].array(None)? {
            leaves.push(PartitionViewLeaf::from_cbor(leaf)?);
        }
        let view = PartitionView {
            partition_id,
            leaves,
        };
        view.check_bounds()?;
        if view.to_cbor()? != data {
            return Err(PartitionViewError::NotCanonical);
        }
        Ok(view)
    }
}
