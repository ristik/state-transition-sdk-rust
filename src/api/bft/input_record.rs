//! Input record (CBOR tag 39002) — the per-block commitment whose `hash` is the
//! certified SMT root.

use alloc::vec::Vec;

use crate::cbor::{
    encode_array, encode_byte_string, encode_nullable, encode_tag, encode_uint, Decoder,
};
use crate::error::Error;

/// CBOR tag for [`InputRecord`].
pub const INPUT_RECORD_TAG: u64 = 39002;
const VERSION: u64 = 1;

/// Input record carried inside a [`UnicityCertificate`](super::UnicityCertificate).
///
/// Every nullable field keeps the CBOR distinction between `null` and an empty byte
/// string, on decode, on encode and in every hash preimage (the shard-tree leaf hashes
/// the exact encoding). In particular `hash: None` (native `null`, `f6`) is the
/// authenticated **empty tree**; `Some(vec![])` (`40`) is a different, non-conforming
/// encoding and is *not* an alias for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputRecord {
    /// Round number.
    pub round_number: u64,
    /// Epoch number.
    pub epoch: u64,
    /// Previous block hash.
    pub previous_hash: Option<Vec<u8>>,
    /// This block's certified state-tree root hash: `None` (native `null`) is the certified
    /// empty tree, otherwise 32 bytes. See [`root_hash`](Self::root_hash).
    pub hash: Option<Vec<u8>>,
    /// Summary value (`null` in the initial and timeout-repeat records of round 0).
    pub summary_value: Option<Vec<u8>>,
    /// Timestamp.
    pub timestamp: u64,
    /// Block hash.
    pub block_hash: Option<Vec<u8>>,
    /// Sum of earned fees.
    pub sum_of_earned_fees: u64,
    /// Executed transactions hash.
    pub executed_transactions_hash: Option<Vec<u8>>,
}

impl InputRecord {
    /// The certified state-tree root this record authenticates: `Ok(None)` for the native
    /// `null` hash (the certified empty tree), `Ok(Some(root))` for exactly 32 bytes, and an
    /// error for anything else — in particular for an empty byte string or the all-zero hash,
    /// which are not the empty tree.
    pub fn root_hash(&self) -> Result<Option<[u8; 32]>, Error> {
        match self.hash.as_deref() {
            None => Ok(None),
            Some(bytes) => <[u8; 32]>::try_from(bytes)
                .map(Some)
                .map_err(|_| Error::UnexpectedValue("input record hash must be null or 32 bytes")),
        }
    }

    /// Decode from CBOR (tagged).
    pub fn from_cbor(d: Decoder<'_>) -> Result<Self, Error> {
        let inner = d.expect_tag(INPUT_RECORD_TAG)?;
        let items = inner.array(Some(10))?;
        if items[0].uint()? != VERSION {
            return Err(Error::UnexpectedValue("unsupported InputRecord version"));
        }
        let opt = |d: Decoder<'_>| {
            d.nullable(|x| x.bytes_value().map(|b| b.to_vec()).map_err(Into::into))
        };
        Ok(InputRecord {
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

    /// Encode to CBOR (tagged).
    pub fn to_cbor(&self) -> Vec<u8> {
        let bs = |v: &Vec<u8>| encode_byte_string(v);
        encode_tag(
            INPUT_RECORD_TAG,
            &encode_array(&[
                &encode_uint(VERSION),
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(hash: Option<Vec<u8>>, summary_value: Option<Vec<u8>>) -> InputRecord {
        InputRecord {
            round_number: 0,
            epoch: 0,
            previous_hash: None,
            hash,
            summary_value,
            timestamp: 1,
            block_hash: None,
            sum_of_earned_fees: 0,
            executed_transactions_hash: None,
        }
    }

    /// Go-valid round-0 records carry a null hash and/or summary value; they must decode and
    /// re-encode byte-identically (the shard-tree leaf hashes the exact encoding).
    #[test]
    fn null_hash_and_summary_value_decode_and_roundtrip() {
        for (hash, summary) in [
            (None, None),
            (None, Some(Vec::new())),
            (Some(alloc::vec![9; 32]), None),
            (Some(alloc::vec![9; 32]), Some(Vec::new())),
        ] {
            let ir = record(hash, summary);
            let bytes = ir.to_cbor();
            let decoded = InputRecord::from_cbor(Decoder::new(&bytes)).unwrap();
            assert_eq!(decoded, ir);
            assert_eq!(decoded.to_cbor(), bytes);
        }
    }

    #[test]
    fn only_null_or_32_bytes_is_a_root_hash() {
        assert_eq!(record(None, None).root_hash(), Ok(None));
        assert_eq!(
            record(Some(alloc::vec![1; 32]), None).root_hash(),
            Ok(Some([1; 32]))
        );
        assert!(record(Some(Vec::new()), None).root_hash().is_err());
        assert!(record(Some(alloc::vec![1; 31]), None).root_hash().is_err());
    }
}
