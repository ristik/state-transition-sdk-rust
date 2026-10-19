//! Shard tree certificate (CBOR tag 39003).

use alloc::vec::Vec;

use super::shard_id::ShardId;
use crate::cbor::{
    encode_array, encode_byte_string, encode_null, encode_tag, encode_uint, Decoder,
};
use crate::error::Error;

/// CBOR tag for [`ShardTreeCertificate`].
pub const SHARD_TREE_CERTIFICATE_TAG: u64 = 39003;
const VERSION: u64 = 1;

/// Proof folding the shard's input record up to the shard-tree root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardTreeCertificate {
    /// The shard this certificate is for.
    pub shard: ShardId,
    /// Sibling hashes from the shard leaf up to the root.
    pub sibling_hash_list: Vec<Vec<u8>>,
    /// The list was `null` on the wire (an empty path collection written by a native encoder).
    /// Kept so that re-encoding reproduces the exact bytes; it has no meaning for verification.
    pub empty_as_null: bool,
}

impl ShardTreeCertificate {
    /// Decode from CBOR (tagged).
    pub fn from_cbor(d: Decoder<'_>) -> Result<Self, Error> {
        let inner = d.expect_tag(SHARD_TREE_CERTIFICATE_TAG)?;
        let items = inner.array(Some(3))?;
        if items[0].uint()? != VERSION {
            return Err(Error::UnexpectedValue(
                "unsupported ShardTreeCertificate version",
            ));
        }
        let shard = ShardId::decode(items[1].bytes_value()?)?;
        // the native encoders write an empty path collection as `null` or as an empty array:
        // both are zero siblings
        let mut sibling_hash_list = Vec::new();
        let empty_as_null = items[2].is_null();
        if !empty_as_null {
            for s in items[2].array(None)? {
                sibling_hash_list.push(s.bytes_value()?.to_vec());
            }
        }
        Ok(ShardTreeCertificate {
            shard,
            sibling_hash_list,
            empty_as_null,
        })
    }

    /// Encode to CBOR (tagged).
    pub fn to_cbor(&self) -> Vec<u8> {
        let siblings: Vec<Vec<u8>> = self
            .sibling_hash_list
            .iter()
            .map(|h| encode_byte_string(h))
            .collect();
        let sibling_refs: Vec<&[u8]> = siblings.iter().map(|v| v.as_slice()).collect();
        encode_tag(
            SHARD_TREE_CERTIFICATE_TAG,
            &encode_array(&[
                &encode_uint(VERSION),
                &encode_byte_string(&self.shard.encode()),
                &if self.empty_as_null && sibling_refs.is_empty() {
                    encode_null()
                } else {
                    encode_array(&sibling_refs)
                },
            ]),
        )
    }
}
