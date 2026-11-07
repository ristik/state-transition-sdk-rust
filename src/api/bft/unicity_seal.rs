//! Unicity seal (CBOR tag 39005): the BFT-signed commitment to a unicity-tree
//! root.

use alloc::string::String;
use alloc::vec::Vec;

use crate::api::network_id::NetworkId;
use crate::cbor::{
    encode_array, encode_byte_string, encode_map, encode_nullable, encode_tag, encode_text_string,
    encode_uint, Decoder,
};
use crate::crypto::hash::{sha256, DataHash};
use crate::error::Error;

/// CBOR tag for [`UnicitySeal`].
pub const UNICITY_SEAL_TAG: u64 = 39005;
const VERSION: u64 = 1;

/// A unicity seal. Its [`hash`](UnicitySeal::hash) is the value validators sign;
/// [`calculate_hash`](UnicitySeal::calculate_hash) recomputes the seal hash with
/// the signatures slot set to `null`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnicitySeal {
    /// Network id.
    pub network_id: NetworkId,
    /// Root-chain round number.
    pub root_chain_round_number: u64,
    /// Epoch.
    pub epoch: u64,
    /// Timestamp.
    pub timestamp: u64,
    /// Previous seal hash.
    pub previous_hash: Option<Vec<u8>>,
    /// The unicity-tree root this seal commits to.
    pub hash: Vec<u8>,
    /// Validator signatures: node id -> 65-byte signature.
    pub signatures: Vec<(String, Vec<u8>)>,
}

/// The most signatures a seal may carry: a resource ceiling equal to the most members a trust-base entry may have (owner §49), counting unknown and bad
/// extras too. Signature validity and the quorum rule are unchanged.
pub const MAX_SEAL_SIGNATURES: usize = 256;

impl UnicitySeal {
    /// Decode from CBOR (tagged).
    pub fn from_cbor(d: Decoder<'_>) -> Result<Self, Error> {
        let inner = d.expect_tag(UNICITY_SEAL_TAG)?;
        let items = inner.array(Some(8))?;
        if items[0].uint()? != VERSION {
            return Err(Error::UnexpectedValue("unsupported UnicitySeal version"));
        }
        let network_id = NetworkId::new(
            u16::try_from(items[1].uint()?).map_err(|_| Error::OutOfRange("network id"))?,
        )?;
        let previous_hash =
            items[5].nullable(|x| x.bytes_value().map(|b| b.to_vec()).map_err(Into::into))?;
        let hash = items[6].bytes_value()?.to_vec();
        let mut signatures = Vec::new();
        if !items[7].is_null() {
            let pairs = items[7].map()?;
            // a resource ceiling checked before the keys and signatures are copied
            if pairs.len() > MAX_SEAL_SIGNATURES {
                return Err(Error::OutOfRange("seal signatures"));
            }
            signatures.reserve(pairs.len());
            for (k, v) in pairs {
                signatures.push((k.text()?.into(), v.bytes_value()?.to_vec()));
            }
        }
        Ok(UnicitySeal {
            network_id,
            root_chain_round_number: items[2].uint()?,
            epoch: items[3].uint()?,
            timestamp: items[4].uint()?,
            previous_hash,
            hash,
            signatures,
        })
    }

    fn encode(&self, include_signatures: bool) -> Vec<u8> {
        let sig_bytes = if include_signatures {
            let mut entries: Vec<(Vec<u8>, Vec<u8>)> = self
                .signatures
                .iter()
                .map(|(k, v)| (encode_text_string(k), encode_byte_string(v)))
                .collect();
            encode_map(&mut entries)
        } else {
            crate::cbor::encode_null()
        };
        encode_tag(
            UNICITY_SEAL_TAG,
            &encode_array(&[
                &encode_uint(VERSION),
                &encode_uint(self.network_id.id() as u64),
                &encode_uint(self.root_chain_round_number),
                &encode_uint(self.epoch),
                &encode_uint(self.timestamp),
                &encode_nullable(self.previous_hash.as_ref(), |v| encode_byte_string(v)),
                &encode_byte_string(&self.hash),
                &sig_bytes,
            ]),
        )
    }

    /// Encode to CBOR (tagged), including signatures.
    pub fn to_cbor(&self) -> Vec<u8> {
        self.encode(true)
    }

    /// The seal hash validators sign: `H(toCBOR with signatures = null)`.
    pub fn calculate_hash(&self) -> DataHash {
        sha256(&self.encode(false))
    }
}
