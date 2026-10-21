//! What the aggregator answers when asked about a state.

use alloc::vec::Vec;

use super::bft::UnicityCertificate;
use super::inclusion_proof::{DecodedParts, INCLUSION_PROOF_TAG, VERSION};
use super::InclusionProof;
use crate::cbor::{encode_array, encode_null, encode_tag, encode_uint, Decoder};
use crate::error::Error;

/// The aggregator's answer about a state: a certified leaf, or the absence of
/// one.
///
/// This is the wire shape, and it has two forms. Keeping that distinction here
/// rather than inside [`InclusionProof`] is what lets the proof itself be
/// complete by construction: a verifier holding one never has to ask whether it
/// describes a leaf.
// `Certified` is larger than `NotCertified` by the certification data and the
// inclusion certificate (216 bytes). Boxing the proof would only invert the
// imbalance, since `NotCertified` still carries a whole unicity certificate,
// and it would cost an allocation on every proof lookup.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InclusionProofResponse {
    /// The aggregator has certified this state.
    ///
    /// The round it was served against is the proof's own, so there is no
    /// second certificate to supply and none that could disagree with it.
    Certified {
        /// Block number the answer was served at.
        block_number: u64,
        /// The certified leaf.
        proof: InclusionProof,
    },
    /// The aggregator has not certified this state yet, so only the round is
    /// meaningful.
    NotCertified {
        /// Block number the answer was served at.
        block_number: u64,
        /// Certificate of the round the answer was served against.
        unicity_certificate: UnicityCertificate,
    },
}

impl InclusionProofResponse {
    /// Decode the `[blockNumber, InclusionProof]` response payload.
    pub fn from_cbor(d: Decoder<'_>) -> Result<Self, Error> {
        let items = d.array(Some(2))?;
        let block_number = items[0].uint()?;
        let parts = DecodedParts::from_cbor(items[1], None)?;

        if parts.certification_data.is_none() {
            return Ok(InclusionProofResponse::NotCertified {
                block_number,
                unicity_certificate: parts.unicity_certificate,
            });
        }
        Ok(InclusionProofResponse::Certified {
            block_number,
            proof: parts.into_certified()?,
        })
    }

    /// Encode to CBOR.
    pub fn to_cbor(&self) -> Vec<u8> {
        match self {
            InclusionProofResponse::Certified {
                block_number,
                proof,
            } => encode_array(&[&encode_uint(*block_number), &proof.to_cbor()]),
            InclusionProofResponse::NotCertified {
                block_number,
                unicity_certificate,
            } => encode_array(&[
                &encode_uint(*block_number),
                &encode_tag(
                    INCLUSION_PROOF_TAG,
                    &encode_array(&[
                        &encode_uint(VERSION),
                        &encode_null(),
                        &encode_null(),
                        &encode_null(),
                        &unicity_certificate.to_cbor(),
                    ]),
                ),
            ]),
        }
    }

    /// Block number the answer was served at.
    pub fn block_number(&self) -> u64 {
        match self {
            InclusionProofResponse::Certified { block_number, .. }
            | InclusionProofResponse::NotCertified { block_number, .. } => *block_number,
        }
    }

    /// The certified leaf, if there is one.
    pub fn inclusion_proof(&self) -> Option<&InclusionProof> {
        match self {
            InclusionProofResponse::Certified { proof, .. } => Some(proof),
            InclusionProofResponse::NotCertified { .. } => None,
        }
    }

    /// Certificate of the round the answer was served against.
    pub fn unicity_certificate(&self) -> &UnicityCertificate {
        match self {
            InclusionProofResponse::Certified { proof, .. } => &proof.unicity_certificate,
            InclusionProofResponse::NotCertified {
                unicity_certificate,
                ..
            } => unicity_certificate,
        }
    }
}
