//! Inclusion proof (CBOR tag 39033): the aggregator's response binding a
//! transaction to a unique, BFT-certified position in the state tree.

use alloc::vec::Vec;

use super::bft::{RootTrustBase, UnicityCertificate};
use super::certification::CertificationData;
use super::inclusion_certificate::InclusionCertificate;
use super::StateId;
use crate::cbor::{encode_array, encode_byte_string, encode_tag, encode_uint, Decoder};
use crate::error::Error;
use crate::verify::{self, VerificationError};

/// CBOR tag for [`InclusionProof`].
pub const INCLUSION_PROOF_TAG: u64 = 39033;
pub(super) const VERSION: u64 = 1;

/// A proof of inclusion in the sparse Merkle tree, plus the unicity certificate
/// that anchors the tree root to the BFT consensus.
///
/// An `InclusionProof` describes a certified leaf, so every field is present.
/// The aggregator's answer for a state it has not certified yet is not an
/// inclusion proof at all: see [`InclusionProofResponse`], which is the type
/// that can express it.
///
/// [`InclusionProofResponse`]: super::InclusionProofResponse
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    /// What was certified.
    pub certification_data: CertificationData,
    /// Reference time of the round the certified leaf was created in.
    ///
    /// It cannot be recovered from the certificate chain: an aggregator serves
    /// proofs against the current certified root, whose input record time is
    /// that of the latest round rather than the one the leaf was created under.
    pub reference_time: u64,
    /// The SMT path.
    pub inclusion_certificate: InclusionCertificate,
    /// The BFT unicity certificate.
    pub unicity_certificate: UnicityCertificate,
}

impl InclusionProof {
    /// Decode from CBOR (tagged).
    ///
    /// The bytes must describe a certified leaf. The same wire form can also
    /// say that no leaf is certified yet, but that is not an `InclusionProof`:
    /// [`InclusionProofResponse`] is the type that carries it, and it decodes
    /// that case itself.
    ///
    /// [`InclusionProofResponse`]: super::InclusionProofResponse
    pub fn from_cbor(d: Decoder<'_>) -> Result<Self, Error> {
        let parts = DecodedParts::from_cbor(d, None)?;
        parts.into_certified()
    }

    /// Like [`from_cbor`](Self::from_cbor), decoding the unicity certificate
    /// through `interner` so identical certificates of one operation are parsed once.
    pub fn from_cbor_interned(
        d: Decoder<'_>,
        interner: &mut super::bft::UcInterner,
    ) -> Result<Self, Error> {
        DecodedParts::from_cbor(d, Some(interner))?.into_certified()
    }

    /// Encode to CBOR (tagged).
    pub fn to_cbor(&self) -> Vec<u8> {
        encode_tag(
            INCLUSION_PROOF_TAG,
            &encode_array(&[
                &encode_uint(VERSION),
                &self.certification_data.to_cbor(),
                &encode_uint(self.reference_time),
                &encode_byte_string(&self.inclusion_certificate.encode()),
                &self.unicity_certificate.to_cbor(),
            ]),
        )
    }

    /// Verify that this proof includes `state_id` at its certified root.
    ///
    /// This verifies the state relation, certification data, shard, quorum UC,
    /// and unlock witness. Transaction/token verification may impose additional
    /// application-level constraints.
    ///
    /// `reference_time` is the value the leaf was built from; it is taken from
    /// the caller rather than from this proof's certificate, because the tree
    /// is append-only and a proof may be issued against a later root.
    pub fn verify_for(
        &self,
        state_id: &StateId,
        reference_time: u64,
        trust_base: &RootTrustBase,
    ) -> Result<(), VerificationError> {
        verify::verify_inclusion_proof_for(trust_base, self, state_id, reference_time)
    }
}

/// The five wire slots of a tag-39033 structure, with the three leaf fields
/// still optional.
///
/// Shared by [`InclusionProof::from_cbor`] and the response decoder so that the
/// tag, version and "all three or none" checks exist once.
pub(super) struct DecodedParts {
    pub(super) certification_data: Option<CertificationData>,
    pub(super) reference_time: Option<u64>,
    pub(super) inclusion_certificate: Option<InclusionCertificate>,
    pub(super) unicity_certificate: UnicityCertificate,
}

impl DecodedParts {
    pub(super) fn from_cbor(
        d: Decoder<'_>,
        interner: Option<&mut super::bft::UcInterner>,
    ) -> Result<Self, Error> {
        let inner = d.expect_tag(INCLUSION_PROOF_TAG)?;
        let items = inner.array(Some(5))?;
        if items[0].uint()? != VERSION {
            return Err(Error::UnexpectedValue("unsupported InclusionProof version"));
        }
        let certification_data = items[1].nullable(CertificationData::from_cbor)?;
        let reference_time = items[2].nullable(|x| x.uint().map_err(Into::into))?;
        let inclusion_certificate =
            items[3].nullable(|x| InclusionCertificate::decode(x.bytes_value()?))?;

        // The three leaf fields travel together: all present once the request
        // has been included in a certified round, all absent while it is still
        // pending. Anything in between is a protocol violation, and rejecting
        // it here is what lets `InclusionProof` require all three.
        let present = certification_data.is_some() as u8
            + reference_time.is_some() as u8
            + inclusion_certificate.is_some() as u8;
        if present != 0 && present != 3 {
            return Err(Error::UnexpectedValue(
                "InclusionProof must carry certification data, reference time and inclusion certificate together, or none of them",
            ));
        }

        Ok(DecodedParts {
            certification_data,
            reference_time,
            inclusion_certificate,
            unicity_certificate: match interner {
                Some(i) => i.decode(items[4])?,
                None => UnicityCertificate::from_cbor(items[4])?,
            },
        })
    }

    /// Require a certified leaf.
    pub(super) fn into_certified(self) -> Result<InclusionProof, Error> {
        match (
            self.certification_data,
            self.reference_time,
            self.inclusion_certificate,
        ) {
            (Some(certification_data), Some(reference_time), Some(inclusion_certificate)) => {
                Ok(InclusionProof {
                    certification_data,
                    reference_time,
                    inclusion_certificate,
                    unicity_certificate: self.unicity_certificate,
                })
            }
            _ => Err(Error::UnexpectedValue(
                "expected a certified leaf, but the inclusion proof describes none",
            )),
        }
    }
}
