//! Non-inclusion proof (CBOR tag 39034): an absence certificate plus the BFT
//! certificate authenticating the SMT root at one certified point in time.

use alloc::vec::Vec;

use super::bft::{RootTrustBase, UnicityCertificate};
use super::{NonInclusionCertificate, StateId};
use crate::cbor::{encode_array, encode_byte_string, encode_tag, encode_uint, Decoder};
use crate::error::Error;
use crate::verify::{self, NonInclusionContext, VerificationError};

/// CBOR tag for [`NonInclusionProof`].
pub const NON_INCLUSION_PROOF_TAG: u64 = 39034;
const VERSION: u64 = 1;

/// Proof that a state id was absent at the root authenticated by a Unicity
/// Certificate.
///
/// This is a snapshot statement.  Verification does not assert that the state
/// remains absent at a later root; callers with freshness requirements must
/// apply their own certified-round or timestamp policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonInclusionProof {
    certificate: NonInclusionCertificate,
    unicity_certificate: UnicityCertificate,
    /// Local request context. This is deliberately not part of the wire format.
    requested_state_id: Option<StateId>,
}

impl NonInclusionProof {
    /// Construct a proof using the canonical version-1 certificate profile.
    pub fn new(
        certificate: NonInclusionCertificate,
        unicity_certificate: UnicityCertificate,
    ) -> Self {
        Self {
            certificate,
            unicity_certificate,
            requested_state_id: None,
        }
    }

    /// Decode a tagged proof in the canonical version-1 certificate profile.
    pub fn from_cbor(decoder: Decoder<'_>) -> Result<Self, Error> {
        let items = decoder
            .expect_tag(NON_INCLUSION_PROOF_TAG)?
            .array(Some(3))?;
        if items[0].uint()? != VERSION {
            return Err(Error::UnexpectedValue(
                "unsupported NonInclusionProof version",
            ));
        }
        let certificate = NonInclusionCertificate::decode(items[1].bytes_value()?)?;
        let unicity_certificate = UnicityCertificate::from_cbor(items[2])?;
        Ok(Self {
            certificate,
            unicity_certificate,
            requested_state_id: None,
        })
    }

    /// Encode using the canonical version-1 certificate profile.
    pub fn to_cbor(&self) -> Vec<u8> {
        encode_tag(
            NON_INCLUSION_PROOF_TAG,
            &encode_array(&[
                &encode_uint(VERSION),
                &encode_byte_string(&self.certificate.encode()),
                &self.unicity_certificate.to_cbor(),
            ]),
        )
    }

    /// The relation-specific SMT certificate.
    pub fn certificate(&self) -> &NonInclusionCertificate {
        &self.certificate
    }

    /// The BFT certificate anchoring this proof's SMT root.
    pub fn unicity_certificate(&self) -> &UnicityCertificate {
        &self.unicity_certificate
    }

    /// Bind this proof to the state id used to request it.
    ///
    /// The binding is local misuse-prevention metadata and is not serialized by
    /// [`to_cbor`](Self::to_cbor). Verification still authenticates the bound
    /// id cryptographically against the certificate.
    pub fn for_state(mut self, state_id: &StateId) -> Result<Self, VerificationError> {
        if self
            .requested_state_id
            .as_ref()
            .is_some_and(|requested| requested != state_id)
        {
            return Err(VerificationError::NonInclusionTargetMismatch);
        }
        self.requested_state_id = Some(state_id.clone());
        Ok(self)
    }

    /// The state id stamped onto this proof by the client, if any.
    pub fn requested_state_id(&self) -> Option<&StateId> {
        self.requested_state_id.as_ref()
    }

    /// Verify a client-bound proof against `trust_base`.
    ///
    /// The unicity certificate is authenticated strictly (network, exact epoch,
    /// root round not before the epoch start, quorum), but nothing here says which
    /// partition, shard or configuration it belongs to or how recent it is: prefer
    /// [`verify_in_context`](Self::verify_in_context).
    ///
    /// Proofs returned by the provided clients are bound automatically. A proof
    /// decoded directly from untrusted bytes has no request context; use
    /// [`verify_for`](Self::verify_for) for that case.
    pub fn verify(&self, trust_base: &RootTrustBase) -> Result<(), VerificationError> {
        let target = self
            .requested_state_id
            .as_ref()
            .ok_or(VerificationError::NonInclusionTargetMissing)?;
        verify::verify_non_inclusion_proof(trust_base, self, target)
    }

    /// Verify a client-bound proof, additionally against the caller's expectations
    /// (partition, optional shard and configuration pin, minimum root round, end of
    /// the authority's interval). See [`NonInclusionContext`].
    pub fn verify_in_context(
        &self,
        trust_base: &RootTrustBase,
        context: &NonInclusionContext,
    ) -> Result<(), VerificationError> {
        let target = self
            .requested_state_id
            .as_ref()
            .ok_or(VerificationError::NonInclusionTargetMissing)?;
        verify::verify_non_inclusion_proof_in_context(trust_base, self, target, context)
    }

    /// [`verify_in_context`](Self::verify_in_context) for a directly decoded proof
    /// and an explicit `target` (a different target than a client-bound one is
    /// rejected).
    pub fn verify_for_in_context(
        &self,
        target: &StateId,
        trust_base: &RootTrustBase,
        context: &NonInclusionContext,
    ) -> Result<(), VerificationError> {
        if self
            .requested_state_id
            .as_ref()
            .is_some_and(|requested| requested != target)
        {
            return Err(VerificationError::NonInclusionTargetMismatch);
        }
        verify::verify_non_inclusion_proof_in_context(trust_base, self, target, context)
    }

    /// Verify a directly decoded proof for an explicit `target` (strict authority
    /// authentication; see [`verify`](Self::verify)).
    ///
    /// If the proof is already client-bound, a different target is rejected so
    /// request context cannot be silently replaced.
    pub fn verify_for(
        &self,
        target: &StateId,
        trust_base: &RootTrustBase,
    ) -> Result<(), VerificationError> {
        if self
            .requested_state_id
            .as_ref()
            .is_some_and(|requested| requested != target)
        {
            return Err(VerificationError::NonInclusionTargetMismatch);
        }
        verify::verify_non_inclusion_proof(trust_base, self, target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoder_rejects_wrong_tag_version_and_shape() {
        let wrong_tag = encode_tag(
            NON_INCLUSION_PROOF_TAG + 1,
            &encode_array(&[
                &encode_uint(VERSION),
                &encode_byte_string(&[]),
                &encode_uint(0),
            ]),
        );
        assert!(NonInclusionProof::from_cbor(Decoder::new(&wrong_tag)).is_err());

        let wrong_version = encode_tag(
            NON_INCLUSION_PROOF_TAG,
            &encode_array(&[
                &encode_uint(VERSION + 1),
                &encode_byte_string(&[]),
                &encode_uint(0),
            ]),
        );
        assert!(NonInclusionProof::from_cbor(Decoder::new(&wrong_version)).is_err());

        let wrong_shape = encode_tag(
            NON_INCLUSION_PROOF_TAG,
            &encode_array(&[&encode_uint(VERSION), &encode_byte_string(&[])]),
        );
        assert!(NonInclusionProof::from_cbor(Decoder::new(&wrong_shape)).is_err());
    }

    #[test]
    fn decoder_rejects_legacy_unicity_certificate_profile() {
        let legacy_uc = encode_tag(1007, &encode_array(&[]));
        let proof = encode_tag(
            NON_INCLUSION_PROOF_TAG,
            &encode_array(&[&encode_uint(VERSION), &encode_byte_string(&[]), &legacy_uc]),
        );

        assert!(NonInclusionProof::from_cbor(Decoder::new(&proof)).is_err());
    }
}
