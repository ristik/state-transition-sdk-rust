//! Non-inclusion proof (CBOR tag 39034): an absence certificate plus the BFT
//! certificate authenticating the SMT root at one certified point in time.

use alloc::vec::Vec;

use super::bft::{RootTrustBase, UnicityCertificate};
use super::{NonInclusionCertificate, StateId};
use crate::cbor::{encode_array, encode_byte_string, encode_tag, encode_uint, Decoder};
use crate::error::Error;
use crate::verify::{self, NonInclusionContext, NonInclusionOutcome, VerificationError};

/// CBOR tag for [`NonInclusionProof`].
pub const NON_INCLUSION_PROOF_TAG: u64 = 39034;
const VERSION: u64 = 1;

/// Proof that a state id was absent at the root authenticated by a Unicity
/// Certificate.
///
/// This is a snapshot statement.
///
/// **Non-inclusion proves absence only at the authenticated snapshot returned by verification.
/// It does not prove absence now, continuous absence, or that a token can be spent. Compare the
/// snapshot’s network and root round (or its certified seal timestamp under your application's
/// time policy) with an independently trusted requirement. The seal timestamp is a
/// consensus-certified time, not proof of real-time freshness. Do not use unverified response
/// metadata for this check.**
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

    /// Verify a client-bound proof against `trust_base` and report the authenticated snapshot.
    ///
    /// The unicity certificate is authenticated strictly (network, exact epoch, root round
    /// not before the epoch start, quorum, the fixed aggregation partition and the
    /// `context` pins) before anything is exposed. A rejection carries no snapshot.
    ///
    /// Proofs returned by the provided clients are bound automatically. A proof decoded
    /// directly from untrusted bytes has no request context; use
    /// [`verify_for_at_snapshot`](Self::verify_for_at_snapshot) for that case.
    ///
    /// **Non-inclusion proves absence only at the authenticated snapshot returned by verification.
    /// It does not prove absence now, continuous absence, or that a token can be spent. Compare the
    /// snapshot’s network and root round (or its certified seal timestamp under your application's
    /// time policy) with an independently trusted requirement. The seal timestamp is a
    /// consensus-certified time, not proof of real-time freshness. Do not use unverified response
    /// metadata for this check.**
    ///
    /// ```no_run
    /// # use unicity_token::api::{bft::RootTrustBase, NonInclusionProof};
    /// # use unicity_token::verify::{NonInclusionContext, NonInclusionOutcome};
    /// # struct Checkpoint { network_id: u16, required_root_round: u64 }
    /// # fn policy(
    /// #     proof: &NonInclusionProof,
    /// #     trust_base: &RootTrustBase,
    /// #     checkpoint: &Checkpoint, // obtained independently of the proof and of the server response
    /// # ) -> Result<(), &'static str> {
    /// let outcome = proof
    ///     .verify_at_snapshot(trust_base, &NonInclusionContext::new())
    ///     .map_err(|_| "no verified absence")?;
    /// let NonInclusionOutcome::AbsentAtSnapshot { snapshot, .. } = outcome else {
    ///     return Err("no verified absence");
    /// };
    /// if snapshot.network_id().id() != checkpoint.network_id
    ///     || snapshot.root_round() < checkpoint.required_root_round
    /// {
    ///     return Err("snapshot does not meet application policy");
    /// }
    /// // Absence at `snapshot` only; any spend/finality decision needs its own policy.
    /// # Ok(())
    /// # }
    /// ```
    pub fn verify_at_snapshot(
        &self,
        trust_base: &RootTrustBase,
        context: &NonInclusionContext,
    ) -> Result<NonInclusionOutcome, VerificationError> {
        let target = self
            .requested_state_id
            .as_ref()
            .ok_or(VerificationError::NonInclusionTargetMissing)?;
        verify::verify_non_inclusion_at_snapshot(trust_base, self, target, context)
    }

    /// [`verify_at_snapshot`](Self::verify_at_snapshot) for a directly decoded proof and an
    /// explicit `target` (a different target than a client-bound one is rejected, so request
    /// context can not be silently replaced).
    ///
    /// **Non-inclusion proves absence only at the authenticated snapshot returned by verification.
    /// It does not prove absence now, continuous absence, or that a token can be spent. Compare the
    /// snapshot’s network and root round (or its certified seal timestamp under your application's
    /// time policy) with an independently trusted requirement. The seal timestamp is a
    /// consensus-certified time, not proof of real-time freshness. Do not use unverified response
    /// metadata for this check.**
    pub fn verify_for_at_snapshot(
        &self,
        target: &StateId,
        trust_base: &RootTrustBase,
        context: &NonInclusionContext,
    ) -> Result<NonInclusionOutcome, VerificationError> {
        if self
            .requested_state_id
            .as_ref()
            .is_some_and(|requested| requested != target)
        {
            return Err(VerificationError::NonInclusionTargetMismatch);
        }
        verify::verify_non_inclusion_at_snapshot(trust_base, self, target, context)
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
