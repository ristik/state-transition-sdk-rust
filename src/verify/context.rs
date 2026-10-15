//! Shared state and cumulative limits for recursive token verification.

use crate::api::bft::RootTrustBase;
use crate::cbor::DecodeLimits;
use crate::transaction::Token;

use super::{verify_token_in_context, MintJustificationRegistry, SealSession, VerificationError};

/// Resource limits applied across one complete, possibly recursive verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationLimits {
    /// Limits used when decoding an embedded token or justification.
    pub decode: DecodeLimits,
    /// Maximum number of recursively embedded source tokens.
    pub max_embedded_token_depth: usize,
    /// Maximum cumulative encoded bytes processed as embedded tokens.
    pub max_total_embedded_token_bytes: usize,
    /// Maximum transfer history length of any token in the chain.
    pub max_token_transfers: usize,
}

impl VerificationLimits {
    /// Defaults suitable for host verification and bounded no_std guests.
    pub const DEFAULT: Self = Self {
        decode: DecodeLimits::DEFAULT,
        max_embedded_token_depth: 32,
        max_total_embedded_token_bytes: 16 * 1024 * 1024,
        max_token_transfers: 4096,
    };
}

impl Default for VerificationLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Verification behavior in addition to cumulative resource limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VerificationPolicy {
    /// Cumulative limits for this verification.
    pub limits: VerificationLimits,
    /// Reject application data unless a matching token-data verifier is registered.
    pub require_token_data_verifier: bool,
}

/// Mutable context shared by all recursively invoked verifiers.
pub struct VerificationContext<'a> {
    trust_base: &'a RootTrustBase,
    registry: &'a MintJustificationRegistry,
    policy: VerificationPolicy,
    seals: SealSession<'a>,
    embedded_token_depth: usize,
    total_embedded_token_bytes: usize,
}

impl core::fmt::Debug for VerificationContext<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VerificationContext")
            .field("policy", &self.policy)
            .field("embedded_token_depth", &self.embedded_token_depth)
            .field(
                "total_embedded_token_bytes",
                &self.total_embedded_token_bytes,
            )
            .finish_non_exhaustive()
    }
}

impl<'a> VerificationContext<'a> {
    pub(crate) fn new(
        trust_base: &'a RootTrustBase,
        registry: &'a MintJustificationRegistry,
        policy: VerificationPolicy,
    ) -> Self {
        Self {
            trust_base,
            registry,
            policy,
            seals: SealSession::new(trust_base),
            embedded_token_depth: 0,
            total_embedded_token_bytes: 0,
        }
    }

    /// A context that continues an existing operation's seal session (so seals
    /// authenticated earlier in the same operation are not checked again).
    #[cfg(feature = "client")]
    pub(crate) fn with_session(
        seals: SealSession<'a>,
        registry: &'a MintJustificationRegistry,
        policy: VerificationPolicy,
    ) -> Self {
        Self {
            trust_base: seals.trust_base(),
            registry,
            policy,
            seals,
            embedded_token_depth: 0,
            total_embedded_token_bytes: 0,
        }
    }

    /// Hand the operation's seal session back.
    #[cfg(feature = "client")]
    pub(crate) fn into_session(self) -> SealSession<'a> {
        self.seals
    }

    /// Root of trust used by the entire recursive verification chain.
    pub fn trust_base(&self) -> &RootTrustBase {
        self.trust_base
    }

    /// The seal authentication session shared by the whole recursive
    /// verification: repeated seals are checked against the quorum once.
    pub fn seals(&mut self) -> &mut SealSession<'a> {
        &mut self.seals
    }

    /// Active verification policy and limits.
    pub fn policy(&self) -> VerificationPolicy {
        self.policy
    }

    /// Verify an embedded source token under the same trust base and registry.
    pub fn verify_embedded_token(
        &mut self,
        token: &Token,
        encoded_len: usize,
    ) -> Result<(), VerificationError> {
        if self.embedded_token_depth == self.policy.limits.max_embedded_token_depth {
            return Err(VerificationError::VerificationLimitExceeded(
                "embedded token depth",
            ));
        }
        let total = self
            .total_embedded_token_bytes
            .checked_add(encoded_len)
            .ok_or(VerificationError::VerificationLimitExceeded(
                "embedded token bytes",
            ))?;
        if total > self.policy.limits.max_total_embedded_token_bytes {
            return Err(VerificationError::VerificationLimitExceeded(
                "embedded token bytes",
            ));
        }

        self.embedded_token_depth += 1;
        self.total_embedded_token_bytes = total;
        let result = verify_token_in_context(token, self);
        self.embedded_token_depth -= 1;
        result
    }

    pub(crate) fn registry(&self) -> &'a MintJustificationRegistry {
        self.registry
    }
}
