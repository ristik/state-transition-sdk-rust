//! Typed outcomes and errors of explicit consolidation.
//!
//! Three families are kept apart on purpose:
//!
//! * [`Unavailable`](ConsolidationOutcome::Unavailable): the specified
//!   material/pressure outcomes (no capability, view not retained or published,
//!   busy). Nothing is wrong with any signature; the original token is intact
//!   and a *new* attempt may succeed. It does not certify the input.
//! * [`ConsolidationError::Transport`]/[`Server`](ConsolidationError::Server)/
//!   [`Timeout`](ConsolidationError::Timeout)/[`Cancelled`](ConsolidationError::Cancelled):
//!   operational failures keep their own types.
//! * [`ConsolidationError::Integrity`]: authentication or binding failed. This is
//!   never disguised as unavailability.

use alloc::string::String;
use core::fmt;

use super::super::batch::BatchFailure;
use crate::api::bft::ShardId;
use crate::consolidation::PartitionViewError;
use crate::transaction::Token;
use crate::verify::VerificationError;

/// Why consolidation is unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnavailableReason {
    /// The endpoint has no `get_inclusion_proofs.v1`. Retrying can not help.
    UnsupportedCapability,
    /// The endpoint can not serve this partition/configuration. Not retryable.
    UnsupportedConfiguration,
    /// The target view is evicted (or was never retained).
    TargetNotRetained,
    /// The target is not served yet: publication lag, no finalized view, or a
    /// latest seal older than the evidence. Waiting on a fixed root can not add
    /// a missing leaf; a new attempt may succeed.
    TargetNotYetAvailable,
    /// The latest view carries no partition view (for example after a restart).
    PartitionViewUnavailable,
    /// The aggregator is under pressure.
    Busy,
}

/// Result of an explicit consolidation that did not fail.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum ConsolidationOutcome {
    /// An owned, fully verified token whose replaceable outer-history proofs
    /// share one seal. The input is untouched.
    Consolidated {
        /// The verified token.
        token: Token,
        /// What was done.
        summary: ConsolidationSummary,
    },
    /// Consolidation is unavailable now; the caller keeps its original token.
    Unavailable {
        /// Why.
        reason: UnavailableReason,
        /// Whether a *new* attempt may succeed.
        retryable: bool,
    },
}

/// Instrumentation of a consolidation (see the scope note on seal counts).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsolidationSummary {
    /// Number of replaceable outer-history proofs.
    pub outer_proofs: usize,
    /// Distinct complete seals among them before consolidation.
    pub outer_seals_before: usize,
    /// Distinct complete seals among them after (1 when consolidated).
    pub outer_seals_after: usize,
    /// The input already shared one seal: nothing was fetched.
    pub already_shared: bool,
    /// Shards that participate.
    pub shards: usize,
    /// Batch requests made (master wave + exact-root wave).
    pub requests: usize,
    /// The master shard.
    pub master: Option<ShardId>,
    /// Root round of the master seal (the output's shared seal).
    pub master_round: Option<u64>,
    /// Minimum root round the evidence required.
    pub required_round: u64,
    /// Quorum-signature verifications executed to authenticate the original
    /// evidence and the master seal.
    pub consolidation_quorum_checks: u64,
    /// Quorum-signature verifications of the *whole recursive verification* of
    /// the output token. Nested proofs inside signed mint justifications keep
    /// their own seals and may need more than one.
    pub verification_quorum_checks: u64,
}

/// What failed integrity.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum IntegrityError {
    /// The master view or its seal is not authenticated by the trusted
    /// authority (signature, network, epoch, tree, topology).
    View(PartitionViewError),
    /// The original proofs could not be authenticated.
    Evidence(VerificationError),
    /// A served proof is not bound to the original input.
    Binding {
        /// Shard that served it.
        shard: ShardId,
        /// Index within that shard's request.
        index: usize,
        /// What differed.
        what: &'static str,
    },
    /// The evidence does not belong to the configured partition/shard/pins.
    Context {
        /// What differs.
        what: &'static str,
    },
    /// A response is not for the exact root that was requested.
    RootSubstitution {
        /// Shard that served it.
        shard: ShardId,
    },
    /// The certificate derived for a participating shard is unusable.
    Certificate {
        /// The shard.
        shard: ShardId,
        /// What is wrong.
        what: &'static str,
    },
    /// The rebuilt token failed complete verification.
    Verification(VerificationError),
}

/// A failed consolidation. Never a statement that the input token is valid.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConsolidationError {
    /// The input token does not verify.
    InvalidToken(VerificationError),
    /// Caller or configuration error.
    Configuration(String),
    /// More state ids for one shard than one batch may carry (no chunking yet).
    TooManyStates {
        /// Shard.
        shard: ShardId,
        /// Distinct state ids needed.
        count: usize,
        /// Server limit.
        limit: usize,
    },
    /// The HTTP exchange failed.
    Transport {
        /// Shard.
        shard: ShardId,
        /// Failure.
        failure: BatchFailure,
    },
    /// The server reported an operational failure (database, internal, unknown
    /// code); it is not unavailability.
    Server {
        /// Shard.
        shard: ShardId,
        /// The failure with the original JSON-RPC code.
        failure: BatchFailure,
    },
    /// The server refused the request itself (invalid params, limit exceeded).
    Rejected {
        /// Shard.
        shard: ShardId,
        /// The failure.
        failure: BatchFailure,
    },
    /// A response is malformed or inconsistent with the request.
    InvalidResponse {
        /// Shard.
        shard: ShardId,
        /// What is wrong.
        what: &'static str,
    },
    /// Authentication or binding failed.
    Integrity(IntegrityError),
    /// The total deadline expired.
    Timeout,
    /// The caller cancelled.
    Cancelled,
}

impl fmt::Display for ConsolidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConsolidationError::InvalidToken(e) => write!(f, "input token does not verify: {e}"),
            ConsolidationError::Configuration(m) => write!(f, "configuration: {m}"),
            ConsolidationError::TooManyStates { count, limit, .. } => {
                write!(f, "{count} states for one shard, batch limit is {limit}")
            }
            ConsolidationError::Transport { shard, failure } => {
                write!(
                    f,
                    "transport failure for shard {:?}: {failure}",
                    shard.to_bit_string()
                )
            }
            ConsolidationError::Server { shard, failure } => {
                write!(
                    f,
                    "server failure for shard {:?}: {failure}",
                    shard.to_bit_string()
                )
            }
            ConsolidationError::Rejected { shard, failure } => {
                write!(
                    f,
                    "request rejected by shard {:?}: {failure}",
                    shard.to_bit_string()
                )
            }
            ConsolidationError::InvalidResponse { shard, what } => {
                write!(
                    f,
                    "invalid response from shard {:?}: {what}",
                    shard.to_bit_string()
                )
            }
            ConsolidationError::Integrity(e) => write!(f, "integrity failure: {e:?}"),
            ConsolidationError::Timeout => write!(f, "consolidation deadline expired"),
            ConsolidationError::Cancelled => write!(f, "consolidation cancelled"),
        }
    }
}

impl core::error::Error for ConsolidationError {}
