//! Optional batch inclusion-proof capability (`get_inclusion_proofs.v1`).
//!
//! Separate from [`AggregatorClient`] so existing transports and test doubles
//! need not implement it. A batch is one finalized local view of the aggregator:
//! it returns **all** requested proofs, in request order, or fails. It is never
//! emulated from unrelated single-proof calls, and a decoded batch is not a
//! verified proof.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use super::AggregatorClient;
use crate::api::inclusion_proof::InclusionProof;
use crate::api::StateId;
use crate::consolidation::PartitionView;

/// Maximum number of distinct state ids in one batch request (server limit).
pub const MAX_BATCH_STATE_IDS: usize = 256;

/// JSON-RPC error codes of `get_inclusion_proofs.v1`.
pub mod rpc_code {
    /// Invalid request envelope.
    pub const INVALID_REQUEST: i64 = -32600;
    /// Method not found: the endpoint has no batch capability.
    pub const METHOD_NOT_FOUND: i64 = -32601;
    /// Invalid params.
    pub const INVALID_PARAMS: i64 = -32602;
    /// Database error (operational failure, not absence).
    pub const DATABASE_ERROR: i64 = -32004;
    /// Concurrency limit exceeded (busy).
    pub const CONCURRENCY_LIMIT: i64 = -32006;
    /// Method-specific size/count limit.
    pub const LIMIT_EXCEEDED: i64 = -32007;
    /// The requested proof material can not be served.
    pub const PROOF_UNAVAILABLE: i64 = -32008;
}

/// Which view of the aggregator a batch is served against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateRoot {
    /// The latest finalized view; the response carries the partition view.
    Latest,
    /// Exactly the view whose raw SMT root (`InputRecord.hash`) is given. It is
    /// never silently replaced by another root.
    Exact([u8; 32]),
}

/// One batch request.
#[derive(Debug, Clone, Copy)]
pub struct BatchRequest<'a> {
    /// Distinct state ids (1..=[`MAX_BATCH_STATE_IDS`]), all routed to this shard.
    pub state_ids: &'a [StateId],
    /// The requested view.
    pub state_root: StateRoot,
}

/// Per-request limits the transport must honor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestOptions {
    /// Time the request may take, in milliseconds (the caller's remaining
    /// deadline). A blocking transport that can not interrupt an in-flight
    /// request must at least not exceed it.
    pub timeout_ms: u64,
}

/// One served proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchProof {
    /// The aggregator's local block number (unsigned metadata).
    pub block_number: u64,
    /// The certified leaf; its certificate is the aggregator's local one.
    pub proof: InclusionProof,
}

/// A decoded batch response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProofBatch {
    /// One proof per requested state id, in request order.
    pub proofs: Vec<BatchProof>,
    /// The partition view; present only for [`StateRoot::Latest`].
    pub partition_view: Option<PartitionView>,
}

/// A typed transport/server failure of one batch call. Orchestration classifies
/// it; transports must not guess whether it means "unavailable".
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BatchFailure {
    /// A JSON-RPC error object (code and the optional `data` fields).
    Rpc {
        /// JSON-RPC error code.
        code: i64,
        /// Message text (unstable; do not match on it).
        message: String,
        /// `data.reason`.
        reason: Option<String>,
        /// `data.detail`.
        detail: Option<String>,
        /// `data.retryable`.
        retryable: Option<bool>,
    },
    /// The HTTP exchange failed (connection error, TLS, I/O).
    Transport(String),
    /// A non-2xx HTTP status.
    Http {
        /// Status code.
        status: u16,
    },
    /// The response is malformed (bad envelope, hex, CBOR, shape).
    Decode(String),
    /// The response exceeded the client-side size limit.
    TooLarge {
        /// The limit in bytes.
        limit: usize,
    },
    /// The request ran out of time.
    Timeout,
    /// The caller cancelled.
    Cancelled,
}

impl fmt::Display for BatchFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BatchFailure::Rpc { code, detail, .. } => {
                write!(f, "json-rpc error {code}")?;
                if let Some(d) = detail {
                    write!(f, " ({d})")?;
                }
                Ok(())
            }
            BatchFailure::Transport(m) => write!(f, "transport error: {m}"),
            BatchFailure::Http { status } => write!(f, "http status {status}"),
            BatchFailure::Decode(m) => write!(f, "malformed response: {m}"),
            BatchFailure::TooLarge { limit } => write!(f, "response exceeds {limit} bytes"),
            BatchFailure::Timeout => write!(f, "request timed out"),
            BatchFailure::Cancelled => write!(f, "request cancelled"),
        }
    }
}

impl core::error::Error for BatchFailure {}

/// Optional aggregator capability: multi-state inclusion proofs from one
/// finalized local view (`get_inclusion_proofs.v1`).
///
/// Implementations return decoded, **unverified** material and report failures
/// as [`BatchFailure`]; they must not retry or resubmit anything.
pub trait BatchAggregatorClient: AggregatorClient {
    /// Fetch the proofs of `request.state_ids` from one finalized view.
    fn get_inclusion_proofs(
        &self,
        request: &BatchRequest<'_>,
        options: &RequestOptions,
    ) -> Result<InclusionProofBatch, BatchFailure>;
}
