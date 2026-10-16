//! Optional batch inclusion-proof capability (`get_inclusion_proofs.v1`).
//!
//! Separate from [`AggregatorClient`] so existing transports and test doubles
//! need not implement it. A batch is one finalized local view of the aggregator:
//! it returns **all** requested proofs, in request order, or fails. It is never
//! emulated from unrelated single-proof calls, and a decoded batch is not a
//! verified proof.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use super::AggregatorClient;
use crate::api::inclusion_proof::InclusionProof;
use crate::api::StateId;
use crate::consolidation::PartitionView;

/// Maximum number of distinct state ids in one batch request (server limit).
pub const MAX_BATCH_STATE_IDS: usize = 256;

/// Largest value of `waitMs` / `waitedMs` on the wire: 2^53 - 1, the
/// interoperable safe-integer range.
pub const MAX_WAIT_MS: u64 = 9_007_199_254_740_991;

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

/// `data.detail` values of a `proof_unavailable` (-32008) batch error that carry
/// the aggregator's per-state status hints. Like all statuses they are
/// **unauthenticated hints**, never evidence about the state itself.
pub mod detail {
    /// Accepted, not yet in a published certified state (retryable).
    pub const STATE_PENDING: &str = "state_pending";
    /// Admitted, then dropped as expired (not retryable; the same signed request may be resubmitted).
    pub const STATE_EXPIRED: &str = "state_expired";
    /// Not seen at this node: a routing or input error, not retryable unavailability.
    pub const STATE_UNKNOWN: &str = "state_unknown";
    /// An exact-root request whose root does not contain the state (not retryable).
    pub const STATE_NOT_IN_ROOT: &str = "state_not_in_root";
}

/// Class key under which a bare (unclassified) `data.indexes` array is reported.
pub const UNCLASSIFIED: &str = "";

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

/// A decoded batch response together with the long-poll echo.
///
/// `waited_ms` is **unauthenticated timing metadata**: the server's claim of how
/// long it held the request. It is `None` when the response carried no echo (a
/// server without long-poll support, or a request that did not ask for one) and
/// is never evidence about the proofs, which are verified on their own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaitedBatch {
    /// The batch itself.
    pub batch: InclusionProofBatch,
    /// `result.waitedMs`, when present.
    pub waited_ms: Option<u64>,
}

/// A failed [`BatchAggregatorClient::get_inclusion_proofs_with_wait`] call with
/// the long-poll echo of the error, if any (`error.data.waitedMs`).
///
/// Kept beside [`BatchFailure`] instead of inside it so existing code that
/// builds or matches `BatchFailure::Rpc` keeps compiling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaitedFailure {
    /// The typed failure.
    pub failure: BatchFailure,
    /// `error.data.waitedMs`, when present on a handled error.
    pub waited_ms: Option<u64>,
}

impl From<BatchFailure> for WaitedFailure {
    fn from(failure: BatchFailure) -> Self {
        WaitedFailure {
            failure,
            waited_ms: None,
        }
    }
}

impl fmt::Display for WaitedFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.failure.fmt(f)
    }
}

impl core::error::Error for WaitedFailure {}

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
        /// `data.indexes`: positions in the request of the states the error is
        /// about, **per class** (`pending`, `expired`, `unknown`, `not_in_root`),
        /// e.g. `{"unknown": [0], "pending": [2, 3]}` for a mixed outcome. Empty when
        /// absent. A server that sends a bare array gets its entries under
        /// [`UNCLASSIFIED`].
        indexes: BTreeMap<String, Vec<usize>>,
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

    /// [`get_inclusion_proofs`](Self::get_inclusion_proofs) asking the aggregator
    /// to hold a **latest** request for up to `wait_ms` milliseconds while every
    /// missing state is still pending (`waitMs`; zero asks for the echo only).
    ///
    /// The default implementation does not know the extension: it sends no wait,
    /// reports no echo and behaves exactly like the plain call. Transports that
    /// support it must never send `waitMs` for [`StateRoot::Exact`] (the server
    /// rejects that combination), must apply `options.timeout_ms` to the whole
    /// call (the caller sizes `wait_ms` so that the wait plus a response margin
    /// fits it) and must reject a malformed echo as
    /// [`BatchFailure::Decode`]. It does not retry; see
    /// [`get_latest_negotiating_wait`] for the parser-compatibility retry.
    #[allow(clippy::result_large_err)]
    fn get_inclusion_proofs_with_wait(
        &self,
        request: &BatchRequest<'_>,
        options: &RequestOptions,
        wait_ms: u64,
    ) -> Result<WaitedBatch, WaitedFailure> {
        let _ = wait_ms;
        self.get_inclusion_proofs(request, options)
            .map(|batch| WaitedBatch {
                batch,
                waited_ms: None,
            })
            .map_err(WaitedFailure::from)
    }
}

/// Whether `failure` is the generic strict-parser rejection (`-32602`,
/// `invalid_request`, `malformed_params`) that an endpoint without `waitMs`
/// support answers to a batch carrying it. The field name is not part of the
/// response, so this is the only signal there is.
pub fn is_malformed_params(failure: &BatchFailure) -> bool {
    matches!(
        failure,
        BatchFailure::Rpc { code, reason, detail, .. }
            if *code == rpc_code::INVALID_PARAMS
                && reason.as_deref() == Some("invalid_request")
                && detail.as_deref() == Some("malformed_params")
    )
}

/// The result of [`get_latest_negotiating_wait`]: the outcome plus accounting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatedBatch {
    /// The outcome of the last request made.
    pub result: Result<WaitedBatch, WaitedFailure>,
    /// Requests made: 1, or 2 after a parser-negotiation retry.
    pub requests: u32,
    /// Whether the retry without `waitMs` happened. The caller should then omit
    /// the wait for the rest of its operation.
    pub retried_without_wait: bool,
}

/// One **latest** batch request with `waitMs`, plus at most one retry without it.
///
/// If the endpoint answers with the generic `-32602 invalid_request
/// malformed_params` error (a strict batch parser that does not know `waitMs`),
/// the identical request is repeated once without the wait; its outcome, success
/// or error, is final. No other failure is retried, and other parameters are
/// untouched. `options.timeout_ms` is the caller's remaining deadline: the retry
/// gets what is left of it by `elapsed_ms`, never a fresh budget. When nothing is
/// left the first error is returned.
///
/// `now_ms` is a monotonic millisecond clock (the caller's, so `no_std` hosts
/// can supply their own).
pub fn get_latest_negotiating_wait<C: BatchAggregatorClient + ?Sized>(
    client: &C,
    state_ids: &[StateId],
    options: &RequestOptions,
    wait_ms: u64,
    now_ms: &dyn Fn() -> u64,
) -> NegotiatedBatch {
    let request = BatchRequest {
        state_ids,
        state_root: StateRoot::Latest,
    };
    let started = now_ms();
    let first = client.get_inclusion_proofs_with_wait(&request, options, wait_ms);
    let rejected = matches!(&first, Err(e) if is_malformed_params(&e.failure));
    if !rejected {
        return NegotiatedBatch {
            result: first,
            requests: 1,
            retried_without_wait: false,
        };
    }
    let left = options
        .timeout_ms
        .saturating_sub(now_ms().saturating_sub(started));
    if left == 0 {
        return NegotiatedBatch {
            result: first,
            requests: 1,
            retried_without_wait: false,
        };
    }
    let second = client
        .get_inclusion_proofs(&request, &RequestOptions { timeout_ms: left })
        .map(|batch| WaitedBatch {
            batch,
            waited_ms: None,
        })
        .map_err(WaitedFailure::from);
    NegotiatedBatch {
        result: second,
        requests: 2,
        retried_without_wait: true,
    }
}
