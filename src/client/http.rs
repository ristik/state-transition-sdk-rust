//! Blocking JSON-RPC [`AggregatorClient`] for talking to a live aggregator /
//! gateway (`http` feature).
//!
//! This is the synchronous transport for production use: it speaks the same
//! JSON-RPC protocol as the reference SDKs (methods `certification_request`,
//! `get_inclusion_proof.v2`, and `get_non_inclusion_proof.v1`), authenticates
//! with an optional `X-API-Key`, and
//! **polls** `get_inclusion_proof` until the aggregator has certified the state
//! (so the [`mint`](super::mint)/[`transfer`](super::transfer) helpers work
//! unchanged against live infrastructure).

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;
use std::io::Read;
use std::time::Duration;
use zeroize::Zeroize;

use crate::api::certification_request::CertificationRequest;
use crate::api::inclusion_proof::InclusionProof;
use crate::api::{
    CertificationData, InclusionProofResponse, NonInclusionProof, ProofStatus, StateId,
};
use crate::cbor::Decoder;

use super::{
    rpc_code, AggregatorClient, BatchAggregatorClient, BatchFailure, BatchProof, BatchRequest,
    InclusionProofBatch, MembershipStatus, NonInclusionAggregatorClient, RequestOptions, StateRoot,
    MAX_BATCH_STATE_IDS, UNCLASSIFIED,
};
use crate::consolidation::PartitionView;

const MAX_RESPONSE_BODY_BYTES: usize = 8 * 1024 * 1024;
const MAX_ERROR_BODY_BYTES: usize = 64 * 1024;
const MAX_PROOF_HEX_CHARS: usize = MAX_RESPONSE_BODY_BYTES - 1024;
// Shared proof-lookup states. JSON-RPC 2.0 reserves -32000..-32099 for
// implementation-defined server errors; the Unicity aggregators keep
// -32000..-32019 for implementation-private codes (aggregator-go allocates
// -32000..-32006 there) and -32020..-32039 for these, which describe the
// protocol rather than one server.
const RPC_STATE_NOT_FOUND: i64 = -32020;
const RPC_INCLUSION_PENDING: i64 = -32021;
const RPC_STATE_INCLUDED: i64 = -32022;

/// Default number of `unknown` status answers tolerated while waiting for a proof
/// before failing: right after a submission an HA instance that did not admit the
/// request may not have seen it yet.
pub const DEFAULT_UNKNOWN_GRACE: u32 = 2;

/// Errors from the HTTP aggregator client.
///
/// Non-exhaustive: variants are added as the aggregator API grows (for example
/// the proof status hints); match with a wildcard arm.
#[derive(Debug)]
#[non_exhaustive]
pub enum HttpError {
    /// Unsafe or invalid client configuration.
    Configuration(String),
    /// Network/transport failure.
    Transport(String),
    /// Non-2xx HTTP response.
    Http {
        /// HTTP status code.
        status: u16,
        /// Response body.
        body: String,
    },
    /// JSON-RPC `error` object returned by the aggregator.
    Rpc {
        /// JSON-RPC error code.
        code: i64,
        /// JSON-RPC error message.
        message: String,
    },
    /// A response could not be decoded.
    Decode(String),
    /// A response exceeded the explicit transport limit.
    ResponseTooLarge {
        /// Maximum accepted bytes.
        limit: usize,
    },
    /// The aggregator rejected the certification request (status != SUCCESS).
    Rejected(String),
    /// Polling for the inclusion proof exceeded the configured attempts.
    Timeout,
    /// The aggregator has no certified or pending record for this state id.
    StateNotFound,
    /// The aggregator reports (an unauthenticated hint, see [`ProofStatus`]) that
    /// the request was admitted but dropped before inclusion, because its timeout
    /// passed. Waiting can not help; the caller may resubmit the same signed request.
    StateExpired,
    /// The aggregator reports (an unauthenticated hint, see [`ProofStatus`]) that
    /// it does not know the state id, beyond the configured grace period. This is
    /// not proof of absence or of non-spending: the request may have been lost,
    /// misrouted, forgotten by a restart, or be known to another instance.
    StateUnknown,
    /// No certified state is available from which to prove absence.
    CertifiedStateUnavailable,
    /// The requested state is present at the certified root.
    StateIncluded,
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpError::Configuration(m) => write!(f, "configuration error: {m}"),
            HttpError::Transport(m) => write!(f, "transport error: {m}"),
            HttpError::Http { status, body } => write!(f, "http {status}: {body:?}"),
            HttpError::Rpc { code, message } => {
                write!(f, "json-rpc error {code}: {message:?}")
            }
            HttpError::Decode(m) => write!(f, "decode error: {m}"),
            HttpError::ResponseTooLarge { limit } => {
                write!(f, "response exceeds {limit} byte limit")
            }
            HttpError::Rejected(s) => write!(f, "certification rejected: {s:?}"),
            HttpError::Timeout => write!(f, "timed out waiting for inclusion proof"),
            HttpError::StateNotFound => write!(f, "state is not known to the aggregator"),
            HttpError::StateExpired => {
                write!(f, "aggregator reports the request expired before inclusion")
            }
            HttpError::StateUnknown => {
                write!(
                    f,
                    "aggregator reports the state id as unknown (hint, not proof of absence)"
                )
            }
            HttpError::CertifiedStateUnavailable => {
                write!(f, "no certified state is available")
            }
            HttpError::StateIncluded => {
                write!(f, "state is already included at the certified root")
            }
        }
    }
}

impl std::error::Error for HttpError {}

/// A blocking JSON-RPC aggregator client.
#[derive(Clone)]
pub struct HttpAggregatorClient {
    url: String,
    api_key: Option<SecretString>,
    agent: ureq::Agent,
    poll_interval: Duration,
    poll_attempts: u32,
    unknown_grace: u32,
    allow_insecure_http: bool,
}

#[derive(Clone)]
struct SecretString(String);

impl SecretString {
    fn expose(&self) -> &str {
        &self.0
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for HttpAggregatorClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpAggregatorClient")
            .field("url", &"<redacted>")
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .field("poll_interval", &self.poll_interval)
            .field("poll_attempts", &self.poll_attempts)
            .field("unknown_grace", &self.unknown_grace)
            .field("allow_insecure_http", &self.allow_insecure_http)
            .finish_non_exhaustive()
    }
}

impl HttpAggregatorClient {
    /// Create a client pointing at the aggregator's JSON-RPC `url`.
    pub fn new(url: impl Into<String>) -> Self {
        HttpAggregatorClient {
            url: url.into(),
            api_key: None,
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(30))
                .https_only(true)
                .redirects(0)
                .build(),
            poll_interval: Duration::from_secs(1),
            poll_attempts: 60,
            unknown_grace: DEFAULT_UNKNOWN_GRACE,
            allow_insecure_http: false,
        }
    }

    /// Create and immediately validate a production HTTPS endpoint.
    pub fn try_new(url: impl Into<String>) -> Result<Self, HttpError> {
        let client = Self::new(url);
        client.validate_endpoint()?;
        Ok(client)
    }

    /// Create a redirect-free client that permits plaintext HTTP without an
    /// API key. Intended only for loopback development and tests.
    pub fn new_insecure_http(url: impl Into<String>) -> Self {
        HttpAggregatorClient {
            url: url.into(),
            api_key: None,
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(30))
                .redirects(0)
                .build(),
            poll_interval: Duration::from_secs(1),
            poll_attempts: 60,
            unknown_grace: DEFAULT_UNKNOWN_GRACE,
            allow_insecure_http: true,
        }
    }

    /// Set the API key sent as `X-API-Key` on certification requests.
    pub fn with_api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = Some(SecretString(key.into()));
        self
    }

    /// Configure inclusion-proof polling: wait `interval` between up to
    /// `attempts` probes.
    pub fn with_polling(mut self, interval: Duration, attempts: u32) -> Self {
        self.poll_interval = interval;
        self.poll_attempts = attempts;
        self
    }

    /// How many `unknown` status answers [`get_inclusion_proof`](AggregatorClient::get_inclusion_proof)
    /// tolerates before failing with [`HttpError::StateUnknown`] (default
    /// [`DEFAULT_UNKNOWN_GRACE`]; `0` fails on the first one).
    ///
    /// Right after a submission the aggregator that serves the lookup may not have
    /// seen the request yet (a replica behind a load balancer, a queue not yet
    /// drained), so a short grace avoids reporting a transient `unknown`. The
    /// counter resets whenever the aggregator answers `pending`. A lookup of an id
    /// that was never submitted therefore costs `grace + 1` polls before it fails.
    pub fn with_unknown_grace(mut self, polls: u32) -> Self {
        self.unknown_grace = polls;
        self
    }

    /// One proof lookup, without waiting, returning the aggregator's status hint
    /// next to the response. The status is `None` for servers that do not support
    /// it (and for values this version does not know).
    ///
    /// The hint is **unauthenticated**: use it for control flow and user feedback
    /// only. It never replaces verification of the returned proof.
    pub fn lookup_inclusion_proof(
        &self,
        state_id: &StateId,
    ) -> Result<(InclusionProofResponse, Option<ProofStatus>), HttpError> {
        let params = serde_json::json!({
            "stateId": hex::encode(state_id.bytes()),
            "includeStatus": true,
        });
        let result = self.rpc("get_inclusion_proof.v2", params, &[])?;
        let (encoded, status) = split_status_result(&result)?;
        if encoded.len() > MAX_PROOF_HEX_CHARS {
            return Err(HttpError::ResponseTooLarge {
                limit: MAX_PROOF_HEX_CHARS,
            });
        }
        let bytes = hex::decode(encoded).map_err(|e| HttpError::Decode(e.to_string()))?;
        Ok((decode_inclusion_proof_response(&bytes)?, status))
    }

    /// Determine whether `state_id` is included or absent at a certified root.
    ///
    /// This hides the endpoint-selection round trip: absence normally takes one
    /// RPC, while an included state triggers an inclusion-proof lookup after the
    /// non-inclusion endpoint reports that the relation is false. The two RPCs
    /// are not an atomic read if the certified root advances between them; each
    /// returned proof authenticates the root it carries.
    pub fn membership_status(&self, state_id: &StateId) -> Result<MembershipStatus, HttpError> {
        match NonInclusionAggregatorClient::get_non_inclusion_proof(self, state_id) {
            Ok(proof) => Ok(MembershipStatus::Absent(proof)),
            Err(HttpError::StateIncluded) => AggregatorClient::get_inclusion_proof(self, state_id)
                .map(MembershipStatus::Included),
            Err(error) => Err(error),
        }
    }

    fn validate_endpoint(&self) -> Result<url::Url, HttpError> {
        let parsed = url::Url::parse(&self.url)
            .map_err(|e| HttpError::Configuration(format!("invalid gateway URL: {e}")))?;
        if !matches!(parsed.scheme(), "http" | "https") || parsed.host().is_none() {
            return Err(HttpError::Configuration(
                "gateway URL must be an absolute HTTP(S) URL".to_string(),
            ));
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(HttpError::Configuration(
                "gateway URL must not contain credentials".to_string(),
            ));
        }
        if parsed.fragment().is_some() {
            return Err(HttpError::Configuration(
                "gateway URL must not contain a fragment".to_string(),
            ));
        }
        if parsed.scheme() != "https" && !self.allow_insecure_http {
            return Err(HttpError::Configuration(
                "gateway URL must use HTTPS".to_string(),
            ));
        }
        if parsed.scheme() != "https" && self.api_key.is_some() {
            return Err(HttpError::Configuration(
                "API keys must never be sent over plaintext HTTP".to_string(),
            ));
        }
        Ok(parsed)
    }

    /// Perform one JSON-RPC call, returning the `result` value.
    fn rpc(
        &self,
        method: &str,
        params: serde_json::Value,
        headers: &[(&str, &str)],
    ) -> Result<serde_json::Value, HttpError> {
        self.rpc_raw(method, params, headers, None)
            .map_err(|e| match e {
                RawFailure::Http { status, body, .. } => HttpError::Http { status, body },
                RawFailure::Transport(m) => HttpError::Transport(m),
                RawFailure::Envelope(EnvelopeError::Decode(m)) => HttpError::Decode(m),
                RawFailure::Envelope(EnvelopeError::Rpc { code, message, .. }) => {
                    HttpError::Rpc { code, message }
                }
                RawFailure::TooLarge(limit) => HttpError::ResponseTooLarge { limit },
                RawFailure::Config(e) => e,
            })
    }

    /// One JSON-RPC call with an optional per-request timeout, keeping the
    /// structured error data.
    fn rpc_raw(
        &self,
        method: &str,
        params: serde_json::Value,
        headers: &[(&str, &str)],
        timeout: Option<Duration>,
    ) -> Result<serde_json::Value, RawFailure> {
        self.validate_endpoint().map_err(RawFailure::Config)?;
        let id = request_id();
        let body = serde_json::json!({
            "id": id,
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        })
        .to_string();

        let mut request = self
            .agent
            .post(&self.url)
            .set("Content-Type", "application/json");
        if let Some(t) = timeout {
            request = request.timeout(t);
        }
        for (k, v) in headers {
            request = request.set(k, v);
        }

        let response = match request.send_string(&body) {
            Ok(r) => r,
            Err(ureq::Error::Status(status, r)) => {
                let body = read_response_raw(r, MAX_ERROR_BODY_BYTES)?;
                // a JSON-RPC error may ride on a non-2xx status: keep it typed
                let rpc = match decode_rpc_envelope(&body, &id) {
                    Err(e @ EnvelopeError::Rpc { .. }) => Some(e),
                    _ => None,
                };
                return Err(RawFailure::Http { status, body, rpc });
            }
            Err(e) => return Err(RawFailure::Transport(e.to_string())),
        };
        if !(200..300).contains(&response.status()) {
            return Err(RawFailure::Http {
                status: response.status(),
                body: read_response_raw(response, MAX_ERROR_BODY_BYTES)?,
                rpc: None,
            });
        }

        let text = read_response_raw(response, MAX_RESPONSE_BODY_BYTES)?;
        decode_rpc_envelope(&text, &id).map_err(RawFailure::Envelope)
    }
}

/// Failure of one raw JSON-RPC exchange.
enum RawFailure {
    Http {
        status: u16,
        body: String,
        rpc: Option<EnvelopeError>,
    },
    Transport(String),
    Envelope(EnvelopeError),
    TooLarge(usize),
    Config(HttpError),
}

fn read_response_raw(response: ureq::Response, limit: usize) -> Result<String, RawFailure> {
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| RawFailure::Transport(e.to_string()))?;
    if bytes.len() > limit {
        return Err(RawFailure::TooLarge(limit));
    }
    String::from_utf8(bytes).map_err(|e| RawFailure::Envelope(EnvelopeError::Decode(e.to_string())))
}

/// A decoded JSON-RPC envelope failure.
enum EnvelopeError {
    Decode(String),
    Rpc {
        code: i64,
        message: String,
        data: Option<serde_json::Value>,
    },
}

fn decode_rpc_envelope(text: &str, expected_id: &str) -> Result<serde_json::Value, EnvelopeError> {
    let decode = |m: &str| EnvelopeError::Decode(m.to_string());
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|e| EnvelopeError::Decode(e.to_string()))?;
    let object = value
        .as_object()
        .ok_or_else(|| decode("JSON-RPC response must be an object"))?;
    if object.get("jsonrpc").and_then(|v| v.as_str()) != Some("2.0") {
        return Err(decode("invalid or missing JSON-RPC version"));
    }
    let response_id = object
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| decode("invalid or missing JSON-RPC id"))?;
    if response_id != expected_id {
        return Err(decode("JSON-RPC id mismatch"));
    }

    match (object.get("result"), object.get("error")) {
        (Some(_), Some(_)) => Err(decode("JSON-RPC response contains both result and error")),
        (Some(result), None) => Ok(result.clone()),
        (None, Some(error)) => {
            let code = error
                .get("code")
                .and_then(|v| v.as_i64())
                .ok_or_else(|| decode("invalid JSON-RPC error code"))?;
            let message = error
                .get("message")
                .and_then(|v| v.as_str())
                .ok_or_else(|| decode("invalid JSON-RPC error message"))?;
            Err(EnvelopeError::Rpc {
                code,
                message: message.to_string(),
                data: error.get("data").cloned(),
            })
        }
        (None, None) => Err(decode(
            "JSON-RPC response contains neither result nor error",
        )),
    }
}

#[cfg(test)]
fn decode_rpc_response(text: &str, expected_id: &str) -> Result<serde_json::Value, HttpError> {
    decode_rpc_envelope(text, expected_id).map_err(|e| match e {
        EnvelopeError::Decode(m) => HttpError::Decode(m),
        EnvelopeError::Rpc { code, message, .. } => HttpError::Rpc { code, message },
    })
}

/// Decode the `[blockNumber, InclusionProof]` response payload.
fn decode_inclusion_proof_response(bytes: &[u8]) -> Result<InclusionProofResponse, HttpError> {
    let d = Decoder::new(bytes);
    d.finish().map_err(|e| HttpError::Decode(e.to_string()))?;
    InclusionProofResponse::from_cbor(d).map_err(|e| HttpError::Decode(e.to_string()))
}

/// Decode the `[blockNumber, NonInclusionProof]` response payload.
fn decode_non_inclusion_proof_response(bytes: &[u8]) -> Result<NonInclusionProof, HttpError> {
    let d = Decoder::new(bytes);
    d.finish().map_err(|e| HttpError::Decode(e.to_string()))?;
    let items = d
        .array(Some(2))
        .map_err(|e| HttpError::Decode(e.to_string()))?;
    items[0]
        .uint()
        .map_err(|e| HttpError::Decode(e.to_string()))?;
    NonInclusionProof::from_cbor(items[1]).map_err(|e| HttpError::Decode(e.to_string()))
}

impl AggregatorClient for HttpAggregatorClient {
    type Error = HttpError;

    fn submit_certification_request(&self, data: &CertificationData) -> Result<(), HttpError> {
        let request = CertificationRequest::new(data);
        let state_id_hex = hex::encode(request.state_id().bytes());
        let params = serde_json::Value::String(hex::encode(request.to_cbor()));

        let mut headers: Vec<(&str, &str)> = alloc::vec![("X-State-ID", state_id_hex.as_str())];
        if let Some(key) = &self.api_key {
            headers.push(("X-API-Key", key.expose()));
        }

        let result = self.rpc("certification_request", params, &headers)?;
        let status = result
            .get("status")
            .and_then(|s| s.as_str())
            .unwrap_or_default();
        if status != "SUCCESS" {
            return Err(HttpError::Rejected(status.to_string()));
        }
        Ok(())
    }

    /// Wait for the certified proof of `state_id`.
    ///
    /// Asks for the aggregator's status hint (`includeStatus`) and accepts both
    /// result shapes: a plain string (legacy server) behaves exactly as before.
    /// While the response is not a certified proof: `pending` (or no status)
    /// keeps polling, `expired` fails at once with [`HttpError::StateExpired`] and
    /// `unknown` fails with [`HttpError::StateUnknown`] after the configured
    /// grace ([`with_unknown_grace`](HttpAggregatorClient::with_unknown_grace)),
    /// so lost or expired submissions are reported instead of waited out.
    ///
    /// The status is an unauthenticated hint: a certified proof is returned
    /// whatever the status says, and the caller must still verify it.
    fn get_inclusion_proof(&self, state_id: &StateId) -> Result<InclusionProof, HttpError> {
        let params = serde_json::json!({
            "stateId": hex::encode(state_id.bytes()),
            "includeStatus": true,
        });
        let mut unknown_seen = 0u32;

        for attempt in 0..self.poll_attempts {
            let result = match self.rpc("get_inclusion_proof.v2", params.clone(), &[]) {
                Ok(result) => result,
                Err(HttpError::Rpc { code, .. }) if code == RPC_INCLUSION_PENDING => {
                    if attempt + 1 < self.poll_attempts {
                        std::thread::sleep(self.poll_interval);
                    }
                    continue;
                }
                Err(HttpError::Rpc { code, .. }) if code == RPC_STATE_NOT_FOUND => {
                    return Err(HttpError::StateNotFound);
                }
                Err(HttpError::Http { status: 404, .. }) => {
                    return Err(HttpError::StateNotFound);
                }
                Err(error) => return Err(error),
            };
            let (encoded, status) = split_status_result(&result)?;
            if encoded.len() > MAX_PROOF_HEX_CHARS {
                return Err(HttpError::ResponseTooLarge {
                    limit: MAX_PROOF_HEX_CHARS,
                });
            }
            let bytes = hex::decode(encoded).map_err(|e| HttpError::Decode(e.to_string()))?;

            // A response carrying no proof on this method means the leaf is not
            // certified yet. `get_inclusion_proof.v2` never answers with a
            // non-inclusion proof (that is `get_non_inclusion_proof.v1`), so the
            // uncertified response is unambiguous and is aggregator-go's way of
            // reporting pending. The status hint, when present, refines that into
            // "keep waiting" / "will never be certified here".
            match decode_inclusion_proof_response(&bytes)? {
                InclusionProofResponse::Certified { proof, .. } => return Ok(proof),
                InclusionProofResponse::NotCertified { .. } => match status {
                    Some(ProofStatus::Expired) => return Err(HttpError::StateExpired),
                    Some(ProofStatus::Unknown) => {
                        unknown_seen += 1;
                        if unknown_seen > self.unknown_grace {
                            return Err(HttpError::StateUnknown);
                        }
                    }
                    // pending, an `included` hint without a proof, no status, or a
                    // status this version does not know: the legacy behavior
                    _ => unknown_seen = 0,
                },
            }
            if attempt + 1 < self.poll_attempts {
                std::thread::sleep(self.poll_interval);
            }
        }
        Err(HttpError::Timeout)
    }
}

/// Split a `get_inclusion_proof.v2` result into the proof hex and the optional
/// status hint: a string is the legacy result, an object is `{proof, status}`.
fn split_status_result(
    result: &serde_json::Value,
) -> Result<(&str, Option<ProofStatus>), HttpError> {
    if let Some(s) = result.as_str() {
        return Ok((s, None));
    }
    let object = result
        .as_object()
        .ok_or_else(|| HttpError::Decode("expected hex string".to_string()))?;
    let proof = object
        .get("proof")
        .and_then(|v| v.as_str())
        .ok_or_else(|| HttpError::Decode("status result lacks a proof string".to_string()))?;
    let status = object
        .get("status")
        .and_then(|v| v.as_str())
        .and_then(ProofStatus::from_wire);
    Ok((proof, status))
}

impl NonInclusionAggregatorClient for HttpAggregatorClient {
    fn get_non_inclusion_proof(&self, state_id: &StateId) -> Result<NonInclusionProof, HttpError> {
        let params = serde_json::json!({ "stateId": hex::encode(state_id.bytes()) });
        let result = match self.rpc("get_non_inclusion_proof.v1", params, &[]) {
            Ok(result) => result,
            Err(HttpError::Http { status: 404, .. }) => {
                return Err(HttpError::CertifiedStateUnavailable)
            }
            Err(HttpError::Rpc { code, .. }) if code == RPC_STATE_INCLUDED => {
                return Err(HttpError::StateIncluded)
            }
            Err(error) => return Err(error),
        };
        let encoded = result
            .as_str()
            .ok_or_else(|| HttpError::Decode("expected hex string".to_string()))?;
        if encoded.len() > MAX_PROOF_HEX_CHARS {
            return Err(HttpError::ResponseTooLarge {
                limit: MAX_PROOF_HEX_CHARS,
            });
        }
        let bytes = hex::decode(encoded).map_err(|e| HttpError::Decode(e.to_string()))?;
        decode_non_inclusion_proof_response(&bytes)?
            .for_state(state_id)
            .map_err(|error| HttpError::Decode(error.to_string()))
    }
}

impl BatchAggregatorClient for HttpAggregatorClient {
    fn get_inclusion_proofs(
        &self,
        request: &BatchRequest<'_>,
        options: &RequestOptions,
    ) -> Result<InclusionProofBatch, BatchFailure> {
        let ids = request.state_ids;
        if ids.is_empty() || ids.len() > MAX_BATCH_STATE_IDS {
            return Err(BatchFailure::Rpc {
                code: rpc_code::INVALID_PARAMS,
                message: "state id count out of range".to_string(),
                reason: Some("invalid_request".to_string()),
                detail: Some("state_count".to_string()),
                retryable: Some(false),
                indexes: BTreeMap::new(),
            });
        }
        let state_root = match request.state_root {
            StateRoot::Latest => "latest".to_string(),
            StateRoot::Exact(root) => hex::encode(root),
        };
        let params = serde_json::json!({
            "stateIds": ids.iter().map(|s| hex::encode(s.bytes())).collect::<Vec<_>>(),
            "stateRoot": state_root,
        });
        let result = self
            .rpc_raw(
                "get_inclusion_proofs.v1",
                params,
                &[],
                Some(Duration::from_millis(options.timeout_ms.max(1))),
            )
            .map_err(batch_failure)?;
        decode_batch_result(&result)
    }
}

fn batch_failure(failure: RawFailure) -> BatchFailure {
    match failure {
        RawFailure::Http { rpc: Some(e), .. } => batch_failure(RawFailure::Envelope(e)),
        RawFailure::Http { status, .. } => BatchFailure::Http { status },
        RawFailure::Transport(m) if m.contains("timed out") => BatchFailure::Timeout,
        RawFailure::Transport(m) => BatchFailure::Transport(m),
        RawFailure::TooLarge(limit) => BatchFailure::TooLarge { limit },
        RawFailure::Config(e) => BatchFailure::Transport(e.to_string()),
        RawFailure::Envelope(EnvelopeError::Decode(m)) => BatchFailure::Decode(m),
        RawFailure::Envelope(EnvelopeError::Rpc {
            code,
            message,
            data,
        }) => {
            let text = |k: &str| {
                data.as_ref()
                    .and_then(|d| d.get(k))
                    .and_then(|v| v.as_str())
                    .map(ToString::to_string)
            };
            BatchFailure::Rpc {
                code,
                message,
                reason: text("reason"),
                detail: text("detail"),
                retryable: data
                    .as_ref()
                    .and_then(|d| d.get("retryable"))
                    .and_then(|v| v.as_bool()),
                indexes: data
                    .as_ref()
                    .and_then(|d| d.get("indexes"))
                    .map(parse_indexes)
                    .unwrap_or_default(),
            }
        }
    }
}

/// `data.indexes`: an object of per-class arrays (the contract), tolerating a bare
/// array as one unclassified entry; anything else is ignored.
fn parse_indexes(value: &serde_json::Value) -> BTreeMap<String, Vec<usize>> {
    let list = |v: &serde_json::Value| -> Option<Vec<usize>> {
        v.as_array().map(|a| {
            a.iter()
                .filter_map(|i| i.as_u64().and_then(|i| usize::try_from(i).ok()))
                .collect()
        })
    };
    match value {
        serde_json::Value::Object(classes) => classes
            .iter()
            .filter_map(|(class, v)| list(v).map(|l| (class.clone(), l)))
            .collect(),
        other => list(other)
            .map(|l| BTreeMap::from([(UNCLASSIFIED.to_string(), l)]))
            .unwrap_or_default(),
    }
}

/// Decode `{"proofs": [<hex CBOR>...], "partitionView": <hex CBOR>?}`.
fn decode_batch_result(result: &serde_json::Value) -> Result<InclusionProofBatch, BatchFailure> {
    let bad = |m: &str| BatchFailure::Decode(m.to_string());
    let object = result
        .as_object()
        .ok_or_else(|| bad("batch result must be an object"))?;
    if object.keys().any(|k| k != "proofs" && k != "partitionView") {
        return Err(bad("unknown field in batch result"));
    }
    let hex_field = |v: &serde_json::Value| -> Result<Vec<u8>, BatchFailure> {
        let s = v.as_str().ok_or_else(|| bad("expected a hex string"))?;
        if s.len() > MAX_PROOF_HEX_CHARS {
            return Err(BatchFailure::TooLarge {
                limit: MAX_PROOF_HEX_CHARS,
            });
        }
        hex::decode(s).map_err(|e| BatchFailure::Decode(e.to_string()))
    };
    let proofs = object
        .get("proofs")
        .and_then(|v| v.as_array())
        .ok_or_else(|| bad("missing proofs array"))?
        .iter()
        .map(|v| {
            let bytes = hex_field(v)?;
            match decode_inclusion_proof_response(&bytes) {
                Ok(InclusionProofResponse::Certified {
                    block_number,
                    proof,
                }) => Ok(BatchProof {
                    block_number,
                    proof,
                }),
                Ok(InclusionProofResponse::NotCertified { .. }) => {
                    Err(bad("batch carries an uncertified proof"))
                }
                Err(e) => Err(BatchFailure::Decode(e.to_string())),
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    let partition_view = match object.get("partitionView") {
        None => None,
        Some(v) => Some(
            PartitionView::from_cbor(&hex_field(v)?)
                .map_err(|e| BatchFailure::Decode(e.to_string()))?,
        ),
    };
    Ok(InclusionProofBatch {
        proofs,
        partition_view,
    })
}

/// A random JSON-RPC request id.
fn request_id() -> String {
    let mut bytes = [0u8; 16];
    if getrandom::getrandom(&mut bytes).is_err() {
        return "0".to_string();
    }
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_endpoint_and_api_key() {
        let client =
            HttpAggregatorClient::new("https://user:password@example.invalid/rpc?secret=1")
                .with_api_key("AUDIT_SECRET");
        let debug = format!("{client:?}");
        assert!(!debug.contains("AUDIT_SECRET"));
        assert!(!debug.contains("password"));
        assert!(!debug.contains("secret=1"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn production_client_requires_safe_https_url() {
        assert!(HttpAggregatorClient::try_new("http://example.invalid").is_err());
        assert!(HttpAggregatorClient::try_new("not a URL").is_err());
        assert!(HttpAggregatorClient::try_new("https://user:pass@example.invalid").is_err());
        assert!(HttpAggregatorClient::try_new("https://example.invalid/rpc#fragment").is_err());
        assert!(HttpAggregatorClient::try_new("https://example.invalid/rpc").is_ok());
    }

    #[test]
    fn insecure_client_refuses_api_keys_before_network_io() {
        let client = HttpAggregatorClient::new_insecure_http("http://127.0.0.1:1")
            .with_api_key("must-not-leak");
        assert!(matches!(
            client.rpc("test", serde_json::json!({}), &[]),
            Err(HttpError::Configuration(_))
        ));
    }

    #[test]
    fn validates_json_rpc_envelope_and_correlation() {
        assert_eq!(
            decode_rpc_response(
                r#"{"jsonrpc":"2.0","id":"expected","result":7}"#,
                "expected",
            )
            .unwrap(),
            serde_json::json!(7)
        );
        for response in [
            r#"{"jsonrpc":"1.0","id":"expected","result":7}"#,
            r#"{"jsonrpc":"2.0","id":"wrong","result":7}"#,
            r#"{"jsonrpc":"2.0","id":"expected","result":7,"error":{"code":1,"message":"x"}}"#,
            r#"{"jsonrpc":"2.0","id":"expected"}"#,
        ] {
            assert!(matches!(
                decode_rpc_response(response, "expected"),
                Err(HttpError::Decode(_))
            ));
        }
    }

    #[test]
    fn insecure_http_endpoint_is_allowed_without_key() {
        let client = HttpAggregatorClient::new_insecure_http("http://127.0.0.1:8080/rpc");
        assert!(client.validate_endpoint().is_ok());
    }

    #[test]
    fn rejects_non_http_scheme() {
        assert!(HttpAggregatorClient::new("ftp://example.invalid/rpc")
            .validate_endpoint()
            .is_err());
    }

    #[test]
    fn request_id_is_unique_hex() {
        let a = request_id();
        let b = request_id();
        assert_eq!(a.len(), 32);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn decode_inclusion_proof_response_rejects_malformed() {
        use crate::cbor::{encode_array, encode_uint};

        // Empty input.
        assert!(decode_inclusion_proof_response(&[]).is_err());

        // Wrong array length (a single element).
        let one = encode_array(&[encode_uint(1).as_slice()]);
        assert!(decode_inclusion_proof_response(&one).is_err());

        // Well-formed 2-element array whose second element is not a proof.
        let two = encode_array(&[encode_uint(1).as_slice(), encode_uint(2).as_slice()]);
        assert!(decode_inclusion_proof_response(&two).is_err());

        // Trailing bytes after the payload are rejected.
        let mut trailing = two.clone();
        trailing.push(0xff);
        assert!(decode_inclusion_proof_response(&trailing).is_err());
    }

    #[test]
    fn decode_non_inclusion_proof_response_rejects_malformed() {
        use crate::cbor::{encode_array, encode_uint};

        assert!(decode_non_inclusion_proof_response(&[]).is_err());
        let one = encode_array(&[encode_uint(1).as_slice()]);
        assert!(decode_non_inclusion_proof_response(&one).is_err());
        let two = encode_array(&[encode_uint(1).as_slice(), encode_uint(2).as_slice()]);
        assert!(decode_non_inclusion_proof_response(&two).is_err());
    }
}
