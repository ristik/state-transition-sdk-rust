//! Unit tests for the blocking HTTP JSON-RPC transport (`client::http`).
//!
//! These drive a real [`HttpAggregatorClient`] against a local loopback mock
//! server (via `new_insecure_http`), exercising the success path and every
//! error branch — request framing, headers, JSON-RPC error mapping, HTTP status
//! errors, certification rejection, inclusion-proof decoding, and the polling /
//! timeout loop, and dedicated non-inclusion lookup — without touching live
//! infrastructure.
#![cfg(feature = "http")]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use unicity_token::api::inclusion_proof::INCLUSION_PROOF_TAG;
use unicity_token::api::{
    CertificationData, InclusionProof, InclusionProofResponse, NonInclusionCertificate,
    NonInclusionProof, ProofStatus, StateId,
};
use unicity_token::cbor::{encode_array, encode_null, encode_tag, encode_uint};
use unicity_token::client::{
    AggregatorClient, HttpAggregatorClient, HttpError, MembershipStatus,
    NonInclusionAggregatorClient,
};
use unicity_token::transaction::Token;

const FIXTURE: &str = include_str!("vectors/transition_flow.json");

// --- fixture helpers -------------------------------------------------------

fn field<'a>(json: &'a str, key: &str) -> &'a str {
    let needle = format!("\"{key}\"");
    let start = json.find(&needle).expect("key present") + needle.len();
    let rest = &json[start..];
    let q1 = rest.find('"').expect("open quote") + 1;
    let q2 = rest[q1..].find('"').expect("close quote") + q1;
    &rest[q1..q2]
}

/// A real `InclusionProof` and `CertificationData` taken from the cross-SDK
/// fixture (the first transfer of the Carol token).
fn fixture_proof_and_data() -> (InclusionProof, CertificationData) {
    let carol = hex::decode(field(FIXTURE, "carolToken")).unwrap();
    let token = Token::from_cbor(&carol).unwrap();
    let proof = token.transactions()[0].inclusion_proof().clone();
    let data = proof.certification_data.clone();
    (proof, data)
}

/// Wrap an inclusion proof as the `[blockNumber, InclusionProof]` response body
/// the aggregator returns, hex-encoded.
fn proof_response_hex(proof: &InclusionProof) -> String {
    hex::encode(
        InclusionProofResponse::Certified {
            block_number: 7,
            proof: proof.clone(),
        }
        .to_cbor(),
    )
}

/// The same wrapper for a leaf that is not certified yet: the three leaf fields
/// are absent together, which is what aggregator-go returns while pending.
fn empty_proof_response_hex(proof: &InclusionProof) -> String {
    hex::encode(
        InclusionProofResponse::NotCertified {
            block_number: 7,
            unicity_certificate: proof.unicity_certificate.clone(),
        }
        .to_cbor(),
    )
}

/// A response whose leaf fields are only partly present, which no aggregator
/// may send. Assembled by hand: neither `InclusionProof` nor
/// `InclusionProofResponse` can represent it, which is what this asserts.
fn partial_proof_response_hex(proof: &InclusionProof, keep_reference_time: bool) -> String {
    let reference_time = if keep_reference_time {
        encode_uint(proof.reference_time)
    } else {
        encode_null()
    };
    let inner = encode_tag(
        INCLUSION_PROOF_TAG,
        &encode_array(&[
            &encode_uint(1),
            &encode_null(),
            &reference_time,
            &encode_null(),
            &proof.unicity_certificate.to_cbor(),
        ]),
    );
    hex::encode(encode_array(&[encode_uint(7).as_slice(), inner.as_slice()]))
}

fn fixture_non_inclusion_proof() -> NonInclusionProof {
    let (inclusion, _) = fixture_proof_and_data();
    NonInclusionProof::new(
        NonInclusionCertificate::from_parts([0u8; 32], vec![], [0xa5; 32], [0x5a; 32]).unwrap(),
        inclusion.unicity_certificate,
    )
}

fn non_inclusion_response_hex(proof: &NonInclusionProof) -> String {
    let block = encode_uint(7);
    let body = encode_array(&[block.as_slice(), proof.to_cbor().as_slice()]);
    hex::encode(body)
}

// --- mock JSON-RPC server --------------------------------------------------

/// A loopback HTTP server that records requests and replies with canned
/// responses (response `i` for connection `i`, repeating the last one).
struct MockServer {
    url: String,
    requests: Arc<Mutex<Vec<String>>>,
}

impl MockServer {
    fn start(responses: Vec<Vec<u8>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();

        std::thread::spawn(move || {
            for (i, stream) in listener.incoming().enumerate() {
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
                let request = read_http_request(&mut stream);

                let response = responses
                    .get(i)
                    .or_else(|| responses.last())
                    .cloned()
                    .unwrap_or_default();
                let response = correlate_response_id(response, &request);
                captured.lock().unwrap().push(request);
                let _ = stream.write_all(&response);
                let _ = stream.flush();
            }
        });

        MockServer {
            url: format!("http://127.0.0.1:{port}/"),
            requests,
        }
    }

    fn request_count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }

    fn last_request(&self) -> String {
        self.requests
            .lock()
            .unwrap()
            .last()
            .cloned()
            .unwrap_or_default()
    }
}

fn correlate_response_id(response: Vec<u8>, request: &str) -> Vec<u8> {
    let Ok(response_text) = String::from_utf8(response.clone()) else {
        return response;
    };
    let Some((headers, body)) = response_text.split_once("\r\n\r\n") else {
        return response;
    };
    let Some(request_body) = request.split_once("\r\n\r\n").map(|(_, body)| body) else {
        return response;
    };
    let Ok(request_json) = serde_json::from_str::<serde_json::Value>(request_body) else {
        return response;
    };
    let Some(request_id) = request_json.get("id") else {
        return response;
    };
    let Ok(mut response_json) = serde_json::from_str::<serde_json::Value>(body) else {
        return response;
    };
    let Some(object) = response_json.as_object_mut() else {
        return response;
    };
    if !object.contains_key("id") {
        return response;
    }
    object.insert("id".to_string(), request_id.clone());
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("HTTP/1.1 "))
        .unwrap_or("200 OK");
    http_response(status, &response_json.to_string())
}

/// Read a full HTTP request (headers + Content-Length body) from the stream.
fn read_http_request(stream: &mut std::net::TcpStream) -> String {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
                    let header_end = pos + 4;
                    let content_length = content_length(&buf[..header_end]);
                    if buf.len() >= header_end + content_length {
                        break;
                    }
                }
            }
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn content_length(headers: &[u8]) -> usize {
    let text = String::from_utf8_lossy(headers);
    for line in text.lines() {
        if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            if let Ok(n) = value.trim().parse::<usize>() {
                return n;
            }
        }
    }
    0
}

fn http_response(status_line: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn redirect_response(status_line: &str, location: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status_line}\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
}

fn ok_json(result: &str) -> Vec<u8> {
    http_response(
        "200 OK",
        &format!(r#"{{"jsonrpc":"2.0","id":"1","result":{result}}}"#),
    )
}

fn client(url: &str) -> HttpAggregatorClient {
    HttpAggregatorClient::new_insecure_http(url).with_polling(Duration::from_millis(5), 3)
}

// --- tests -----------------------------------------------------------------

#[test]
fn submit_success_sends_method_and_state_id_header() {
    let server = MockServer::start(vec![ok_json(r#"{"status":"SUCCESS"}"#)]);
    let (_, data) = fixture_proof_and_data();

    client(&server.url)
        .submit_certification_request(&data)
        .expect("submit should succeed");

    let request = server.last_request();
    assert!(request.starts_with("POST "), "expected POST: {request}");
    assert!(request.contains("certification_request"));
    assert!(request.to_ascii_lowercase().contains("x-state-id:"));
}

#[test]
fn submit_rejected_status_maps_to_rejected_error() {
    let server = MockServer::start(vec![ok_json(
        r#"{"status":"SIGNATURE_VERIFICATION_FAILED"}"#,
    )]);
    let (_, data) = fixture_proof_and_data();

    let err = client(&server.url)
        .submit_certification_request(&data)
        .unwrap_err();
    assert!(
        matches!(err, HttpError::Rejected(ref s) if s == "SIGNATURE_VERIFICATION_FAILED"),
        "unexpected: {err}"
    );
}

#[test]
fn jsonrpc_error_object_maps_to_rpc_error() {
    let body = r#"{"jsonrpc":"2.0","id":"1","error":{"code":-32000,"message":"boom"}}"#;
    let server = MockServer::start(vec![http_response("200 OK", body)]);
    let (_, data) = fixture_proof_and_data();

    let err = client(&server.url)
        .submit_certification_request(&data)
        .unwrap_err();
    assert!(
        matches!(err, HttpError::Rpc { code: -32000, ref message } if message == "boom"),
        "unexpected: {err}"
    );
}

#[test]
fn http_status_error_is_surfaced() {
    let server = MockServer::start(vec![http_response("500 Internal Server Error", "nope")]);
    let (_, data) = fixture_proof_and_data();

    let err = client(&server.url)
        .submit_certification_request(&data)
        .unwrap_err();
    assert!(
        matches!(err, HttpError::Http { status: 500, .. }),
        "unexpected: {err}"
    );
}

#[test]
fn missing_result_maps_to_decode_error() {
    let server = MockServer::start(vec![http_response(
        "200 OK",
        r#"{"jsonrpc":"2.0","id":"1"}"#,
    )]);
    let (_, data) = fixture_proof_and_data();

    let err = client(&server.url)
        .submit_certification_request(&data)
        .unwrap_err();
    assert!(matches!(err, HttpError::Decode(_)), "unexpected: {err}");
}

#[test]
fn get_inclusion_proof_returns_complete_proof() {
    let (proof, data) = fixture_proof_and_data();
    let server = MockServer::start(vec![ok_json(&format!(
        "\"{}\"",
        proof_response_hex(&proof)
    ))]);

    let state_id = StateId::derive(data.lock_script(), data.source_state_hash());
    let got = client(&server.url)
        .get_inclusion_proof(&state_id)
        .expect("should return a complete proof");
    assert_eq!(got.certification_data, data);
    assert_eq!(got.reference_time, proof.reference_time);
    assert_eq!(server.request_count(), 1, "should not poll once complete");

    // The state-id header is not sent for proof lookups.
    assert!(!server
        .last_request()
        .to_ascii_lowercase()
        .contains("x-api-key:"));
}

#[test]
fn get_inclusion_proof_rejects_incomplete_response_without_polling() {
    let (proof, data) = fixture_proof_and_data();
    let response = ok_json(&format!("\"{}\"", partial_proof_response_hex(&proof, true)));
    let server = MockServer::start(vec![response]);

    let state_id = StateId::derive(data.lock_script(), data.source_state_hash());
    let err = client(&server.url)
        .get_inclusion_proof(&state_id)
        .unwrap_err();
    assert!(matches!(err, HttpError::Decode(_)), "unexpected: {err}");
    assert_eq!(server.request_count(), 1);
}

#[test]
fn get_inclusion_proof_fails_fast_for_unknown_state() {
    let body = r#"{"jsonrpc":"2.0","id":"1","error":{"code":-32020,"message":"not found"}}"#;
    let server = MockServer::start(vec![http_response("404 Not Found", body)]);
    let (_, data) = fixture_proof_and_data();
    let state_id = StateId::derive(data.lock_script(), data.source_state_hash());

    let err = client(&server.url)
        .get_inclusion_proof(&state_id)
        .unwrap_err();
    assert!(matches!(err, HttpError::StateNotFound), "unexpected: {err}");
    assert_eq!(server.request_count(), 1);
}

/// aggregator-go reports a pending leaf in band, as a successful response whose
/// certification data and inclusion certificate are absent. `get_inclusion_proof
/// .v2` never answers with a non-inclusion proof, so that response is
/// unambiguous and the client keeps polling on it.
#[test]
fn get_inclusion_proof_polls_an_in_band_pending_response() {
    let (proof, data) = fixture_proof_and_data();
    let pending = ok_json(&format!("\"{}\"", empty_proof_response_hex(&proof)));
    let complete = ok_json(&format!("\"{}\"", proof_response_hex(&proof)));
    let server = MockServer::start(vec![pending.clone(), pending, complete]);
    let state_id = StateId::derive(data.lock_script(), data.source_state_hash());

    let got = client(&server.url)
        .get_inclusion_proof(&state_id)
        .expect("pending request should eventually resolve");
    assert_eq!(got, proof);
    assert_eq!(server.request_count(), 3);
}

/// rugregator reports it out of band instead, which additionally lets the client
/// tell "not yet" apart from "no such state".
#[test]
fn get_inclusion_proof_polls_an_explicit_pending_status() {
    let (proof, data) = fixture_proof_and_data();
    let pending = http_response(
        "200 OK",
        r#"{"jsonrpc":"2.0","id":"1","error":{"code":-32021,"message":"certification is pending"}}"#,
    );
    let complete = ok_json(&format!("\"{}\"", proof_response_hex(&proof)));
    let server = MockServer::start(vec![pending.clone(), pending, complete]);
    let state_id = StateId::derive(data.lock_script(), data.source_state_hash());

    let got = client(&server.url)
        .get_inclusion_proof(&state_id)
        .expect("pending request should eventually resolve");
    assert_eq!(got, proof);
    assert_eq!(server.request_count(), 3);
}

#[test]
fn get_non_inclusion_proof_is_a_single_dedicated_lookup() {
    let proof = fixture_non_inclusion_proof();
    let server = MockServer::start(vec![ok_json(&format!(
        "\"{}\"",
        non_inclusion_response_hex(&proof)
    ))]);
    let (_, data) = fixture_proof_and_data();
    let state_id = StateId::derive(data.lock_script(), data.source_state_hash());

    let got = client(&server.url)
        .get_non_inclusion_proof(&state_id)
        .expect("proof should decode");
    assert_eq!(got.to_cbor(), proof.to_cbor());
    assert_eq!(got.requested_state_id(), Some(&state_id));
    assert_eq!(server.request_count(), 1);
    assert!(server.last_request().contains("get_non_inclusion_proof.v1"));
}

#[test]
fn membership_status_hides_relation_endpoint_selection() {
    let absent_proof = fixture_non_inclusion_proof();
    let absent = MockServer::start(vec![ok_json(&format!(
        "\"{}\"",
        non_inclusion_response_hex(&absent_proof)
    ))]);
    let (_, data) = fixture_proof_and_data();
    let state_id = StateId::derive(data.lock_script(), data.source_state_hash());

    let status = client(&absent.url).membership_status(&state_id).unwrap();
    let MembershipStatus::Absent(proof) = status else {
        panic!("expected absence")
    };
    assert_eq!(proof.requested_state_id(), Some(&state_id));
    assert_eq!(absent.request_count(), 1);

    let (included_proof, _) = fixture_proof_and_data();
    let relation_false = http_response(
        "200 OK",
        r#"{"jsonrpc":"2.0","id":"1","error":{"code":-32022,"message":"state is already included"}}"#,
    );
    let included = MockServer::start(vec![
        relation_false,
        ok_json(&format!("\"{}\"", proof_response_hex(&included_proof))),
    ]);

    let status = client(&included.url).membership_status(&state_id).unwrap();
    assert!(matches!(status, MembershipStatus::Included(_)));
    assert_eq!(included.request_count(), 2);
}

#[test]
fn non_inclusion_lookup_maps_false_relation_and_missing_root() {
    let (_, data) = fixture_proof_and_data();
    let state_id = StateId::derive(data.lock_script(), data.source_state_hash());

    let included = MockServer::start(vec![http_response(
        "200 OK",
        r#"{"jsonrpc":"2.0","id":"1","error":{"code":-32022,"message":"state is already included"}}"#,
    )]);
    assert!(matches!(
        client(&included.url).get_non_inclusion_proof(&state_id),
        Err(HttpError::StateIncluded)
    ));

    let unavailable = MockServer::start(vec![http_response(
        "404 Not Found",
        r#"{"jsonrpc":"2.0","id":"1","error":{"code":-32020,"message":"not found"}}"#,
    )]);
    assert!(matches!(
        client(&unavailable.url).get_non_inclusion_proof(&state_id),
        Err(HttpError::CertifiedStateUnavailable)
    ));
}

#[test]
fn get_non_inclusion_proof_rejects_malformed_result() {
    let (_, data) = fixture_proof_and_data();
    let state_id = StateId::derive(data.lock_script(), data.source_state_hash());
    for response in [ok_json("123"), ok_json("\"zzzz\""), ok_json("\"deadbeef\"")] {
        let server = MockServer::start(vec![response]);
        assert!(matches!(
            client(&server.url).get_non_inclusion_proof(&state_id),
            Err(HttpError::Decode(_))
        ));
    }
}

#[test]
fn get_inclusion_proof_rejects_non_string_result() {
    let server = MockServer::start(vec![ok_json("123")]);
    let (_, data) = fixture_proof_and_data();
    let state_id = StateId::derive(data.lock_script(), data.source_state_hash());

    let err = client(&server.url)
        .get_inclusion_proof(&state_id)
        .unwrap_err();
    assert!(matches!(err, HttpError::Decode(_)), "unexpected: {err}");
}

#[test]
fn get_inclusion_proof_rejects_bad_hex_and_bad_cbor() {
    let (_, data) = fixture_proof_and_data();
    let state_id = StateId::derive(data.lock_script(), data.source_state_hash());

    // Not hex.
    let server = MockServer::start(vec![ok_json("\"zzzz\"")]);
    assert!(matches!(
        client(&server.url).get_inclusion_proof(&state_id),
        Err(HttpError::Decode(_))
    ));

    // Valid hex, but not a valid `[blockNumber, InclusionProof]` payload.
    let server = MockServer::start(vec![ok_json("\"deadbeef\"")]);
    assert!(matches!(
        client(&server.url).get_inclusion_proof(&state_id),
        Err(HttpError::Decode(_))
    ));
}

#[test]
fn transport_error_when_server_unreachable() {
    // Nothing is listening on this port.
    let (_, data) = fixture_proof_and_data();
    let err = client("http://127.0.0.1:1/")
        .submit_certification_request(&data)
        .unwrap_err();
    assert!(
        matches!(err, HttpError::Transport(_) | HttpError::Http { .. }),
        "unexpected: {err}"
    );
}

#[test]
fn requests_do_not_follow_redirects() {
    for (status_line, status) in [
        ("301 Moved Permanently", 301),
        ("302 Found", 302),
        ("303 See Other", 303),
        ("307 Temporary Redirect", 307),
        ("308 Permanent Redirect", 308),
    ] {
        let server = MockServer::start(vec![redirect_response(
            status_line,
            "http://127.0.0.1:1/steal",
        )]);
        let (_, data) = fixture_proof_and_data();
        let err = client(&server.url)
            .submit_certification_request(&data)
            .unwrap_err();
        assert!(
            matches!(err, HttpError::Http { status: actual, .. } if actual == status),
            "redirect must be returned instead of followed: {err}"
        );
    }
}

#[test]
fn oversized_error_response_is_rejected() {
    let body = "x".repeat(64 * 1024 + 1);
    let server = MockServer::start(vec![http_response("500 Internal Server Error", &body)]);
    let (_, data) = fixture_proof_and_data();
    assert!(matches!(
        client(&server.url).submit_certification_request(&data),
        Err(HttpError::ResponseTooLarge { limit: 65_536 })
    ));
}

// --- proof status hints (opt-in includeStatus) ------------------------------

/// A `{proof, status}` result as returned when `includeStatus` is set.
fn status_json(proof_hex: &str, status: &str) -> Vec<u8> {
    ok_json(&format!(r#"{{"proof":"{proof_hex}","status":"{status}"}}"#))
}

fn pending_hex() -> (InclusionProof, String, String) {
    let (proof, _) = fixture_proof_and_data();
    let empty = empty_proof_response_hex(&proof);
    let full = proof_response_hex(&proof);
    (proof, empty, full)
}

fn fixture_state_id() -> StateId {
    let (_, data) = fixture_proof_and_data();
    StateId::derive(data.lock_script(), data.source_state_hash())
}

#[test]
fn the_request_opts_into_the_status_hint() {
    let (proof, _, full) = pending_hex();
    let server = MockServer::start(vec![ok_json(&format!("\"{full}\""))]);
    assert_eq!(
        client(&server.url)
            .get_inclusion_proof(&fixture_state_id())
            .unwrap(),
        proof
    );
    let request = server.last_request();
    assert!(request.contains("get_inclusion_proof.v2"), "{request}");
    assert!(request.contains(r#""includeStatus":true"#), "{request}");
}

#[test]
fn both_result_shapes_return_the_identical_proof() {
    let (proof, _, full) = pending_hex();
    for result in [
        ok_json(&format!("\"{full}\"")), // legacy server: plain string
        status_json(&full, "included"),  // status-aware server
        status_json(&full, "pending"),   // a hint never overrides a certified proof
        status_json(&full, "expired"),   // ... in either direction
        status_json(&full, "unknown"),
        status_json(&full, "some-future-value"), // unknown values are no status
    ] {
        let server = MockServer::start(vec![result]);
        let got = client(&server.url)
            .get_inclusion_proof(&fixture_state_id())
            .unwrap();
        assert_eq!(got, proof);
        assert_eq!(server.request_count(), 1);
    }
}

#[test]
fn pending_keeps_waiting_until_the_proof_arrives() {
    let (proof, empty, full) = pending_hex();
    let pending = status_json(&empty, "pending");
    let server = MockServer::start(vec![
        pending.clone(),
        pending,
        status_json(&full, "included"),
    ]);
    let got = client(&server.url)
        .get_inclusion_proof(&fixture_state_id())
        .unwrap();
    assert_eq!(got, proof);
    assert_eq!(server.request_count(), 3);
}

#[test]
fn expired_stops_at_once_with_a_typed_error() {
    let (_, empty, _) = pending_hex();
    let server = MockServer::start(vec![status_json(&empty, "expired")]);
    let err = client(&server.url)
        .get_inclusion_proof(&fixture_state_id())
        .unwrap_err();
    assert!(matches!(err, HttpError::StateExpired), "{err}");
    assert_eq!(server.request_count(), 1, "no waiting out the timeout");
}

#[test]
fn unknown_fails_after_the_grace_and_the_grace_is_configurable() {
    let (proof, empty, full) = pending_hex();
    let unknown = status_json(&empty, "unknown");

    // default grace (2): the third consecutive unknown fails, without waiting for the timeout
    let server = MockServer::start(vec![unknown.clone()]);
    let c = HttpAggregatorClient::new_insecure_http(&server.url)
        .with_polling(Duration::from_millis(1), 50);
    assert!(matches!(
        c.get_inclusion_proof(&fixture_state_id()),
        Err(HttpError::StateUnknown)
    ));
    assert_eq!(server.request_count(), 3);

    // an HA instance that has not seen the request yet: unknown, unknown, then the proof
    let server = MockServer::start(vec![
        unknown.clone(),
        unknown.clone(),
        status_json(&full, "included"),
    ]);
    assert_eq!(
        client(&server.url)
            .get_inclusion_proof(&fixture_state_id())
            .unwrap(),
        proof
    );

    // no grace: the first unknown fails
    let server = MockServer::start(vec![unknown.clone()]);
    let c = client(&server.url).with_unknown_grace(0);
    assert!(matches!(
        c.get_inclusion_proof(&fixture_state_id()),
        Err(HttpError::StateUnknown)
    ));
    assert_eq!(server.request_count(), 1);

    // `pending` resets the grace: unknown, unknown, pending, unknown, unknown, proof
    let pending = status_json(&empty, "pending");
    let server = MockServer::start(vec![
        unknown.clone(),
        unknown.clone(),
        pending,
        unknown.clone(),
        unknown,
        status_json(&full, "included"),
    ]);
    let c = HttpAggregatorClient::new_insecure_http(&server.url)
        .with_polling(Duration::from_millis(1), 10);
    assert_eq!(c.get_inclusion_proof(&fixture_state_id()).unwrap(), proof);
    assert_eq!(server.request_count(), 6);
}

#[test]
fn without_a_usable_status_the_legacy_behavior_is_unchanged() {
    let (_, empty, _) = pending_hex();
    // legacy string, a status this version does not know, and an `included` hint without a
    // proof are all just "not certified yet": poll until the configured attempts run out
    for result in [
        ok_json(&format!("\"{empty}\"")),
        status_json(&empty, "failed"),
        status_json(&empty, "included"),
    ] {
        let server = MockServer::start(vec![result]);
        let err = client(&server.url)
            .get_inclusion_proof(&fixture_state_id())
            .unwrap_err();
        assert!(matches!(err, HttpError::Timeout), "{err}");
        assert_eq!(server.request_count(), 3);
    }
}

#[test]
fn malformed_status_results_are_decode_errors() {
    for body in [
        r#"{"status":"pending"}"#,             // no proof
        r#"{"proof":123,"status":"pending"}"#, // proof is not a string
        r#"[]"#,
    ] {
        let server = MockServer::start(vec![ok_json(body)]);
        let err = client(&server.url)
            .get_inclusion_proof(&fixture_state_id())
            .unwrap_err();
        assert!(matches!(err, HttpError::Decode(_)), "{body}: {err}");
    }
}

#[test]
fn a_single_lookup_exposes_the_status_hint() {
    let (proof, empty, full) = pending_hex();
    let cases = [
        (
            status_json(&empty, "pending"),
            Some(ProofStatus::Pending),
            false,
        ),
        (
            status_json(&empty, "expired"),
            Some(ProofStatus::Expired),
            false,
        ),
        (
            status_json(&empty, "unknown"),
            Some(ProofStatus::Unknown),
            false,
        ),
        (
            status_json(&full, "included"),
            Some(ProofStatus::Included),
            true,
        ),
        (ok_json(&format!("\"{full}\"")), None, true),
        (ok_json(&format!("\"{empty}\"")), None, false),
        (status_json(&empty, "novel"), None, false),
    ];
    for (body, status, certified) in cases {
        let server = MockServer::start(vec![body]);
        let (response, got) = client(&server.url)
            .lookup_inclusion_proof(&fixture_state_id())
            .unwrap();
        assert_eq!(got, status);
        assert_eq!(response.inclusion_proof().is_some(), certified);
        if certified {
            assert_eq!(response.inclusion_proof(), Some(&proof));
        }
        assert_eq!(server.request_count(), 1, "a lookup never waits");
    }
}
