//! Wire support of the long-poll extension in the blocking HTTP client (T2, T8
//! SDK parts): `waitMs` requests, the `waitedMs` echo in v2 and batch results and
//! errors, strict echo validation and the one-shot parser-negotiation retry.
//! Everything runs against a loopback mock; nothing here is a live server run.
#![cfg(feature = "http")]

mod common;

use std::collections::BTreeMap;
use std::time::Duration;

use common::*;
use unicity_token::api::{InclusionProofResponse, ProofStatus, StateId};
use unicity_token::client::{
    get_latest_negotiating_wait, is_malformed_params, AggregatorClient, BatchAggregatorClient,
    BatchFailure, BatchRequest, HttpAggregatorClient, HttpError, RequestOptions, StateRoot,
    WaitRequest, WaitedFailure,
};

fn client(url: &str) -> HttpAggregatorClient {
    HttpAggregatorClient::new_insecure_http(url).with_polling(Duration::from_millis(5), 3)
}

fn sid() -> StateId {
    state_id(7)
}

fn v2_object(proof_hex: &str, status: Option<&str>, waited: Option<&str>) -> String {
    let mut s = format!(r#"{{"proof":"{proof_hex}""#);
    if let Some(st) = status {
        s.push_str(&format!(r#","status":"{st}""#));
    }
    if let Some(w) = waited {
        s.push_str(&format!(r#","waitedMs":{w}"#));
    }
    s.push('}');
    s
}

// --- v2 requests and echo --------------------------------------------------

#[test]
fn v2_wait_request_carries_wait_ms_and_include_status() {
    let (proof, _) = fixture_proof_and_data();
    let hexp = empty_proof_response_hex(&proof);
    let server =
        Scripted::start(move |_, _| Reply::result(v2_object(&hexp, Some("pending"), Some("8000"))));
    let got = client(&server.url)
        .lookup_inclusion_proof_with_wait(&sid(), &WaitRequest::new(8_000), Duration::from_secs(20))
        .unwrap();
    assert_eq!(got.waited_ms, Some(8_000));
    assert_eq!(got.status, Some(ProofStatus::Pending));
    assert!(matches!(
        got.response,
        InclusionProofResponse::NotCertified { .. }
    ));
    let p = server.request(0).params;
    assert_eq!(p["waitMs"], 8_000);
    assert_eq!(p["includeStatus"], true);
    assert_eq!(server.request(0).method, "get_inclusion_proof.v2");
}

#[test]
fn v2_zero_wait_is_sent_as_zero_and_echo_zero_is_accepted() {
    let (proof, _) = fixture_proof_and_data();
    let hexp = proof_response_hex(&proof);
    let server = Scripted::start(move |_, _| Reply::result(v2_object(&hexp, None, Some("0"))));
    let got = client(&server.url)
        .lookup_inclusion_proof_with_wait(&sid(), &WaitRequest::new(0), Duration::from_secs(5))
        .unwrap();
    assert_eq!(got.waited_ms, Some(0));
    assert_eq!(server.request(0).params["waitMs"], 0);
}

#[test]
fn v2_wait_is_clamped_to_the_timeout_margin_and_omitted_when_nothing_fits() {
    let (proof, _) = fixture_proof_and_data();
    let hexp = proof_response_hex(&proof);
    let server = Scripted::start(move |_, _| Reply::result(format!("\"{hexp}\"")));
    let c = client(&server.url);
    // The wait only has to stay below the timeout (the margin is the caller's).
    c.lookup_inclusion_proof_with_wait(&sid(), &WaitRequest::new(20_000), Duration::from_secs(5))
        .unwrap();
    assert_eq!(server.request(0).params["waitMs"], 3_000); // 5 s call - 2 s default margin
                                                           // Nothing positive fits once the margin is kept: no waitMs on the wire.
    assert_eq!(
        unicity_token::client::wait_on_wire(20_000, 2_000, 2_000),
        None
    );
    assert_eq!(unicity_token::client::wait_on_wire(0, 1, 2_000), Some(0));
    assert_eq!(
        unicity_token::client::wait_on_wire(20_000, 2_001, 2_000),
        Some(1)
    );
    // A legacy bare string has no echo.
    let got = c
        .lookup_inclusion_proof_with_wait(&sid(), &WaitRequest::new(1_000), Duration::from_secs(9))
        .unwrap();
    assert_eq!(got.waited_ms, None);
}

#[test]
fn v2_legacy_requests_never_carry_wait_ms() {
    let (proof, _) = fixture_proof_and_data();
    let hexp = proof_response_hex(&proof);
    let server = Scripted::start(move |_, _| Reply::result(format!("\"{hexp}\"")));
    let c = client(&server.url);
    c.get_inclusion_proof(&sid()).unwrap();
    c.lookup_inclusion_proof(&sid()).unwrap();
    for i in 0..2 {
        assert!(server.request(i).params.get("waitMs").is_none());
    }
}

#[test]
fn v2_malformed_echo_is_a_protocol_error() {
    let (proof, _) = fixture_proof_and_data();
    let hexp = proof_response_hex(&proof);
    for bad in [
        "-1",
        "1.5",
        "1.0",
        "1e3",
        "\"5\"",
        "null",
        "true",
        "[]",
        "{}",
        "9007199254740992",
        "18446744073709551616",
    ] {
        let hexp = hexp.clone();
        let bad_owned = bad.to_string();
        let server =
            Scripted::start(move |_, _| Reply::result(v2_object(&hexp, None, Some(&bad_owned))));
        let err = client(&server.url)
            .lookup_inclusion_proof_with_wait(
                &sid(),
                &WaitRequest::new(1_000),
                Duration::from_secs(9),
            )
            .unwrap_err();
        assert!(matches!(err, HttpError::Decode(_)), "{bad}: {err}");
        // The legacy poller rejects the same malformed metadata.
        let err = client(&server.url).get_inclusion_proof(&sid()).unwrap_err();
        assert!(matches!(err, HttpError::Decode(_)), "legacy {bad}: {err}");
    }
    // The maximum safe integer is fine.
    let h = hexp.clone();
    let server =
        Scripted::start(move |_, _| Reply::result(v2_object(&h, None, Some("9007199254740991"))));
    let got = client(&server.url)
        .lookup_inclusion_proof_with_wait(&sid(), &WaitRequest::new(1_000), Duration::from_secs(9))
        .unwrap();
    assert_eq!(got.waited_ms, Some(9_007_199_254_740_991));
}

#[test]
fn legacy_status_only_object_still_decodes() {
    let (proof, _) = fixture_proof_and_data();
    let hexp = empty_proof_response_hex(&proof);
    let server =
        Scripted::start(move |_, _| Reply::result(v2_object(&hexp, Some("expired"), None)));
    let (resp, status) = client(&server.url).lookup_inclusion_proof(&sid()).unwrap();
    assert!(matches!(resp, InclusionProofResponse::NotCertified { .. }));
    assert_eq!(status, Some(ProofStatus::Expired));
}

// --- batch ----------------------------------------------------------------

fn batch_ids() -> Vec<StateId> {
    vec![state_id(1), state_id(2)]
}

fn opts(ms: u64) -> RequestOptions {
    RequestOptions { timeout_ms: ms }
}

fn pending_error(extra: &str) -> String {
    format!(
        r#"{{"code":-32008,"message":"Proof unavailable","data":{{"reason":"proof_unavailable","detail":"state_pending","retryable":true,"indexes":{{"pending":[0]}}{extra}}}}}"#
    )
}

#[test]
fn batch_wait_is_sent_only_for_latest_and_error_echo_is_typed() {
    let server = Scripted::start(|_, _| Reply::error(pending_error(r#","waitedMs":8000"#)));
    let c = client(&server.url);
    let ids = batch_ids();
    let latest = BatchRequest {
        state_ids: &ids,
        state_root: StateRoot::Latest,
    };
    let err = c
        .get_inclusion_proofs_with_wait(&latest, &opts(20_000), &WaitRequest::new(8_000))
        .unwrap_err();
    assert_eq!(err.waited_ms, Some(8_000));
    let BatchFailure::Rpc {
        code,
        detail,
        retryable,
        indexes,
        ..
    } = &err.failure
    else {
        panic!("{:?}", err.failure)
    };
    assert_eq!(
        (*code, detail.as_deref(), *retryable),
        (-32008, Some("state_pending"), Some(true))
    );
    assert_eq!(
        indexes,
        &BTreeMap::from([("pending".to_string(), vec![0usize])])
    );
    let p = server.request(0).params;
    assert_eq!(p["waitMs"], 8_000);
    assert_eq!(p["stateRoot"], "latest");

    // Exact root: the wait is never sent.
    let exact = BatchRequest {
        state_ids: &ids,
        state_root: StateRoot::Exact([9u8; 32]),
    };
    let _ = c.get_inclusion_proofs_with_wait(&exact, &opts(20_000), &WaitRequest::new(8_000));
    assert!(server.request(1).params.get("waitMs").is_none());
    assert_eq!(
        server.request(1).params["stateRoot"],
        hex::encode([9u8; 32])
    );
}

#[test]
fn batch_plain_call_never_sends_wait_and_error_without_echo_has_none() {
    let server = Scripted::start(|_, _| Reply::error(pending_error("")));
    let ids = batch_ids();
    let latest = BatchRequest {
        state_ids: &ids,
        state_root: StateRoot::Latest,
    };
    let c = client(&server.url);
    let _ = c.get_inclusion_proofs(&latest, &opts(5_000));
    assert!(server.request(0).params.get("waitMs").is_none());
    let err = c
        .get_inclusion_proofs_with_wait(&latest, &opts(20_000), &WaitRequest::new(3_000))
        .unwrap_err();
    assert_eq!(err.waited_ms, None);
}

#[test]
fn batch_malformed_error_echo_is_a_decode_failure() {
    for bad in ["-1", "1.5", "\"8\"", "null", "9007199254740992"] {
        let extra = format!(r#","waitedMs":{bad}"#);
        let server = Scripted::start(move |_, _| Reply::error(pending_error(&extra)));
        let ids = batch_ids();
        let latest = BatchRequest {
            state_ids: &ids,
            state_root: StateRoot::Latest,
        };
        let err = client(&server.url)
            .get_inclusion_proofs_with_wait(&latest, &opts(20_000), &WaitRequest::new(3_000))
            .unwrap_err();
        assert!(
            matches!(err.failure, BatchFailure::Decode(_)),
            "{bad}: {err:?}"
        );
        assert_eq!(err.waited_ms, None);
    }
}

#[test]
fn batch_wait_is_clamped_to_the_call_timeout() {
    let server = Scripted::start(|_, _| Reply::error(pending_error("")));
    let ids = batch_ids();
    let latest = BatchRequest {
        state_ids: &ids,
        state_root: StateRoot::Latest,
    };
    let c = client(&server.url);
    let _ = c.get_inclusion_proofs_with_wait(&latest, &opts(5_000), &WaitRequest::new(20_000));
    assert_eq!(server.request(0).params["waitMs"], 3_000); // 5 s call - 2 s default margin
}

// --- parser negotiation -----------------------------------------------------

fn malformed_params() -> String {
    r#"{"code":-32602,"message":"Invalid params","data":{"reason":"invalid_request","detail":"malformed_params","retryable":false}}"#.to_string()
}

fn clock() -> impl Fn() -> u64 {
    let t0 = std::time::Instant::now();
    move || t0.elapsed().as_millis() as u64
}

#[test]
fn negotiation_retries_exactly_once_without_the_wait() {
    // A strict parser that rejects waitMs and accepts the plain request.
    let server = Scripted::start(|_, seen| {
        if seen.params.get("waitMs").is_some() {
            Reply::error(malformed_params())
        } else {
            Reply::error(pending_error(""))
        }
    });
    let ids = batch_ids();
    let now = clock();
    let out = get_latest_negotiating_wait(
        &client(&server.url),
        &ids,
        &opts(20_000),
        &WaitRequest::new(8_000),
        &now,
    );
    assert_eq!((out.requests, out.retried_without_wait), (2, true));
    assert_eq!(server.count(), 2);
    assert_eq!(server.request(0).params["waitMs"], 8_000);
    let second = server.request(1).params;
    assert!(second.get("waitMs").is_none());
    // Everything else is identical.
    assert_eq!(second["stateIds"], server.request(0).params["stateIds"]);
    assert_eq!(second["stateRoot"], "latest");
    // The second outcome is final, not a retry trigger.
    let WaitedFailure {
        failure, waited_ms, ..
    } = out.result.unwrap_err();
    assert!(matches!(failure, BatchFailure::Rpc { code: -32008, .. }));
    assert_eq!(waited_ms, None);
}

#[test]
fn negotiation_returns_the_second_error_when_it_is_malformed_again() {
    let server = Scripted::start(|_, _| Reply::error(malformed_params()));
    let ids = batch_ids();
    let now = clock();
    let out = get_latest_negotiating_wait(
        &client(&server.url),
        &ids,
        &opts(20_000),
        &WaitRequest::new(8_000),
        &now,
    );
    assert_eq!((out.requests, out.retried_without_wait), (2, true));
    assert_eq!(server.count(), 2, "never a third request");
    assert!(is_malformed_params(&out.result.unwrap_err().failure));
}

#[test]
fn negotiation_does_not_retry_unrelated_failures() {
    let cases: Vec<(&str, Reply)> = vec![
        // wrong detail
        (
            "wrong detail",
            Reply::error(
                r#"{"code":-32602,"message":"x","data":{"reason":"invalid_request","detail":"invalid_state_id"}}"#,
            ),
        ),
        // wrong code
        (
            "wrong code",
            Reply::error(
                r#"{"code":-32600,"message":"x","data":{"reason":"invalid_request","detail":"malformed_params"}}"#,
            ),
        ),
        // wrong reason
        (
            "wrong reason",
            Reply::error(
                r#"{"code":-32602,"message":"x","data":{"reason":"limit_exceeded","detail":"malformed_params"}}"#,
            ),
        ),
        // method not found
        (
            "no method",
            Reply::error(r#"{"code":-32601,"message":"Method not found"}"#),
        ),
        // busy
        (
            "busy",
            Reply::error(
                r#"{"code":-32006,"message":"busy","data":{"reason":"busy","detail":"deadline","retryable":true}}"#,
            ),
        ),
        // proxy HTML
        (
            "html",
            Reply::raw(http_response("502 Bad Gateway", "<html>bad gateway</html>")),
        ),
        // auth
        ("auth", Reply::raw(http_response("401 Unauthorized", "{}"))),
    ];
    for (name, reply) in cases {
        let cell = std::sync::Mutex::new(Some(reply));
        let server =
            Scripted::start(move |_, _| cell.lock().unwrap().take().unwrap_or_else(Reply::silent));
        let ids = batch_ids();
        let now = clock();
        let out = get_latest_negotiating_wait(
            &client(&server.url),
            &ids,
            &opts(5_000),
            &WaitRequest::new(3_000),
            &now,
        );
        assert_eq!(
            (out.requests, out.retried_without_wait),
            (1, false),
            "{name}"
        );
        assert_eq!(server.count(), 1, "{name}");
        assert!(out.result.is_err(), "{name}");
    }
}

#[test]
fn negotiation_does_not_spend_a_fresh_deadline_on_the_retry() {
    // The rejection arrives after 300 ms of a 500 ms deadline: the retry gets at
    // most the remaining time, and a second call that hangs ends by then.
    let server = Scripted::start(|i, _| {
        if i == 0 {
            Reply::error(malformed_params()).after(Duration::from_millis(300))
        } else {
            Reply::silent()
        }
    });
    let ids = batch_ids();
    let now = clock();
    let started = std::time::Instant::now();
    let out = get_latest_negotiating_wait(
        &client(&server.url),
        &ids,
        &opts(500),
        &WaitRequest::new(1).with_margin_ms(0),
        &now,
    );
    let took = started.elapsed();
    assert_eq!(out.requests, 2);
    assert!(matches!(
        out.result.unwrap_err().failure,
        BatchFailure::Timeout
    ));
    assert!(
        took < Duration::from_millis(1_200),
        "deadline renewed: {took:?}"
    );
}

#[test]
fn negotiation_without_time_left_returns_the_first_error() {
    let server =
        Scripted::start(|_, _| Reply::error(malformed_params()).after(Duration::from_millis(80)));
    let ids = batch_ids();
    let now = clock();
    let out = get_latest_negotiating_wait(
        &client(&server.url),
        &ids,
        &opts(50),
        &WaitRequest::new(1),
        &now,
    );
    // the first call either timed out or came back with nothing left
    assert_eq!(out.requests, 1);
    assert_eq!(server.count(), 1);
    assert!(!out.retried_without_wait);
}

#[test]
fn batch_success_echo_is_decoded_and_strictly_validated() {
    let (proof, _) = fixture_proof_and_data();
    let one = proof_response_hex(&proof);
    let body = |extra: &str| format!(r#"{{"proofs":["{one}","{one}"]{extra}}}"#);
    let ids = batch_ids();
    let latest = BatchRequest {
        state_ids: &ids,
        state_root: StateRoot::Latest,
    };

    for (extra, want) in [
        ("", None),
        (r#","waitedMs":0"#, Some(0)),
        (r#","waitedMs":4200"#, Some(4_200)),
    ] {
        let b = body(extra);
        let server = Scripted::start(move |_, _| Reply::result(b.clone()));
        let ok = client(&server.url)
            .get_inclusion_proofs_with_wait(&latest, &opts(20_000), &WaitRequest::new(5_000))
            .unwrap();
        assert_eq!((ok.batch.proofs.len(), ok.waited_ms), (2, want), "{extra}");
        // The plain call decodes the same body (an unrequested echo is admitted).
        let plain = client(&server.url)
            .get_inclusion_proofs(&latest, &opts(5_000))
            .unwrap();
        assert_eq!(plain, ok.batch);
    }
    for bad in [
        r#","waitedMs":-1"#,
        r#","waitedMs":2.5"#,
        r#","waitedMs":"1""#,
        r#","waitedMs":null"#,
        r#","waitedMs":9007199254740992"#,
    ] {
        let b = body(bad);
        let server = Scripted::start(move |_, _| Reply::result(b.clone()));
        let err = client(&server.url)
            .get_inclusion_proofs_with_wait(&latest, &opts(20_000), &WaitRequest::new(5_000))
            .unwrap_err();
        assert!(
            matches!(err.failure, BatchFailure::Decode(_)),
            "{bad}: {err:?}"
        );
    }
    // Other unknown result fields stay rejected.
    let b = body(r#","status":"x""#);
    let server = Scripted::start(move |_, _| Reply::result(b.clone()));
    let err = client(&server.url)
        .get_inclusion_proofs_with_wait(&latest, &opts(20_000), &WaitRequest::new(5_000))
        .unwrap_err();
    assert!(matches!(err.failure, BatchFailure::Decode(_)));
}

// --- frozen cross-implementation fixtures (aggregator-go#225, testdata/longpoll) ---

const ECHO: &str = include_str!("vectors/longpoll/echo.json");
const CAPABILITY: &str = include_str!("vectors/longpoll/capability.json");

fn cases(raw: &str) -> Vec<serde_json::Value> {
    serde_json::from_str::<serde_json::Value>(raw).unwrap()["cases"]
        .as_array()
        .unwrap()
        .clone()
}

#[test]
fn frozen_echo_examples_decode_with_the_contract_placement() {
    let mut v2 = 0;
    let mut batch = 0;
    for case in cases(ECHO) {
        let name = case["name"].as_str().unwrap().to_string();
        let mut response = case["response"].clone();
        // The Go fixtures' proof bytes are synthetic; the contract under test is the
        // envelope and echo placement, so swap in this SDK's own decodable proofs.
        let (proof, _) = fixture_proof_and_data();
        let full = proof_response_hex(&proof);
        let empty = empty_proof_response_hex(&proof);
        if let Some(result) = response.get_mut("result") {
            let swap = |h: &str| {
                if h.len() > 40 {
                    full.clone()
                } else {
                    empty.clone()
                }
            };
            if let Some(h) = result.as_str().map(swap) {
                *result = serde_json::json!(h);
            } else if let Some(h) = result.get("proof").and_then(|p| p.as_str()).map(swap) {
                result["proof"] = serde_json::json!(h);
            } else if let Some(list) = result.get_mut("proofs").and_then(|p| p.as_array_mut()) {
                for item in list {
                    *item = serde_json::json!(full);
                }
                // an unsharded response needs no (here synthetic) partition view
                result.as_object_mut().unwrap().remove("partitionView");
            }
        }
        let server = Scripted::start({
            let r = response.clone();
            move |_, _| match (r.get("result"), r.get("error")) {
                (Some(x), _) => Reply::result(x.to_string()),
                (_, Some(e)) => Reply::error(e.to_string()),
                _ => unreachable!(),
            }
        });
        let c = client(&server.url);
        let want = response
            .get("result")
            .and_then(|r| r.get("waitedMs"))
            .or_else(|| response["error"]["data"].get("waitedMs"))
            .and_then(|v| v.as_u64());
        if name.starts_with("v2/") {
            v2 += 1;
            if response.get("result").is_some() {
                let got = c
                    .lookup_inclusion_proof_with_wait(
                        &sid(),
                        &WaitRequest::new(5_000),
                        Duration::from_secs(20),
                    )
                    .unwrap_or_else(|e| panic!("{name}: {e}"));
                assert_eq!(got.waited_ms, want, "{name}");
                // The status hint rides along unchanged.
                let status = response["result"].get("status").and_then(|s| s.as_str());
                assert_eq!(got.status.is_some(), status.is_some(), "{name}");
            }
        } else {
            batch += 1;
            let ids = batch_ids();
            let latest = BatchRequest {
                state_ids: &ids,
                state_root: StateRoot::Latest,
            };
            let out =
                c.get_inclusion_proofs_with_wait(&latest, &opts(20_000), &WaitRequest::new(5_000));
            if response.get("result").is_some() {
                let ok = out.unwrap_or_else(|e| panic!("{name}: {e:?}"));
                assert_eq!(ok.waited_ms, want, "{name}");
            } else {
                let err = out.unwrap_err();
                assert_eq!(err.waited_ms, want, "{name}: {err:?}");
                let BatchFailure::Rpc { code, .. } = err.failure else {
                    panic!("{name}")
                };
                assert_eq!(code, response["error"]["code"].as_i64().unwrap(), "{name}");
            }
        }
    }
    assert!(v2 >= 10 && batch >= 9, "fixture shrank: {v2}/{batch}");
}

#[test]
fn frozen_capability_table_drives_exactly_the_specified_retries() {
    let ids = batch_ids();
    for case in cases(CAPABILITY) {
        let name = case["name"].as_str().unwrap().to_string();
        let action = case["action"].as_str().unwrap();
        let Some(error) = case["response"].get("error").cloned() else {
            continue;
        };
        let strict = name == "strict-parser-generic-malformed-params";
        let server = Scripted::start(move |_, seen| {
            // the generic rejection answers only requests carrying waitMs; the
            // retry (without it) is then served the same error to show it is final
            let _ = seen;
            Reply::error(error.to_string())
        });
        let now = clock();
        let out = get_latest_negotiating_wait(
            &client(&server.url),
            &ids,
            &opts(5_000),
            &WaitRequest::new(3_000),
            &now,
        );
        let expect = if action == "retry" { 2 } else { 1 };
        assert_eq!(out.requests, expect, "{name}");
        assert_eq!(server.count(), expect as usize, "{name}");
        assert_eq!(out.retried_without_wait, strict, "{name}");
        if expect == 2 {
            assert!(server.request(0).params.get("waitMs").is_some());
            assert!(server.request(1).params.get("waitMs").is_none());
        }
    }
}

#[test]
fn negotiation_does_not_retry_when_the_rejection_echoes_the_wait() {
    // The server understood waitMs (it echoed it): malformed_params is about the
    // request itself, so no retry without the wait.
    let server = Scripted::start(|_, _| {
        Reply::error(
            r#"{"code":-32602,"message":"Invalid params","data":{"reason":"invalid_request","detail":"malformed_params","retryable":false,"waitedMs":0}}"#,
        )
    });
    let ids = batch_ids();
    let now = clock();
    let out = get_latest_negotiating_wait(
        &client(&server.url),
        &ids,
        &opts(5_000),
        &WaitRequest::new(3_000),
        &now,
    );
    assert_eq!((out.requests, out.retried_without_wait), (1, false));
    assert_eq!(server.count(), 1);
    assert_eq!(out.result.unwrap_err().waited_ms, Some(0));
}

#[test]
fn negotiation_does_not_repeat_an_identical_request_when_no_wait_was_sent() {
    // timeout 1 ms: no positive wait fits, so waitMs is absent from the wire and a
    // malformed_params answer is not about it; there is nothing to retry.
    let server = Scripted::start(|_, _| Reply::error(malformed_params()));
    let ids = batch_ids();
    let now = clock();
    let out = get_latest_negotiating_wait(
        &client(&server.url),
        &ids,
        &opts(1),
        &WaitRequest::new(5_000),
        &now,
    );
    assert_eq!((out.requests, out.retried_without_wait), (1, false));
    assert!(server.count() <= 1, "never a second identical request");
}

#[test]
fn a_small_caller_margin_reaches_the_request() {
    let server = Scripted::start(|_, _| Reply::error(pending_error("")));
    let ids = batch_ids();
    let latest = BatchRequest {
        state_ids: &ids,
        state_root: StateRoot::Latest,
    };
    // the caller sized 1.5 s of wait for a 2 s call (500 ms margin): sent as is
    let _ = client(&server.url).get_inclusion_proofs_with_wait(
        &latest,
        &opts(2_000),
        &WaitRequest::new(1_500).with_margin_ms(500),
    );
    assert_eq!(server.request(0).params["waitMs"], 1_500);
}

#[test]
fn a_one_shot_keeps_the_response_margin_below_the_call_timeout() {
    let (proof, _) = fixture_proof_and_data();
    let hexp = proof_response_hex(&proof);
    let server = Scripted::start(move |_, _| Reply::result(format!("\"{hexp}\"")));
    let c = client(&server.url);
    c.lookup_inclusion_proof_with_wait(&sid(), &WaitRequest::new(20_000), Duration::from_secs(5))
        .unwrap();
    c.lookup_inclusion_proof_with_wait(
        &sid(),
        &WaitRequest::new(20_000).with_margin_ms(500),
        Duration::from_secs(5),
    )
    .unwrap();
    assert_eq!(server.request(0).params["waitMs"], 3_000);
    assert_eq!(server.request(1).params["waitMs"], 4_500);
}

/// A transport relying on the trait's default method sends no wait and says so;
/// a rejection is then not about a wait and must not be retried.
struct DefaultImpl(HttpAggregatorClient);
impl AggregatorClient for DefaultImpl {
    type Error = HttpError;
    fn submit_certification_request(
        &self,
        d: &unicity_token::api::CertificationData,
    ) -> Result<(), HttpError> {
        self.0.submit_certification_request(d)
    }
    fn get_inclusion_proof(
        &self,
        s: &StateId,
    ) -> Result<unicity_token::api::InclusionProof, HttpError> {
        self.0.get_inclusion_proof(s)
    }
}
impl BatchAggregatorClient for DefaultImpl {
    fn get_inclusion_proofs(
        &self,
        r: &BatchRequest<'_>,
        o: &RequestOptions,
    ) -> Result<unicity_token::client::InclusionProofBatch, BatchFailure> {
        self.0.get_inclusion_proofs(r, o)
    }
}

#[test]
fn a_default_implementation_transport_is_never_retried_identically() {
    let server = Scripted::start(|_, _| Reply::error(malformed_params()));
    let ids = batch_ids();
    let now = clock();
    let c = DefaultImpl(client(&server.url));
    let out = get_latest_negotiating_wait(&c, &ids, &opts(5_000), &WaitRequest::new(3_000), &now);
    assert_eq!((out.requests, out.retried_without_wait), (1, false));
    assert_eq!(server.count(), 1);
    assert_eq!(out.result.unwrap_err().sent_wait_ms, None);
}

#[test]
fn the_http_transport_reports_the_wait_it_sent() {
    let server = Scripted::start(|_, _| Reply::error(pending_error("")));
    let ids = batch_ids();
    let latest = BatchRequest {
        state_ids: &ids,
        state_root: StateRoot::Latest,
    };
    let c = client(&server.url);
    let sent = |ms: u64, timeout: u64| {
        c.get_inclusion_proofs_with_wait(&latest, &opts(timeout), &WaitRequest::new(ms))
            .unwrap_err()
            .sent_wait_ms
    };
    assert_eq!(sent(1_000, 10_000), Some(1_000));
    assert_eq!(sent(0, 10_000), Some(0));
    assert_eq!(sent(20_000, 10_000), Some(8_000));
    assert_eq!(sent(1_000, 2_000), None, "margin leaves nothing");
    let exact = BatchRequest {
        state_ids: &ids,
        state_root: StateRoot::Exact([9; 32]),
    };
    let e = c
        .get_inclusion_proofs_with_wait(&exact, &opts(10_000), &WaitRequest::new(1_000))
        .unwrap_err();
    assert_eq!(e.sent_wait_ms, None);
}

// Gateway answer for a batch spanning several shards: HTTP 400 with the unchanged JSON-RPC -32602 body and id
// (arch-lb-compat §D). The classifier reads the RPC error behind the 400; it is not the "retry without waitMs"
// malformed_params case, so no second request is made.
#[test]
fn a_gateway_http_400_mixed_shard_answer_keeps_its_rpc_classification() {
    let server = Scripted::start(|_, _| {
        Reply::error_status(
            "400 Bad Request",
            // the gateway's exact body (aggregator-subscription batchShardErrorBody): code, message, id; no data
            r#"{"code":-32602,"message":"stateIds belong to more than one shard; send one request per shard"}"#,
        )
    });
    let ids = batch_ids();
    let now = clock();
    let out = get_latest_negotiating_wait(
        &client(&server.url),
        &ids,
        &opts(20_000),
        &WaitRequest::new(8_000),
        &now,
    );
    assert_eq!((out.requests, out.retried_without_wait), (1, false));
    assert_eq!(server.count(), 1, "not retried without waitMs");
    let failure = out.result.unwrap_err().failure;
    assert!(!is_malformed_params(&failure), "{failure:?}");
    assert!(
        matches!(failure, BatchFailure::Rpc { code: -32602, .. }),
        "{failure:?}"
    );
    // and the same through the plain batch call
    let latest = BatchRequest {
        state_ids: &ids,
        state_root: StateRoot::Latest,
    };
    let err = client(&server.url)
        .get_inclusion_proofs(&latest, &opts(20_000))
        .unwrap_err();
    assert!(
        matches!(err, BatchFailure::Rpc { code: -32602, .. }),
        "{err:?}"
    );
}
