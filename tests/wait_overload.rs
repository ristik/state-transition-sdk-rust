//! Overload answers to a proof read (HTTP 503 or 429, JSON-RPC -32006, `data.retryable`) are
//! inconclusive: one pause of max(interval, Retry-After), then plain reads; a pause that does not
//! fit the budget fails at once with the overload as cause. Request counts and the gaps between
//! requests are the checks (gaps with generous upper margins).
#![cfg(feature = "http")]

mod common;

use std::error::Error;
use std::time::Duration;

use common::*;
use unicity_token::client::{AggregatorClient, HttpAggregatorClient, HttpError, WaitOptions};

fn client(url: &str, interval_ms: u64) -> HttpAggregatorClient {
    HttpAggregatorClient::new_insecure_http(url)
        .with_polling(Duration::from_millis(interval_ms), 3)
        .with_unknown_grace(2)
}

fn pending() -> String {
    format!(
        r#"{{"proof":"{}","status":"pending","waitedMs":0}}"#,
        empty_proof_response_hex(&fixture_proof_and_data().0)
    )
}
fn proof() -> String {
    format!(
        r#"{{"proof":"{}","status":"included"}}"#,
        proof_response_hex(&fixture_proof_and_data().0)
    )
}
fn http_status(status: &str, headers: &[&str]) -> Reply {
    Reply::raw(http_response_with(status, headers, "overloaded"))
}
fn wait_param(server: &Scripted, i: usize) -> Option<u64> {
    server
        .request(i)
        .params
        .get("waitMs")
        .and_then(|v| v.as_u64())
}
fn gap(server: &Scripted, i: usize) -> Duration {
    server.request(i + 1).at - server.request(i).at
}

/// Script: overload answer, pending, pending, proof.
fn after_overload(first: Reply) -> Scripted {
    let first = std::sync::Mutex::new(Some(first));
    Scripted::start(move |i, _| match i {
        0 => first.lock().unwrap().take().unwrap(),
        1 | 2 => Reply::result(pending()),
        _ => Reply::result(proof()),
    })
}

fn assert_overload_then_plain_reads(
    server: &Scripted,
    c: &HttpAggregatorClient,
    pause_at_least: Duration,
) {
    let out = c.wait_for_inclusion_proof_with_stats(
        &state_id(7),
        &WaitOptions::new(Duration::from_secs(10)),
    );
    assert!(out.result.is_ok(), "{:?}", out.result);
    assert_eq!(out.stats.requests, 4);
    assert_eq!(out.stats.overloaded, 1);
    assert!(wait_param(server, 0).is_some(), "the first read long polls");
    for i in 1..4 {
        assert_eq!(wait_param(server, i), None, "read {i} is plain");
    }
    assert!(gap(server, 0) >= pause_at_least, "{:?}", gap(server, 0));
    // (the pause plan itself is unit tested in `client::http`; no wall-clock upper bounds here)
}

#[test]
fn http_503_then_pending_then_proof() {
    let server = after_overload(http_status("503 Service Unavailable", &[]));
    assert_overload_then_plain_reads(
        &server,
        &client(&server.url, 100),
        Duration::from_millis(95),
    );
}

#[test]
fn rpc_32006_busy_then_pending_then_proof() {
    let server = after_overload(Reply::error(r#"{"code":-32006,"message":"busy"}"#));
    assert_overload_then_plain_reads(
        &server,
        &client(&server.url, 100),
        Duration::from_millis(95),
    );
}

#[test]
fn data_retryable_true_on_any_code_is_an_overload_answer() {
    let server = after_overload(Reply::error(
        r#"{"code":-32099,"message":"later","data":{"retryable":true}}"#,
    ));
    assert_overload_then_plain_reads(
        &server,
        &client(&server.url, 100),
        Duration::from_millis(95),
    );
}

#[test]
fn http_429_with_retry_after_pauses_the_larger_of_interval_and_retry_after() {
    let server = after_overload(http_status("429 Too Many Requests", &["Retry-After: 1"]));
    assert_overload_then_plain_reads(
        &server,
        &client(&server.url, 20),
        Duration::from_millis(950),
    );
}

#[test]
fn a_retry_after_below_the_interval_does_not_shorten_the_pause() {
    // 0 s asked, 200 ms interval
    let server = after_overload(http_status("503 Service Unavailable", &["Retry-After: 0"]));
    assert_overload_then_plain_reads(
        &server,
        &client(&server.url, 200),
        Duration::from_millis(195),
    );
}

#[test]
fn an_unparseable_retry_after_is_ignored() {
    let server = after_overload(http_status(
        "503 Service Unavailable",
        &["Retry-After: Wed, 21 Oct 2026 07:28:00 GMT"],
    ));
    assert_overload_then_plain_reads(
        &server,
        &client(&server.url, 100),
        Duration::from_millis(95),
    );
}

#[test]
fn a_retry_after_beyond_the_remaining_budget_fails_at_once_with_the_overload_as_cause() {
    let server =
        Scripted::start(|_, _| http_status("503 Service Unavailable", &["Retry-After: 30"]));
    let out = client(&server.url, 20).wait_for_inclusion_proof_with_stats(
        &state_id(7),
        &WaitOptions::new(Duration::from_secs(10)),
    );
    assert_eq!(server.count(), 1);
    let Err(error) = out.result else {
        panic!("expected an error")
    };
    let HttpError::OverloadTimeout { retry_after, cause } = &error else {
        panic!("{error:?}")
    };
    assert_eq!(*retry_after, Some(Duration::from_secs(30)));
    assert!(
        matches!(**cause, HttpError::Http { status: 503, .. }),
        "{cause:?}"
    );
    assert!(error.source().is_some());
    let message = error.to_string();
    assert!(
        message.contains("overloaded") && message.contains("30000 ms"),
        "{message}"
    );
}

#[test]
fn a_retry_after_over_sixty_seconds_is_capped_at_sixty() {
    let server =
        Scripted::start(|_, _| http_status("429 Too Many Requests", &["Retry-After: 600"]));
    let out = client(&server.url, 20).wait_for_inclusion_proof_with_stats(
        &state_id(7),
        &WaitOptions::new(Duration::from_secs(10)),
    );
    let Err(HttpError::OverloadTimeout { retry_after, .. }) = out.result else {
        panic!("{:?}", out.result)
    };
    assert_eq!(retry_after, Some(Duration::from_secs(60)));
}

#[test]
fn a_non_retryable_error_still_ends_the_wait_at_once() {
    for reply in [
        http_status("500 Internal Server Error", &[]),
        Reply::error(r#"{"code":-32000,"message":"bad"}"#),
        Reply::error(r#"{"code":-32099,"message":"no","data":{"retryable":false}}"#),
    ] {
        let reply = std::sync::Mutex::new(Some(reply));
        let server = Scripted::start(move |_, _| reply.lock().unwrap().take().unwrap());
        let out = client(&server.url, 20).wait_for_inclusion_proof_with_stats(
            &state_id(7),
            &WaitOptions::new(Duration::from_secs(10)),
        );
        assert!(
            matches!(
                out.result,
                Err(HttpError::Http { .. }) | Err(HttpError::Rpc { .. })
            ),
            "{:?}",
            out.result
        );
        assert_eq!(server.count(), 1);
        assert_eq!(out.stats.overloaded, 0);
    }
}

#[test]
fn the_attempts_loop_follows_the_same_rule() {
    let server = after_overload(http_status("503 Service Unavailable", &[]));
    let c = client(&server.url, 100)
        .with_polling(Duration::from_millis(100), 6)
        .with_long_poll(false);
    assert!(c.get_inclusion_proof(&state_id(7)).is_ok());
    assert_eq!(server.count(), 4);
    assert!(gap(&server, 0) >= Duration::from_millis(95));

    // a pause beyond the budget (interval * attempts) fails at once
    let server =
        Scripted::start(|_, _| http_status("503 Service Unavailable", &["Retry-After: 30"]));
    let c = client(&server.url, 100).with_long_poll(false);
    assert!(matches!(
        c.get_inclusion_proof(&state_id(7)),
        Err(HttpError::OverloadTimeout { .. })
    ));
    assert_eq!(server.count(), 1);
}

#[test]
fn a_retry_after_on_an_http_200_rpc_error_is_honored() {
    let (f, p) = (proof(), pending());
    let server = Scripted::start(move |i, _| match i {
        0 => Reply::error_with_headers(r#"{"code":-32006,"message":"busy"}"#, &["Retry-After: 1"]),
        1 => Reply::result(p.clone()),
        _ => Reply::result(f.clone()),
    });
    let c = client(&server.url, 20);
    let out = c.wait_for_inclusion_proof_with_stats(
        &state_id(7),
        &WaitOptions::new(Duration::from_secs(10)),
    );
    assert!(out.result.is_ok(), "{:?}", out.result);
    assert_eq!(out.stats.requests, 3);
    assert_eq!(out.stats.overloaded, 1);
    assert!(
        gap(&server, 0) >= Duration::from_millis(950),
        "{:?}",
        gap(&server, 0)
    );
    assert_eq!(wait_param(&server, 1), None);
}

#[test]
fn a_huge_all_digit_retry_after_saturates_and_fails_at_once() {
    let server = Scripted::start(|_, _| {
        http_status(
            "503 Service Unavailable",
            &["Retry-After: 99999999999999999999999999"],
        )
    });
    let out = client(&server.url, 20).wait_for_inclusion_proof_with_stats(
        &state_id(7),
        &WaitOptions::new(Duration::from_secs(10)),
    );
    let Err(HttpError::OverloadTimeout { retry_after, .. }) = out.result else {
        panic!("{:?}", out.result)
    };
    assert_eq!(retry_after, Some(Duration::from_secs(60)));
    assert_eq!(server.count(), 1, "one request, no tight loop");
}

#[test]
fn a_retryable_unknown_or_pending_is_an_overload_never_a_failure_or_a_resubmit() {
    for code in [-32020, -32021] {
        let (f, p) = (proof(), pending());
        let body = format!(r#"{{"code":{code},"message":"later","data":{{"retryable":true}}}}"#);
        let server = Scripted::start(move |i, seen| {
            if seen.method == "certification_request" {
                return Reply::result(r#"{"status":"SUCCESS"}"#);
            }
            match i {
                1 => Reply::error(body.clone()),
                2 => Reply::result(p.clone()),
                _ => Reply::result(f.clone()),
            }
        });
        let (_, data) = fixture_proof_and_data();
        let c = client(&server.url, 20).with_unknown_grace(0);
        let got = c.submit_and_wait(&data, 3).expect("the wait goes on");
        assert_eq!(got.certification_data, data);
        let methods: Vec<String> = (0..server.count())
            .map(|i| server.request(i).method)
            .collect();
        assert_eq!(
            methods
                .iter()
                .filter(|m| *m == "certification_request")
                .count(),
            1,
            "{code}: never resubmitted, {methods:?}"
        );
        // and directly: the wait counts it as an overload and then reads plainly
        let (f, body) = (
            proof(),
            format!(r#"{{"code":{code},"message":"x","data":{{"retryable":true}}}}"#),
        );
        let server = Scripted::start(move |i, _| {
            if i == 0 {
                Reply::error(body.clone())
            } else {
                Reply::result(f.clone())
            }
        });
        let out = client(&server.url, 20)
            .with_unknown_grace(0)
            .wait_for_inclusion_proof_with_stats(
                &state_id(7),
                &WaitOptions::new(Duration::from_secs(10)),
            );
        assert!(out.result.is_ok(), "{code}: {:?}", out.result);
        assert_eq!((out.stats.overloaded, out.stats.requests), (1, 2));
        assert_eq!(wait_param(&server, 1), None);
    }
}

#[test]
fn a_plain_unknown_or_pending_error_keeps_its_meaning() {
    let server =
        Scripted::start(|_, _| Reply::error(r#"{"code":-32020,"message":"no such state"}"#));
    let out = client(&server.url, 20).wait_for_inclusion_proof_with_stats(
        &state_id(7),
        &WaitOptions::new(Duration::from_secs(10)),
    );
    assert!(
        matches!(out.result, Err(HttpError::StateNotFound)),
        "{:?}",
        out.result
    );
    assert_eq!(out.stats.overloaded, 0);
}
