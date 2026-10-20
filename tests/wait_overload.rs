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
        &["Retry-After: soon"],
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

// aggregator-go answers its server-wide concurrency limit before parsing the request: the id can not be echoed
// (rust#64). Rules (b) and (c) of the spec: a null-id -32006 / data.retryable is an overload, any other unmatched
// answer stays terminal.
const NULL_ID_BUSY: &str =
    r#"{"jsonrpc":"2.0","error":{"code":-32006,"message":"Concurrency limit exceeded"},"id":null}"#;

fn exact(body: &'static str) -> Reply {
    Reply::raw(http_response_with("200 OK", &[], body))
}

#[test]
fn a_null_id_busy_answer_is_an_overload_through_the_wait() {
    let server = after_overload(exact(NULL_ID_BUSY));
    assert_overload_then_plain_reads(&server, &client(&server.url, 50), Duration::from_millis(45));
}

#[test]
fn a_null_id_retryable_error_is_an_overload() {
    let server = after_overload(exact(
        r#"{"jsonrpc":"2.0","error":{"code":-32099,"message":"later","data":{"retryable":true}},"id":null}"#,
    ));
    assert_overload_then_plain_reads(&server, &client(&server.url, 50), Duration::from_millis(45));
}

#[test]
fn a_null_id_busy_answer_never_resubmits_through_submit_and_wait() {
    let (f, p) = (proof(), pending());
    let server = Scripted::start(move |i, seen| {
        if seen.method == "certification_request" {
            return Reply::result(r#"{"status":"SUCCESS"}"#);
        }
        match i {
            1 => exact(NULL_ID_BUSY),
            2 => Reply::result(p.clone()),
            _ => Reply::result(f.clone()),
        }
    });
    let (_, data) = fixture_proof_and_data();
    let got = client(&server.url, 20)
        .with_unknown_grace(0)
        .submit_and_wait(&data, 3)
        .expect("the wait goes on");
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
        "{methods:?}"
    );
    assert_eq!(
        methods.len(),
        4,
        "submit, busy, pending, proof: {methods:?}"
    );
}

#[test]
fn other_unmatched_answers_stay_terminal() {
    for body in [
        // null id, not an overload
        r#"{"jsonrpc":"2.0","error":{"code":-32000,"message":"bad"},"id":null}"#,
        r#"{"jsonrpc":"2.0","error":{"code":-32099,"message":"no","data":{"retryable":false}},"id":null}"#,
        // unmatched pending / not found / unknown
        r#"{"jsonrpc":"2.0","error":{"code":-32021,"message":"pending"},"id":null}"#,
        r#"{"jsonrpc":"2.0","error":{"code":-32020,"message":"none"},"id":null}"#,
        // a different non-null id, even for a busy answer
        r#"{"jsonrpc":"2.0","error":{"code":-32006,"message":"busy"},"id":"someone-else"}"#,
        r#"{"jsonrpc":"2.0","error":{"code":-32006,"message":"busy"},"id":7}"#,
        // a null id with a result
        r#"{"jsonrpc":"2.0","result":{},"id":null}"#,
    ] {
        let server = Scripted::start(move |_, _| exact(body));
        let out = client(&server.url, 20).wait_for_inclusion_proof_with_stats(
            &state_id(7),
            &WaitOptions::new(Duration::from_secs(10)),
        );
        assert!(
            matches!(out.result, Err(HttpError::Decode(_))),
            "{body}: {:?}",
            out.result
        );
        assert_eq!(server.count(), 1, "{body}");
        assert_eq!(out.stats.overloaded, 0, "{body}");
    }
}

// --- intermediary errors (502/504), spec "Intermediary errors" -----------------------------------------------

fn gateway_error(status: &str) -> Reply {
    Reply::raw(http_response_with(
        status,
        &[],
        "<html>upstream timed out</html>",
    ))
}

#[test]
fn http_502_and_504_are_inconclusive_in_a_wait_then_plain_reads() {
    for status in ["502 Bad Gateway", "504 Gateway Timeout"] {
        let server = after_overload(gateway_error(status));
        let c = client(&server.url, 50);
        let out = c.wait_for_inclusion_proof_with_stats(
            &state_id(7),
            &WaitOptions::new(Duration::from_secs(10)),
        );
        assert!(out.result.is_ok(), "{status}: {:?}", out.result);
        assert_eq!(out.stats.requests, 4, "{status}");
        assert!(wait_param(&server, 0).is_some());
        for i in 1..4 {
            assert_eq!(wait_param(&server, i), None, "{status}: read {i} is plain");
        }
        assert!(gap(&server, 0) >= Duration::from_millis(45));
    }
}

#[test]
fn a_502_with_an_oversized_or_non_json_body_is_still_classified_by_its_status() {
    for body in ["x".repeat(200_000), String::new(), "{not json".to_string()] {
        let server = Scripted::start({
            let body = body.clone();
            move |i, _| {
                if i == 0 {
                    Reply::raw(http_response_with("502 Bad Gateway", &[], &body))
                } else {
                    Reply::result(proof())
                }
            }
        });
        let out = client(&server.url, 20).wait_for_inclusion_proof_with_stats(
            &state_id(7),
            &WaitOptions::new(Duration::from_secs(10)),
        );
        assert!(out.result.is_ok(), "{} bytes: {:?}", body.len(), out.result);
        assert_eq!(server.count(), 2);
    }
}

#[test]
fn a_504_pause_beyond_the_budget_fails_within_it_with_the_gateway_error_as_cause() {
    let server = Scripted::start(|_, _| {
        Reply::raw(http_response_with(
            "504 Gateway Timeout",
            &["Retry-After: 30"],
            "slow",
        ))
    });
    let out = client(&server.url, 20).wait_for_inclusion_proof_with_stats(
        &state_id(7),
        &WaitOptions::new(Duration::from_secs(10)),
    );
    let Err(HttpError::OverloadTimeout { cause, .. }) = out.result else {
        panic!("{:?}", out.result)
    };
    assert!(matches!(*cause, HttpError::Http { status: 504, .. }));
    assert_eq!(server.count(), 1);
}

#[test]
fn a_502_during_submit_and_wait_never_resubmits() {
    let (f, p) = (proof(), pending());
    let server = Scripted::start(move |i, seen| {
        if seen.method == "certification_request" {
            return Reply::result(r#"{"status":"SUCCESS"}"#);
        }
        match i {
            1 => gateway_error("502 Bad Gateway"),
            2 => Reply::result(p.clone()),
            _ => Reply::result(f.clone()),
        }
    });
    let (_, data) = fixture_proof_and_data();
    assert!(client(&server.url, 20).submit_and_wait(&data, 3).is_ok());
    let methods: Vec<String> = (0..server.count())
        .map(|i| server.request(i).method)
        .collect();
    assert_eq!(
        methods
            .iter()
            .filter(|m| *m == "certification_request")
            .count(),
        1
    );
}

#[test]
fn one_shot_apis_still_surface_502_503_504_429() {
    for (status, code) in [
        ("502 Bad Gateway", 502),
        ("503 Service Unavailable", 503),
        ("504 Gateway Timeout", 504),
        ("429 Too Many Requests", 429),
    ] {
        let server = Scripted::start(move |_, _| gateway_error(status));
        let err = client(&server.url, 20)
            .lookup_inclusion_proof(&state_id(7))
            .unwrap_err();
        assert!(
            matches!(err, HttpError::Http { status: s, .. } if s == code),
            "{status}: {err:?}"
        );
        assert_eq!(server.count(), 1);
    }
}

#[test]
fn a_retry_after_http_date_is_honored_in_the_wait() {
    // a date two seconds ahead; whole seconds, so the pause is at least ~1 s
    let when = std::time::SystemTime::now() + Duration::from_secs(2);
    let secs = when
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let (f, p) = (proof(), pending());
    let header = format!("Retry-After: {}", http_date(secs));
    let server = Scripted::start(move |i, _| match i {
        0 => Reply::raw(http_response_with(
            "503 Service Unavailable",
            &[&header],
            "busy",
        )),
        1 => Reply::result(p.clone()),
        _ => Reply::result(f.clone()),
    });
    let out = client(&server.url, 20).wait_for_inclusion_proof_with_stats(
        &state_id(7),
        &WaitOptions::new(Duration::from_secs(10)),
    );
    assert!(out.result.is_ok());
    assert!(
        gap(&server, 0) >= Duration::from_millis(900),
        "{:?}",
        gap(&server, 0)
    );
}

/// IMF-fixdate of a Unix time (test helper).
fn http_date(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (z, era);
    z = days + 719_468;
    era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    let wd = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"][(days.rem_euclid(7)) as usize];
    let mon = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ][(m - 1) as usize];
    format!(
        "{wd}, {d:02} {mon} {y} {:02}:{:02}:{:02} GMT",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

// --- error-body read failures and cancellation (rev-agg) ------------------------------------------------

#[test]
fn a_timeout_while_the_error_body_is_read_is_a_timeout_not_a_status() {
    // 504 head with a declared 100-byte body of which 4 arrive, then silence
    let server = Scripted::start(|_, _| {
        Reply::partial(
            b"HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 100\r\nConnection: close\r\n\r\nslow"
                .to_vec(),
        )
    });
    let out = client(&server.url, 20).wait_for_inclusion_proof_with_stats(
        &state_id(7),
        &WaitOptions::new(Duration::from_millis(1_500)),
    );
    assert!(
        matches!(out.result, Err(HttpError::Timeout)),
        "{:?}",
        out.result
    );
    assert_eq!(server.count(), 1, "not an overload pause and retry");
    assert_eq!(out.stats.overloaded, 0);
    // a one-shot call reports the transport timeout, not an HTTP status
    let err = client(&server.url, 20)
        .lookup_inclusion_proof_with_wait(
            &state_id(7),
            &unicity_token::client::WaitRequest::new(0),
            Duration::from_millis(500),
        )
        .unwrap_err();
    assert!(matches!(err, HttpError::Transport(_)), "{err:?}");
}

#[test]
fn a_cancel_landing_during_a_gateway_error_is_cancelled_not_an_overload_timeout() {
    let server = Scripted::start(|_, _| {
        Reply::raw(http_response_with(
            "504 Gateway Timeout",
            &["Retry-After: 30"],
            "slow",
        ))
        .after(Duration::from_millis(400))
    });
    let cancel = unicity_token::client::CancelToken::new();
    let remote = cancel.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        remote.cancel();
    });
    let out = client(&server.url, 20).wait_for_inclusion_proof_with_stats(
        &state_id(7),
        &WaitOptions::new(Duration::from_secs(10)).with_cancel(cancel),
    );
    assert!(
        matches!(out.result, Err(HttpError::Cancelled)),
        "{:?}",
        out.result
    );
    assert_eq!(server.count(), 1);
}

#[test]
fn an_answer_without_an_id_is_a_protocol_error_even_for_a_retryable_busy() {
    // a *missing* id is not the null id of the pre-parse limit
    let body =
        r#"{"jsonrpc":"2.0","error":{"code":-32006,"message":"busy","data":{"retryable":true}}}"#;
    let server = Scripted::start(move |_, _| exact(body));
    let out = client(&server.url, 20).wait_for_inclusion_proof_with_stats(
        &state_id(7),
        &WaitOptions::new(Duration::from_secs(10)),
    );
    assert!(
        matches!(out.result, Err(HttpError::Decode(_))),
        "{:?}",
        out.result
    );
    assert_eq!(server.count(), 1);
    assert_eq!(out.stats.overloaded, 0);
}
