//! The deadline-based wait (`wait_for_inclusion_proof`): budgets, pacing, unknown
//! grace, cancellation and blocking-timeout behaviour against a loopback mock.
//! Wall-clock assertions use generous margins and are indicative only; request
//! counts and the sent `waitMs` values are the exact checks.
#![cfg(feature = "http")]

mod common;

use std::time::{Duration, Instant};

use common::*;
use unicity_token::client::{
    AggregatorClient, CancelToken, HttpAggregatorClient, HttpError, WaitOptions,
};

fn client(url: &str, interval_ms: u64) -> HttpAggregatorClient {
    HttpAggregatorClient::new_insecure_http(url)
        .with_polling(Duration::from_millis(interval_ms), 3)
        .with_unknown_grace(2)
}

fn obj(proof: &str, status: Option<&str>, echo: Option<u64>) -> String {
    let mut s = format!(r#"{{"proof":"{proof}""#);
    if let Some(st) = status {
        s.push_str(&format!(r#","status":"{st}""#));
    }
    if let Some(e) = echo {
        s.push_str(&format!(r#","waitedMs":{e}"#));
    }
    s.push('}');
    s
}

fn empty() -> String {
    empty_proof_response_hex(&fixture_proof_and_data().0)
}
fn full() -> String {
    proof_response_hex(&fixture_proof_and_data().0)
}
fn secs(s: u64) -> Duration {
    Duration::from_secs(s)
}
fn wait_param(server: &Scripted, i: usize) -> Option<u64> {
    server
        .request(i)
        .params
        .get("waitMs")
        .and_then(|v| v.as_u64())
}

#[test]
fn returns_the_proof_and_sends_the_budgeted_wait() {
    let (e, f) = (empty(), full());
    let server = Scripted::start(move |i, _| {
        if i == 0 {
            Reply::result(obj(&e, Some("pending"), Some(250))).after(Duration::from_millis(250))
        } else {
            Reply::result(obj(&f, Some("included"), Some(40)))
        }
    });
    let c = client(&server.url, 20);
    let out = c.wait_for_inclusion_proof_with_stats(&state_id(7), &WaitOptions::new(secs(10)));
    assert!(out.result.is_ok());
    assert_eq!(out.stats.requests, 2);
    assert_eq!(out.stats.long_poll_requests, 2);
    // min(20 s, 10 s - 2 s margin), less the few ms already spent
    assert!((7_900..=8_000).contains(&wait_param(&server, 0).unwrap()));
    assert!(wait_param(&server, 1).unwrap() <= 8_000);
    assert_eq!(server.request(0).params["includeStatus"], true);
}

#[test]
fn long_poll_off_sends_no_wait_and_polls_by_interval() {
    let (e, f) = (empty(), full());
    let server = Scripted::start(move |i, _| {
        if i < 2 {
            Reply::result(obj(&e, Some("pending"), None))
        } else {
            Reply::result(obj(&f, None, None))
        }
    });
    let c = client(&server.url, 30);
    let started = Instant::now();
    let out = c.wait_for_inclusion_proof_with_stats(
        &state_id(7),
        &WaitOptions::new(secs(10)).with_long_poll(false),
    );
    assert!(out.result.is_ok());
    assert_eq!(out.stats.long_poll_requests, 0);
    for i in 0..3 {
        assert_eq!(wait_param(&server, i), None);
    }
    assert!(
        started.elapsed() >= Duration::from_millis(55),
        "two 30 ms pauses"
    );
}

#[test]
fn get_inclusion_proof_with_long_poll_off_is_the_attempts_loop_and_never_waits() {
    let e = empty();
    let server = Scripted::start(move |_, _| Reply::result(obj(&e, Some("pending"), None)));
    let c = client(&server.url, 5).with_long_poll(false);
    assert!(matches!(
        c.get_inclusion_proof(&state_id(7)),
        Err(HttpError::Timeout)
    ));
    assert_eq!(server.count(), 3, "its 3 configured attempts");
    for i in 0..3 {
        assert_eq!(wait_param(&server, i), None);
    }
}

#[test]
fn a_missing_echo_drops_the_wait_for_the_rest_of_the_call_and_paces() {
    let e = empty();
    let server = Scripted::start(move |_, _| Reply::result(obj(&e, Some("pending"), None)));
    let c = client(&server.url, 80);
    let out = c.wait_for_inclusion_proof_with_stats(
        &state_id(7),
        &WaitOptions::new(Duration::from_millis(600)).with_margin(Duration::from_millis(100)),
    );
    assert!(matches!(out.result, Err(HttpError::Timeout)));
    assert!(out.stats.wait_dropped_for_missing_echo);
    // only the first request asked for a wait (it fits: 600 - 2000 < 0 -> none?)
    let n = server.count();
    assert!(
        (2..=9).contains(&n),
        "paced, not a tight loop: {n} requests"
    );
    for i in 1..n {
        assert_eq!(wait_param(&server, i), None);
    }
    // gaps respect the interval
    let at: Vec<_> = (0..n).map(|i| server.request(i).at).collect();
    for w in at.windows(2) {
        assert!(
            w[1] - w[0] >= Duration::from_millis(70),
            "gap {:?}",
            w[1] - w[0]
        );
    }
}

#[test]
fn a_zero_echo_keeps_asking_but_never_loops_tightly() {
    let e = empty();
    let server = Scripted::start(move |_, _| Reply::result(obj(&e, Some("pending"), Some(0))));
    let c = client(&server.url, 100);
    let out = c.wait_for_inclusion_proof_with_stats(&state_id(7), &WaitOptions::new(secs(3)));
    assert!(matches!(out.result, Err(HttpError::Timeout)));
    assert!(!out.stats.wait_dropped_for_missing_echo);
    assert_eq!(out.stats.immediate_rechecks, 0);
    let n = server.count();
    assert!(n <= 32, "3 s / 100 ms pause bounds the requests: {n}");
    assert!((900..=1_000).contains(&wait_param(&server, 0).unwrap())); // 3 s - 2 s margin
    assert!(
        wait_param(&server, 1).is_some(),
        "keeps asking while a wait fits"
    );
    let at: Vec<_> = (0..n).map(|i| server.request(i).at).collect();
    for w in at.windows(2) {
        assert!(
            w[1] - w[0] >= Duration::from_millis(90),
            "{:?}",
            w[1] - w[0]
        );
    }
}

#[test]
fn a_positive_echo_after_a_slow_call_rechecks_immediately() {
    let (e, f) = (empty(), full());
    // The first call takes longer than the 100 ms interval and echoes it; the
    // second must follow at once, without a pause.
    let server = Scripted::start(move |i, _| match i {
        0 => Reply::result(obj(&e, Some("pending"), Some(150))).after(Duration::from_millis(150)),
        _ => Reply::result(obj(&f, None, Some(0))),
    });
    let c = client(&server.url, 100);
    let out = c.wait_for_inclusion_proof_with_stats(&state_id(7), &WaitOptions::new(secs(10)));
    assert!(out.result.is_ok());
    assert_eq!(out.stats.immediate_rechecks, 1);
    let gap = server.request(1).at - server.request(0).at;
    assert!(gap < Duration::from_millis(400), "{gap:?}");
}

#[test]
fn a_positive_echo_after_a_fast_call_still_sleeps_the_rest_of_the_interval() {
    let (e, f) = (empty(), full());
    let server = Scripted::start(move |i, _| match i {
        0 => Reply::result(obj(&e, Some("pending"), Some(5))),
        _ => Reply::result(obj(&f, None, Some(0))),
    });
    let c = client(&server.url, 300);
    let out = c.wait_for_inclusion_proof_with_stats(&state_id(7), &WaitOptions::new(secs(10)));
    assert!(out.result.is_ok());
    assert_eq!(out.stats.immediate_rechecks, 0);
    let gap = server.request(1).at - server.request(0).at;
    assert!(gap >= Duration::from_millis(200), "{gap:?}");
}

#[test]
fn unknown_grace_counts_consecutive_answers_and_resets_on_pending() {
    let e = empty();
    let answers = [
        "unknown", "unknown", "pending", "unknown", "unknown", "unknown",
    ];
    let server = Scripted::start(move |i, _| {
        Reply::result(obj(&e, Some(answers[i.min(answers.len() - 1)]), Some(0)))
    });
    let c = client(&server.url, 5);
    let out = c.wait_for_inclusion_proof_with_stats(&state_id(7), &WaitOptions::new(secs(10)));
    assert!(matches!(out.result, Err(HttpError::StateUnknown)));
    assert_eq!(
        server.count(),
        6,
        "grace 2 survives two, resets, then fails on the third in a row"
    );
    assert_eq!(out.stats.unknown, 5);
}

#[test]
fn expired_is_terminal_and_a_proof_wins_over_a_status() {
    let (e, f) = (empty(), full());
    let server = Scripted::start({
        let e = e.clone();
        move |_, _| Reply::result(obj(&e, Some("expired"), Some(0)))
    });
    let c = client(&server.url, 5);
    assert!(matches!(
        c.wait_for_inclusion_proof(&state_id(7), &WaitOptions::new(secs(5))),
        Err(HttpError::StateExpired)
    ));
    assert_eq!(server.count(), 1);
    // an `expired` hint next to an actual proof is not trusted over the proof
    let server = Scripted::start(move |_, _| Reply::result(obj(&f, Some("expired"), Some(0))));
    assert!(client(&server.url, 5)
        .wait_for_inclusion_proof(&state_id(7), &WaitOptions::new(secs(5)))
        .is_ok());
}

#[test]
fn legacy_rug_errors_keep_their_meaning() {
    let f = full();
    // -32021 pending keeps polling, then the proof
    let server = Scripted::start(move |i, _| {
        if i < 2 {
            Reply::error(r#"{"code":-32021,"message":"pending"}"#)
        } else {
            Reply::result(format!("\"{f}\""))
        }
    });
    let out = client(&server.url, 5)
        .wait_for_inclusion_proof_with_stats(&state_id(7), &WaitOptions::new(secs(5)));
    assert!(out.result.is_ok());
    assert_eq!(server.count(), 3);
    assert_eq!(out.stats.pending, 2);
    // -32020 and HTTP 404 are "not found"
    let server = Scripted::start(|_, _| Reply::error(r#"{"code":-32020,"message":"nf"}"#));
    assert!(matches!(
        client(&server.url, 5).wait_for_inclusion_proof(&state_id(7), &WaitOptions::new(secs(5))),
        Err(HttpError::StateNotFound)
    ));
    let server = Scripted::start(|_, _| Reply::raw(http_response("404 Not Found", "{}")));
    assert!(matches!(
        client(&server.url, 5).wait_for_inclusion_proof(&state_id(7), &WaitOptions::new(secs(5))),
        Err(HttpError::StateNotFound)
    ));
}

#[test]
fn a_legacy_bare_string_pending_server_is_polled_without_a_wait_after_the_first_call() {
    let e = empty();
    let server = Scripted::start(move |_, _| Reply::result(format!("\"{e}\"")));
    let c = client(&server.url, 20);
    let out = c.wait_for_inclusion_proof_with_stats(&state_id(7), &WaitOptions::new(secs(3)));
    assert!(matches!(out.result, Err(HttpError::Timeout)));
    assert!(out.stats.wait_dropped_for_missing_echo);
    assert!((900..=1_000).contains(&wait_param(&server, 0).unwrap()));
    for i in 1..server.count() {
        assert_eq!(wait_param(&server, i), None);
    }
}

#[test]
fn a_malformed_echo_is_rejected_and_never_extends_anything() {
    let e = empty();
    let server = Scripted::start(move |_, _| {
        Reply::result(format!(
            r#"{{"proof":"{e}","status":"pending","waitedMs":-5}}"#
        ))
    });
    assert!(matches!(
        client(&server.url, 5).wait_for_inclusion_proof(&state_id(7), &WaitOptions::new(secs(5))),
        Err(HttpError::Decode(_))
    ));
}

#[test]
fn the_total_deadline_is_not_renewed_by_repeated_calls() {
    let e = empty();
    let server = Scripted::start(move |_, _| Reply::result(obj(&e, Some("pending"), Some(0))));
    let c = client(&server.url, 50);
    let started = Instant::now();
    let r = c.wait_for_inclusion_proof(&state_id(7), &WaitOptions::new(Duration::from_millis(700)));
    let took = started.elapsed();
    assert!(matches!(r, Err(HttpError::Timeout)));
    assert!(
        took >= Duration::from_millis(650) && took < Duration::from_millis(1_500),
        "{took:?}"
    );
}

#[test]
fn a_hung_server_ends_at_the_deadline_not_at_the_transport_default() {
    let server = Scripted::start(|_, _| Reply::silent());
    let c = client(&server.url, 50);
    let started = Instant::now();
    let r = c.wait_for_inclusion_proof(&state_id(7), &WaitOptions::new(Duration::from_millis(600)));
    let took = started.elapsed();
    assert!(matches!(r, Err(HttpError::Timeout)), "{r:?}");
    assert!(
        took < Duration::from_millis(2_000),
        "blocked past the deadline: {took:?}"
    );
    assert_eq!(server.count(), 1);
}

#[test]
fn a_hung_server_beyond_wait_plus_margin_is_cut_by_the_call_timeout() {
    // 3 s total, 1 s margin: the call timeout is wait + margin = 3 s... use a
    // short max so the call timeout is below the deadline.
    let server = Scripted::start(|_, _| Reply::silent());
    let c = client(&server.url, 50);
    let started = Instant::now();
    let r = c.wait_for_inclusion_proof(
        &state_id(7),
        &WaitOptions::new(secs(30))
            .with_margin(Duration::from_millis(100))
            .with_max_request_timeout(Duration::from_millis(500))
            .with_preferred_wait(Duration::from_millis(300)),
    );
    let took = started.elapsed();
    // wait 300 ms + margin 100 ms = 400 ms call timeout, far below the 30 s deadline
    assert!(matches!(r, Err(HttpError::Transport(_))), "{r:?}");
    assert!(took < Duration::from_millis(1_500), "{took:?}");
    assert_eq!(wait_param(&server, 0), Some(300));
}

#[test]
fn cancellation_is_observed_between_calls_and_during_sleeps() {
    let e = empty();
    let server = Scripted::start(move |_, _| Reply::result(obj(&e, Some("pending"), None)));
    let c = client(&server.url, 5_000); // a 5 s pause the cancel must cut short
    let cancel = CancelToken::new();
    let remote = cancel.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        remote.cancel();
    });
    let started = Instant::now();
    let r = c.wait_for_inclusion_proof(
        &state_id(7),
        &WaitOptions::new(secs(60)).with_cancel(cancel.clone()),
    );
    assert!(matches!(r, Err(HttpError::Cancelled)), "{r:?}");
    assert!(started.elapsed() < Duration::from_millis(1_500));
    // already cancelled: no request at all
    let before = server.count();
    let r = c.wait_for_inclusion_proof(
        &state_id(7),
        &WaitOptions::new(secs(60)).with_cancel(cancel),
    );
    assert!(matches!(r, Err(HttpError::Cancelled)));
    assert_eq!(server.count(), before);
}

#[test]
fn a_refused_connection_is_a_transport_error_not_a_timeout() {
    // grab a free port, then close it so connecting is refused
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let url = format!("http://127.0.0.1:{port}/");
    for total in [Duration::from_millis(500), secs(5), secs(60)] {
        let r = client(&url, 5).wait_for_inclusion_proof(&state_id(7), &WaitOptions::new(total));
        assert!(
            matches!(r, Err(HttpError::Transport(_))),
            "{total:?}: {r:?}"
        );
    }
}

#[test]
fn a_legacy_pending_error_switches_the_wait_off_for_the_rest_of_the_call_only() {
    // S1-style: pending is the -32021 error, the proof (a bare string) comes last.
    let f = full();
    let server = Scripted::start(move |i, _| {
        if i < 3 {
            Reply::error(r#"{"code":-32021,"message":"certification is pending"}"#)
        } else {
            Reply::result(format!("\"{f}\""))
        }
    });
    let c = client(&server.url, 20);
    let out = c.wait_for_inclusion_proof_with_stats(&state_id(7), &WaitOptions::new(secs(10)));
    assert!(out.result.is_ok());
    assert_eq!(out.stats.requests, 4);
    assert_eq!(
        out.stats.long_poll_requests, 1,
        "only the first call asked for a wait"
    );
    assert!(out.stats.wait_dropped_for_missing_echo);
    assert!(wait_param(&server, 0).is_some());
    for i in 1..4 {
        assert_eq!(wait_param(&server, i), None, "request {i}");
    }
    // not a permanent cache: the next wait on the same client asks again
    let before = server.count();
    let _ = c.wait_for_inclusion_proof(&state_id(7), &WaitOptions::new(secs(10)));
    assert!(wait_param(&server, before).is_some());
}

#[test]
fn a_legacy_not_found_is_terminal_and_a_wait_free_pending_stays_wait_free() {
    let server = Scripted::start(|_, _| Reply::error(r#"{"code":-32020,"message":"nf"}"#));
    let out = client(&server.url, 20)
        .wait_for_inclusion_proof_with_stats(&state_id(7), &WaitOptions::new(secs(5)));
    assert!(matches!(out.result, Err(HttpError::StateNotFound)));
    assert_eq!(out.stats.requests, 1);
    // long-poll off: a pending error changes nothing
    let server = Scripted::start(|_, _| Reply::error(r#"{"code":-32021,"message":"pending"}"#));
    let out = client(&server.url, 20).wait_for_inclusion_proof_with_stats(
        &state_id(7),
        &WaitOptions::new(Duration::from_millis(300)).with_long_poll(false),
    );
    assert!(matches!(out.result, Err(HttpError::Timeout)));
    assert!(!out.stats.wait_dropped_for_missing_echo);
}

#[test]
fn a_pending_error_that_echoes_the_wait_keeps_long_poll_on() {
    let f = full();
    let server = Scripted::start(move |i, _| {
        if i < 2 {
            Reply::error(r#"{"code":-32021,"message":"pending","data":{"waitedMs":0}}"#)
        } else {
            Reply::result(obj(&f, None, Some(0)))
        }
    });
    let out = client(&server.url, 20)
        .wait_for_inclusion_proof_with_stats(&state_id(7), &WaitOptions::new(secs(10)));
    assert!(out.result.is_ok());
    assert!(!out.stats.wait_dropped_for_missing_echo);
    for i in 0..3 {
        assert!(wait_param(&server, i).is_some(), "request {i} still asks");
    }
}

#[test]
fn a_pending_error_with_a_malformed_echo_is_a_protocol_error() {
    let server = Scripted::start(|_, _| {
        Reply::error(r#"{"code":-32021,"message":"pending","data":{"waitedMs":-3}}"#)
    });
    let r =
        client(&server.url, 20).wait_for_inclusion_proof(&state_id(7), &WaitOptions::new(secs(5)));
    assert!(matches!(r, Err(HttpError::Decode(_))), "{r:?}");
}
