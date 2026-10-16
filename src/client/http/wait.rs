//! Deadline-based inclusion-proof waiting with optional long-poll (`waitMs`).
//!
//! The legacy [`AggregatorClient::get_inclusion_proof`] keeps its attempts-based
//! polling untouched. [`HttpAggregatorClient::wait_for_inclusion_proof`] is the
//! separately selected policy: one total deadline, a per-call wait clamped to the
//! remaining time, a per-call transport timeout of `wait + margin` inside that
//! deadline, and pacing that never turns a missing or zero echo into a tight loop.
//!
//! It returns the **unverified** proof exactly like the legacy poller; statuses
//! and `waitedMs` are unauthenticated hints used for control flow only.

use std::time::{Duration, Instant};

use super::*;
use crate::client::CancelToken;

/// Default preferred server-side wait per request.
pub const DEFAULT_PREFERRED_WAIT: Duration = Duration::from_secs(20);
/// Default maximum duration of one transport call (the client's own timeout).
pub const DEFAULT_MAX_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Lower bound of the pause after a response that did not prove the server waited.
const MIN_PAUSE: Duration = Duration::from_millis(10);
/// Granularity at which sleeps notice cancellation.
const SLEEP_SLICE: Duration = Duration::from_millis(50);

/// Options of [`HttpAggregatorClient::wait_for_inclusion_proof`].
#[derive(Debug, Clone)]
pub struct WaitOptions {
    total: Duration,
    long_poll: bool,
    preferred_wait: Duration,
    margin: Duration,
    max_request_timeout: Duration,
    poll_interval: Option<Duration>,
    unknown_grace: Option<u32>,
    cancel: Option<CancelToken>,
}

impl WaitOptions {
    /// Wait for at most `total` from the start of the call. The deadline is never
    /// renewed by a fallback, a resume or a retry.
    pub fn new(total: Duration) -> Self {
        WaitOptions {
            total,
            long_poll: true,
            preferred_wait: DEFAULT_PREFERRED_WAIT,
            margin: Duration::from_millis(DEFAULT_WAIT_MARGIN_MS),
            max_request_timeout: DEFAULT_MAX_REQUEST_TIMEOUT,
            poll_interval: None,
            unknown_grace: None,
            cancel: None,
        }
    }

    /// Ask the aggregator to hold requests while the state is pending (default
    /// `true`). `false` sends no `waitMs` at all: plain interval polling.
    pub fn with_long_poll(mut self, enabled: bool) -> Self {
        self.long_poll = enabled;
        self
    }

    /// The server-side wait to prefer per request (default 20 s).
    pub fn with_preferred_wait(mut self, wait: Duration) -> Self {
        self.preferred_wait = wait;
        self
    }

    /// HTTP response margin kept between a wait and its call timeout (default 2 s;
    /// size it for the deployment's latency).
    pub fn with_margin(mut self, margin: Duration) -> Self {
        self.margin = margin;
        self
    }

    /// Longest a single transport call may last (default 30 s, the client's own
    /// timeout); the wait is clamped to `max - margin`.
    pub fn with_max_request_timeout(mut self, max: Duration) -> Self {
        self.max_request_timeout = max;
        self
    }

    /// Pause between probes (default: the client's polling interval).
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = Some(interval);
        self
    }

    /// Consecutive `unknown` answers tolerated (default: the client's grace).
    pub fn with_unknown_grace(mut self, polls: u32) -> Self {
        self.unknown_grace = Some(polls);
        self
    }

    /// Cancellation, observed before every call and during sleeps. A call already
    /// in flight ends at its own timeout: a blocking transport can not be
    /// interrupted.
    pub fn with_cancel(mut self, cancel: CancelToken) -> Self {
        self.cancel = Some(cancel);
        self
    }
}

/// What one call of the wait loop will ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct CallPlan {
    /// `waitMs` to send; `None` sends none.
    pub wait_ms: Option<u64>,
    /// The call's whole transport timeout.
    pub timeout_ms: u64,
}

/// Budget arithmetic of one call, for `remaining_ms` left of the total deadline:
/// `wait = floor(max(0, min(P, R - M, T - M)))`, the call timeout `wait + M`
/// (within `R`), or `min(T, R)` for a call without a wait.
pub(super) fn plan_call(remaining_ms: u64, options: &WaitOptions, send_wait: bool) -> CallPlan {
    let ms = |d: Duration| u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
    let (preferred, margin, max) = (
        ms(options.preferred_wait),
        ms(options.margin),
        ms(options.max_request_timeout),
    );
    let wait = if send_wait && options.long_poll {
        preferred
            .min(remaining_ms.saturating_sub(margin))
            .min(max.saturating_sub(margin))
            .min(MAX_WAIT_MS)
    } else {
        0
    };
    if wait > 0 {
        CallPlan {
            wait_ms: Some(wait),
            timeout_ms: (wait + margin).min(remaining_ms).max(1),
        }
    } else {
        CallPlan {
            wait_ms: None,
            timeout_ms: max.min(remaining_ms).max(1),
        }
    }
}

/// Request accounting of a wait, in counts rather than times.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WaitStats {
    /// Proof requests sent.
    pub requests: u32,
    /// Of those, requests that carried a positive `waitMs`.
    pub long_poll_requests: u32,
    /// Pending answers.
    pub pending: u32,
    /// Unknown answers.
    pub unknown: u32,
    /// Pending answers followed by an immediate re-call (a positive echo after a
    /// call that already took the polling interval).
    pub immediate_rechecks: u32,
    /// Whether a response without an echo made the rest of this wait omit `waitMs`.
    pub wait_dropped_for_missing_echo: bool,
}

/// A finished wait: the result and its accounting.
#[derive(Debug)]
pub struct WaitOutcome {
    /// The unverified proof, or why none was obtained.
    pub result: Result<InclusionProof, HttpError>,
    /// Counts of what happened.
    pub stats: WaitStats,
}

enum Pace {
    /// Sleep this long (bounded by the deadline), then probe again.
    Sleep(Duration),
}

impl HttpAggregatorClient {
    /// Wait for the certified proof of `state_id` until `options`' total deadline.
    ///
    /// Unlike the legacy [`get_inclusion_proof`](AggregatorClient::get_inclusion_proof)
    /// (an attempts count) this is bounded by time alone, so a long server wait can
    /// never multiply into minutes. Each call asks for
    /// `floor(max(0, min(preferred, remaining - margin, max_request - margin)))`
    /// milliseconds of server-side waiting, with a call timeout of `wait + margin`
    /// inside the remaining deadline; when no positive wait fits, or long-poll is
    /// off, the call is an ordinary lookup.
    ///
    /// Pacing: after a pending answer the next probe is immediate only when the
    /// server echoed a positive `waitedMs` **and** the call itself already lasted
    /// the polling interval; otherwise the remaining interval is slept (the full
    /// interval for a missing or zero echo, never less than a few milliseconds).
    /// An answer without any echo to a request that carried a wait means the
    /// endpoint does not do long-poll: the rest of this wait omits `waitMs` (nothing
    /// is remembered beyond the call). `unknown` answers keep the consecutive-count
    /// grace and the normal pause; `expired` ends the wait. Legacy servers' pending
    /// and not-found errors keep their meaning.
    ///
    /// The proof is returned **unverified**; hints and echoes never replace
    /// verification. See [`wait_for_inclusion_proof_with_stats`](Self::wait_for_inclusion_proof_with_stats)
    /// for request counts.
    pub fn wait_for_inclusion_proof(
        &self,
        state_id: &StateId,
        options: &WaitOptions,
    ) -> Result<InclusionProof, HttpError> {
        self.wait_for_inclusion_proof_with_stats(state_id, options)
            .result
    }

    /// [`wait_for_inclusion_proof`](Self::wait_for_inclusion_proof) with its request accounting.
    pub fn wait_for_inclusion_proof_with_stats(
        &self,
        state_id: &StateId,
        options: &WaitOptions,
    ) -> WaitOutcome {
        let mut stats = WaitStats::default();
        let result = self.wait_loop(state_id, options, &mut stats);
        WaitOutcome { result, stats }
    }

    fn wait_loop(
        &self,
        state_id: &StateId,
        options: &WaitOptions,
        stats: &mut WaitStats,
    ) -> Result<InclusionProof, HttpError> {
        let started = Instant::now();
        let deadline = started + options.total;
        let interval = options.poll_interval.unwrap_or(self.poll_interval);
        let grace = options.unknown_grace.unwrap_or(self.unknown_grace);
        let cancelled = || {
            options
                .cancel
                .as_ref()
                .is_some_and(CancelToken::is_cancelled)
        };
        let mut send_wait = true;
        let mut unknown_seen = 0u32;

        loop {
            if cancelled() {
                return Err(HttpError::Cancelled);
            }
            let now = Instant::now();
            let Some(left) = deadline
                .checked_duration_since(now)
                .filter(|d| !d.is_zero())
            else {
                return Err(HttpError::Timeout);
            };
            let plan = plan_call(
                u64::try_from(left.as_millis()).unwrap_or(u64::MAX).max(1),
                options,
                send_wait,
            );
            let mut params = serde_json::json!({
                "stateId": hex::encode(state_id.bytes()),
                "includeStatus": true,
            });
            if let Some(w) = plan.wait_ms {
                params["waitMs"] = serde_json::json!(w);
                stats.long_poll_requests += 1;
            }
            stats.requests += 1;
            let call_started = Instant::now();
            let raw = self.rpc_raw(
                "get_inclusion_proof.v2",
                params,
                &[],
                Some(Duration::from_millis(plan.timeout_ms)),
            );
            let call_took = call_started.elapsed();
            let result = match raw.map_err(raw_to_http) {
                Ok(result) => result,
                Err(HttpError::Rpc { code, .. }) if code == RPC_INCLUSION_PENDING => {
                    stats.pending += 1;
                    self.pause(Pace::Sleep(interval.max(MIN_PAUSE)), deadline, options)?;
                    continue;
                }
                Err(HttpError::Rpc { code, .. }) if code == RPC_STATE_NOT_FOUND => {
                    return Err(HttpError::StateNotFound)
                }
                Err(HttpError::Http { status: 404, .. }) => return Err(HttpError::StateNotFound),
                // A call cut off by the end of the deadline is the deadline.
                Err(HttpError::Transport(_)) if Instant::now() >= deadline => {
                    return Err(HttpError::Timeout)
                }
                Err(error) => return Err(error),
            };
            let V2Result {
                response,
                status,
                waited_ms,
            } = decode_v2_result(&result)?;
            if plan.wait_ms.is_some() && waited_ms.is_none() {
                send_wait = false;
                stats.wait_dropped_for_missing_echo = true;
            }
            match response {
                InclusionProofResponse::Certified { proof, .. } => return Ok(proof),
                InclusionProofResponse::NotCertified { .. } => match status {
                    Some(ProofStatus::Expired) => return Err(HttpError::StateExpired),
                    Some(ProofStatus::Unknown) => {
                        stats.unknown += 1;
                        unknown_seen += 1;
                        if unknown_seen > grace {
                            return Err(HttpError::StateUnknown);
                        }
                        self.pause(Pace::Sleep(interval.max(MIN_PAUSE)), deadline, options)?;
                        continue;
                    }
                    // pending, `included` without a proof, no status, unknown status
                    _ => {
                        stats.pending += 1;
                        unknown_seen = 0;
                    }
                },
            }
            // Pending: immediate re-call only if the server really waited and the
            // call already consumed the polling interval.
            let proven_wait = plan.wait_ms.is_some() && waited_ms.is_some_and(|w| w > 0);
            if proven_wait && call_took >= interval {
                stats.immediate_rechecks += 1;
                continue;
            }
            let pause = if proven_wait {
                interval.saturating_sub(call_took).max(MIN_PAUSE)
            } else {
                interval.max(MIN_PAUSE)
            };
            self.pause(Pace::Sleep(pause), deadline, options)?;
        }
    }

    /// Sleep (cancel-aware, never past the deadline).
    fn pause(&self, pace: Pace, deadline: Instant, options: &WaitOptions) -> Result<(), HttpError> {
        let Pace::Sleep(total) = pace;
        let end = (Instant::now() + total).min(deadline);
        loop {
            if options
                .cancel
                .as_ref()
                .is_some_and(CancelToken::is_cancelled)
            {
                return Err(HttpError::Cancelled);
            }
            let now = Instant::now();
            if now >= end {
                return Ok(());
            }
            std::thread::sleep((end - now).min(SLEEP_SLICE));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(preferred: u64, margin: u64, max: u64) -> WaitOptions {
        WaitOptions::new(Duration::from_secs(3600))
            .with_preferred_wait(Duration::from_millis(preferred))
            .with_margin(Duration::from_millis(margin))
            .with_max_request_timeout(Duration::from_millis(max))
    }

    #[test]
    fn wait_is_the_floor_of_the_smallest_budget_term() {
        let o = opts(20_000, 2_000, 30_000);
        // plenty of time: the preferred window
        assert_eq!(
            plan_call(600_000, &o, true),
            CallPlan {
                wait_ms: Some(20_000),
                timeout_ms: 22_000
            }
        );
        // remaining - margin is smallest
        assert_eq!(
            plan_call(9_000, &o, true),
            CallPlan {
                wait_ms: Some(7_000),
                timeout_ms: 9_000
            }
        );
        // transport max - margin is smallest
        let o = opts(60_000, 2_000, 30_000);
        assert_eq!(
            plan_call(600_000, &o, true),
            CallPlan {
                wait_ms: Some(28_000),
                timeout_ms: 30_000
            }
        );
        // never past the deadline
        for r in [
            1u64, 500, 1_999, 2_000, 2_001, 2_500, 21_999, 22_000, 50_000,
        ] {
            let p = plan_call(r, &opts(20_000, 2_000, 30_000), true);
            assert!(p.timeout_ms <= r.max(1), "{r}: {p:?}");
            if let Some(w) = p.wait_ms {
                assert!(w >= 1 && w + 2_000 <= r, "{r}: {p:?}");
            }
        }
    }

    #[test]
    fn no_positive_wait_means_an_ordinary_lookup() {
        let o = opts(20_000, 2_000, 30_000);
        for r in [1u64, 1_000, 2_000] {
            let p = plan_call(r, &o, true);
            assert_eq!(p.wait_ms, None, "{r}");
            assert_eq!(p.timeout_ms, r, "{r}");
        }
        // long-poll off, or dropped after a missing echo
        assert_eq!(plan_call(600_000, &o, false).wait_ms, None);
        let off = opts(20_000, 2_000, 30_000).with_long_poll(false);
        assert_eq!(plan_call(600_000, &off, true).wait_ms, None);
        // a lookup without a wait is still bounded by the transport maximum
        assert_eq!(plan_call(600_000, &off, true).timeout_ms, 30_000);
        // zero preferred wait or margin >= max transport
        assert_eq!(
            plan_call(600_000, &opts(0, 2_000, 30_000), true).wait_ms,
            None
        );
        assert_eq!(
            plan_call(600_000, &opts(20_000, 40_000, 30_000), true).wait_ms,
            None
        );
    }

    #[test]
    fn many_attempts_of_a_long_wait_cannot_exceed_the_total() {
        // The legacy shape would be 60 x 20 s; here every plan is inside what is left.
        let o = opts(20_000, 2_000, 30_000);
        let mut left = 70_000u64;
        let mut spent = 0u64;
        while left > 0 {
            let p = plan_call(left, &o, true);
            spent += p.timeout_ms;
            left = left.saturating_sub(p.timeout_ms);
        }
        assert_eq!(spent, 70_000);
    }
}
