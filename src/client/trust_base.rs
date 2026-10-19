//! Keeping a trust base history current: fetch the entries a token's certificates need but
//! the history does not hold yet, append them (verified from the latest held entry), retry.
//!
//! * [`TrustBaseSource`] is the capability to ask for a page of entries (the aggregator over
//!   HTTP, a test double, a mirror). It is trusted for nothing: every entry is authenticated
//!   by [`TrustBaseHistory::append`] from the history's own latest entry.
//! * [`update_trust_base`] is the one-shot, clock-free step (`alloc` only).
//! * [`verify_token_updating`] is the loop for host applications (`std`): verify, on
//!   [`VerificationError::UnknownTrustEpoch`] update and verify again, within a small bounded
//!   budget. It is placed beside the HTTP transport as the proof wait loop is; the pure
//!   verification never sleeps and never does I/O.
//!
//! The history is updated in place and append-only: held entries are never replaced.

use core::fmt;

use crate::api::bft::{
    Appended, HistoryError, TrustBaseHistory, TrustBasePage, TrustBaseRequest, TrustBaseStatus,
    MAX_PAGE_ENTRIES,
};

/// A source of trust base entries.
pub trait TrustBaseSource {
    /// Transport-specific error (including a malformed response).
    type Error;

    /// Fetch one page of entries starting at `request.from`.
    fn get_trust_bases(&self, request: &TrustBaseRequest) -> Result<TrustBasePage, Self::Error>;
}

/// Bounds of one [`update_trust_base`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpdateLimits {
    /// Entries asked for per page (`1..=64`; default 64).
    pub page_entries: u32,
    /// Entries appended at most per call (default 1024).
    pub total_entries: usize,
}

impl Default for UpdateLimits {
    fn default() -> Self {
        UpdateLimits {
            page_entries: MAX_PAGE_ENTRIES as u32,
            total_entries: 1024,
        }
    }
}

/// What [`update_trust_base`] achieved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateOutcome {
    /// The history already holds the wanted epoch.
    UpToDate,
    /// Entries were appended and the wanted epoch is now held (or the per-call cap was
    /// reached; check the history).
    Extended {
        /// Entries appended by this call.
        added: usize,
    },
    /// The source does not (yet) have the wanted epoch: not an error.
    NotYetAvailable {
        /// The latest epoch the history holds.
        held: u64,
        /// Entries appended before the source ran out.
        added: usize,
    },
}

/// Why an update failed. None of these is retried silently.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UpdateError<E> {
    /// The source failed (transport, malformed response).
    Source(E),
    /// The source answered with a status that is neither OK nor "not yet available".
    Status(TrustBaseStatus),
    /// The source answered something that contradicts the request.
    Protocol(&'static str),
    /// An entry the source served does not extend the history: broken link, bad signatures, a
    /// conflicting entry. This is an alarm, not a reason to retry.
    Entry(HistoryError),
}

impl<E: fmt::Display> fmt::Display for UpdateError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpdateError::Source(e) => write!(f, "trust base source: {e}"),
            UpdateError::Status(s) => write!(f, "trust base source answered {s}"),
            UpdateError::Protocol(m) => write!(f, "trust base source: {m}"),
            UpdateError::Entry(e) => write!(f, "trust base entry refused: {e}"),
        }
    }
}

#[cfg(feature = "std")]
impl<E: fmt::Display + fmt::Debug> std::error::Error for UpdateError<E> {}

/// Append the entries after the latest held one, from `source`, until the history holds epoch
/// `want` or the source has nothing more. Always asks from `held + 1`; follows the pagination
/// snapshot; stops after `limits.total_entries` appended entries. Every entry is verified by
/// [`TrustBaseHistory::append`]; entries appended before a failure stay (each was verified).
///
/// `want` comes from untrusted token data: it only decides when to stop, never what is
/// requested.
pub fn update_trust_base<S: TrustBaseSource>(
    history: &mut TrustBaseHistory,
    source: &S,
    want: u64,
    limits: &UpdateLimits,
) -> Result<UpdateOutcome, UpdateError<S::Error>> {
    if history.latest().epoch >= want {
        return Ok(UpdateOutcome::UpToDate);
    }
    let page_entries = limits.page_entries.clamp(1, MAX_PAGE_ENTRIES as u32);
    let mut added = 0usize;
    let mut snapshot: Option<(u64, [u8; 32])> = None;
    let mut restarted = false;
    loop {
        let from = history
            .latest()
            .epoch
            .checked_add(1)
            .ok_or(UpdateError::Protocol("epoch overflow"))?;
        let page = source
            .get_trust_bases(&TrustBaseRequest {
                from,
                to: None,
                snapshot,
                max_entries: page_entries,
            })
            .map_err(UpdateError::Source)?;
        if page.network_id != history.network_id() {
            return Err(UpdateError::Entry(HistoryError::WrongNetwork));
        }
        match page.status {
            TrustBaseStatus::Ok => {}
            TrustBaseStatus::NotYetAvailable => {
                return Ok(UpdateOutcome::NotYetAvailable {
                    held: history.latest().epoch,
                    added,
                })
            }
            TrustBaseStatus::HistoryMismatch if snapshot.is_some() && !restarted => {
                // the chain moved under a paged request: start the pagination again once
                snapshot = None;
                restarted = true;
                continue;
            }
            other => return Err(UpdateError::Status(other)),
        }
        if page.from_epoch != from {
            return Err(UpdateError::Protocol(
                "the page does not start at the requested epoch",
            ));
        }
        if page.entries.len() > page_entries as usize {
            return Err(UpdateError::Protocol("more entries than requested"));
        }
        if page.entries.is_empty() && page.next_epoch.is_some() {
            return Err(UpdateError::Protocol("an empty page with a continuation"));
        }
        for entry in page.entries.iter().cloned() {
            match history.append(entry).map_err(UpdateError::Entry)? {
                Appended::Added => added += 1,
                Appended::AlreadyHeld => {
                    return Err(UpdateError::Protocol("the source repeated a held entry"))
                }
            }
        }
        if history.latest().epoch >= want || added >= limits.total_entries {
            return Ok(UpdateOutcome::Extended { added });
        }
        match page.next_epoch {
            Some(next) if next == history.latest().epoch + 1 => {
                snapshot = page.end_entry_id.map(|id| (page.effective_end, id));
            }
            Some(_) => return Err(UpdateError::Protocol("the continuation skips an epoch")),
            None => {
                return Ok(if added > 0 && history.latest().epoch >= want {
                    UpdateOutcome::Extended { added }
                } else {
                    UpdateOutcome::NotYetAvailable {
                        held: history.latest().epoch,
                        added,
                    }
                })
            }
        }
    }
}

#[cfg(feature = "std")]
pub use waiting::{verify_token_updating, UpdatePolicy, VerifyUpdateError};

#[cfg(feature = "std")]
mod waiting {
    use super::*;
    use crate::transaction::Token;
    use crate::verify::VerificationError;
    use std::time::{Duration, Instant};

    /// Bounds of [`verify_token_updating`]: a finite, small budget, because a token can name an
    /// epoch that will never exist.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct UpdatePolicy {
        /// Pause between attempts while the source does not have the epoch (default 2 s).
        pub interval: Duration,
        /// Attempts while the epoch is not available (default 5).
        pub attempts: u32,
        /// Overall time budget (default 10 s).
        pub deadline: Duration,
        /// Bounds of each update call.
        pub limits: UpdateLimits,
    }

    impl Default for UpdatePolicy {
        fn default() -> Self {
            UpdatePolicy {
                interval: Duration::from_secs(2),
                attempts: 5,
                deadline: Duration::from_secs(10),
                limits: UpdateLimits::default(),
            }
        }
    }

    /// Why [`verify_token_updating`] gave up.
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum VerifyUpdateError<E> {
        /// Verification failed for a reason that is not a missing epoch (final).
        Verification(VerificationError),
        /// The source did not have the epoch within the budget. Retry later.
        EpochUnavailable {
            /// The latest epoch the history holds.
            held: u64,
            /// The epoch the token's certificate names.
            wanted: u64,
            /// Attempts made.
            attempts: u32,
        },
        /// Fetching or authenticating entries failed (an alarm, not retried).
        Update(UpdateError<E>),
    }

    impl<E: fmt::Display> fmt::Display for VerifyUpdateError<E> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                VerifyUpdateError::Verification(e) => write!(f, "{e}"),
                VerifyUpdateError::EpochUnavailable {
                    held,
                    wanted,
                    attempts,
                } => write!(
                    f,
                    "trust base epoch {wanted} not available (holding {held}) after {attempts} attempts"
                ),
                VerifyUpdateError::Update(e) => write!(f, "{e}"),
            }
        }
    }

    impl<E: fmt::Display + fmt::Debug> std::error::Error for VerifyUpdateError<E> {}

    /// Verify `token` against `history`; when a certificate names an epoch the history does not
    /// hold ([`VerificationError::unknown_trust_epoch`]), fetch the entries after the latest held
    /// one from `source`, append them (verified, in place) and verify again.
    ///
    /// Only a missing epoch triggers an update; any other verification failure returns at once.
    /// If the source does not have the epoch, the call waits `policy.interval` and asks again
    /// up to `policy.attempts` times within `policy.deadline`, then returns
    /// [`VerifyUpdateError::EpochUnavailable`].
    pub fn verify_token_updating<S: TrustBaseSource>(
        token: &Token,
        history: &mut TrustBaseHistory,
        source: &S,
        policy: &UpdatePolicy,
    ) -> Result<(), VerifyUpdateError<S::Error>> {
        let start = Instant::now();
        let mut attempts = 0u32;
        let mut added_total = 0usize;
        loop {
            let err = match crate::verify::verify_token(token, history) {
                Ok(()) => return Ok(()),
                Err(e) => e,
            };
            let Some(wanted) = err.unknown_trust_epoch() else {
                return Err(VerifyUpdateError::Verification(err));
            };
            let remaining = policy.limits.total_entries.saturating_sub(added_total);
            let limits = UpdateLimits {
                total_entries: remaining.max(1),
                ..policy.limits
            };
            match update_trust_base(history, source, wanted, &limits)
                .map_err(VerifyUpdateError::Update)?
            {
                UpdateOutcome::Extended { added } => {
                    added_total += added;
                    if added_total >= policy.limits.total_entries {
                        return Err(VerifyUpdateError::EpochUnavailable {
                            held: history.latest().epoch,
                            wanted,
                            attempts,
                        });
                    }
                }
                UpdateOutcome::NotYetAvailable { held, added } => {
                    added_total += added;
                    attempts += 1;
                    if attempts >= policy.attempts
                        || start.elapsed() + policy.interval > policy.deadline
                    {
                        return Err(VerifyUpdateError::EpochUnavailable {
                            held,
                            wanted,
                            attempts,
                        });
                    }
                    std::thread::sleep(policy.interval);
                }
                UpdateOutcome::UpToDate => {
                    // the history holds the epoch but verification still wants it: nothing to fetch
                    return Err(VerifyUpdateError::Verification(err));
                }
            }
        }
    }
}
