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
        // never ask for more than the per-call cap still allows
        let remaining = limits.total_entries.saturating_sub(added).max(1);
        let asked = page_entries.min(u32::try_from(remaining).unwrap_or(u32::MAX));
        let page = source
            .get_trust_bases(&TrustBaseRequest {
                from,
                to: None,
                snapshot,
                max_entries: asked,
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
        if page.entries.len() > asked as usize {
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
        let mut capped = false;
        loop {
            let err = match crate::verify::verify_token(token, history) {
                Ok(()) => return Ok(()),
                Err(e) => e,
            };
            let Some(wanted) = err.unknown_trust_epoch() else {
                return Err(VerifyUpdateError::Verification(err));
            };
            if capped {
                // the entry cap was reached and the last page did not bring the epoch
                return Err(VerifyUpdateError::EpochUnavailable {
                    held: history.latest().epoch,
                    wanted,
                    attempts,
                });
            }
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
                    // at the cap: verify once more (the last page may have brought the epoch),
                    // then give up
                    capped = added_total >= policy.limits.total_entries;
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

#[cfg(all(test, feature = "client"))]
mod tests {
    //! The guards of `update_trust_base` against a scripted source. Each test violates exactly
    //! one of them, so removing that guard makes it fail.
    use super::*;
    use crate::api::bft::{TrustBaseEntry, TrustBaseMember};
    use crate::api::NetworkId;
    use crate::crypto::signer::{Secp256k1Signer, Signer};
    use alloc::collections::VecDeque;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::cell::RefCell;

    /// One validator, so a single signature is a quorum: epochs `1..=n`.
    fn chain(n: u64) -> Vec<TrustBaseEntry> {
        let s = Secp256k1Signer::from_bytes(&[5; 32]).unwrap();
        let members = || vec![TrustBaseMember::new("n0", s.public_key(), 1)];
        let mut out = vec![TrustBaseEntry::genesis(NetworkId::LOCAL, 1, 1, members())];
        for e in 2..=n {
            let prev = out.last().unwrap();
            let mut next = TrustBaseEntry::new(
                NetworkId::LOCAL,
                e,
                prev.epoch_start + 10,
                members(),
                1,
                None,
                None,
                prev.entry_id(),
            );
            next.sign("n0", &s);
            out.push(next);
        }
        out
    }

    fn history() -> TrustBaseHistory {
        TrustBaseHistory::from_genesis(chain(1).remove(0), None).unwrap()
    }

    fn page(
        from: u64,
        end: u64,
        entries: Vec<TrustBaseEntry>,
        next: Option<u64>,
        status: TrustBaseStatus,
    ) -> TrustBasePage {
        TrustBasePage {
            network_id: NetworkId::LOCAL,
            status,
            from_epoch: from,
            effective_end: end,
            end_entry_id: Some([7; 32]),
            entries,
            next_epoch: next,
        }
    }

    struct Script {
        pages: RefCell<VecDeque<TrustBasePage>>,
        requests: RefCell<Vec<TrustBaseRequest>>,
    }

    impl Script {
        fn new(pages: Vec<TrustBasePage>) -> Self {
            Script {
                pages: RefCell::new(pages.into()),
                requests: RefCell::new(Vec::new()),
            }
        }
    }

    impl TrustBaseSource for Script {
        type Error = &'static str;
        fn get_trust_bases(&self, r: &TrustBaseRequest) -> Result<TrustBasePage, &'static str> {
            self.requests.borrow_mut().push(r.clone());
            self.pages
                .borrow_mut()
                .pop_front()
                .ok_or("script exhausted")
        }
    }

    fn run(
        h: &mut TrustBaseHistory,
        pages: Vec<TrustBasePage>,
        want: u64,
        limits: UpdateLimits,
    ) -> (Result<UpdateOutcome, UpdateError<&'static str>>, Script) {
        let s = Script::new(pages);
        let r = update_trust_base(h, &s, want, &limits);
        (r, s)
    }

    fn ok(from: u64, entries: Vec<TrustBaseEntry>, next: Option<u64>) -> TrustBasePage {
        page(from, 9, entries, next, TrustBaseStatus::Ok)
    }

    #[test]
    fn a_page_must_start_at_the_requested_epoch() {
        let c = chain(3);
        let mut h = history();
        let (r, _) = run(
            &mut h,
            vec![ok(3, vec![c[1].clone()], None)], // asked from 2
            2,
            UpdateLimits::default(),
        );
        assert!(
            matches!(r, Err(UpdateError::Protocol(m)) if m.contains("start")),
            "{r:?}"
        );
        assert_eq!(h.latest().epoch, 1);
    }

    #[test]
    fn a_page_may_not_carry_more_entries_than_asked() {
        let c = chain(3);
        let mut h = history();
        let limits = UpdateLimits {
            page_entries: 1,
            total_entries: 100,
        };
        let (r, s) = run(
            &mut h,
            vec![ok(2, vec![c[1].clone(), c[2].clone()], None)],
            3,
            limits,
        );
        assert!(
            matches!(r, Err(UpdateError::Protocol(m)) if m.contains("more entries")),
            "{r:?}"
        );
        assert_eq!(s.requests.borrow()[0].max_entries, 1);
        assert_eq!(h.latest().epoch, 1);
    }

    #[test]
    fn an_empty_page_with_a_continuation_is_refused() {
        let mut h = history();
        let (r, _) = run(
            &mut h,
            vec![ok(2, vec![], Some(2))],
            2,
            UpdateLimits::default(),
        );
        assert!(
            matches!(r, Err(UpdateError::Protocol(m)) if m.contains("empty page")),
            "{r:?}"
        );
    }

    #[test]
    fn a_repeated_held_entry_is_refused() {
        let c = chain(2);
        let mut h = history();
        // a page that starts where asked but carries the entry already held
        let (r, _) = run(
            &mut h,
            vec![ok(2, vec![c[0].clone()], None)],
            2,
            UpdateLimits::default(),
        );
        assert!(
            matches!(r, Err(UpdateError::Protocol(m)) if m.contains("repeated")),
            "{r:?}"
        );
    }

    #[test]
    fn a_continuation_may_not_skip_an_epoch() {
        let c = chain(4);
        let mut h = history();
        let (r, _) = run(
            &mut h,
            vec![ok(2, vec![c[1].clone()], Some(4))], // the next page should start at 3
            4,
            UpdateLimits::default(),
        );
        assert!(
            matches!(r, Err(UpdateError::Protocol(m)) if m.contains("skips")),
            "{r:?}"
        );
        assert_eq!(h.latest().epoch, 2, "the verified entry stays");
    }

    #[test]
    fn a_page_of_another_network_is_refused() {
        let c = chain(2);
        let mut h = history();
        let mut p = ok(2, vec![c[1].clone()], None);
        p.network_id = NetworkId::MAINNET;
        let (r, _) = run(&mut h, vec![p], 2, UpdateLimits::default());
        assert_eq!(r, Err(UpdateError::Entry(HistoryError::WrongNetwork)));
        assert_eq!(h.latest().epoch, 1);
    }

    #[test]
    fn a_changed_chain_restarts_the_pagination_once_and_only_with_a_snapshot() {
        let c = chain(6);
        let mismatch = |from| page(from, 9, vec![], None, TrustBaseStatus::HistoryMismatch);

        // one restart is allowed: snapshot, mismatch, restart without snapshot, snapshot, mismatch
        let mut h = history();
        let (r, s) = run(
            &mut h,
            vec![
                ok(2, vec![c[1].clone()], Some(3)),
                mismatch(3),
                ok(3, vec![c[2].clone()], Some(4)),
                mismatch(4),
                ok(4, vec![c[3].clone()], None), // never reached: a second restart is refused
            ],
            6,
            UpdateLimits::default(),
        );
        assert_eq!(
            r,
            Err(UpdateError::Status(TrustBaseStatus::HistoryMismatch))
        );
        let requests = s.requests.borrow();
        assert_eq!(requests.len(), 4, "exactly one restart");
        assert!(requests[0].snapshot.is_none());
        assert!(requests[1].snapshot.is_some());
        assert!(
            requests[2].snapshot.is_none(),
            "the restart drops the snapshot"
        );
        assert!(requests[3].snapshot.is_some());

        // a mismatch on a request that carried no snapshot is not a restart
        let mut h = history();
        let (r, s) = run(
            &mut h,
            vec![mismatch(2), ok(2, vec![c[1].clone()], None)],
            2,
            UpdateLimits::default(),
        );
        assert_eq!(
            r,
            Err(UpdateError::Status(TrustBaseStatus::HistoryMismatch))
        );
        assert_eq!(s.requests.borrow().len(), 1);
    }

    #[test]
    fn the_per_call_cap_limits_what_is_asked() {
        let c = chain(5);
        let mut h = history();
        let limits = UpdateLimits {
            page_entries: 64,
            total_entries: 2,
        };
        let (r, s) = run(
            &mut h,
            vec![ok(2, vec![c[1].clone(), c[2].clone()], Some(4))],
            5,
            limits,
        );
        assert_eq!(r, Ok(UpdateOutcome::Extended { added: 2 }));
        assert_eq!(
            s.requests.borrow()[0].max_entries,
            2,
            "no overshoot by a page"
        );
    }
}
