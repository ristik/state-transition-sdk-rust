//! Catching a [`TrustBaseHistory`] up from untrusted sources (the GetTrustBase fetch loop), and verify-update-retry.
//!
//! It follows bft-core `gettrustbase.Sync` and the JS SDK's `TrustBaseUpdater`: the entries after the held tip are fetched page by page
//! and each is appended through [`TrustBaseHistory::append`], which authenticates it from the entry before it. The first page of a
//! paged range freezes its end epoch and end entry id and every later page echoes them, so a source that lags or is on another
//! history is skipped and the next source continues from the same cursor. An authenticated prefix is kept even when a later page fails.
//!
//! * **Transport behind a trait.** A [`TrustBaseSource`] returns the encoded response (tag 39015) for a [`TrustBaseRequest`]; this
//!   module has no I/O, no clock and no threads, so it is `no_std + alloc`. The blocking HTTP source of an aggregator
//!   (`GET /api/v1/trustbases`) is `HttpAggregatorClient` (feature `http`). The pause between passes and cancellation are callbacks of
//!   [`UpdateOptions`].
//! * **Sources are untrusted.** A source's tip is unauthenticated metadata: a lagging or hostile source cannot end an update as
//!   "current"; only when every source says there is nothing newer is the history taken as current, and that is a result (0 appended),
//!   not an error, and nothing in it is authenticated. Busy and unavailable are asked again on the next pass, other refusals are final
//!   for the call.
//! * A held history is never empty here (it starts at its genesis), so there are no "empty history" options as in JS; and a `&mut`
//!   history cannot be updated twice at once, so there is no in-flight sharing.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use super::trust_base_entry::ID_LEN;
use super::trust_base_history::{Appended, HistoryError, TrustBaseHistory};
use super::trust_base_range::{
    RangeError, RangeLimits, TrustBaseRange, TrustBaseStatus, PAGE_LIMITS,
};
use crate::api::NetworkId;
use crate::verify::VerificationError;

/// The end epoch and its entry id that the first page of a paged range announced, echoed on every later page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    /// The announced last epoch.
    pub end: u64,
    /// Identity of the entry at `end`.
    pub entry_id: [u8; ID_LEN],
}

/// One GetTrustBase request (bft-core `gettrustbase.Request`, without the end epoch, which the SDK never sets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustBaseRequest {
    /// First epoch wanted: the latest held epoch + 1, or the cursor of the previous page.
    pub from_epoch: u64,
    /// Most entries wanted in the response.
    pub max_entries: usize,
    /// The network.
    pub network_id: NetworkId,
    /// The snapshot the first page announced, echoed on later pages.
    pub snapshot: Option<Snapshot>,
}

/// A source could not deliver a response (transport failure, a non-success status, an oversized body). Opaque on purpose: the updater
/// treats every such failure the same, asking the next source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceError(pub String);

impl fmt::Display for SourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SourceError {}

/// Where newer Unicity Trust Base entries are fetched from: an aggregator's `GET /api/v1/trustbases`, a mirror, a test double. A source is
/// untrusted: it returns the encoded response (tag 39015), whatever its status, and the caller decodes it with the page limits and appends
/// every entry through [`TrustBaseHistory::append`].
pub trait TrustBaseSource {
    /// The encoded response to `request`.
    fn get_trust_base_page(&self, request: &TrustBaseRequest) -> Result<Vec<u8>, SourceError>;
}

impl<T: TrustBaseSource + ?Sized> TrustBaseSource for &T {
    fn get_trust_base_page(&self, request: &TrustBaseRequest) -> Result<Vec<u8>, SourceError> {
        (**self).get_trust_base_page(request)
    }
}

/// Options of [`update`].
#[derive(Clone, Copy)]
pub struct UpdateOptions<'a> {
    /// Passes over the sources before giving up. Default 2.
    pub rounds: u32,
    /// Pause between passes, in milliseconds, handed to `pause`. Default 200.
    pub backoff_ms: u64,
    /// Page budget of the response decode. Default [`PAGE_LIMITS`].
    pub limits: RangeLimits,
    /// Waits between passes (`std::thread::sleep` for a blocking caller). `None` retries at once.
    pub pause: Option<&'a dyn Fn(u64)>,
    /// Checked before every request; `true` ends the update with [`UpdateFailure::Cancelled`] (the appended prefix is kept).
    pub cancelled: Option<&'a dyn Fn() -> bool>,
}

impl fmt::Debug for UpdateOptions<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpdateOptions")
            .field("rounds", &self.rounds)
            .field("backoff_ms", &self.backoff_ms)
            .field("limits", &self.limits)
            .field("pause", &self.pause.map(|_| "<fn>"))
            .field("cancelled", &self.cancelled.map(|_| "<fn>"))
            .finish()
    }
}

impl Default for UpdateOptions<'_> {
    fn default() -> Self {
        UpdateOptions {
            rounds: 2,
            backoff_ms: 200,
            limits: PAGE_LIMITS,
            pause: None,
            cancelled: None,
        }
    }
}

/// Why one source did not serve (part of an [`UpdateError`]).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UpdateCause {
    /// The source could not deliver a response.
    Source {
        /// Index in the source list.
        source: usize,
        /// The failure.
        error: SourceError,
    },
    /// The response was not a valid page.
    Page {
        /// Index in the source list.
        source: usize,
        /// The failure.
        error: RangeError,
    },
    /// The source answered with a status other than OK (and not "nothing newer").
    Status {
        /// Index in the source list.
        source: usize,
        /// The status.
        status: TrustBaseStatus,
    },
    /// An OK page that does not continue the requested range or the frozen snapshot.
    NotContinuing {
        /// Index in the source list.
        source: usize,
    },
    /// The source served an entry the history refuses.
    Refused {
        /// Index in the source list.
        source: usize,
        /// The refusal.
        error: HistoryError,
    },
}

/// The kind of an [`UpdateError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateFailure {
    /// The source list is empty.
    NoSource,
    /// No source served the range: every source failed, refused, or served an entry the history refuses.
    NoneServed,
    /// `cancelled` returned true.
    Cancelled,
}

/// An update that did not end with "current". Entries appended before the failure are held (`appended`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateError {
    /// What happened.
    pub failure: UpdateFailure,
    /// What each source did, in order.
    pub causes: Vec<UpdateCause>,
    /// Entries appended before the failure; the authenticated prefix is kept.
    pub appended: usize,
}

impl fmt::Display for UpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match self.failure {
            UpdateFailure::NoSource => "no source",
            UpdateFailure::NoneServed => "no source served the range",
            UpdateFailure::Cancelled => "the update was cancelled",
        };
        write!(f, "trust base update: {what} ({} appended)", self.appended)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UpdateError {}

fn next_from(history: &TrustBaseHistory) -> u64 {
    history.latest().epoch.saturating_add(1)
}

/// Fetch and append the entries after the held tip.
///
/// Returns the number of entries appended. `0` means the history is current as far as every source says (all answered "nothing newer"):
/// a result, not an error, and nothing in it is authenticated. `Err` means no source served the range (every source failed, refused, or
/// served an entry the history refuses), or the update was cancelled; the entries appended before are held either way.
pub fn update(
    history: &mut TrustBaseHistory,
    sources: &[&dyn TrustBaseSource],
    options: &UpdateOptions<'_>,
) -> Result<usize, UpdateError> {
    let mut causes: Vec<UpdateCause> = Vec::new();
    let mut appended = 0usize;
    let fail = |failure, causes, appended| UpdateError {
        failure,
        causes,
        appended,
    };
    if sources.is_empty() {
        return Err(fail(UpdateFailure::NoSource, causes, appended));
    }
    let network = history.network_id();
    let mut finally_refused = alloc::vec![false; sources.len()];
    // The cursor and the frozen snapshot belong to the whole call, not to a source: the next source continues where the last stopped, and
    // a source that only knows the older tip cannot end the call as "current" once any source announced a higher end. Both reset when an
    // entry is refused. (The history cannot move on by other means while this holds it mutably, so unlike JS there is no re-sync here.)
    let mut from = next_from(history);
    let mut snapshot: Option<Snapshot> = None;

    for round in 0..options.rounds {
        if round > 0 {
            if let Some(pause) = options.pause {
                pause(options.backoff_ms);
            }
        }
        let mut current = 0usize;
        for (index, source) in sources.iter().enumerate() {
            if finally_refused[index] {
                continue;
            }
            loop {
                if options.cancelled.is_some_and(|c| c()) {
                    return Err(fail(UpdateFailure::Cancelled, causes, appended));
                }
                let request = TrustBaseRequest {
                    from_epoch: from,
                    max_entries: options.limits.max_entries,
                    network_id: network,
                    snapshot,
                };
                let bytes = match source.get_trust_base_page(&request) {
                    Ok(b) => b,
                    Err(error) => {
                        causes.push(UpdateCause::Source {
                            source: index,
                            error,
                        });
                        break;
                    }
                };
                let page = match TrustBaseRange::decode(&bytes, &options.limits, network) {
                    Ok(p) => p,
                    Err(error) => {
                        causes.push(UpdateCause::Page {
                            source: index,
                            error,
                        });
                        break;
                    }
                };

                // A source's tip is unauthenticated metadata: a lagging or hostile source must not end the update. Only when every source
                // says there is nothing newer is the history taken as current.
                if page.status == TrustBaseStatus::NotYetAvailable
                    && snapshot.is_none()
                    && page.effective_end < from
                {
                    current += 1;
                    break;
                }
                // A source that refuses the echoed snapshot as another history may be the honest one: the snapshot came from whichever source
                // answered the first page, and a hostile first page can announce a fake end. Drop it, start again from the tip and ask the same
                // source once more without it; a mismatch without a snapshot is final, so this terminates.
                if page.status == TrustBaseStatus::HistoryMismatch && snapshot.is_some() {
                    causes.push(UpdateCause::Status {
                        source: index,
                        status: page.status,
                    });
                    snapshot = None;
                    from = next_from(history);
                    continue;
                }
                if page.status != TrustBaseStatus::Ok {
                    causes.push(UpdateCause::Status {
                        source: index,
                        status: page.status,
                    });
                    // Busy and unavailable may pass; the other refusals will not.
                    if page.status != TrustBaseStatus::Busy
                        && page.status != TrustBaseStatus::Unavailable
                    {
                        finally_refused[index] = true;
                    }
                    break;
                }
                if page.from_epoch != from
                    || snapshot.is_some_and(|s| {
                        page.effective_end != s.end || page.end_entry_id != Some(s.entry_id)
                    })
                {
                    causes.push(UpdateCause::NotContinuing { source: index });
                    break;
                }

                let mut refused = false;
                for entry in page.entries {
                    match history.append(entry) {
                        Ok(Appended::Added) => appended += 1,
                        Ok(Appended::AlreadyHeld) => {}
                        Err(error) => {
                            // The source served an entry the history refuses: keep the authenticated prefix, drop the snapshot, try the
                            // next source.
                            causes.push(UpdateCause::Refused {
                                source: index,
                                error,
                            });
                            refused = true;
                            snapshot = None;
                            from = next_from(history);
                            break;
                        }
                    }
                }
                if refused {
                    break;
                }
                let Some(next) = page.next_epoch else {
                    return Ok(appended);
                };
                if snapshot.is_none() {
                    snapshot = Some(Snapshot {
                        end: page.effective_end,
                        entry_id: page.end_entry_id.unwrap_or([0; ID_LEN]),
                    });
                }
                from = next;
            }
        }
        if current == sources.len() {
            return Ok(appended);
        }
    }
    Err(fail(UpdateFailure::NoneServed, causes, appended))
}

/// Verify, and when the only thing missing is a trust base entry, update the history from the sources and verify once more.
///
/// `verify` is run first. A result that is not the typed no-entry failure ([`VerificationError::UnknownTrustEpoch`]), `Ok` or any other
/// error, is returned as it is: no fetch can help it. On the typed no-entry failure the history is updated (see [`update`]); if that
/// appended nothing, the first result stands, and otherwise `verify` runs once more and its result is returned, whatever it is. There is
/// no loop: one update, one retry.
///
/// The outer `Err` is an update that failed (as opposed to finding nothing newer) and whose appended prefix does not make the
/// verification possible: a later page may fail after the entry that was needed arrived, so the prefix is verified against before giving up.
pub fn verify_with_update<T>(
    history: &mut TrustBaseHistory,
    sources: &[&dyn TrustBaseSource],
    options: &UpdateOptions<'_>,
    mut verify: impl FnMut(&TrustBaseHistory) -> Result<T, VerificationError>,
) -> Result<Result<T, VerificationError>, UpdateError> {
    let is_missing = |r: &Result<T, VerificationError>| {
        matches!(r, Err(VerificationError::UnknownTrustEpoch { .. }))
    };
    let first = verify(history);
    if !is_missing(&first) {
        return Ok(first);
    }
    match update(history, sources, options) {
        Ok(0) => Ok(first),
        Ok(_) => Ok(verify(history)),
        Err(error) => {
            if error.appended > 0 {
                let retried = verify(history);
                if !is_missing(&retried) {
                    return Ok(retried);
                }
            }
            Err(error)
        }
    }
}
