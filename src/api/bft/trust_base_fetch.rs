//! The `GetTrustBase` exchange: how a verifier asks an aggregator (or any peer) for the
//! trust base entries it does not hold, and the response it gets back.
//!
//! The wire is bft-core's `gettrustbase` response (tag 39015, version 1):
//! `[1, network, status, fromEpoch, effectiveEnd, endEntryId|null, entries[], nextEpoch|null]`,
//! the entries being canonical tag-39000 V2 entries embedded verbatim. The tag numbers are
//! provisional until the registry assigns them. A page carries no authority: the receiver
//! verifies every entry from its own latest held entry
//! ([`TrustBaseHistory::append`](super::TrustBaseHistory::append)).

use alloc::vec::Vec;
use core::fmt;

use super::trust_base_entry::{TrustBaseEntry, ID_LEN};
use super::trust_base_history::{
    GET_TRUST_BASE_RESPONSE_TAG, GET_TRUST_BASE_VERSION, MAX_BUNDLE_BYTES,
};
use crate::api::NetworkId;
use crate::cbor::Decoder;

/// The most entries one page carries (the server's cap).
pub const MAX_PAGE_ENTRIES: usize = 64;
/// The most bytes one page may have.
pub const MAX_PAGE_BYTES: usize = 1 << 20;

/// The status inside a `GetTrustBase` response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TrustBaseStatus {
    /// The page holds the entries asked for.
    Ok,
    /// The request was malformed.
    InvalidRequest,
    /// The request names another network.
    WrongNetwork,
    /// `from` is ahead of the server's latest entry: no entries (yet).
    NotYetAvailable,
    /// The snapshot (end epoch and identity) of a paged request differs from the server's chain.
    HistoryMismatch,
    /// The byte budget is too small for one entry.
    LimitTooSmall,
    /// The server is busy; try again later.
    Busy,
    /// The server cannot serve the request now.
    Unavailable,
}

impl TrustBaseStatus {
    fn from_code(code: u64) -> Option<Self> {
        Some(match code {
            0 => TrustBaseStatus::Ok,
            1 => TrustBaseStatus::InvalidRequest,
            2 => TrustBaseStatus::WrongNetwork,
            3 => TrustBaseStatus::NotYetAvailable,
            4 => TrustBaseStatus::HistoryMismatch,
            5 => TrustBaseStatus::LimitTooSmall,
            6 => TrustBaseStatus::Busy,
            7 => TrustBaseStatus::Unavailable,
            _ => return None,
        })
    }
}

impl fmt::Display for TrustBaseStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            TrustBaseStatus::Ok => "OK",
            TrustBaseStatus::InvalidRequest => "InvalidRequest",
            TrustBaseStatus::WrongNetwork => "WrongNetwork",
            TrustBaseStatus::NotYetAvailable => "NotYetAvailable",
            TrustBaseStatus::HistoryMismatch => "HistoryMismatch",
            TrustBaseStatus::LimitTooSmall => "LimitTooSmall",
            TrustBaseStatus::Busy => "Busy",
            TrustBaseStatus::Unavailable => "Unavailable",
        };
        f.write_str(name)
    }
}

/// A request for trust base entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustBaseRequest {
    /// First epoch wanted.
    pub from: u64,
    /// Last epoch wanted; `None` is the server's latest.
    pub to: Option<u64>,
    /// Pagination snapshot echoed from the previous page: `(effective_end, end_entry_id)`.
    pub snapshot: Option<(u64, [u8; ID_LEN])>,
    /// The most entries to return (`1..=`[`MAX_PAGE_ENTRIES`]).
    pub max_entries: u32,
}

/// One page of a `GetTrustBase` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustBasePage {
    /// The network the server speaks for.
    pub network_id: NetworkId,
    /// The status.
    pub status: TrustBaseStatus,
    /// First epoch of the page.
    pub from_epoch: u64,
    /// The end of the (frozen) range the server serves.
    pub effective_end: u64,
    /// Identity of the entry at `effective_end`.
    pub end_entry_id: Option<[u8; ID_LEN]>,
    /// The entries, contiguous and ascending from `from_epoch`; decoded and validated, not yet
    /// authenticated.
    pub entries: Vec<TrustBaseEntry>,
    /// Where the next page starts; `None` when this was the last page.
    pub next_epoch: Option<u64>,
}

/// Why a response is not a well-formed page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageError(pub &'static str);

impl fmt::Display for PageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GetTrustBase response: {}", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PageError {}

impl TrustBasePage {
    /// Strictly decode a tag-39015 response: exact tag and version, a known status, at most
    /// [`MAX_PAGE_ENTRIES`] entries and [`MAX_PAGE_BYTES`] bytes, every entry a canonical valid
    /// V2 entry, epochs contiguous from `from_epoch`, no entries unless the status is OK.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, PageError> {
        let e = PageError;
        if bytes.len() > MAX_PAGE_BYTES.min(MAX_BUNDLE_BYTES) {
            return Err(e("page exceeds the size bound"));
        }
        // (the tag and array accessors refuse bytes after the item, so a trailing byte is an error)
        let inner = Decoder::new(bytes)
            .expect_tag(GET_TRUST_BASE_RESPONSE_TAG)
            .map_err(|_| e("not a GetTrustBase response (tag)"))?;
        let f = inner
            .array(Some(8))
            .map_err(|_| e("not an 8-element array"))?;
        let uint = |d: &Decoder<'_>| d.uint().map_err(|_| e("malformed integer"));
        if uint(&f[0])? != GET_TRUST_BASE_VERSION {
            return Err(e("version is not 1"));
        }
        let network_id =
            NetworkId::new(u16::try_from(uint(&f[1])?).map_err(|_| e("network id out of range"))?)
                .map_err(|_| e("invalid network id"))?;
        let status = TrustBaseStatus::from_code(uint(&f[2])?).ok_or(e("unknown status"))?;
        let from_epoch = uint(&f[3])?;
        let effective_end = uint(&f[4])?;
        let end_entry_id = f[5]
            .nullable(|x| x.bytes_value().map(<[u8]>::to_vec).map_err(Into::into))
            .map_err(|_| e("malformed end entry id"))?
            .map(|v| <[u8; ID_LEN]>::try_from(v.as_slice()))
            .transpose()
            .map_err(|_| e("end entry id is not 32 bytes"))?;
        let next_epoch = f[7]
            .nullable(|x| x.uint().map_err(Into::into))
            .map_err(|_| e("malformed next epoch"))?;
        let items = f[6]
            .array(None)
            .map_err(|_| e("entries are not an array"))?;
        if items.len() > MAX_PAGE_ENTRIES {
            return Err(e("too many entries"));
        }
        if status != TrustBaseStatus::Ok && !items.is_empty() {
            return Err(e("entries with a status other than OK"));
        }
        let mut entries: Vec<TrustBaseEntry> = Vec::with_capacity(items.len());
        for (i, item) in items.iter().enumerate() {
            let entry = TrustBaseEntry::from_cbor(item.bytes())
                .map_err(|_| e("an entry is not a canonical valid V2 entry"))?;
            if entry.network_id != network_id {
                return Err(e("an entry of another network"));
            }
            if Some(entry.epoch) != from_epoch.checked_add(i as u64) {
                return Err(e("entries are not contiguous from the first epoch"));
            }
            entries.push(entry);
        }
        if let Some(last) = entries.last() {
            if last.epoch > effective_end {
                return Err(e("an entry beyond the effective end"));
            }
        }
        Ok(TrustBasePage {
            network_id,
            status,
            from_epoch,
            effective_end,
            end_entry_id,
            entries,
            next_epoch,
        })
    }
}
