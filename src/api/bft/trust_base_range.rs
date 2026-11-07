//! One page of the GetTrustBase protocol: the tag-39015 response to a request for the entries from an epoch on.
//!
//! A status other than OK carries no entries and no cursor. An OK page is a contiguous ascending run of entries of the
//! response's network starting at `from_epoch`, linked by entry id, ending at `effective_end` when no cursor remains, or at the
//! epoch before the cursor otherwise. The reference is bft-core `gettrustbase.DecodeResponse`; the shared vectors are
//! `tests/vectors/gettrustbase` (bft-core 5d9a8eaa).
//!
//! Decoding checks structure and links only. Nothing here is authenticated: `effective_end` and `end_entry_id` are the source's
//! claim, and every entry is authenticated by [`TrustBaseHistory::append`](super::TrustBaseHistory::append) from the latest held
//! entry. (A release bundle is the stricter special case, see `TrustBaseHistory::from_bundle`.)

use alloc::vec::Vec;
use core::fmt;

use super::trust_base_entry::{TrustBaseEntry, ID_LEN, MAX_ENTRY_BYTES};
use super::trust_base_history::{GET_TRUST_BASE_RESPONSE_TAG, GET_TRUST_BASE_VERSION};
use crate::api::NetworkId;
use crate::cbor::Decoder;

/// Status of a GetTrustBase response. The numbers are the wire values (bft-core `gettrustbase.Status`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustBaseStatus {
    /// The page carries entries.
    Ok,
    /// The request was malformed.
    InvalidRequest,
    /// The source serves another network.
    WrongNetwork,
    /// The source has nothing from the requested epoch yet.
    NotYetAvailable,
    /// The source is on another history than the echoed snapshot.
    HistoryMismatch,
    /// The requested page size is below the source's minimum.
    LimitTooSmall,
    /// The source is busy; ask again.
    Busy,
    /// The source cannot answer now; ask again.
    Unavailable,
}

impl TrustBaseStatus {
    /// The status of a wire value, `None` for 8 and above.
    pub fn from_wire(value: u64) -> Option<Self> {
        Some(match value {
            0 => Self::Ok,
            1 => Self::InvalidRequest,
            2 => Self::WrongNetwork,
            3 => Self::NotYetAvailable,
            4 => Self::HistoryMismatch,
            5 => Self::LimitTooSmall,
            6 => Self::Busy,
            7 => Self::Unavailable,
            _ => return None,
        })
    }

    /// The wire value.
    pub fn wire(self) -> u64 {
        self as u64
    }
}

/// Budget of a page decode; `max_bytes` is checked before anything is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RangeLimits {
    /// Encoded response bytes.
    pub max_bytes: usize,
    /// Entries in a page.
    pub max_entries: usize,
}

/// The page caps of the GetTrustBase protocol (bft-core `gettrustbase.PageLimits`).
pub const PAGE_LIMITS: RangeLimits = RangeLimits {
    max_bytes: 1 << 20,
    max_entries: 64,
};

/// Why a page was refused. The two classes are those of the shared vectors.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RangeError {
    /// Not a well-formed deterministic response (or an embedded entry), or over the byte budget.
    Encoding(&'static str),
    /// A well-formed response that breaks a consistency rule: status and cursor, network, start, order, links, end.
    Response(&'static str),
}

impl fmt::Display for RangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RangeError::Encoding(m) => write!(f, "malformed GetTrustBase response: {m}"),
            RangeError::Response(m) => write!(f, "inconsistent GetTrustBase response: {m}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RangeError {}

/// One decoded page. See the module docs for what is and is not checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustBaseRange {
    /// The status.
    pub status: TrustBaseStatus,
    /// The network of the response (the one that was asked for).
    pub network_id: NetworkId,
    /// First epoch of the page (advisory for a status other than OK).
    pub from_epoch: u64,
    /// The source's last epoch (advisory for a status other than OK).
    pub effective_end: u64,
    /// The identity of the entry at `effective_end` (absent or advisory for a status other than OK; unchecked on a cursor page that ends before it).
    pub end_entry_id: Option<[u8; ID_LEN]>,
    /// The entries, structurally decoded and linked, signatures unchecked. Empty unless the status is OK.
    pub entries: Vec<TrustBaseEntry>,
    /// The epoch to ask for next, when the page does not reach `effective_end`.
    pub next_epoch: Option<u64>,
}

impl TrustBaseRange {
    /// Strictly decode one page.
    ///
    /// `expected_network` is the network that was asked for; a response for another one is refused.
    pub fn decode(
        bytes: &[u8],
        limits: &RangeLimits,
        expected_network: NetworkId,
    ) -> Result<TrustBaseRange, RangeError> {
        use RangeError::{Encoding, Response};
        if bytes.len() > limits.max_bytes {
            return Err(Encoding("response exceeds the byte budget"));
        }
        let top = Decoder::new(bytes);
        top.finish().map_err(|_| Encoding("malformed CBOR"))?;
        let inner = top
            .expect_tag(GET_TRUST_BASE_RESPONSE_TAG)
            .map_err(|_| Encoding("not a GetTrustBase response (tag)"))?;
        let f = inner
            .array(Some(8))
            .map_err(|_| Encoding("response is not an 8-element array"))?;
        let uint = |d: &Decoder<'_>| d.uint().map_err(|_| Encoding("malformed integer"));
        if uint(&f[0])? != GET_TRUST_BASE_VERSION {
            return Err(Encoding("response version is not 1"));
        }
        let network = NetworkId::new(
            u16::try_from(uint(&f[1])?).map_err(|_| Encoding("network id out of range"))?,
        )
        .map_err(|_| Encoding("invalid network id"))?;
        let status =
            TrustBaseStatus::from_wire(uint(&f[2])?).ok_or(Encoding("status out of range"))?;
        let from_epoch = uint(&f[3])?;
        let effective_end = uint(&f[4])?;
        let end_entry_id: Option<[u8; ID_LEN]> = f[5]
            .nullable(|x| x.bytes_value().map(<[u8]>::to_vec).map_err(Into::into))
            .map_err(|_| Encoding("malformed end entry id"))?
            .map(|v| {
                v.as_slice()
                    .try_into()
                    .map_err(|_| Encoding("end entry id is not 32 bytes"))
            })
            .transpose()?;
        let items = f[6]
            .array(None)
            .map_err(|_| Encoding("entries are not an array"))?;
        let next_epoch = f[7]
            .nullable(|x| x.uint().map_err(Into::into))
            .map_err(|_| Encoding("malformed cursor"))?;
        if items.len() > limits.max_entries {
            return Err(Response("entry count exceeds the bound"));
        }
        if network != expected_network {
            return Err(Response("a response for another network"));
        }

        if status != TrustBaseStatus::Ok {
            if !items.is_empty() || next_epoch.is_some() {
                return Err(Response(
                    "a status other than OK carries entries or a cursor",
                ));
            }
            return Ok(TrustBaseRange {
                status,
                network_id: network,
                from_epoch,
                effective_end,
                end_entry_id,
                entries: Vec::new(),
                next_epoch: None,
            });
        }
        if items.is_empty() {
            return Err(Response("an OK response without entries"));
        }
        let end_entry_id_ok = end_entry_id.ok_or(Response("no end entry id"))?;

        let mut entries: Vec<TrustBaseEntry> = Vec::with_capacity(items.len());
        let mut previous_id = [0u8; ID_LEN];
        for item in &items {
            if item.bytes().len() > MAX_ENTRY_BYTES {
                return Err(Response("entry exceeds the size bound"));
            }
            let entry = TrustBaseEntry::from_cbor(item.bytes())
                .map_err(|_| Encoding("an embedded entry is not a version 2 entry"))?;
            if entry.network_id != network {
                return Err(Response("an entry of another network"));
            }
            match entries.last() {
                None => {
                    if entry.epoch != from_epoch {
                        return Err(Response("the first entry is not at the page's start epoch"));
                    }
                }
                Some(prev) => {
                    if prev.epoch == u64::MAX || entry.epoch != prev.epoch + 1 {
                        return Err(Response("entry epochs are not consecutive"));
                    }
                    if entry.previous_entry_id != previous_id {
                        return Err(Response("an entry does not link to its predecessor"));
                    }
                }
            }
            previous_id = entry.entry_id();
            entries.push(entry);
        }

        let last = entries[entries.len() - 1].epoch;
        match next_epoch {
            None => {
                if last != effective_end {
                    return Err(Response(
                        "the page ends before the effective end without a cursor",
                    ));
                }
            }
            Some(next) => {
                if last == u64::MAX || next != last + 1 || next > effective_end {
                    return Err(Response("the cursor does not follow the last entry"));
                }
            }
        }
        if last == effective_end && end_entry_id_ok != previous_id {
            return Err(Response("the end entry id differs from the last entry"));
        }
        Ok(TrustBaseRange {
            status,
            network_id: network,
            from_epoch,
            effective_end,
            end_entry_id,
            entries,
            next_epoch,
        })
    }
}
