//! The Unicity Trust Base history: every epoch's [`TrustBaseEntry`] a verifier holds.
//!
//! * **Append-only.** A held entry is never replaced or removed. An entry of a held epoch
//!   with the same identity (same unsigned bytes) is a no-op, whatever valid witness it
//!   carries; one with another identity is [`HistoryError::Conflict`].
//! * **Forward verification.** A new entry is verified from the latest held entry (epoch
//!   plus one, same network, later start, predecessor identity, the predecessor members'
//!   strict weighted quorum). A verified entry becomes the anchor of the next. The latest
//!   held entry is effectively the pin.
//! * **Release bundle.** A release ships the complete known history as one tagged
//!   `GetTrustBase` response (tag 39015, status OK, no continuation). It is trusted as
//!   shipped for its authority (there is nothing earlier to verify the genesis against; the
//!   caller can compare [`TrustBaseHistory::genesis_id`] with a pin), and it is checked for
//!   internal consistency like any chain.
//! * Nothing here touches the network or the clock.

use alloc::vec::Vec;
use core::fmt;

use super::trust_base_entry::{TrustBaseEntry, TrustBaseError, ID_LEN, MAX_ENTRY_BYTES};
use crate::api::NetworkId;
use crate::cbor::Decoder;

/// CBOR tag of the `GetTrustBase` request (provisional until registered).
pub const GET_TRUST_BASE_REQUEST_TAG: u64 = 39014;
/// CBOR tag of the `GetTrustBase` response, which is also the release bundle format
/// (provisional until registered).
pub const GET_TRUST_BASE_RESPONSE_TAG: u64 = 39015;
/// Version of the request and response.
pub const GET_TRUST_BASE_VERSION: u64 = 1;
/// Response status OK.
pub const STATUS_OK: u64 = 0;
/// Bound on the encoded size of a bundle.
pub const MAX_BUNDLE_BYTES: usize = 16 << 20;
/// Bound on the number of entries in a bundle.
pub const MAX_BUNDLE_ENTRIES: usize = 4096;

/// Why an entry or bundle was refused by the history.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HistoryError {
    /// The entry itself or its link to the latest held entry is invalid.
    Entry(TrustBaseError),
    /// An entry of this epoch is held with another identity.
    Conflict {
        /// The epoch.
        epoch: u64,
    },
    /// The entry is not directly after the latest held entry.
    Gap {
        /// Epoch of the latest held entry.
        held: u64,
        /// Epoch of the offered entry.
        offered: u64,
    },
    /// The entry is of a network other than the history's.
    WrongNetwork,
    /// The offered entry is older than the genesis entry.
    BeforeGenesis,
    /// The bundle or genesis is malformed.
    Bundle(&'static str),
    /// The genesis identity differs from the pin.
    PinMismatch,
}

impl fmt::Display for HistoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HistoryError::Entry(e) => write!(f, "{e}"),
            HistoryError::Conflict { epoch } => {
                write!(f, "trust base history: another entry of epoch {epoch} is held")
            }
            HistoryError::Gap { held, offered } => write!(
                f,
                "trust base history: epoch {offered} does not directly follow the latest held epoch {held}"
            ),
            HistoryError::WrongNetwork => write!(f, "trust base history: another network"),
            HistoryError::BeforeGenesis => write!(f, "trust base history: epoch before the genesis"),
            HistoryError::Bundle(m) => write!(f, "trust base history: invalid bundle: {m}"),
            HistoryError::PinMismatch => write!(f, "trust base history: genesis differs from the pin"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for HistoryError {}

impl From<TrustBaseError> for HistoryError {
    fn from(e: TrustBaseError) -> Self {
        HistoryError::Entry(e)
    }
}

/// What [`TrustBaseHistory::append`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Appended {
    /// The entry was verified and added.
    Added,
    /// An entry with this identity was already held; nothing changed (the first witness is
    /// kept).
    AlreadyHeld,
}

/// An append-only chain of trust base entries from a genesis entry to the latest held one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustBaseHistory {
    // entries[i] has epoch genesis_epoch + i; never empty
    entries: Vec<TrustBaseEntry>,
}

impl TrustBaseHistory {
    /// A history holding only `genesis`. If `pin` is given the genesis identity has to equal
    /// it.
    pub fn from_genesis(
        genesis: TrustBaseEntry,
        pin: Option<[u8; ID_LEN]>,
    ) -> Result<Self, HistoryError> {
        genesis.verify_genesis()?;
        if let Some(pin) = pin {
            if genesis.entry_id() != pin {
                return Err(HistoryError::PinMismatch);
            }
        }
        Ok(TrustBaseHistory {
            entries: alloc::vec![genesis],
        })
    }

    /// Load a history from the contents of a trust base file: a release bundle (tag-39015
    /// response, see [`from_bundle`](Self::from_bundle)), a single tagged entry (a genesis,
    /// tag 39000), or the V2 JSON form of a genesis (see [`TrustBaseEntry::from_json`]). `pin`
    /// is the deployment's genesis identity, when it has one. Host only.
    #[cfg(feature = "std")]
    pub fn from_file(contents: &[u8], pin: Option<[u8; ID_LEN]>) -> Result<Self, HistoryError> {
        let start = contents.iter().position(|b| !b.is_ascii_whitespace());
        let rest = start.map_or(&contents[..0], |i| &contents[i..]);
        match rest.first() {
            Some(b'{') => {
                let text = core::str::from_utf8(contents)
                    .map_err(|_| HistoryError::Bundle("trust base JSON is not UTF-8"))?;
                Self::from_genesis(TrustBaseEntry::from_json(text)?, pin)
            }
            Some(0xd9) if rest.get(1..3) == Some(&[0x98, 0x58]) => {
                Self::from_genesis(TrustBaseEntry::from_cbor(contents)?, pin)
            }
            _ => Self::from_bundle(contents, pin),
        }
    }

    /// A history from entries the caller already trusts: the chain is checked (each entry's
    /// structure, same network, epoch plus one, rising start rounds, the predecessor's identity)
    /// but **no signature is verified**. For a history authenticated by other means (a release
    /// bundle shipped with the application, a conformance fixture); anything received from a
    /// peer goes through [`append`](Self::append) or [`install_bundle`](Self::install_bundle),
    /// which verify the predecessor's quorum. Unlike every other entry point it admits epoch 0
    /// (test environments and conformance fixtures, never a real network).
    pub fn from_trusted_chain(entries: Vec<TrustBaseEntry>) -> Result<Self, HistoryError> {
        let mut it = entries.into_iter();
        let genesis = it.next().ok_or(HistoryError::Bundle("no entries"))?;
        genesis.validate_inner(true)?;
        let mut h = TrustBaseHistory {
            entries: alloc::vec![genesis],
        };
        for e in it {
            e.validate_inner(true)?;
            let prev = h.latest();
            if e.network_id != prev.network_id {
                return Err(HistoryError::WrongNetwork);
            }
            if prev.epoch.checked_add(1) != Some(e.epoch) {
                return Err(HistoryError::Gap {
                    held: prev.epoch,
                    offered: e.epoch,
                });
            }
            if e.epoch_start <= prev.epoch_start {
                return Err(HistoryError::Entry(TrustBaseError::Chain(
                    "epoch start does not increase",
                )));
            }
            if e.previous_entry_id != prev.entry_id() {
                return Err(HistoryError::Entry(TrustBaseError::Chain(
                    "previous entry id does not match",
                )));
            }
            h.entries.push(e);
        }
        Ok(h)
    }

    /// Decode a tagged `GetTrustBase` response used as a release bundle: status OK, entries
    /// contiguous from a genesis entry to the release tip, no continuation. The chain is
    /// verified link by link (weighted quorum of each predecessor included); the genesis is
    /// taken as shipped, or compared with `pin` when given.
    pub fn from_bundle(bytes: &[u8], pin: Option<[u8; ID_LEN]>) -> Result<Self, HistoryError> {
        if bytes.len() > MAX_BUNDLE_BYTES {
            return Err(HistoryError::Bundle("bundle exceeds the size bound"));
        }
        let b = |m: &'static str| HistoryError::Bundle(m);
        let top = Decoder::new(bytes);
        top.finish().map_err(|_| b("malformed CBOR"))?;
        let inner = top
            .expect_tag(GET_TRUST_BASE_RESPONSE_TAG)
            .map_err(|_| b("not a GetTrustBase response (tag)"))?;
        let f = inner
            .array(Some(8))
            .map_err(|_| b("response is not an 8-element array"))?;
        let uint = |d: &Decoder<'_>| d.uint().map_err(|_| b("malformed integer"));
        if uint(&f[0])? != GET_TRUST_BASE_VERSION {
            return Err(b("response version is not 1"));
        }
        let network =
            NetworkId::new(u16::try_from(uint(&f[1])?).map_err(|_| b("network id out of range"))?)
                .map_err(|_| b("invalid network id"))?;
        if uint(&f[2])? != STATUS_OK {
            return Err(b("status is not OK"));
        }
        let from = uint(&f[3])?;
        let effective_end = uint(&f[4])?;
        let end_id: Option<[u8; ID_LEN]> = f[5]
            .nullable(|x| x.bytes_value().map(<[u8]>::to_vec).map_err(Into::into))
            .map_err(|_| b("malformed end entry id"))?
            .map(|v| <[u8; ID_LEN]>::try_from(v.as_slice()))
            .transpose()
            .map_err(|_| b("end entry id is not 32 bytes"))?;
        if !f[7].is_null() {
            return Err(b("a bundle has no continuation"));
        }
        let items = f[6]
            .array(None)
            .map_err(|_| b("entries are not an array"))?;
        if items.is_empty() || items.len() > MAX_BUNDLE_ENTRIES {
            return Err(b("entry count outside 1..=4096"));
        }
        let mut history: Option<TrustBaseHistory> = None;
        for item in &items {
            if item.bytes().len() > MAX_ENTRY_BYTES {
                return Err(b("entry exceeds the size bound"));
            }
            let entry = TrustBaseEntry::from_cbor(item.bytes())?;
            if entry.network_id != network {
                return Err(HistoryError::WrongNetwork);
            }
            match history.as_mut() {
                None => history = Some(Self::from_genesis(entry, pin)?),
                Some(h) => {
                    if h.append(entry)? != Appended::Added {
                        return Err(b("repeated entry"));
                    }
                }
            }
        }
        let history = history.ok_or_else(|| b("no entries"))?;
        if history.genesis().epoch != from {
            return Err(b("first entry is not the declared start epoch"));
        }
        if history.latest().epoch != effective_end {
            return Err(b("last entry is not the declared end epoch"));
        }
        if let Some(id) = end_id {
            if history.latest().entry_id() != id {
                return Err(b("last entry does not match the declared end identity"));
            }
        }
        Ok(history)
    }

    /// The genesis entry.
    pub fn genesis(&self) -> &TrustBaseEntry {
        &self.entries[0]
    }

    /// Identity of the genesis entry (what a deployment pins).
    pub fn genesis_id(&self) -> [u8; ID_LEN] {
        self.entries[0].entry_id()
    }

    /// The latest held entry.
    pub fn latest(&self) -> &TrustBaseEntry {
        &self.entries[self.entries.len() - 1]
    }

    /// The network of the history.
    pub fn network_id(&self) -> NetworkId {
        self.entries[0].network_id
    }

    /// The held entry of `epoch`.
    pub fn get(&self, epoch: u64) -> Option<&TrustBaseEntry> {
        let first = self.entries[0].epoch;
        epoch
            .checked_sub(first)
            .and_then(|i| usize::try_from(i).ok())
            .and_then(|i| self.entries.get(i))
    }

    /// All held entries in ascending epoch order.
    pub fn entries(&self) -> &[TrustBaseEntry] {
        &self.entries
    }

    /// Offer an entry. A held epoch with the same identity is [`Appended::AlreadyHeld`]
    /// (nothing changes); a held epoch with another identity is a conflict; the entry
    /// directly after the latest held one is verified from it (strict) and added; anything
    /// else is refused. Nothing is added unless every check passed.
    pub fn append(&mut self, entry: TrustBaseEntry) -> Result<Appended, HistoryError> {
        if entry.network_id != self.network_id() {
            return Err(HistoryError::WrongNetwork);
        }
        let first = self.entries[0].epoch;
        if entry.epoch < first {
            return Err(HistoryError::BeforeGenesis);
        }
        if let Some(held) = self.get(entry.epoch) {
            entry.validate()?;
            if held.entry_id() != entry.entry_id() {
                return Err(HistoryError::Conflict { epoch: entry.epoch });
            }
            // the same entry: a no-op, but only for a valid witness (the first one stays)
            if entry.epoch == first {
                entry.verify_genesis()?;
            } else if let Some(prev) = self.get(entry.epoch - 1) {
                entry.verify_successor(prev)?;
            }
            return Ok(Appended::AlreadyHeld);
        }
        let latest = self.latest();
        if latest.epoch.checked_add(1) != Some(entry.epoch) {
            return Err(HistoryError::Gap {
                held: latest.epoch,
                offered: entry.epoch,
            });
        }
        entry.verify_successor(latest)?;
        self.entries.push(entry);
        Ok(Appended::Added)
    }

    /// Merge a release bundle or `GetTrustBase` response into this history. The bundle is
    /// decoded and verified on its own first ([`from_bundle`](Self::from_bundle)); then every
    /// entry is offered in order (identical held entries are no-ops, a different entry of a
    /// held epoch or another genesis is a conflict). All or nothing: on any refusal this
    /// history is unchanged. Returns [`Appended::Added`] when the tip advanced.
    pub fn install_bundle(&mut self, bytes: &[u8]) -> Result<Appended, HistoryError> {
        let bundle = Self::from_bundle(bytes, None)?;
        if bundle.network_id() != self.network_id() {
            return Err(HistoryError::WrongNetwork);
        }
        if bundle.genesis().entry_id() != self.genesis_id() {
            return Err(HistoryError::Conflict {
                epoch: self.genesis().epoch,
            });
        }
        let mut merged = self.clone();
        let mut advanced = false;
        for e in bundle.entries {
            if merged.append(e)? == Appended::Added {
                advanced = true;
            }
        }
        *self = merged;
        Ok(if advanced {
            Appended::Added
        } else {
            Appended::AlreadyHeld
        })
    }

    /// Offer entries in order. Stops at the first refusal; entries added before it stay (a
    /// verified entry is valid by itself). Returns how many were added.
    pub fn extend<I: IntoIterator<Item = TrustBaseEntry>>(
        &mut self,
        entries: I,
    ) -> Result<usize, HistoryError> {
        let mut added = 0;
        for e in entries {
            if self.append(e)? == Appended::Added {
                added += 1;
            }
        }
        Ok(added)
    }

    /// Encode the history as a release bundle (tagged `GetTrustBase` response, status OK).
    pub fn to_bundle(&self) -> Vec<u8> {
        use crate::cbor::{encode_array, encode_byte_string, encode_null, encode_tag, encode_uint};
        let raw: Vec<Vec<u8>> = self.entries.iter().map(TrustBaseEntry::to_cbor).collect();
        let refs: Vec<&[u8]> = raw.iter().map(Vec::as_slice).collect();
        let inner = encode_array(&[
            &encode_uint(GET_TRUST_BASE_VERSION),
            &encode_uint(u64::from(self.network_id().id())),
            &encode_uint(STATUS_OK),
            &encode_uint(self.genesis().epoch),
            &encode_uint(self.latest().epoch),
            &encode_byte_string(&self.latest().entry_id()),
            &encode_array(&refs),
            &encode_null(),
        ]);
        encode_tag(GET_TRUST_BASE_RESPONSE_TAG, &inner)
    }
}
