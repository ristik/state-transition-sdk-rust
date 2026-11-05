//! The Trust Base cache: release pins, a storage-agnostic store contract and an
//! open/merge/flush session over a [`TrustBaseHistory`] (design: `briefs/utb-cache-design.md`).
//!
//! * **Core only.** No filesystem, browser storage or HTTP; `alloc`/`no_std` compatible. The
//!   caller supplies a [`TrustBaseStore`] (an in-memory one ships here), the transport and the
//!   refresh timing; futures are caller-driven.
//! * **Cached bytes have exactly the trust of fetched bytes.** Every entry of the embedded
//!   release bundle and of the cache is verified strictly from the authenticated genesis on
//!   each open; nothing is trusted for its name, age or revision.
//! * **Pins.** A [`PinSpec`] holds the complete history from genesis to the release tip and
//!   both identities. A cache diverging at or before the checkpoint is rejected
//!   ([`CacheReject::PinMismatch`]), never an alternative authority.
//! * **Conflicts.** An authenticated fork after the checkpoint latches the session
//!   ([`SessionError::Conflict`], then [`SessionError::HistoryConflicted`] on every later
//!   use); the latch is process-local, not a persistent guarantee.
//! * **CAS saves.** One complete bundle per flush, written by compare-and-swap against the
//!   revision just read and validated; a changed revision is retried at most three times.

use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::fmt;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

use super::trust_base_entry::{TrustBaseEntry, ID_LEN};
use super::trust_base_history::{Appended, BundleLimits, HistoryError, TrustBaseHistory};
use crate::api::NetworkId;
use crate::crypto::hash::sha256;

/// Version of the store key layout.
pub const STORE_KEY_VERSION: &str = "v1";
/// The trust namespace of the built-in release table.
pub const PUBLIC_NAMESPACE: &str = "public";
/// Writes retried after a changed revision, per flush.
pub const MAX_CAS_ATTEMPTS: usize = 3;
/// Longest custom namespace.
pub const MAX_NAMESPACE_BYTES: usize = 64;

/// The immutable release table. Every row is a vendored, reviewed asset; the table ships
/// **empty** until the owner approves the public bundles.
pub const RELEASE_PINS: &[ReleasePinRow] = &[];

/// One row of the release table (static assets).
#[derive(Debug, Clone, Copy)]
pub struct ReleasePinRow {
    /// Network.
    pub network_id: u16,
    /// Epoch of the genesis entry.
    pub genesis_epoch: u64,
    /// Identity of the genesis entry.
    pub genesis_entry_id: [u8; ID_LEN],
    /// Epoch of the release tip.
    pub pinned_epoch: u64,
    /// Identity of the release tip.
    pub pinned_entry_id: [u8; ID_LEN],
    /// The complete history, genesis to the tip, as a tag-39015 bundle.
    pub bundle: &'static [u8],
    /// SHA-256 of `bundle`.
    pub bundle_sha256: [u8; 32],
}

impl ReleasePinRow {
    /// The row as an owned [`PinSpec`].
    pub fn to_spec(&self) -> Result<PinSpec, CacheError> {
        Ok(PinSpec {
            network_id: NetworkId::new(self.network_id)
                .map_err(|_| CacheError::ReleasePinInvalid("invalid network id"))?,
            genesis_epoch: self.genesis_epoch,
            genesis_entry_id: self.genesis_entry_id,
            pinned_epoch: self.pinned_epoch,
            pinned_entry_id: self.pinned_entry_id,
            bundle: self.bundle.to_vec(),
            bundle_sha256: self.bundle_sha256,
        })
    }
}

/// An authenticated pin: a complete embedded history and the identities that bind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinSpec {
    /// Network.
    pub network_id: NetworkId,
    /// Epoch of the genesis entry.
    pub genesis_epoch: u64,
    /// Identity of the genesis entry.
    pub genesis_entry_id: [u8; ID_LEN],
    /// Epoch of the release tip (the checkpoint).
    pub pinned_epoch: u64,
    /// Identity of the release tip.
    pub pinned_entry_id: [u8; ID_LEN],
    /// The complete history, genesis to exactly the tip, as a tag-39015 bundle.
    pub bundle: Vec<u8>,
    /// SHA-256 of `bundle`.
    pub bundle_sha256: [u8; 32],
}

impl PinSpec {
    /// Verify the pin and return its history: digest, structure, every predecessor signature,
    /// both identities and both epochs. Anything wrong is the fatal `ReleasePinInvalid`.
    pub fn verify(&self, limits: &BundleLimits) -> Result<TrustBaseHistory, CacheError> {
        let bad = CacheError::ReleasePinInvalid;
        if sha256(&self.bundle).data() != self.bundle_sha256.as_slice() {
            return Err(bad("bundle digest differs from the pin"));
        }
        let h =
            TrustBaseHistory::from_bundle_with(&self.bundle, Some(self.genesis_entry_id), limits)
                .map_err(|_| bad("embedded bundle does not verify"))?;
        if h.network_id() != self.network_id {
            return Err(bad("embedded bundle is of another network"));
        }
        if h.genesis().epoch != self.genesis_epoch {
            return Err(bad("genesis epoch differs from the pin"));
        }
        if h.latest().epoch != self.pinned_epoch || h.latest().entry_id() != self.pinned_entry_id {
            return Err(bad("tip differs from the pin"));
        }
        Ok(h)
    }
}

/// Where the authority of a session comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Authority {
    /// The built-in release table row of the network (namespace `public`).
    Release,
    /// A public network with a newer pin: has to extend the release lineage and contain its
    /// checkpoint.
    ReleaseOverride(PinSpec),
    /// An explicit private or test authority in its own namespace (never `public`).
    Custom {
        /// The trust namespace; storage and memoization are never shared with another.
        namespace: String,
        /// The authenticated pin.
        pin: PinSpec,
    },
}

/// The key of one cached history: layout version, network, genesis identity, trust
/// namespace. Endpoints, tips and SDK versions are not part of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreKey(pub String);

impl StoreKey {
    /// `utb/v1/<network decimal>/<genesis id hex>/<namespace>`.
    pub fn new(network: NetworkId, genesis_id: &[u8; ID_LEN], namespace: &str) -> Self {
        StoreKey(alloc::format!(
            "utb/{}/{}/{}/{}",
            STORE_KEY_VERSION,
            network.id(),
            hex::encode(genesis_id),
            namespace
        ))
    }
}

/// A store revision: an opaque token bound to the read contents (here a content digest). Not
/// authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revision(pub Vec<u8>);

impl Revision {
    /// The revision token of `bytes`: SHA-256.
    pub fn of(bytes: &[u8]) -> Self {
        Revision(sha256(bytes).data().to_vec())
    }
}

/// A store read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreRead {
    /// Nothing stored under the key.
    Absent,
    /// A coherent snapshot.
    Present {
        /// Revision of exactly these bytes.
        revision: Revision,
        /// The stored bundle.
        bytes: Vec<u8>,
    },
}

/// A store compare-and-swap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreCas {
    /// Replaced; the new revision.
    Written(Revision),
    /// The stored revision is not the expected one; nothing changed.
    Changed,
}

/// A typed storage failure.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StoreError {
    /// The stored value exceeds the read budget (checked before allocating).
    TooLarge,
    /// Another process holds the store.
    Busy,
    /// No permission.
    Permission,
    /// Out of space or quota.
    Quota,
    /// Any other I/O failure.
    Io(String),
}

/// Async storage of complete bundles. A successful compare-and-swap atomically compares and
/// replaces across all cooperating writers; reads return coherent snapshots.
#[allow(async_fn_in_trait)]
pub trait TrustBaseStore {
    /// Read the value under `key`, refusing a value larger than `max_bytes` before allocating.
    async fn read(&self, key: &StoreKey, max_bytes: usize) -> Result<StoreRead, StoreError>;
    /// Replace the value if its revision is `expected` (`None`: absent).
    async fn compare_and_swap(
        &self,
        key: &StoreKey,
        expected: Option<&Revision>,
        bytes: &[u8],
    ) -> Result<StoreCas, StoreError>;
}

impl<T: TrustBaseStore + ?Sized> TrustBaseStore for &T {
    async fn read(&self, key: &StoreKey, max_bytes: usize) -> Result<StoreRead, StoreError> {
        (**self).read(key, max_bytes).await
    }
    async fn compare_and_swap(
        &self,
        key: &StoreKey,
        expected: Option<&Revision>,
        bytes: &[u8],
    ) -> Result<StoreCas, StoreError> {
        (**self).compare_and_swap(key, expected, bytes).await
    }
}

/// The in-memory store (single-threaded interior mutability; the contract is identical to a
/// durable store's).
#[derive(Debug, Default)]
pub struct MemoryStore {
    map: RefCell<Vec<(StoreKey, Vec<u8>)>>,
}

impl MemoryStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Put `bytes` under `key`, bypassing compare-and-swap (test setup or a competing writer).
    pub fn put(&self, key: &StoreKey, bytes: &[u8]) {
        let mut m = self.map.borrow_mut();
        match m.iter_mut().find(|(k, _)| k == key) {
            Some(slot) => slot.1 = bytes.to_vec(),
            None => m.push((key.clone(), bytes.to_vec())),
        }
    }

    /// The bytes under `key`.
    pub fn get(&self, key: &StoreKey) -> Option<Vec<u8>> {
        self.map
            .borrow()
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
    }
}

impl TrustBaseStore for MemoryStore {
    async fn read(&self, key: &StoreKey, max_bytes: usize) -> Result<StoreRead, StoreError> {
        match self.get(key) {
            None => Ok(StoreRead::Absent),
            Some(b) if b.len() > max_bytes => Err(StoreError::TooLarge),
            Some(b) => Ok(StoreRead::Present {
                revision: Revision::of(&b),
                bytes: b,
            }),
        }
    }

    async fn compare_and_swap(
        &self,
        key: &StoreKey,
        expected: Option<&Revision>,
        bytes: &[u8],
    ) -> Result<StoreCas, StoreError> {
        let current = self.get(key).map(|b| Revision::of(&b));
        if current.as_ref() != expected {
            return Ok(StoreCas::Changed);
        }
        self.put(key, bytes);
        Ok(StoreCas::Written(Revision::of(bytes)))
    }
}

/// Why a cache was not used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheReject {
    /// Not a complete canonical bundle that verifies strictly from its genesis.
    Malformed,
    /// A bundle of another network.
    WrongNetwork,
    /// A bundle of another genesis.
    WrongGenesis,
    /// Diverges from, or does not reach, the release checkpoint.
    PinMismatch,
    /// Larger than the read budget.
    Oversize,
}

/// A non-fatal observation of [`open`](Session::open) or [`flush`](Session::flush); the app
/// decides how to present it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Diagnostic {
    /// The cache was rejected and the embedded history used.
    CacheRejected(CacheReject),
    /// The cache could not be read; the embedded history is used.
    CacheUnavailable(StoreError),
}

/// A fatal failure to open, or a pending persistence failure.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CacheError {
    /// The embedded asset is invalid: never rescued by a cache or remote source.
    ReleasePinInvalid(&'static str),
    /// No pin for the network.
    UnknownNetwork,
    /// An override or a custom authority is not acceptable (older, conflicting, or a bad
    /// namespace).
    PinMismatch,
    /// Storage failed; verified in-memory history is unaffected.
    Unavailable(StoreError),
    /// The compare-and-swap lost the race on every attempt; retry later.
    Contended,
    /// The session is conflicted (or the store holds an authenticated fork): nothing is
    /// written.
    HistoryConflicted,
}

impl fmt::Display for CacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CacheError::ReleasePinInvalid(m) => write!(f, "ReleasePinInvalid: {m}"),
            CacheError::UnknownNetwork => write!(f, "UnknownNetwork"),
            CacheError::PinMismatch => write!(f, "PinMismatch"),
            CacheError::Unavailable(e) => write!(f, "CacheUnavailable: {e:?}"),
            CacheError::Contended => write!(f, "CacheContended"),
            CacheError::HistoryConflicted => write!(f, "HistoryConflicted"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CacheError {}

/// Evidence of an authenticated fork after the checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConflictEvidence {
    /// Network.
    pub network: NetworkId,
    /// Epoch of the fork.
    pub epoch: u64,
    /// Identity of the held entry.
    pub held_entry_id: [u8; ID_LEN],
    /// Identity of the offered entry.
    pub offered_entry_id: [u8; ID_LEN],
    /// The held entry's bytes (bounded by the entry limit).
    pub held_bytes: Vec<u8>,
    /// The offered entry's bytes.
    pub offered_bytes: Vec<u8>,
}

/// Why an offer to the session failed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionError {
    /// An ordinary refusal (invalid witness, gap, parse error): nothing latches.
    Refused(HistoryError),
    /// The entry disagrees with the release checkpoint (at or before the pinned epoch): the
    /// checkpoint selects authority; the session is not poisoned.
    PinMismatch,
    /// An authenticated fork after the checkpoint: this session is now conflicted.
    Conflict(alloc::boxed::Box<ConflictEvidence>),
    /// The session is conflicted; every append, refresh and verification fails.
    HistoryConflicted,
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionError::Refused(e) => write!(f, "{e}"),
            SessionError::PinMismatch => write!(f, "PinMismatch"),
            SessionError::Conflict(c) => write!(f, "Conflict at epoch {}", c.epoch),
            SessionError::HistoryConflicted => write!(f, "HistoryConflicted"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SessionError {}

/// Options of a session (resource policy).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionOptions {
    /// Bundle bounds for the embedded pin, the cache and merged bundles.
    pub limits: BundleLimits,
    /// Yield to the executor after this many verified entries when loading a bundle; 0 never.
    pub yield_every: usize,
}

impl Default for SessionOptions {
    fn default() -> Self {
        SessionOptions {
            limits: BundleLimits::default(),
            yield_every: 64,
        }
    }
}

/// The result of [`Session::flush`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Flush {
    /// The store holds the session's complete history (`wrote`: false when it already did).
    Saved {
        /// Whether bytes were written.
        wrote: bool,
        /// A damaged cache that was replaced, reported before replacement.
        diagnostics: Vec<Diagnostic>,
    },
    /// Not saved; the session stays dirty and verified.
    Pending(CacheError),
}

struct YieldNow(bool);

impl Future for YieldNow {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.0 {
            return Poll::Ready(());
        }
        self.0 = true;
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

/// An open history bound to a store. Mutations are serialized by `&mut self`.
pub struct Session<S: TrustBaseStore> {
    store: S,
    key: StoreKey,
    pinned_epoch: u64,
    history: TrustBaseHistory,
    dirty: bool,
    conflict: Option<ConflictEvidence>,
    options: SessionOptions,
}

enum Loaded {
    Ok(TrustBaseHistory),
    Reject(CacheReject),
}

fn classify(e: &HistoryError) -> CacheReject {
    match e {
        HistoryError::WrongNetwork => CacheReject::WrongNetwork,
        HistoryError::PinMismatch => CacheReject::WrongGenesis,
        _ => CacheReject::Malformed,
    }
}

impl<S: TrustBaseStore> Session<S> {
    /// Select the authority, verify the pin, read the cache and merge. The embedded history is
    /// the fallback of any unusable cache; nothing is written.
    pub async fn open(
        network: NetworkId,
        authority: Authority,
        store: S,
        options: SessionOptions,
    ) -> Result<(Self, Vec<Diagnostic>), CacheError> {
        Self::open_in(RELEASE_PINS, network, authority, store, options).await
    }

    /// [`open`](Self::open) over an explicit release table (tests and release tooling; the
    /// built-in table is [`RELEASE_PINS`]).
    pub async fn open_in(
        table: &[ReleasePinRow],
        network: NetworkId,
        authority: Authority,
        store: S,
        options: SessionOptions,
    ) -> Result<(Self, Vec<Diagnostic>), CacheError> {
        let (namespace, pin) = Self::select(table, network, authority, &options)?;
        let embedded = pin.verify(&options.limits)?;
        let key = StoreKey::new(network, &pin.genesis_entry_id, &namespace);
        let mut diagnostics = Vec::new();
        let max = options.limits.max_bytes;
        let mut session = Session {
            store,
            key,
            pinned_epoch: pin.pinned_epoch,
            history: embedded,
            dirty: false,
            conflict: None,
            options,
        };
        match session.store.read(&session.key, max).await {
            Ok(StoreRead::Absent) => {}
            Ok(StoreRead::Present { bytes, .. }) => {
                match session.load_cache(&bytes).await {
                    Loaded::Ok(cache) => {
                        if cache.latest().epoch > session.history.latest().epoch {
                            // a longer compatible cache is the held history (first held
                            // witnesses are kept; an older SDK never truncates it)
                            session.history = cache;
                        } else {
                            // a shorter prefix is extended from the embedded bundle
                            session.dirty = cache.latest().epoch < session.history.latest().epoch;
                        }
                    }
                    Loaded::Reject(r) => {
                        diagnostics.push(Diagnostic::CacheRejected(r));
                    }
                }
            }
            Err(StoreError::TooLarge) => {
                diagnostics.push(Diagnostic::CacheRejected(CacheReject::Oversize))
            }
            Err(e) => diagnostics.push(Diagnostic::CacheUnavailable(e)),
        }
        Ok((session, diagnostics))
    }

    fn select(
        table: &[ReleasePinRow],
        network: NetworkId,
        authority: Authority,
        options: &SessionOptions,
    ) -> Result<(String, PinSpec), CacheError> {
        let row = table.iter().find(|r| r.network_id == network.id());
        match authority {
            Authority::Release => {
                let row = row.ok_or(CacheError::UnknownNetwork)?;
                Ok((String::from(PUBLIC_NAMESPACE), row.to_spec()?))
            }
            Authority::ReleaseOverride(spec) => {
                let row = row.ok_or(CacheError::UnknownNetwork)?;
                if spec.network_id != network {
                    return Err(CacheError::PinMismatch);
                }
                row.to_spec()?.verify(&options.limits)?;
                let over = spec.verify(&options.limits)?;
                let contains = over
                    .get(row.pinned_epoch)
                    .is_some_and(|e| e.entry_id() == row.pinned_entry_id);
                if over.genesis_id() != row.genesis_entry_id || !contains {
                    return Err(CacheError::PinMismatch);
                }
                Ok((String::from(PUBLIC_NAMESPACE), spec))
            }
            Authority::Custom { namespace, pin } => {
                if namespace.is_empty()
                    || namespace.len() > MAX_NAMESPACE_BYTES
                    || namespace == PUBLIC_NAMESPACE
                    || namespace.contains('/')
                    || pin.network_id != network
                {
                    return Err(CacheError::PinMismatch);
                }
                Ok((namespace, pin))
            }
        }
    }

    /// Strictly load cache bytes from the pinned genesis, then check them against the
    /// checkpoint. Staged: nothing is published here.
    async fn load_cache(&self, bytes: &[u8]) -> Loaded {
        let parsed = match TrustBaseHistory::parse_bundle(bytes, &self.options.limits) {
            Ok(p) => p,
            Err(e) => return Loaded::Reject(classify(&e)),
        };
        if parsed.network != self.history.network_id() {
            return Loaded::Reject(CacheReject::WrongNetwork);
        }
        let genesis = Some(self.history.genesis_id());
        let mut h: Option<TrustBaseHistory> = None;
        for (i, e) in parsed.entries.iter().cloned().enumerate() {
            if self.options.yield_every != 0 && i != 0 && i % self.options.yield_every == 0 {
                YieldNow(false).await;
            }
            match TrustBaseHistory::accept_bundle_entry(h.take(), e, genesis) {
                Ok(n) => h = Some(n),
                Err(e) => return Loaded::Reject(classify(&e)),
            }
        }
        let cache = match TrustBaseHistory::finish_bundle(h, &parsed) {
            Ok(c) => c,
            Err(e) => return Loaded::Reject(classify(&e)),
        };
        // agree with the checkpoint over the overlap, and reach it when longer
        let overlap = cache.latest().epoch.min(self.pinned_epoch);
        let same = |epoch: u64| match (cache.get(epoch), self.history.get(epoch)) {
            (Some(a), Some(b)) => a.entry_id() == b.entry_id(),
            _ => false,
        };
        if !same(overlap) {
            return Loaded::Reject(CacheReject::PinMismatch);
        }
        Loaded::Ok(cache)
    }

    /// The immutable history view for verification. Fails for a conflicted session.
    pub fn history(&self) -> Result<&TrustBaseHistory, SessionError> {
        match self.conflict {
            Some(_) => Err(SessionError::HistoryConflicted),
            None => Ok(&self.history),
        }
    }

    /// The held history as a complete bundle. Available also after a conflict (evidence and
    /// export stay available).
    pub fn export_bundle(&self) -> Vec<u8> {
        self.history.to_bundle()
    }

    /// The conflict evidence, available for export after the session latched.
    pub fn conflict(&self) -> Option<&ConflictEvidence> {
        self.conflict.as_ref()
    }

    /// The session's key in the store.
    pub fn key(&self) -> &StoreKey {
        &self.key
    }

    /// Whether the history holds entries the store may not.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Offer one entry (a fetched one). Valid entries mark the session dirty.
    pub fn append(&mut self, entry: TrustBaseEntry) -> Result<Appended, SessionError> {
        if self.conflict.is_some() {
            return Err(SessionError::HistoryConflicted);
        }
        let offered_bytes = entry.to_cbor();
        match self.history.append(entry) {
            Ok(a) => {
                if a == Appended::Added {
                    self.dirty = true;
                }
                Ok(a)
            }
            Err(HistoryError::Conflict {
                network,
                epoch,
                held,
                offered,
            }) => {
                if epoch <= self.pinned_epoch {
                    return Err(SessionError::PinMismatch);
                }
                let held_bytes = self
                    .history
                    .get(epoch)
                    .map(TrustBaseEntry::to_cbor)
                    .unwrap_or_default();
                let ev = ConflictEvidence {
                    network,
                    epoch,
                    held_entry_id: held,
                    offered_entry_id: offered,
                    held_bytes,
                    offered_bytes,
                };
                self.conflict = Some(ev.clone());
                Err(SessionError::Conflict(alloc::boxed::Box::new(ev)))
            }
            Err(HistoryError::PinMismatch) => Err(SessionError::PinMismatch),
            Err(e) => Err(SessionError::Refused(e)),
        }
    }

    /// Offer a fetched bundle or response page in order. Entries verified before a refusal
    /// stay (each is valid by itself). Returns how many were added.
    pub async fn merge_bundle(&mut self, bytes: &[u8]) -> Result<usize, SessionError> {
        let parsed = TrustBaseHistory::parse_bundle(bytes, &self.options.limits)
            .map_err(SessionError::Refused)?;
        if parsed.network != self.history.network_id() {
            return Err(SessionError::Refused(HistoryError::WrongNetwork));
        }
        let mut added = 0;
        for (i, e) in parsed.entries.into_iter().enumerate() {
            if self.options.yield_every != 0 && i != 0 && i % self.options.yield_every == 0 {
                YieldNow(false).await;
            }
            if self.append(e)? == Appended::Added {
                added += 1;
            }
        }
        Ok(added)
    }

    /// Save one complete bundle. Rereads and fully validates the stored bytes under the pin,
    /// imports compatible new entries, keeps the longer suffix, and writes by compare-and-swap
    /// against the revision just read; a changed revision is retried at most
    /// [`MAX_CAS_ATTEMPTS`] times in total. A damaged cache is replaced only against its exact
    /// observed revision and after being reported. An authenticated fork in the store is never
    /// overwritten: the session latches.
    pub async fn flush(&mut self) -> Flush {
        if self.conflict.is_some() {
            return Flush::Pending(CacheError::HistoryConflicted);
        }
        let mut diagnostics = Vec::new();
        for _ in 0..MAX_CAS_ATTEMPTS {
            let read = match self
                .store
                .read(&self.key, self.options.limits.max_bytes)
                .await
            {
                Ok(r) => r,
                Err(e) => return Flush::Pending(CacheError::Unavailable(e)),
            };
            let (expected, disk_tip) = match read {
                StoreRead::Absent => (None, None),
                StoreRead::Present { revision, bytes } => match self.load_cache(&bytes).await {
                    Loaded::Ok(h) => {
                        // import what the store holds past the checkpoint; a fork latches
                        let pinned = self.pinned_epoch;
                        for e in h.entries().iter().filter(|e| e.epoch > pinned) {
                            match self.append(e.clone()) {
                                Ok(_) => {}
                                Err(SessionError::PinMismatch) | Err(SessionError::Refused(_)) => {
                                    return Flush::Pending(CacheError::PinMismatch)
                                }
                                Err(_) => return Flush::Pending(CacheError::HistoryConflicted),
                            }
                        }
                        (Some(revision), Some(h.latest().entry_id()))
                    }
                    Loaded::Reject(r) => {
                        diagnostics.push(Diagnostic::CacheRejected(r));
                        (Some(revision), None)
                    }
                },
            };
            let ours = self.history.latest().entry_id();
            if disk_tip == Some(ours) || (expected.is_none() && !self.dirty) {
                // the store holds this history (other valid witnesses are not worth a
                // rewrite), or there is nothing of ours to save
                self.dirty = false;
                return Flush::Saved {
                    wrote: false,
                    diagnostics,
                };
            }
            let out = self.history.to_bundle();
            match self
                .store
                .compare_and_swap(&self.key, expected.as_ref(), &out)
                .await
            {
                Ok(StoreCas::Written(_)) => {
                    self.dirty = false;
                    return Flush::Saved {
                        wrote: true,
                        diagnostics,
                    };
                }
                Ok(StoreCas::Changed) => continue,
                Err(e) => return Flush::Pending(CacheError::Unavailable(e)),
            }
        }
        Flush::Pending(CacheError::Contended)
    }
}

impl<S: TrustBaseStore> fmt::Debug for Session<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("key", &self.key)
            .field("tip", &self.history.latest().epoch)
            .field("dirty", &self.dirty)
            .field("conflicted", &self.conflict.is_some())
            .finish_non_exhaustive()
    }
}
