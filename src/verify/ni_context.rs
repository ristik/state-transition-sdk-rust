//! The verification context and the discriminated result of a non-inclusion proof.
//!
//! A non-inclusion proof is a statement about **one partition's** certified root at
//! one root round. Authenticating the unicity certificate under the trust base proves
//! the statement for that snapshot only. The partition is the fixed
//! [`AGGREGATION_PARTITION_ID`](crate::api::AGGREGATION_PARTITION_ID); the
//! [`NonInclusionContext`] carries the optional pins of the caller, which come from
//! the caller's own configuration or authenticated history, never from the proof or
//! an aggregator response. Freshness is a decision of the caller *after* verification,
//! made on the returned [`NonInclusionSnapshot`].

use crate::api::bft::ShardId;
use crate::api::{NetworkId, StateId};
use crate::crypto::hash::{DataHasher, HashAlgorithm};

/// What a verified non-inclusion proof must additionally satisfy.
///
/// Built with [`new`](Self::new) and the `with_*` methods; the expectations are
/// immutable once the verification runs and are part of the identity under which
/// authentication verdicts are reused, so a verdict reached under one context is
/// never inherited by another. The default context pins nothing: the network,
/// authority, epoch interval, quorum and the fixed partition are always enforced.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NonInclusionContext {
    shard: Option<ShardId>,
    shard_conf_hash: Option<[u8; 32]>,
    authority_end_round: Option<u64>,
}

impl NonInclusionContext {
    /// A context without optional pins.
    pub fn new() -> Self {
        Self::default()
    }

    /// Expect the certificate of exactly this shard (otherwise any shard that
    /// contains the target passes the existing membership checks).
    pub fn with_shard(mut self, shard: ShardId) -> Self {
        self.shard = Some(shard);
        self
    }

    /// Pin the shard configuration hash the certificate must commit to.
    pub fn with_shard_conf_hash(mut self, hash: [u8; 32]) -> Self {
        self.shard_conf_hash = Some(hash);
        self
    }

    /// The first root round that is *not* governed by the verifying authority: from
    /// the authenticated authority history (the next epoch's start, or a known
    /// retirement boundary). A seal at or after it is rejected. Never infer it from
    /// the proof.
    pub fn with_authority_end_round(mut self, round: u64) -> Self {
        self.authority_end_round = Some(round);
        self
    }

    pub(crate) fn shard(&self) -> Option<&ShardId> {
        self.shard.as_ref()
    }

    pub(crate) fn shard_conf_hash(&self) -> Option<&[u8; 32]> {
        self.shard_conf_hash.as_ref()
    }

    pub(crate) fn authority_end_round(&self) -> Option<u64> {
        self.authority_end_round
    }
}

/// The authenticated snapshot a non-inclusion verification speaks about. Every field comes
/// from the authenticated unicity certificate (its seal and input record), never from RPC
/// block metadata or receipt time.
///
/// **Non-inclusion proves absence only at the authenticated snapshot returned by verification.
/// It does not prove absence now, continuous absence, or that a token can be spent. Compare the
/// snapshot’s network and root round (or its certified seal timestamp under your application's
/// time policy) with an independently trusted requirement. The seal timestamp is a
/// consensus-certified time, not proof of real-time freshness. Do not use unverified response
/// metadata for this check.**
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonInclusionSnapshot {
    pub(crate) network_id: NetworkId,
    pub(crate) partition_id: u32,
    pub(crate) shard_id: ShardId,
    pub(crate) root_round: u64,
    pub(crate) seal_timestamp_seconds: u64,
    pub(crate) root_epoch: u64,
    pub(crate) shard_round: u64,
    pub(crate) shard_epoch: u64,
    pub(crate) state_root: Option<[u8; 32]>,
}

impl NonInclusionSnapshot {
    /// The network the seal belongs to.
    pub fn network_id(&self) -> NetworkId {
        self.network_id
    }

    /// The partition (always the fixed aggregation partition).
    pub fn partition_id(&self) -> u32 {
        self.partition_id
    }

    /// The certified shard.
    pub fn shard_id(&self) -> &ShardId {
        &self.shard_id
    }

    /// The root chain round of the seal.
    pub fn root_round(&self) -> u64 {
        self.root_round
    }

    /// The seal's certified timestamp in Unix seconds (consensus time, not real-time freshness).
    pub fn seal_timestamp_seconds(&self) -> u64 {
        self.seal_timestamp_seconds
    }

    /// The root chain epoch of the seal.
    pub fn root_epoch(&self) -> u64 {
        self.root_epoch
    }

    /// The shard's round number from the certified input record.
    pub fn shard_round(&self) -> u64 {
        self.shard_round
    }

    /// The shard's epoch from the certified input record.
    pub fn shard_epoch(&self) -> u64 {
        self.shard_epoch
    }

    /// The certified state-tree root; `None` is the certified empty tree.
    pub fn state_root(&self) -> Option<[u8; 32]> {
        self.state_root
    }
}

/// The result of a successful (authenticated) non-inclusion verification.
///
/// A rejected proof is an `Err` and carries **no** snapshot metadata.
///
/// **Non-inclusion proves absence only at the authenticated snapshot returned by verification.
/// It does not prove absence now, continuous absence, or that a token can be spent. Compare the
/// snapshot’s network and root round (or its certified seal timestamp under your application's
/// time policy) with an independently trusted requirement. The seal timestamp is a
/// consensus-certified time, not proof of real-time freshness. Do not use unverified response
/// metadata for this check.**
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NonInclusionOutcome {
    /// The queried state is absent at `snapshot`.
    AbsentAtSnapshot {
        /// The queried state id.
        state_id: StateId,
        /// The authenticated snapshot.
        snapshot: NonInclusionSnapshot,
    },
    /// A valid path proves the queried state is **present** at `snapshot`.
    IncludedAtSnapshot {
        /// The queried state id.
        state_id: StateId,
        /// The authenticated snapshot.
        snapshot: NonInclusionSnapshot,
    },
}

impl NonInclusionOutcome {
    /// The authenticated snapshot.
    pub fn snapshot(&self) -> &NonInclusionSnapshot {
        match self {
            Self::AbsentAtSnapshot { snapshot, .. } | Self::IncludedAtSnapshot { snapshot, .. } => {
                snapshot
            }
        }
    }

    /// The queried state id.
    pub fn state_id(&self) -> &StateId {
        match self {
            Self::AbsentAtSnapshot { state_id, .. } | Self::IncludedAtSnapshot { state_id, .. } => {
                state_id
            }
        }
    }

    /// `true` only for [`AbsentAtSnapshot`](Self::AbsentAtSnapshot).
    pub fn is_absent(&self) -> bool {
        matches!(self, Self::AbsentAtSnapshot { .. })
    }
}

/// The verdict namespace of the strict non-inclusion check. Distinct from the legacy
/// namespace (all zero) of ordinary proofs.
pub(crate) fn digest_of(c: &NonInclusionContext) -> [u8; 32] {
    let mut h = DataHasher::new(HashAlgorithm::Sha256)
        .expect("sha256")
        .update(b"unicity-token/non-inclusion-policy/v2")
        .update(&crate::api::AGGREGATION_PARTITION_ID.to_be_bytes());
    let opt = |present: bool| [u8::from(present)];
    h = h.update(&opt(c.shard.is_some()));
    if let Some(s) = &c.shard {
        let e = s.encode();
        h = h.update(&(e.len() as u64).to_be_bytes()).update(&e);
    }
    h = h.update(&opt(c.shard_conf_hash.is_some()));
    if let Some(x) = &c.shard_conf_hash {
        h = h.update(x);
    }
    h = h.update(&opt(c.authority_end_round.is_some()));
    if let Some(r) = c.authority_end_round {
        h = h.update(&r.to_be_bytes());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().data());
    out
}
