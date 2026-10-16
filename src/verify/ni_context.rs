//! The verification context of a non-inclusion proof.
//!
//! A non-inclusion proof is a statement about **one partition's** certified root at
//! one root round. Authenticating the unicity certificate under the trust base is
//! necessary but says nothing about *which* partition, shard or configuration the
//! certificate is for, nor how fresh it is. [`NonInclusionContext`] carries the
//! caller's expectations; every field comes from the caller's own configuration or
//! authenticated history, never from the proof or an aggregator response.

use crate::api::bft::ShardId;
use crate::crypto::hash::{DataHasher, HashAlgorithm};

/// What a verified non-inclusion proof must additionally satisfy.
///
/// Built with [`new`](Self::new) and the `with_*` methods; the expectations are
/// immutable once the verification runs and are part of the identity under which
/// authentication verdicts are reused, so a verdict reached under one context is
/// never inherited by another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonInclusionContext {
    partition_id: u32,
    shard: Option<ShardId>,
    shard_conf_hash: Option<[u8; 32]>,
    min_root_round: Option<u64>,
    authority_end_round: Option<u64>,
}

impl NonInclusionContext {
    /// Expect a certificate of `partition_id`.
    pub fn new(partition_id: u32) -> Self {
        Self {
            partition_id,
            shard: None,
            shard_conf_hash: None,
            min_root_round: None,
            authority_end_round: None,
        }
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

    /// Require a root round of at least `round`: an authenticated certificate that
    /// is older is a valid statement about the past, not about the freshness the
    /// caller needs.
    pub fn with_min_root_round(mut self, round: u64) -> Self {
        self.min_root_round = Some(round);
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

    /// The expected partition.
    pub fn partition_id(&self) -> u32 {
        self.partition_id
    }

    pub(crate) fn shard(&self) -> Option<&ShardId> {
        self.shard.as_ref()
    }

    pub(crate) fn shard_conf_hash(&self) -> Option<&[u8; 32]> {
        self.shard_conf_hash.as_ref()
    }

    pub(crate) fn min_root_round(&self) -> Option<u64> {
        self.min_root_round
    }

    pub(crate) fn authority_end_round(&self) -> Option<u64> {
        self.authority_end_round
    }
}

/// The verdict namespace of the strict non-inclusion check, with or without a
/// context. Distinct from the legacy namespace (all zero) of ordinary proofs.
pub(crate) fn digest_of(context: Option<&NonInclusionContext>) -> [u8; 32] {
    let mut h = DataHasher::new(HashAlgorithm::Sha256)
        .expect("sha256")
        .update(b"unicity-token/non-inclusion-policy/v1");
    match context {
        None => h = h.update(&[0]),
        Some(c) => {
            h = h.update(&[1]).update(&c.partition_id.to_be_bytes());
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
            h = h.update(&opt(c.min_root_round.is_some()));
            if let Some(r) = c.min_root_round {
                h = h.update(&r.to_be_bytes());
            }
            h = h.update(&opt(c.authority_end_round.is_some()));
            if let Some(r) = c.authority_end_round {
                h = h.update(&r.to_be_bytes());
            }
        }
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().data());
    out
}
