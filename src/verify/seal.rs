//! Operation-scoped authentication of unicity seals.
//!
//! A [`SealSession`] binds one [`RootTrustBase`] (the authority) to a small,
//! bounded memo of *successful* quorum-signature checks. Tokens whose history
//! shares a seal (for example after proof consolidation), or whose nested
//! proofs repeat one, pay for the signature work once per session.
//!
//! The memo only ever skips the quorum signature check of a seal whose complete
//! encoding (signatures included) has already passed that check under the same
//! trust base. Every other rule - unicity-tree path, shard path, network,
//! reference times, predicates - is evaluated by the caller each time.
//! Failures are never remembered, and a different signature witness for the
//! same unsigned seal is a different key, so it can not reuse a verdict.
//!
//! The memo key is a SHA-256 digest of the length-delimited complete seal
//! encoding, so its size is bounded regardless of how many signatures an
//! attacker-supplied seal carries. The session owns its authority by
//! reference, hence a verdict can never be applied under another trust base.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use crate::api::bft::{RootTrustBase, UnicitySeal};
use crate::crypto::hash::{DataHasher, HashAlgorithm};
use crate::crypto::signature::Signature;

use super::VerificationError;

/// Default number of successful seals remembered by a session.
pub const DEFAULT_SEAL_MEMO_CAPACITY: usize = 64;

/// Earliest plausible seal timestamp (2023-04-20), as in the reference
/// implementation's seal sanity check.
const GENESIS_TIME: u64 = 1_681_971_084;

const MEMO_DOMAIN: &[u8] = b"unicity-token/seal-memo/v1";

/// Counters of the signature work a session performed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SealStats {
    /// Quorum-signature verifications actually executed (memo misses).
    pub quorum_checks: u64,
    /// Seals accepted from the memo without repeating the signature work.
    pub memo_hits: u64,
}

/// Authenticates unicity seals against a trusted authority.
pub trait SealAuthenticator {
    /// Succeeds only for a seal authenticated by the verifier's authority:
    /// network, epoch, position and quorum signatures.
    fn authenticate_seal(&mut self, seal: &UnicitySeal) -> Result<(), VerificationError>;
}

/// One operation's seal authentication state: an authority and a bounded memo.
#[derive(Debug)]
pub struct SealSession<'a> {
    trust_base: &'a RootTrustBase,
    validated: bool,
    capacity: usize,
    // digests of complete seal encodings, oldest first
    memo: Vec<[u8; 32]>,
    stats: SealStats,
}

impl<'a> SealSession<'a> {
    /// Session with the [`DEFAULT_SEAL_MEMO_CAPACITY`].
    pub fn new(trust_base: &'a RootTrustBase) -> Self {
        Self::with_capacity(trust_base, DEFAULT_SEAL_MEMO_CAPACITY)
    }

    /// Session remembering at most `capacity` seals; `0` disables reuse.
    pub fn with_capacity(trust_base: &'a RootTrustBase, capacity: usize) -> Self {
        Self {
            trust_base,
            validated: false,
            capacity,
            memo: Vec::new(),
            stats: SealStats::default(),
        }
    }

    /// The authority of this session.
    pub fn trust_base(&self) -> &'a RootTrustBase {
        self.trust_base
    }

    /// Signature work performed so far.
    pub fn stats(&self) -> SealStats {
        self.stats
    }

    pub(crate) fn ensure_trust_base(&mut self) -> Result<(), VerificationError> {
        if !self.validated {
            self.trust_base
                .validate()
                .map_err(VerificationError::InvalidTrustBase)?;
            self.validated = true;
        }
        Ok(())
    }

    /// Content identity of the authority: a digest over the trust base's
    /// version, network, epoch, epoch start, threshold and every validator
    /// (id, key, stake). Two sessions with the same identity judge seals alike.
    pub fn authority_identity(&self) -> [u8; 32] {
        let tb = self.trust_base;
        let mut h = DataHasher::new(HashAlgorithm::Sha256)
            .expect("sha256")
            .update(b"unicity-token/authority/v1")
            .update(&tb.version.to_be_bytes())
            .update(&tb.network_id.id().to_be_bytes())
            .update(&tb.epoch.to_be_bytes())
            .update(&tb.epoch_start_round.to_be_bytes())
            .update(&tb.quorum_threshold.to_be_bytes())
            .update(&(tb.root_nodes.len() as u64).to_be_bytes());
        for n in &tb.root_nodes {
            h = h
                .update(&(n.node_id.len() as u64).to_be_bytes())
                .update(n.node_id.as_bytes())
                .update(n.signing_key.as_bytes())
                .update(&n.stake.to_be_bytes());
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(h.finalize().data());
        id
    }

    fn key(seal: &UnicitySeal) -> [u8; 32] {
        let encoded = seal.to_cbor();
        let digest = DataHasher::new(HashAlgorithm::Sha256)
            .expect("sha256")
            .update(MEMO_DOMAIN)
            .update(&(encoded.len() as u64).to_be_bytes())
            .update(&encoded)
            .finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(digest.data());
        key
    }

    /// Check the quorum of valid, distinct root-node signatures over `seal`,
    /// reusing an earlier success of the identical complete seal.
    ///
    /// This is only the signature part; callers check network, unicity-tree
    /// root and everything else themselves.
    pub fn verify_quorum(&mut self, seal: &UnicitySeal) -> Result<(), VerificationError> {
        // an unsafe authority (no validators, zero threshold, ...) never yields
        // or caches a success
        self.ensure_trust_base()?;
        let key = Self::key(seal);
        if self.memo.contains(&key) {
            self.stats.memo_hits += 1;
            return Ok(());
        }
        self.stats.quorum_checks += 1;
        quorum_met(self.trust_base, seal)?;
        if self.capacity > 0 {
            if self.memo.len() == self.capacity {
                self.memo.remove(0);
            }
            self.memo.push(key);
        }
        Ok(())
    }
}

impl SealAuthenticator for SealSession<'_> {
    /// The strict policy used when a seal becomes the master of derived
    /// certificates: the seal must be of the trust base's network and epoch and
    /// not predate the epoch, then pass the (memoized) quorum check.
    fn authenticate_seal(&mut self, seal: &UnicitySeal) -> Result<(), VerificationError> {
        self.ensure_trust_base()?;
        // the quorum rule implemented here counts signers; a stake-weighted
        // authority would be judged by another rule, so refuse it explicitly,
        // before any memo lookup or signature work
        if self.trust_base.root_nodes.iter().any(|n| n.stake != 1) {
            return Err(VerificationError::UnsupportedAuthority);
        }
        check_seal_shape(seal)?;
        let tb = self.trust_base;
        if seal.network_id != tb.network_id {
            return Err(VerificationError::SealNetworkMismatch);
        }
        if seal.epoch != tb.epoch {
            return Err(VerificationError::SealEpochMismatch);
        }
        if seal.root_chain_round_number < tb.epoch_start_round {
            return Err(VerificationError::SealBeforeEpochStart);
        }
        self.verify_quorum(seal)
    }
}

/// Structural sanity of a seal, independent of any authority.
pub(crate) fn check_seal_shape(seal: &UnicitySeal) -> Result<(), VerificationError> {
    if seal.root_chain_round_number < 1
        || seal.timestamp < GENESIS_TIME
        || seal.signatures.is_empty()
        || seal
            .signatures
            .iter()
            .any(|(id, sig)| id.is_empty() || sig.is_empty())
    {
        return Err(VerificationError::SealMalformed);
    }
    Ok(())
}

/// The count of distinct, valid root-node signatures over the seal hash must
/// reach the trust base threshold.
fn quorum_met(trust_base: &RootTrustBase, seal: &UnicitySeal) -> Result<(), VerificationError> {
    let seal_hash = seal.calculate_hash();
    let mut counted: BTreeSet<&str> = BTreeSet::new();
    let mut counted_keys = Vec::new();
    for (node_id, signature) in &seal.signatures {
        if counted.contains(node_id.as_str()) {
            continue;
        }
        let Some(key) = trust_base.signing_key(node_id) else {
            continue;
        };
        if counted_keys.contains(&key) {
            continue;
        }
        let Ok(sig) = Signature::decode(signature) else {
            continue;
        };
        if sig.verify(seal_hash.data(), key) {
            counted.insert(node_id.as_str());
            counted_keys.push(key);
        }
    }

    if (counted.len() as u64) < trust_base.quorum_threshold {
        return Err(VerificationError::QuorumNotMet);
    }
    Ok(())
}
