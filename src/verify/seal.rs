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

use super::memo::FifoIndex;
use super::VerificationError;
use crate::api::bft::UnicityCertificate;

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
    /// Certificate-body checks actually executed (tree/shard path recomputation
    /// to the seal hash, network): one per distinct certificate, not per proof.
    pub body_checks: u64,
    /// Proofs whose identical certificate had already passed the body check.
    pub body_hits: u64,
    /// Index slots examined by memo lookups and evictions: O(1) expected per
    /// operation, independent of the capacity.
    pub memo_probes: u64,
}

/// Authenticates unicity seals against a trusted authority.
pub trait SealAuthenticator {
    /// Succeeds only for a seal authenticated by the verifier's authority:
    /// network, epoch, position and quorum signatures.
    fn authenticate_seal(&mut self, seal: &UnicitySeal) -> Result<(), VerificationError>;

    /// [`authenticate_seal`](Self::authenticate_seal) under an immutable caller
    /// policy (for example the partition and pinned configuration hashes a view
    /// is authenticated for). An authenticator that remembers verdicts must
    /// namespace them by `policy`; the default ignores it, which is only right
    /// for authenticators that do not memoize.
    fn authenticate_seal_under(
        &mut self,
        seal: &UnicitySeal,
        policy: &[u8; 32],
    ) -> Result<(), VerificationError> {
        let _ = policy;
        self.authenticate_seal(seal)
    }
}

/// One operation's seal authentication state: an authority and a bounded memo.
#[derive(Debug)]
pub struct SealSession<'a> {
    trust_base: &'a RootTrustBase,
    validated: bool,
    // digests of complete seal encodings, bounded FIFO with O(1) indexed lookup
    memo: FifoIndex<[u8; 32]>,
    // certificates whose body (and seal) already passed under (policy, this authority)
    bodies: FifoIndex<([u8; 32], UnicityCertificate)>,
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
            memo: FifoIndex::new(capacity),
            bodies: FifoIndex::new(capacity),
            stats: SealStats::default(),
        }
    }

    /// The authority of this session.
    pub fn trust_base(&self) -> &'a RootTrustBase {
        self.trust_base
    }

    /// Signature work performed so far.
    pub fn stats(&self) -> SealStats {
        SealStats {
            memo_probes: self.memo.probes() + self.bodies.probes(),
            ..self.stats
        }
    }

    /// Whether this exact certificate (complete seal witness included) already
    /// passed the body check and quorum under `policy` in this session.
    pub(crate) fn body_verified(&mut self, uc: &UnicityCertificate, policy: &[u8; 32]) -> bool {
        let hit = self
            .bodies
            .contains(uc_fingerprint(uc, policy), |(p, c)| p == policy && c == uc);
        if hit {
            self.stats.body_hits += 1;
        }
        hit
    }

    /// Record a body check that is about to run (or just ran).
    pub(crate) fn note_body_check(&mut self) {
        self.stats.body_checks += 1;
    }

    /// Remember a certificate whose body and quorum both passed.
    pub(crate) fn remember_body(&mut self, uc: &UnicityCertificate, policy: &[u8; 32]) {
        self.bodies
            .insert(uc_fingerprint(uc, policy), (*policy, uc.clone()));
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

    fn key(seal: &UnicitySeal, policy: &[u8; 32]) -> [u8; 32] {
        let encoded = seal.to_cbor();
        let digest = DataHasher::new(HashAlgorithm::Sha256)
            .expect("sha256")
            .update(MEMO_DOMAIN)
            .update(policy)
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
        self.verify_quorum_under(seal, &[0; 32])
    }

    /// [`verify_quorum`](Self::verify_quorum) with the memo namespaced by an
    /// immutable policy digest: a verdict reached under one policy is never
    /// reused under another.
    pub fn verify_quorum_under(
        &mut self,
        seal: &UnicitySeal,
        policy: &[u8; 32],
    ) -> Result<(), VerificationError> {
        // an unsafe authority (no validators, zero threshold, ...) never yields
        // or caches a success
        self.ensure_trust_base()?;
        let key = Self::key(seal, policy);
        let hash = u64::from_le_bytes(key[..8].try_into().expect("8 bytes"));
        if self.memo.contains(hash, |k| k == &key) {
            self.stats.memo_hits += 1;
            return Ok(());
        }
        self.stats.quorum_checks += 1;
        quorum_met(self.trust_base, seal)?;
        self.memo.insert(hash, key);
        Ok(())
    }
}

impl SealAuthenticator for SealSession<'_> {
    /// The strict policy used when a seal becomes the master of derived
    /// certificates: the seal must be of the trust base's network and epoch and
    /// not predate the epoch, then pass the (memoized) quorum check.
    fn authenticate_seal(&mut self, seal: &UnicitySeal) -> Result<(), VerificationError> {
        self.authenticate_seal_under(seal, &[0; 32])
    }

    fn authenticate_seal_under(
        &mut self,
        seal: &UnicitySeal,
        policy: &[u8; 32],
    ) -> Result<(), VerificationError> {
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
        self.verify_quorum_under(seal, policy)
    }
}

/// A cheap, well-mixed fingerprint of a certificate for indexing only (FNV-1a
/// over fields that differ between distinct bodies). Equality of the complete
/// certificate, not this value, decides a hit.
fn uc_fingerprint(uc: &UnicityCertificate, policy: &[u8; 32]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut eat = |bytes: &[u8]| {
        for b in bytes {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
    };
    eat(&policy[..8]);
    eat(&uc.unicity_seal.hash);
    eat(&uc.shard_tree_certificate.shard.encode());
    eat(&uc.input_record.hash);
    eat(&uc.input_record.round_number.to_be_bytes());
    eat(&uc.unicity_seal.root_chain_round_number.to_be_bytes());
    h
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
