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
use crate::api::bft::UnicityCertificate;
use crate::fifo_index::FifoIndex;

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
    /// is authenticated for). An authenticator that remembers verdicts must key
    /// each by everything it depends on: a signature-only verdict by the complete
    /// seal and the authority; anything evaluated under `policy` also by `policy`;
    /// strict per-call checks (network, epoch, position) are never memoized. The
    /// default ignores `policy`, which is only right for authenticators that do
    /// not memoize.
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

    /// Memo key of the signature verdict: the complete seal encoding. The verdict
    /// "this exact seal carries a quorum of valid signatures of *this session's*
    /// authority" does not depend on any caller policy, so one verification serves
    /// every policy; all policy-dependent rules (network, epoch, position, body,
    /// pins) are evaluated by the callers each time or kept in the policy-keyed
    /// body memo.
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
        self.verify_quorum_under(seal, &[0; 32])
    }

    /// [`verify_quorum`](Self::verify_quorum) for a caller that evaluates under an
    /// immutable `policy`. The signature verdict is a property of the complete
    /// seal and this session's authority only, so it is shared by all policies
    /// (the total number of native quorum verifications is the number of distinct
    /// seals); the policy-dependent verdicts of whole certificates stay namespaced
    /// by it in the body memo.
    pub fn verify_quorum_under(
        &mut self,
        seal: &UnicitySeal,
        _policy: &[u8; 32],
    ) -> Result<(), VerificationError> {
        // an unsafe authority (no validators, zero threshold, ...) never yields
        // or caches a success
        self.ensure_trust_base()?;
        let key = Self::key(seal);
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
    eat(uc.input_record.hash.as_deref().unwrap_or(&[]));
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

/// Signature work of one quorum check (the metric of its early exit).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct QuorumWork {
    /// Signature encodings parsed.
    pub decodes: u64,
    /// ECDSA verifications executed.
    pub verifications: u64,
}

/// The count of distinct, valid root-node signatures over the seal hash must
/// reach the trust base threshold.
///
/// This is the one quorum implementation of the crate. It stops as soon as the
/// threshold is reached: later signatures are neither decoded nor verified, which
/// cannot change the verdict because the count only grows. Entries that do not
/// count - a repeated node id, an unknown node, a key already counted, an
/// undecodable or invalid signature - are skipped exactly as before.
fn quorum_met(trust_base: &RootTrustBase, seal: &UnicitySeal) -> Result<(), VerificationError> {
    quorum_met_counted(trust_base, seal, &mut QuorumWork::default())
}

pub(crate) fn quorum_met_counted(
    trust_base: &RootTrustBase,
    seal: &UnicitySeal,
    work: &mut QuorumWork,
) -> Result<(), VerificationError> {
    let threshold = trust_base.quorum_threshold;
    if threshold == 0 {
        return Ok(());
    }
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
        work.decodes += 1;
        let Ok(sig) = Signature::decode(signature) else {
            continue;
        };
        work.verifications += 1;
        if sig.verify(seal_hash.data(), key) {
            counted.insert(node_id.as_str());
            counted_keys.push(key);
            if counted.len() as u64 >= threshold {
                return Ok(());
            }
        }
    }
    Err(VerificationError::QuorumNotMet)
}

#[cfg(all(test, feature = "client"))]
mod tests {
    use super::*;
    use crate::api::bft::root_trust_base::RootTrustBaseNodeInfo;
    use crate::api::NetworkId;
    use crate::crypto::hash::{DataHash, HashAlgorithm};
    use crate::crypto::signer::{Secp256k1Signer, Signer};
    use alloc::format;
    use alloc::string::String;
    use alloc::vec;

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }
    }

    fn signers(n: usize) -> Vec<Secp256k1Signer> {
        (0..n)
            .map(|i| Secp256k1Signer::from_bytes(&[i as u8 + 1; 32]).unwrap())
            .collect()
    }

    fn trust_base(signers: &[Secp256k1Signer], threshold: u64) -> RootTrustBase {
        RootTrustBase::new(
            1,
            NetworkId::LOCAL,
            1,
            1,
            signers
                .iter()
                .enumerate()
                .map(|(i, s)| RootTrustBaseNodeInfo {
                    node_id: format!("n{i}"),
                    signing_key: s.public_key(),
                    stake: 1,
                })
                .collect(),
            threshold,
        )
    }

    fn seal_with(signatures: Vec<(String, Vec<u8>)>) -> UnicitySeal {
        UnicitySeal {
            network_id: NetworkId::LOCAL,
            root_chain_round_number: 5,
            epoch: 1,
            timestamp: 1_731_504_000,
            previous_hash: None,
            hash: vec![7; 32],
            signatures,
        }
    }

    fn sign(signer: &Secp256k1Signer, seal: &UnicitySeal) -> Vec<u8> {
        let digest: DataHash = seal.calculate_hash();
        assert_eq!(digest.algorithm(), HashAlgorithm::Sha256);
        signer.sign(&digest).encode().to_vec()
    }

    /// The previous implementation: scans every signature (the reference model).
    fn reference(trust_base: &RootTrustBase, seal: &UnicitySeal) -> (bool, u64) {
        let seal_hash = seal.calculate_hash();
        let mut counted: BTreeSet<&str> = BTreeSet::new();
        let mut keys = Vec::new();
        let mut verifications = 0;
        for (node_id, signature) in &seal.signatures {
            if counted.contains(node_id.as_str()) {
                continue;
            }
            let Some(key) = trust_base.signing_key(node_id) else {
                continue;
            };
            if keys.contains(&key) {
                continue;
            }
            let Ok(sig) = Signature::decode(signature) else {
                continue;
            };
            verifications += 1;
            if sig.verify(seal_hash.data(), key) {
                counted.insert(node_id.as_str());
                keys.push(key);
            }
        }
        (
            counted.len() as u64 >= trust_base.quorum_threshold,
            verifications,
        )
    }

    fn verdict(tb: &RootTrustBase, seal: &UnicitySeal) -> (bool, QuorumWork) {
        let mut work = QuorumWork::default();
        let ok = quorum_met_counted(tb, seal, &mut work).is_ok();
        (ok, work)
    }

    /// The signature verdict is a property of the complete seal and the session's
    /// authority: one native verification per distinct seal, whatever the policy that
    /// asks; a different witness, a failure and another authority are never covered.
    #[test]
    fn signature_verdicts_are_shared_across_policies_but_nothing_looser() {
        let signers = signers(4);
        let tb = trust_base(&signers, 3);
        let mut seal = seal_with(Vec::new());
        seal.signatures = (0..3)
            .map(|i| (format!("n{i}"), sign(&signers[i], &seal)))
            .collect();

        let mut session = SealSession::new(&tb);
        let (p1, p2) = ([1u8; 32], [2u8; 32]);
        session.verify_quorum(&seal).unwrap(); // zero policy: input evidence
        session.verify_quorum_under(&seal, &p1).unwrap(); // a view / direct target
        session.verify_quorum_under(&seal, &p2).unwrap();
        let s = session.stats();
        assert_eq!((s.quorum_checks, s.memo_hits), (1, 2));
        assert_eq!(session.authenticate_seal_under(&seal, &p1), Ok(()));
        assert_eq!(session.stats().quorum_checks, 1);

        // another witness for the same unsigned seal is another seal
        let mut other = seal.clone();
        other
            .signatures
            .push(("n3".into(), sign(&signers[3], &seal)));
        session.verify_quorum_under(&other, &p1).unwrap();
        assert_eq!(session.stats().quorum_checks, 2);

        // failures are never remembered
        let mut bad = seal.clone();
        bad.signatures.truncate(2);
        for _ in 0..2 {
            assert!(session.verify_quorum_under(&bad, &p1).is_err());
        }
        assert_eq!(session.stats().quorum_checks, 4);

        // another authority never inherits a verdict (the memo belongs to the session)
        let other_tb = trust_base(&signers, 4);
        let mut fresh = SealSession::new(&other_tb);
        assert!(fresh.verify_quorum_under(&seal, &p1).is_err());
        assert_eq!(fresh.stats().quorum_checks, 1);
    }

    #[test]
    fn stops_at_the_threshold_whatever_the_number_of_valid_signatures() {
        let threshold = 5u64;
        for n in [5usize, 6, 8, 12, 20, 40] {
            let signers = signers(n);
            let tb = trust_base(&signers, threshold);
            let mut seal = seal_with(Vec::new());
            let sigs: Vec<_> = signers
                .iter()
                .enumerate()
                .map(|(i, s)| (format!("n{i}"), sign(s, &seal)))
                .collect();
            seal.signatures = sigs;
            let (ok, work) = verdict(&tb, &seal);
            assert!(ok);
            assert_eq!(
                work,
                QuorumWork {
                    decodes: threshold,
                    verifications: threshold
                },
                "N={n}: exactly the threshold, no further decode/verify"
            );
            // the reference scanned them all
            assert_eq!(reference(&tb, &seal), (true, n as u64));
            // and the public check agrees
            let mut session = SealSession::new(&tb);
            session.verify_quorum(&seal).unwrap();
        }
    }

    #[test]
    fn one_short_of_the_threshold_verifies_everything_and_fails() {
        let signers = signers(9);
        let tb = trust_base(&signers, 5);
        let mut seal = seal_with(Vec::new());
        seal.signatures = signers
            .iter()
            .take(4)
            .enumerate()
            .map(|(i, s)| (format!("n{i}"), sign(s, &seal)))
            .collect();
        let (ok, work) = verdict(&tb, &seal);
        assert!(!ok);
        assert_eq!(work.verifications, 4);
        assert_eq!(quorum_met(&tb, &seal), Err(VerificationError::QuorumNotMet));
    }

    /// Junk before, between and after valid signatures never changes the verdict.
    #[test]
    fn invalid_duplicate_and_unknown_signers_in_any_order_give_the_reference_result() {
        let signers = signers(8);
        let mut rng = Rng(99);
        let outsider = Secp256k1Signer::from_bytes(&[0xee; 32]).unwrap();
        for case in 0..300u64 {
            let threshold = 1 + rng.next() % 6;
            let mut tb = trust_base(&signers, threshold);
            if case % 5 == 0 {
                // two node ids with one key: the key counts once (unvalidated trust base)
                tb.root_nodes[1].signing_key = tb.root_nodes[0].signing_key.clone();
            }
            let mut seal = seal_with(Vec::new());
            let mut sigs: Vec<(String, Vec<u8>)> = Vec::new();
            for _ in 0..(rng.next() % 14) {
                let i = (rng.next() % 8) as usize;
                let id = format!("n{i}");
                let valid = sign(&signers[i], &seal);
                let entry = match rng.next() % 6 {
                    0..=2 => (id, valid),
                    3 => {
                        let mut bad = valid;
                        bad[(rng.next() % 64) as usize] ^= 1; // invalid (or non-canonical)
                        (id, bad)
                    }
                    4 => (id, vec![1, 2, 3]), // undecodable
                    _ => ("stranger".into(), sign(&outsider, &seal)), // unknown node
                };
                sigs.push(entry);
                if rng.next() % 5 == 0 {
                    sigs.push(sigs[sigs.len() - 1].clone()); // the same node twice
                }
            }
            seal.signatures = sigs;
            let (ok, work) = verdict(&tb, &seal);
            let (ref_ok, ref_verifications) = reference(&tb, &seal);
            assert_eq!(ok, ref_ok, "case {case}");
            assert!(work.verifications <= ref_verifications, "case {case}");
            assert!(work.decodes >= work.verifications);
            if !ok {
                // an unreachable quorum scans everything, like before
                assert_eq!(work.verifications, ref_verifications, "case {case}");
            }
        }
    }

    #[test]
    fn invalid_entries_before_valid_ones_are_skipped_then_it_stops() {
        let signers = signers(6);
        let tb = trust_base(&signers, 3);
        let mut seal = seal_with(Vec::new());
        let good = |i: usize, seal: &UnicitySeal| (format!("n{i}"), sign(&signers[i], seal));
        let mut bad = good(0, &seal);
        bad.1[9] ^= 1;
        seal.signatures = vec![
            ("ghost".into(), vec![0; 65]), // unknown: not even decoded
            ("n0".into(), vec![1, 2]),     // undecodable: decoded, not verified
            bad,                           // verified, invalid
            good(1, &seal),                // valid 1
            good(1, &seal),                // the same node again: skipped
            good(2, &seal),                // valid 2
            good(0, &seal),                // valid 3 -> stop
            good(3, &seal),                // never looked at
            ("n4".into(), vec![9]),        // never looked at
        ];
        let (ok, work) = verdict(&tb, &seal);
        assert!(ok);
        // n0(undecodable) + n0(bad) + n1 + n2 + n0(valid)
        assert_eq!(work.decodes, 5);
        assert_eq!(work.verifications, 4);
        assert!(reference(&tb, &seal).0);
    }

    #[test]
    fn one_key_under_two_node_ids_counts_once() {
        let signers = signers(3);
        let mut tb = trust_base(&signers, 2);
        tb.root_nodes[1].signing_key = tb.root_nodes[0].signing_key.clone();
        let mut seal = seal_with(Vec::new());
        seal.signatures = vec![
            ("n0".into(), sign(&signers[0], &seal)),
            ("n1".into(), sign(&signers[0], &seal)), // same key, other node id
        ];
        let (ok, work) = verdict(&tb, &seal);
        assert!(!ok);
        assert_eq!(
            work.verifications, 1,
            "the second entry is skipped before any decode"
        );
        seal.signatures
            .push(("n2".into(), sign(&signers[2], &seal)));
        assert!(verdict(&tb, &seal).0);
    }
}
