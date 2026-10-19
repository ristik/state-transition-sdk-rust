//! Operation-scoped authentication of unicity seals against the trust base history.
//!
//! A [`SealSession`] binds one [`TrustBaseHistory`] (the authorities) to a small, bounded
//! memo of *successful* quorum-signature checks. Every seal is judged by the entry of its own
//! epoch (`seal.epoch`), whatever the latest epoch is: a token certified long ago verifies with
//! no age limit as long as the history holds the entry of that epoch. Tokens whose history
//! shares a seal (for example after proof consolidation), or whose nested proofs repeat one,
//! pay for the signature work once per session.
//!
//! The seal rule is the native one (bridge verifier, bft-core `b1ref`): the epoch's entry
//! must exist and contain the seal's root round (`start <= r`, and `r < next start` when the
//! successor is held; the newest epoch is open-ended until its successor is known), every
//! supplied signature is checked with no early exit, an unknown signer or any bad signature
//! fails the seal, a signature is 64 bytes or 65 with recovery byte 0/1, and the signed
//! weights have to reach the entry's threshold (`floor(2W/3)+1`).
//!
//! The memo only ever skips the quorum signature check of a seal whose complete encoding
//! (signatures included) has already passed under the same entry (its identity is part of the
//! key). Every other rule - unicity-tree path, shard path, network, reference times,
//! predicates - is evaluated by the caller each time. Failures are never remembered, and a
//! different signature witness for the same unsigned seal is a different key, so it can not
//! reuse a verdict.

use alloc::vec::Vec;

use crate::api::bft::trust_base_entry::TrustBaseEntry;
use crate::api::bft::{TrustBaseHistory, UnicityCertificate, UnicitySeal};
use crate::api::NetworkId;
use crate::crypto::hash::{DataHasher, HashAlgorithm};
use crate::crypto::signature::verify_seal_signature;
use crate::fifo_index::FifoIndex;

use super::VerificationError;

/// Default number of successful seals remembered by a session.
pub const DEFAULT_SEAL_MEMO_CAPACITY: usize = 64;

/// The most signatures a seal may carry (the election cap on a committee).
pub const MAX_SEAL_SIGNATURES: usize = 16;

/// Earliest plausible seal timestamp (2023-04-20), as in the reference
/// implementation's seal sanity check.
const GENESIS_TIME: u64 = 1_681_971_084;

const MEMO_DOMAIN: &[u8] = b"unicity-token/seal-memo/v2";
const AUTHORITY_DOMAIN: &[u8] = b"unicity-token/authority/v2";

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
    /// Succeeds only for a seal authenticated by the verifier's authority: network, epoch,
    /// position and quorum signatures.
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

/// One operation's seal authentication state: a trust base history and a bounded memo.
#[derive(Debug)]
pub struct SealSession<'a> {
    history: &'a TrustBaseHistory,
    // digests of (entry identity, complete seal encoding), bounded FIFO with O(1) indexed lookup
    memo: FifoIndex<[u8; 32]>,
    // certificates whose body (and seal) already passed under (policy, their epoch's entry)
    bodies: FifoIndex<([u8; 32], UnicityCertificate)>,
    stats: SealStats,
}

impl<'a> SealSession<'a> {
    /// Session with the [`DEFAULT_SEAL_MEMO_CAPACITY`].
    pub fn new(history: &'a TrustBaseHistory) -> Self {
        Self::with_capacity(history, DEFAULT_SEAL_MEMO_CAPACITY)
    }

    /// Session remembering at most `capacity` seals; `0` disables reuse.
    pub fn with_capacity(history: &'a TrustBaseHistory, capacity: usize) -> Self {
        Self {
            history,
            memo: FifoIndex::new(capacity),
            bodies: FifoIndex::new(capacity),
            stats: SealStats::default(),
        }
    }

    /// The trust base history of this session.
    pub fn history(&self) -> &'a TrustBaseHistory {
        self.history
    }

    /// The network of the history.
    pub fn network_id(&self) -> NetworkId {
        self.history.network_id()
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

    /// The entry that judges `seal`: the history's entry of `seal.epoch`, provided the seal's
    /// network and root round belong to it. The newest epoch is open-ended until its successor
    /// is held.
    ///
    /// * network of another history: `SealNetworkMismatch`;
    /// * epoch above the latest held one: `UnknownTrustEpoch` (retryable after an update);
    /// * epoch below the first held one: `EpochBeforeGenesis`;
    /// * round before the epoch's start: `SealBeforeEpochStart`;
    /// * round at or after the successor's start: `SealAfterAuthorityEnd`.
    pub fn authority_for(
        &self,
        seal: &UnicitySeal,
    ) -> Result<&'a TrustBaseEntry, VerificationError> {
        let history: &'a TrustBaseHistory = self.history;
        if seal.network_id != history.network_id() {
            return Err(VerificationError::SealNetworkMismatch);
        }
        let entry = match history.get(seal.epoch) {
            Some(e) => e,
            None if seal.epoch > history.latest().epoch => {
                return Err(VerificationError::UnknownTrustEpoch { epoch: seal.epoch })
            }
            None => return Err(VerificationError::EpochBeforeGenesis),
        };
        if seal.root_chain_round_number < entry.epoch_start {
            return Err(VerificationError::SealBeforeEpochStart);
        }
        if let Some(next) = history.get(seal.epoch.saturating_add(1)) {
            if seal.root_chain_round_number >= next.epoch_start {
                return Err(VerificationError::SealAfterAuthorityEnd);
            }
        }
        Ok(entry)
    }

    /// Identity of the authority that judges `seal`: a digest over the identity of its epoch's
    /// entry. Two sessions with the same history entry judge seals alike.
    pub fn authority_identity(&self, seal: &UnicitySeal) -> Result<[u8; 32], VerificationError> {
        let entry = self.authority_for(seal)?;
        let digest = DataHasher::new(HashAlgorithm::Sha256)
            .expect("sha256")
            .update(AUTHORITY_DOMAIN)
            .update(&entry.entry_id())
            .finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(digest.data());
        Ok(id)
    }

    /// Memo key of the signature verdict: the entry identity and the complete seal encoding.
    /// The verdict "this exact seal carries a quorum of valid signatures of *this entry*" does
    /// not depend on any caller policy, so one verification serves every policy.
    fn key(entry: &TrustBaseEntry, seal: &UnicitySeal) -> [u8; 32] {
        let encoded = seal.to_cbor();
        let digest = DataHasher::new(HashAlgorithm::Sha256)
            .expect("sha256")
            .update(MEMO_DOMAIN)
            .update(&entry.entry_id())
            .update(&(encoded.len() as u64).to_be_bytes())
            .update(&encoded)
            .finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(digest.data());
        key
    }

    /// Authenticate `seal`: the authority of its epoch (see
    /// [`authority_for`](Self::authority_for)) and the weighted quorum of valid signatures,
    /// reusing an earlier success of the identical complete seal under the same entry.
    ///
    /// This is only the signature part; callers check the unicity-tree root and everything
    /// else themselves.
    pub fn verify_quorum(&mut self, seal: &UnicitySeal) -> Result<(), VerificationError> {
        self.verify_quorum_under(seal, &[0; 32])
    }

    /// [`verify_quorum`](Self::verify_quorum) for a caller that evaluates under an immutable
    /// `policy`. The signature verdict is a property of the complete seal and its entry only,
    /// so it is shared by all policies; the policy-dependent verdicts of whole certificates
    /// stay namespaced by it in the body memo.
    pub fn verify_quorum_under(
        &mut self,
        seal: &UnicitySeal,
        _policy: &[u8; 32],
    ) -> Result<(), VerificationError> {
        let entry = self.authority_for(seal)?;
        let key = Self::key(entry, seal);
        let hash = u64::from_le_bytes(key[..8].try_into().expect("8 bytes"));
        if self.memo.contains(hash, |k| k == &key) {
            self.stats.memo_hits += 1;
            return Ok(());
        }
        self.stats.quorum_checks += 1;
        quorum_met(entry, seal)?;
        self.memo.insert(hash, key);
        Ok(())
    }
}

impl SealAuthenticator for SealSession<'_> {
    /// The strict policy used when a seal becomes the master of derived certificates: the
    /// seal must have a sane shape and belong to its epoch's entry, then pass the (memoized)
    /// quorum check.
    fn authenticate_seal(&mut self, seal: &UnicitySeal) -> Result<(), VerificationError> {
        self.authenticate_seal_under(seal, &[0; 32])
    }

    fn authenticate_seal_under(
        &mut self,
        seal: &UnicitySeal,
        policy: &[u8; 32],
    ) -> Result<(), VerificationError> {
        check_seal_shape(seal)?;
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
        || seal.signatures.len() > MAX_SEAL_SIGNATURES
        || seal
            .signatures
            .iter()
            .any(|(id, sig)| id.is_empty() || sig.is_empty())
    {
        return Err(VerificationError::SealMalformed);
    }
    Ok(())
}

/// The native quorum rule over `seal` under `entry`: every supplied signature is checked
/// (no early exit); a signer that is not a member of the entry, a repeated signer or any
/// signature that is malformed or does not verify fails the seal; the signed weights, summed
/// with checked arithmetic, have to reach the entry's threshold.
fn quorum_met(entry: &TrustBaseEntry, seal: &UnicitySeal) -> Result<(), VerificationError> {
    let seal_hash = seal.calculate_hash();
    let mut weight = 0u64;
    let mut seen: Vec<&str> = Vec::with_capacity(seal.signatures.len());
    for (node_id, signature) in &seal.signatures {
        if seen.contains(&node_id.as_str()) {
            return Err(VerificationError::SealSignerInvalid);
        }
        seen.push(node_id.as_str());
        let member = entry
            .member(node_id)
            .ok_or(VerificationError::SealSignerInvalid)?;
        verify_seal_signature(signature, seal_hash.data(), &member.signing_key)
            .map_err(|_| VerificationError::SealSignerInvalid)?;
        weight = weight
            .checked_add(member.weight)
            .ok_or(VerificationError::SealSignerInvalid)?;
    }
    if weight < entry.quorum_threshold {
        return Err(VerificationError::QuorumNotMet);
    }
    Ok(())
}

#[cfg(all(test, feature = "client"))]
mod tests {
    use super::*;
    use crate::api::bft::{TrustBaseEntry, TrustBaseMember};
    use crate::crypto::hash::HashAlgorithm;
    use crate::crypto::signer::{Secp256k1Signer, Signer};
    use alloc::format;
    use alloc::string::String;
    use alloc::vec;

    fn signers(n: usize) -> Vec<Secp256k1Signer> {
        (0..n)
            .map(|i| Secp256k1Signer::from_bytes(&[i as u8 + 1; 32]).unwrap())
            .collect()
    }

    /// A one-entry history, epoch 1 from round 1, validator `n{i}` with weight `weights[i]`.
    fn history(signers: &[Secp256k1Signer], weights: &[u64]) -> TrustBaseHistory {
        let members = signers
            .iter()
            .zip(weights)
            .enumerate()
            .map(|(i, (s, w))| TrustBaseMember::new(format!("n{i}"), s.public_key(), *w))
            .collect();
        TrustBaseHistory::from_genesis(
            TrustBaseEntry::genesis(NetworkId::LOCAL, 1, 1, members),
            None,
        )
        .unwrap()
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
        let digest = seal.calculate_hash();
        assert_eq!(digest.algorithm(), HashAlgorithm::Sha256);
        signer.sign(&digest).encode().to_vec()
    }

    fn signed_by(signers: &[Secp256k1Signer], who: &[usize]) -> UnicitySeal {
        let mut seal = seal_with(Vec::new());
        seal.signatures = who
            .iter()
            .map(|&i| (format!("n{i}"), sign(&signers[i], &seal)))
            .collect();
        seal
    }

    #[test]
    fn a_weighted_quorum_counts_weights_not_signers() {
        let s = signers(3);
        // weights 98, 1, 1: the threshold is floor(200/3)+1 = 67
        let h = history(&s, &[98, 1, 1]);
        assert_eq!(h.latest().quorum_threshold, 67);
        assert_eq!(
            SealSession::new(&h).verify_quorum(&signed_by(&s, &[0])),
            Ok(())
        );
        assert_eq!(
            SealSession::new(&h).verify_quorum(&signed_by(&s, &[1, 2])),
            Err(VerificationError::QuorumNotMet)
        );
    }

    #[test]
    fn the_native_seal_rule_is_strict_and_has_no_early_exit() {
        let s = signers(4);
        let h = history(&s, &[1, 1, 1, 1]); // threshold 3
        let good = signed_by(&s, &[0, 1, 2]);
        assert_eq!(SealSession::new(&h).verify_quorum(&good), Ok(()));

        // a bad signature after the quorum was reached still fails the seal
        let mut bad_extra = signed_by(&s, &[0, 1, 2, 3]);
        bad_extra.signatures[3].1[5] ^= 1;
        assert_eq!(
            SealSession::new(&h).verify_quorum(&bad_extra),
            Err(VerificationError::SealSignerInvalid)
        );
        // an unknown signer fails it too
        let mut unknown = good.clone();
        unknown
            .signatures
            .push(("zz".into(), unknown.signatures[0].1.clone()));
        assert_eq!(
            SealSession::new(&h).verify_quorum(&unknown),
            Err(VerificationError::SealSignerInvalid)
        );
        // a repeated signer
        let mut twice = good.clone();
        twice.signatures.push(twice.signatures[0].clone());
        assert_eq!(
            SealSession::new(&h).verify_quorum(&twice),
            Err(VerificationError::SealSignerInvalid)
        );
        // 64 bytes, or 65 with the recovery byte 0/1 ignored, are signatures; others are not
        let mut compact = good.clone();
        compact.signatures[0].1.truncate(64);
        assert_eq!(SealSession::new(&h).verify_quorum(&compact), Ok(()));
        let mut ignored = good.clone();
        ignored.signatures[0].1[64] ^= 1;
        assert_eq!(SealSession::new(&h).verify_quorum(&ignored), Ok(()));
        let mut v2 = good.clone();
        v2.signatures[0].1[64] = 2;
        assert_eq!(
            SealSession::new(&h).verify_quorum(&v2),
            Err(VerificationError::SealSignerInvalid)
        );
        // below the threshold
        assert_eq!(
            SealSession::new(&h).verify_quorum(&signed_by(&s, &[0, 1])),
            Err(VerificationError::QuorumNotMet)
        );
    }

    #[test]
    fn at_most_sixteen_signatures() {
        let s = signers(17);
        let h = history(&s, &[1; 17]);
        let seal = signed_by(&s, &(0..17).collect::<Vec<_>>());
        assert_eq!(
            SealSession::new(&h).authenticate_seal(&seal),
            Err(VerificationError::SealMalformed)
        );
    }

    #[test]
    fn verdicts_are_bound_to_the_entry_and_the_complete_seal() {
        let s = signers(3);
        let h = history(&s, &[1, 1, 1]); // threshold 3
        let seal = signed_by(&s, &[0, 1, 2]);
        let mut session = SealSession::new(&h);
        session.verify_quorum(&seal).unwrap();
        session.verify_quorum(&seal).unwrap();
        let st = session.stats();
        assert_eq!((st.quorum_checks, st.memo_hits), (1, 1));

        // another valid witness of the same unsigned seal (the 64-byte form) is another key
        let mut twin = seal.clone();
        twin.signatures[0].1.truncate(64);
        session.verify_quorum(&twin).unwrap();
        assert_eq!(session.stats().quorum_checks, 2);

        // a tampered witness never reuses a verdict
        let mut tampered = seal.clone();
        tampered.signatures[0].1[3] ^= 1;
        assert!(session.verify_quorum(&tampered).is_err());
        assert_eq!(session.stats().quorum_checks, 3);

        // capacity 0: nothing is reused
        let mut none = SealSession::with_capacity(&h, 0);
        none.verify_quorum(&seal).unwrap();
        none.verify_quorum(&seal).unwrap();
        assert_eq!((none.stats().quorum_checks, none.stats().memo_hits), (2, 0));

        // the entry identity is part of the authority identity: another entry, another identity
        let mut other_entry = h.latest().clone();
        other_entry.state_hash = Some(vec![9; 32]);
        let other = TrustBaseHistory::from_genesis(other_entry, None).unwrap();
        assert_ne!(
            SealSession::new(&h).authority_identity(&seal).unwrap(),
            SealSession::new(&other).authority_identity(&seal).unwrap()
        );
    }

    #[test]
    fn the_authority_is_the_entry_of_the_seal_epoch() {
        let s = signers(1);
        let g = history(&s, &[1]); // epoch 1 from round 1
        let mut h = g.clone();
        let mut next = TrustBaseEntry::new(
            NetworkId::LOCAL,
            2,
            10,
            g.latest().members.clone(),
            1,
            None,
            None,
            g.latest().entry_id(),
        );
        next.sign("n0", &s[0]);
        h.append(next).unwrap();

        let at = |epoch: u64, round: u64| {
            let mut seal = seal_with(Vec::new());
            seal.epoch = epoch;
            seal.root_chain_round_number = round;
            seal.signatures = vec![("n0".into(), sign(&s[0], &seal))];
            seal
        };
        let mut session = SealSession::new(&h);
        assert_eq!(session.verify_quorum(&at(1, 9)), Ok(()));
        assert_eq!(
            session.verify_quorum(&at(1, 10)),
            Err(VerificationError::SealAfterAuthorityEnd)
        );
        assert_eq!(session.verify_quorum(&at(2, 10)), Ok(()));
        assert_eq!(
            session.verify_quorum(&at(2, 9)),
            Err(VerificationError::SealBeforeEpochStart)
        );
        assert_eq!(
            session.verify_quorum(&at(3, 99)),
            Err(VerificationError::UnknownTrustEpoch { epoch: 3 })
        );
        assert_eq!(
            session.verify_quorum(&at(0, 5)),
            Err(VerificationError::EpochBeforeGenesis)
        );
        let mut foreign = at(1, 5);
        foreign.network_id = NetworkId::MAINNET;
        assert_eq!(
            session.verify_quorum(&foreign),
            Err(VerificationError::SealNetworkMismatch)
        );
    }
}
