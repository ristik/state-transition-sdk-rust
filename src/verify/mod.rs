//! The verification engine: establishes an unbroken chain of cryptographic
//! checks from the [`RootTrustBase`] down to every state in a token's history.
//!
//! ## Threat model
//!
//! The token is fully attacker-controlled bytes. An adversary wins if we accept
//! a forged genesis, a stolen/forged transfer, a double-spend, or a history
//! whose links don't actually connect. Each rule below closes one of those.
//!
//! ## Enforced invariants
//!
//! * **I1/I2 — chain linkage.** A transfer's source-state hash and lock script
//!   are *reconstructed* from its predecessor during [`Token::from_cbor`], not
//!   read from the wire. The inclusion proof is then verified against a
//!   `stateId` derived from those reconstructed values, so a transfer can only
//!   verify if it genuinely spends its predecessor's output state.
//! * **I3 — certification binding.** All certification state fields must equal
//!   the reconstructed transaction fields, the certified `transactionHash`
//!   must equal the recomputed transaction hash, and the spend signature is
//!   checked over the reconstructed source-state hash.
//! * **I4 — no structural-only trust.** Decoding never confers validity; only
//!   this module does.
//! * **I5 — signature canonicality.** Signatures must be exactly 65 bytes and
//!   low-`s` (enforced in [`Signature`](crate::crypto::signature::Signature)).
//! * **I6 — quorum honesty.** The trust base must have a positive, attainable
//!   threshold and unique validator ids/keys. Only distinct root-node signing
//!   identities count toward the threshold.
//!
//! [`RootTrustBase`]: crate::api::bft::RootTrustBase
//! [`Token::from_cbor`]: crate::transaction::Token::from_cbor

mod context;
mod error;
mod mint_justification;
mod seal;

pub use context::{VerificationContext, VerificationLimits, VerificationPolicy};
pub use error::VerificationError;
pub use mint_justification::{
    MintJustificationRegistry, MintJustificationVerifier, TokenDataVerifier,
};
pub use seal::{SealAuthenticator, SealSession, SealStats, DEFAULT_SEAL_MEMO_CAPACITY};

use crate::api::bft::{RootTrustBase, UnicityCertificate};
use crate::api::inclusion_proof::InclusionProof;
use crate::api::leaf_value::calculate_leaf_value;
use crate::api::{NonInclusionProof, StateId};
use crate::crypto::hash::{DataHash, HashAlgorithm};
use crate::predicate::builtin::SignaturePredicate;
use crate::predicate::unlock::verify_signature_unlock;
use crate::predicate::EncodedPredicate;
use crate::transaction::{Minter, Token, Transaction};

/// Verify a whole token: genesis first, then every transfer in order.
///
/// Any mint justification is rejected as unsupported (fail closed). To accept
/// justified mints (e.g. token splits), use [`verify_token_with`] with a
/// [`MintJustificationRegistry`] holding the relevant verifiers.
pub fn verify_token(token: &Token, trust_base: &RootTrustBase) -> Result<(), VerificationError> {
    verify_token_with(token, trust_base, &MintJustificationRegistry::new())
}

/// Verify a whole token, dispatching any mint justification through `registry`.
pub fn verify_token_with(
    token: &Token,
    trust_base: &RootTrustBase,
    registry: &MintJustificationRegistry,
) -> Result<(), VerificationError> {
    verify_token_with_policy(token, trust_base, registry, VerificationPolicy::default())
}

/// Verify a token with explicit cumulative limits and payload-validation policy.
pub fn verify_token_with_policy(
    token: &Token,
    trust_base: &RootTrustBase,
    registry: &MintJustificationRegistry,
    policy: VerificationPolicy,
) -> Result<(), VerificationError> {
    verify_token_with_seal_stats(token, trust_base, registry, policy).0
}

/// Like [`verify_token_with_policy`], additionally reporting how much quorum
/// signature work the (operation-scoped) seal session performed. Seals shared
/// by several proofs of the token, including nested source tokens, are
/// authenticated once while they remain in the session's bounded memo.
pub fn verify_token_with_seal_stats(
    token: &Token,
    trust_base: &RootTrustBase,
    registry: &MintJustificationRegistry,
    policy: VerificationPolicy,
) -> (Result<(), VerificationError>, SealStats) {
    let mut context = VerificationContext::new(trust_base, registry, policy);
    let result = trust_base
        .validate()
        .map_err(VerificationError::InvalidTrustBase)
        .and_then(|()| verify_token_in_context(token, &mut context));
    (result, context.seals().stats())
}

pub(crate) fn verify_token_in_context(
    token: &Token,
    context: &mut VerificationContext<'_>,
) -> Result<(), VerificationError> {
    if token.transactions().len() > context.policy().limits.max_token_transfers {
        return Err(VerificationError::VerificationLimitExceeded(
            "token transfer count",
        ));
    }
    verify_genesis(token, context)?;

    for (i, transfer) in token.transactions().iter().enumerate() {
        verify_inclusion_proof(
            context.seals(),
            transfer.inclusion_proof(),
            transfer.transaction(),
            transfer.reference_time(),
        )
        .map_err(|e| VerificationError::Transfer {
            index: i,
            source: alloc::boxed::Box::new(e),
        })?;
    }
    Ok(())
}

fn verify_genesis(
    token: &Token,
    context: &mut VerificationContext<'_>,
) -> Result<(), VerificationError> {
    let genesis = token.genesis();
    let mint = genesis.transaction();
    let trust_base = context.trust_base();

    // Network must match the trust base.
    if mint.network_id() != trust_base.network_id {
        return Err(VerificationError::NetworkMismatch);
    }

    // The genesis must be locked to the deterministic universal-minter key for
    // this token id — proving no one minted a competing history for the id.
    let expected_lock = SignaturePredicate::new(
        Minter::public_key(mint.token_id())
            .map_err(|_| VerificationError::InvalidMintLockScript)?,
    )
    .to_encoded();

    let certified_lock = genesis.inclusion_proof().certification_data.lock_script();
    if certified_lock != &expected_lock {
        return Err(VerificationError::InvalidMintLockScript);
    }

    verify_inclusion_proof(
        context.seals(),
        genesis.inclusion_proof(),
        mint,
        genesis.reference_time(),
    )
    .map_err(|e| VerificationError::Genesis(alloc::boxed::Box::new(e)))?;

    // Mint justification: dispatch through the registry. An empty registry
    // rejects any present justification (fail closed); a registered verifier
    // (e.g. the split verifier) may recursively re-enter verification.
    let registry = context.registry();
    registry.verify_token_data(token.genesis(), context)?;
    registry.verify_genesis(token.genesis(), context)?;

    Ok(())
}

/// Verify a single inclusion proof for `transaction`.
fn verify_inclusion_proof(
    seals: &mut SealSession<'_>,
    proof: &InclusionProof,
    transaction: &impl Transaction,
    reference_time: u64,
) -> Result<(), VerificationError> {
    let certification_data = &proof.certification_data;

    if certification_data.lock_script() != transaction.lock_script()
        || certification_data.source_state_hash() != transaction.source_state_hash()
        || certification_data.expires_at() != transaction.expires_at()
    {
        return Err(VerificationError::CertificationDataMismatch);
    }

    // The certified transaction hash must be this transaction's hash.
    let tx_hash = transaction.calculate_transaction_hash();
    if certification_data.transaction_hash() != &tx_hash {
        return Err(VerificationError::TransactionHashMismatch);
    }

    // Derive the state id from the transaction's reconstructed state, then
    // delegate the relation, shard, UC, and witness checks to the public
    // state-membership verifier.
    let state_id = StateId::derive(transaction.lock_script(), transaction.source_state_hash());
    verify_inclusion_proof_in(seals, proof, &state_id, reference_time)
}

/// Verify that `state_id` is included at the certified root carried by `proof`.
///
/// This verifies the proof's certification data and witness, but does not claim
/// that its transaction hash belongs to a caller-supplied transaction object.
pub fn verify_inclusion_proof_for(
    trust_base: &RootTrustBase,
    proof: &InclusionProof,
    state_id: &StateId,
    reference_time: u64,
) -> Result<(), VerificationError> {
    verify_inclusion_proof_in(
        &mut SealSession::new(trust_base),
        proof,
        state_id,
        reference_time,
    )
}

/// [`verify_inclusion_proof_for`] within a caller-owned seal session, so that
/// several proofs under one seal share a single signature check.
pub fn verify_inclusion_proof_in(
    seals: &mut SealSession<'_>,
    proof: &InclusionProof,
    state_id: &StateId,
    reference_time: u64,
) -> Result<(), VerificationError> {
    seals.ensure_trust_base()?;
    let inclusion_certificate = &proof.inclusion_certificate;
    let certification_data = &proof.certification_data;

    let certified_state_id = StateId::derive(
        certification_data.lock_script(),
        certification_data.source_state_hash(),
    );
    if &certified_state_id != state_id {
        return Err(VerificationError::CertificationDataMismatch);
    }

    // The request was admissible only in a round strictly before its deadline. A
    // request that carried no deadline was admitted under a service-assigned
    // one, which is not recorded and is not re-checked here.
    if let Some(expires_at) = certification_data.expires_at() {
        if reference_time >= expires_at {
            return Err(VerificationError::RequestExpired);
        }
    }

    let expected_root = DataHash::new(
        HashAlgorithm::Sha256,
        proof.unicity_certificate.input_record.hash.clone(),
    )
    .map_err(|_| VerificationError::PathInvalid)?;
    if proof.reference_time != reference_time {
        return Err(VerificationError::ReferenceTimeMismatch);
    }
    if reference_time > proof.unicity_certificate.input_record.timestamp {
        return Err(VerificationError::ReferenceTimeAfterRound);
    }
    let leaf_value = calculate_leaf_value(certification_data.transaction_hash(), reference_time);
    if !inclusion_certificate.verify(state_id, &leaf_value, &expected_root) {
        return Err(VerificationError::PathInvalid);
    }

    // The shard the proof claims must actually contain this state id.
    let shard = &proof.unicity_certificate.shard_tree_certificate.shard;
    if shard.length() != 0 && !shard.is_prefix_of(state_id.bytes()) {
        return Err(VerificationError::ShardMismatch);
    }

    // The unicity certificate must chain to a quorum-signed seal on our network.
    verify_unicity_certificate(seals, &proof.unicity_certificate)?;

    // Finally, the unlock script must satisfy the (reconstructed) lock script.
    verify_predicate(
        certification_data.lock_script(),
        reference_time,
        certification_data.source_state_hash(),
        certification_data.transaction_hash(),
        certification_data.unlock_script(),
    )?;

    Ok(())
}

fn verify_unicity_certificate(
    seals: &mut SealSession<'_>,
    uc: &UnicityCertificate,
) -> Result<(), VerificationError> {
    let seal = &uc.unicity_seal;

    if seal.network_id != seals.trust_base().network_id {
        return Err(VerificationError::SealNetworkMismatch);
    }

    // The recomputed unicity-tree root must equal the signed seal hash.
    let computed = uc
        .computed_seal_hash()
        .map_err(|_| VerificationError::SealRootMismatch)?;
    if computed.data() != seal.hash.as_slice() {
        return Err(VerificationError::SealRootMismatch);
    }

    // The root must be signed by a quorum of the trusted validators; an
    // identical seal already authenticated in this session is not re-checked.
    seals.verify_quorum(seal)
}

/// Verify that `target` was absent at the certified root carried by `proof`.
///
/// This establishes a snapshot fact only. It does not imply that the state is
/// absent at any later root.
pub fn verify_non_inclusion_proof(
    trust_base: &RootTrustBase,
    proof: &NonInclusionProof,
    target: &StateId,
) -> Result<(), VerificationError> {
    let mut seals = SealSession::new(trust_base);
    seals.ensure_trust_base()?;

    let uc = proof.unicity_certificate();
    let expected_root = match uc.input_record.hash.as_slice() {
        [] => None,
        bytes if bytes.len() == 32 => Some(
            DataHash::new(HashAlgorithm::Sha256, bytes.to_vec())
                .map_err(|_| VerificationError::NonInclusionCertificateInvalid)?,
        ),
        _ => return Err(VerificationError::NonInclusionCertificateInvalid),
    };

    if !proof
        .certificate()
        .authenticates(target, expected_root.as_ref())
    {
        return Err(VerificationError::NonInclusionCertificateInvalid);
    }

    let shard = &uc.shard_tree_certificate.shard;
    if shard.length() != 0 {
        let terminal_in_shard = proof
            .certificate()
            .terminal_key()
            .map_or(true, |terminal| shard.is_prefix_of(terminal));
        if !shard.is_prefix_of(target.bytes()) || !terminal_in_shard {
            return Err(VerificationError::ShardMismatch);
        }
    }

    // Authenticate the root before reporting whether the terminal is the
    // requested state. An untrusted certificate must never yield StateIncluded.
    verify_unicity_certificate(&mut seals, uc)?;

    if proof.certificate().terminal_matches(target) {
        return Err(VerificationError::StateIncluded);
    }
    Ok(())
}

fn verify_predicate(
    lock_script: &EncodedPredicate,
    _reference_time: u64,
    source_state_hash: &DataHash,
    transaction_hash: &DataHash,
    unlock_script: &[u8],
) -> Result<(), VerificationError> {
    // Spendable states are signature-locked; anything else cannot be unlocked.
    let predicate = SignaturePredicate::from_encoded(lock_script)
        .map_err(|_| VerificationError::NotAuthenticated)?;
    if verify_signature_unlock(
        predicate.public_key(),
        source_state_hash,
        transaction_hash,
        unlock_script,
    ) {
        Ok(())
    } else {
        Err(VerificationError::NotAuthenticated)
    }
}

/// Per-rule adversarial tests.
///
/// Each test builds a *fully valid* baseline (a single-leaf inclusion proof,
/// signed by a known root node) and then tampers with exactly one field, so that
/// only the rule under test can fire — proving every verification rule rejects
/// its precise adversarial case and returns its specific error.
#[cfg(all(test, feature = "client"))]
mod tests {
    use super::*;

    /// Verify with a fresh seal session per call (the pre-session behavior).
    fn verify_inclusion_proof(
        trust_base: &RootTrustBase,
        proof: &InclusionProof,
        transaction: &impl Transaction,
        reference_time: u64,
    ) -> Result<(), VerificationError> {
        super::verify_inclusion_proof(
            &mut SealSession::new(trust_base),
            proof,
            transaction,
            reference_time,
        )
    }

    /// Reference time every fixture in this module certifies under.
    const REFERENCE_TIME: u64 = 1755000000;
    /// Exclusive certification request timeout every fixture in this module uses.
    const TIMEOUT: u64 = 1755003600;

    use alloc::string::{String, ToString};

    use crate::api::bft::{
        InputRecord, RootTrustBaseNodeInfo, ShardId, ShardTreeCertificate, UnicityCertificate,
        UnicitySeal, UnicityTreeCertificate,
    };
    use crate::api::{CertificationData, InclusionCertificate, NetworkId, NonInclusionCertificate};
    use crate::cbor::{encode_byte_string, Decoder};
    use crate::crypto::hash::sha256;
    use crate::crypto::signer::{Secp256k1Signer, Signer};
    use crate::predicate::unlock::sign_signature_unlock;
    use crate::transaction::ids::{TokenSalt, TokenType};
    use crate::transaction::{
        CertifiedMintTransaction, CertifiedTransferTransaction, MintTransaction,
        TransferTransaction,
    };

    fn signer(byte: u8) -> Secp256k1Signer {
        Secp256k1Signer::from_bytes(&[byte; 32]).unwrap()
    }

    fn node_info(s: &Secp256k1Signer, id: &str) -> RootTrustBaseNodeInfo {
        RootTrustBaseNodeInfo {
            node_id: id.to_string(),
            signing_key: s.public_key(),
            stake: 1,
        }
    }

    fn trust_base(node: &Secp256k1Signer) -> RootTrustBase {
        RootTrustBase::new(
            0,
            NetworkId::LOCAL,
            0,
            0,
            alloc::vec![node_info(node, "NODE")],
            1,
        )
    }

    fn empty_shard() -> ShardId {
        ShardId::decode(&[0b1000_0000]).unwrap()
    }

    fn mk_seal(hash: Vec<u8>, signatures: Vec<(String, Vec<u8>)>) -> UnicitySeal {
        UnicitySeal {
            network_id: NetworkId::LOCAL,
            root_chain_round_number: 0,
            epoch: 0,
            timestamp: REFERENCE_TIME,
            previous_hash: None,
            hash,
            signatures,
        }
    }

    /// The SMT root for a single `(state_id -> tx_hash)` leaf.
    fn leaf_root(state_id: &StateId, tx_hash: &DataHash) -> [u8; 32] {
        let mut preimage = alloc::vec![0x00u8];
        preimage.extend_from_slice(state_id.bytes());
        preimage.extend_from_slice(tx_hash.data());
        let mut root = [0u8; 32];
        root.copy_from_slice(sha256(&preimage).data());
        root
    }

    fn state_id(bytes: [u8; 32]) -> StateId {
        StateId::from_cbor(Decoder::new(&encode_byte_string(&bytes))).unwrap()
    }

    fn singleton_non_inclusion_proof(
        node: &Secp256k1Signer,
        terminal_key: [u8; 32],
        terminal_value: [u8; 32],
    ) -> NonInclusionProof {
        let terminal = state_id(terminal_key);
        let value = DataHash::new(HashAlgorithm::Sha256, terminal_value.to_vec()).unwrap();
        NonInclusionProof::new(
            NonInclusionCertificate::from_parts(
                [0u8; 32],
                alloc::vec![],
                terminal_key,
                terminal_value,
            )
            .unwrap(),
            signed_uc(node, leaf_root(&terminal, &value)),
        )
    }

    /// A unicity certificate committing to `root`, signed by `node`.
    fn signed_uc(node: &Secp256k1Signer, root: [u8; 32]) -> UnicityCertificate {
        let input_record = InputRecord {
            round_number: 0,
            epoch: 0,
            previous_hash: None,
            hash: root.to_vec(),
            summary_value: Vec::new(),
            timestamp: REFERENCE_TIME,
            block_hash: None,
            sum_of_earned_fees: 0,
            executed_transactions_hash: None,
        };
        let mut uc = UnicityCertificate {
            input_record,
            technical_record_hash: None,
            shard_configuration_hash: alloc::vec![0u8; 32],
            shard_tree_certificate: ShardTreeCertificate {
                shard: empty_shard(),
                sibling_hash_list: Vec::new(),
            },
            unicity_tree_certificate: UnicityTreeCertificate {
                partition_identifier: 0,
                steps: Vec::new(),
            },
            unicity_seal: mk_seal(alloc::vec![0u8; 32], Vec::new()),
        };
        let seal_hash = uc.computed_seal_hash().unwrap().data().to_vec();
        let signature = node
            .sign(&mk_seal(seal_hash.clone(), Vec::new()).calculate_hash())
            .encode()
            .to_vec();
        uc.unicity_seal = mk_seal(seal_hash, alloc::vec![("NODE".to_string(), signature)]);
        uc
    }

    /// Build a valid single-leaf inclusion proof for `transaction`, with the
    /// unlock signed by `owner`.
    fn valid_proof(
        transaction: &impl Transaction,
        owner: &Secp256k1Signer,
        node: &Secp256k1Signer,
    ) -> InclusionProof {
        let tx_hash = transaction.calculate_transaction_hash();
        let state_id = StateId::derive(transaction.lock_script(), transaction.source_state_hash());
        let root = leaf_root(&state_id, &calculate_leaf_value(&tx_hash, REFERENCE_TIME));
        let unlock = sign_signature_unlock(owner, transaction.source_state_hash(), &tx_hash);
        let certification_data = CertificationData::new(
            transaction.lock_script().clone(),
            transaction.source_state_hash().clone(),
            tx_hash,
            unlock,
            Some(transaction.expires_at().expect("explicit timeout fixture")),
        );
        InclusionProof {
            certification_data,
            reference_time: REFERENCE_TIME,
            inclusion_certificate: InclusionCertificate::decode(&[0u8; 32]).unwrap(),
            unicity_certificate: signed_uc(node, root),
        }
    }

    fn make_transfer(owner: &Secp256k1Signer, recipient: &Secp256k1Signer) -> TransferTransaction {
        TransferTransaction::new(
            sha256(b"source-state"),
            SignaturePredicate::new(owner.public_key()).to_encoded(),
            SignaturePredicate::new(recipient.public_key()).to_encoded(),
            alloc::vec![7u8; 32],
            None,
            Some(TIMEOUT),
        )
    }

    /// A valid `(trust_base, node, owner, transfer, proof)` baseline.
    fn transfer_case() -> (
        RootTrustBase,
        Secp256k1Signer,
        Secp256k1Signer,
        TransferTransaction,
        InclusionProof,
    ) {
        let node = signer(0x11);
        let owner = signer(0x22);
        let recipient = signer(0x33);
        let transfer = make_transfer(&owner, &recipient);
        let proof = valid_proof(&transfer, &owner, &node);
        (trust_base(&node), node, owner, transfer, proof)
    }

    /// Re-sign `proof`'s unicity certificate after a field of it was changed so
    /// the seal root/signature stay self-consistent (isolates later rules).
    fn reseal(proof: &mut InclusionProof, node: &Secp256k1Signer) {
        let seal_hash = proof
            .unicity_certificate
            .computed_seal_hash()
            .unwrap()
            .data()
            .to_vec();
        let signature = node
            .sign(&mk_seal(seal_hash.clone(), Vec::new()).calculate_hash())
            .encode()
            .to_vec();
        proof.unicity_certificate.unicity_seal =
            mk_seal(seal_hash, alloc::vec![("NODE".to_string(), signature)]);
    }

    fn cert(proof: &InclusionProof) -> &CertificationData {
        &proof.certification_data
    }

    // --- baseline ----------------------------------------------------------

    #[test]
    fn baseline_transfer_proof_verifies() {
        let (tb, _node, _owner, transfer, proof) = transfer_case();
        assert_eq!(
            verify_inclusion_proof(&tb, &proof, &transfer, REFERENCE_TIME),
            Ok(())
        );
        let target = StateId::derive(transfer.lock_script(), transfer.source_state_hash());
        assert_eq!(proof.verify_for(&target, REFERENCE_TIME, &tb), Ok(()));
        assert_eq!(
            proof.verify_for(&state_id([0xff; 32]), REFERENCE_TIME, &tb),
            Err(VerificationError::CertificationDataMismatch)
        );
    }

    // --- non-inclusion proof rules ----------------------------------------

    #[test]
    fn baseline_non_inclusion_proof_verifies() {
        let node = signer(0x11);
        let proof = singleton_non_inclusion_proof(&node, [0x22; 32], [0x33; 32]);
        let target = state_id([0x44; 32]);
        let trust_base = trust_base(&node);
        assert_eq!(
            verify_non_inclusion_proof(&trust_base, &proof, &target),
            Ok(())
        );
        assert_eq!(
            proof.verify(&trust_base),
            Err(VerificationError::NonInclusionTargetMissing)
        );

        let bound = proof.for_state(&target).unwrap();
        assert_eq!(bound.requested_state_id(), Some(&target));
        assert_eq!(bound.verify(&trust_base), Ok(()));
        assert_eq!(bound.verify_for(&target, &trust_base), Ok(()));
        assert_eq!(
            bound.verify_for(&state_id([0x45; 32]), &trust_base),
            Err(VerificationError::NonInclusionTargetMismatch)
        );
        assert_eq!(
            bound.clone().for_state(&state_id([0x45; 32])),
            Err(VerificationError::NonInclusionTargetMismatch)
        );

        let decoded = NonInclusionProof::from_cbor(crate::cbor::Decoder::new(&bound.to_cbor()))
            .expect("wire roundtrip");
        assert_eq!(decoded.requested_state_id(), None);
    }

    #[test]
    fn non_inclusion_proof_rejects_present_target() {
        let node = signer(0x11);
        let terminal = [0x22; 32];
        let proof = singleton_non_inclusion_proof(&node, terminal, [0x33; 32]);
        assert_eq!(
            verify_non_inclusion_proof(&trust_base(&node), &proof, &state_id(terminal)),
            Err(VerificationError::StateIncluded)
        );
    }

    #[test]
    fn non_inclusion_proof_rejects_tampered_terminal() {
        let node = signer(0x11);
        let proof = singleton_non_inclusion_proof(&node, [0x22; 32], [0x33; 32]);
        let mut encoded = proof.certificate().encode();
        *encoded.last_mut().unwrap() ^= 1;
        let tampered = NonInclusionProof::new(
            NonInclusionCertificate::decode(&encoded).unwrap(),
            proof.unicity_certificate().clone(),
        );
        assert_eq!(
            verify_non_inclusion_proof(&trust_base(&node), &tampered, &state_id([0x44; 32])),
            Err(VerificationError::NonInclusionCertificateInvalid)
        );
    }

    #[test]
    fn non_inclusion_proof_requires_a_trusted_quorum() {
        let trusted = signer(0x11);
        let rogue = signer(0x12);
        let proof = singleton_non_inclusion_proof(&rogue, [0x22; 32], [0x33; 32]);
        assert_eq!(
            verify_non_inclusion_proof(&trust_base(&trusted), &proof, &state_id([0x44; 32])),
            Err(VerificationError::QuorumNotMet)
        );
    }

    #[test]
    fn non_inclusion_terminal_must_belong_to_certified_shard() {
        let node = signer(0x11);
        let proof = singleton_non_inclusion_proof(&node, [0x80; 32], [0x33; 32]);
        let mut uc = proof.unicity_certificate().clone();
        // One-bit shard `0`: the target belongs to it, but the authenticated
        // terminal starts with `1` and therefore cannot belong to this root.
        uc.shard_tree_certificate.shard = ShardId::decode(&[0b0100_0000]).unwrap();
        let seal_hash = uc.computed_seal_hash().unwrap().data().to_vec();
        let signature = node
            .sign(&mk_seal(seal_hash.clone(), Vec::new()).calculate_hash())
            .encode()
            .to_vec();
        uc.unicity_seal = mk_seal(seal_hash, alloc::vec![("NODE".to_string(), signature)]);
        let proof = NonInclusionProof::new(proof.certificate().clone(), uc);

        assert_eq!(
            verify_non_inclusion_proof(&trust_base(&node), &proof, &state_id([0x00; 32])),
            Err(VerificationError::ShardMismatch)
        );
    }

    // --- one test per inclusion-proof rule ---------------------------------

    // A proof missing its leaf fields is no longer representable: the wire is
    // rejected at the decoder, so verification never sees a partial proof.
    // `api::inclusion_proof_response` covers the two admissible wire shapes and
    // `api::inclusion_proof` the partial one.

    #[test]
    fn rule_certification_data_mismatch_lock_script() {
        let (tb, _n, _o, transfer, mut proof) = transfer_case();
        let stranger = signer(0xAB);
        let c = cert(&proof);
        proof.certification_data = CertificationData::new(
            SignaturePredicate::new(stranger.public_key()).to_encoded(), // wrong lock
            c.source_state_hash().clone(),
            c.transaction_hash().clone(),
            c.unlock_script().to_vec(),
            Some(TIMEOUT),
        );
        assert_eq!(
            verify_inclusion_proof(&tb, &proof, &transfer, REFERENCE_TIME),
            Err(VerificationError::CertificationDataMismatch)
        );
    }

    #[test]
    fn rule_certification_data_mismatch_source_state() {
        let (tb, _n, _o, transfer, mut proof) = transfer_case();
        let c = cert(&proof);
        proof.certification_data = CertificationData::new(
            c.lock_script().clone(),
            sha256(b"a-different-source-state"), // wrong source
            c.transaction_hash().clone(),
            c.unlock_script().to_vec(),
            Some(TIMEOUT),
        );
        assert_eq!(
            verify_inclusion_proof(&tb, &proof, &transfer, REFERENCE_TIME),
            Err(VerificationError::CertificationDataMismatch)
        );
    }

    #[test]
    fn rule_certification_data_mismatch_timeout() {
        let (tb, _n, _o, transfer, mut proof) = transfer_case();
        let c = cert(&proof);
        proof.certification_data = CertificationData::new(
            c.lock_script().clone(),
            c.source_state_hash().clone(),
            c.transaction_hash().clone(),
            c.unlock_script().to_vec(),
            Some(TIMEOUT + 1),
        );
        assert_eq!(
            verify_inclusion_proof(&tb, &proof, &transfer, REFERENCE_TIME),
            Err(VerificationError::CertificationDataMismatch)
        );
    }

    /// A proof either establishes a leaf or reports that there is none yet. The
    /// aggregators emit all three leaf fields together or none of them, so a
    /// partially present proof is a protocol violation and is rejected at
    /// decode rather than surfacing as a `None` somewhere downstream.
    ///
    /// The partial shapes are assembled by hand because [`InclusionProof`] can
    /// no longer represent one: that is the point of the type.
    #[test]
    fn rejects_a_partially_present_proof() {
        use crate::cbor::{encode_array, encode_byte_string, encode_null, encode_tag};

        let (_tb, _n, _o, _transfer, proof) = transfer_case();
        let certification_data = proof.certification_data.to_cbor();
        let reference_time = crate::cbor::encode_uint(proof.reference_time);
        let inclusion_certificate = encode_byte_string(&proof.inclusion_certificate.encode());
        let unicity_certificate = proof.unicity_certificate.to_cbor();

        // Every combination of the three leaf fields except all-present and
        // all-absent, which are the two the wire admits.
        for present in [0b001, 0b010, 0b011, 0b100, 0b101, 0b110] {
            let slot = |bit: u8, value: &[u8]| -> alloc::vec::Vec<u8> {
                if present & bit != 0 {
                    value.to_vec()
                } else {
                    encode_null()
                }
            };
            let bytes = encode_tag(
                crate::api::inclusion_proof::INCLUSION_PROOF_TAG,
                &encode_array(&[
                    &crate::cbor::encode_uint(1),
                    &slot(0b100, &certification_data),
                    &slot(0b010, &reference_time),
                    &slot(0b001, &inclusion_certificate),
                    &unicity_certificate,
                ]),
            );
            assert!(
                matches!(
                    InclusionProof::from_cbor(Decoder::new(&bytes)),
                    Err(crate::error::Error::UnexpectedValue(_))
                ),
                "partial proof {present:#05b} was accepted"
            );
        }
    }

    #[test]
    fn rule_request_expires_at_timeout_boundary() {
        let (tb, _n, _o, transfer, proof) = transfer_case();
        assert_eq!(
            verify_inclusion_proof(&tb, &proof, &transfer, TIMEOUT),
            Err(VerificationError::RequestExpired)
        );
    }

    #[test]
    fn rule_reference_time_cannot_postdate_certified_round() {
        let (tb, node, _owner, transfer, mut proof) = transfer_case();
        proof.unicity_certificate.input_record.timestamp = REFERENCE_TIME - 1;
        reseal(&mut proof, &node);

        assert_eq!(
            verify_inclusion_proof(&tb, &proof, &transfer, REFERENCE_TIME),
            Err(VerificationError::ReferenceTimeAfterRound)
        );
    }

    #[test]
    fn rule_transaction_hash_mismatch() {
        let (tb, _n, _o, transfer, mut proof) = transfer_case();
        let c = cert(&proof);
        proof.certification_data = CertificationData::new(
            c.lock_script().clone(),
            c.source_state_hash().clone(),
            sha256(b"not-the-tx-hash"),
            c.unlock_script().to_vec(),
            Some(
                // wrong tx hash
                TIMEOUT,
            ),
        );
        assert_eq!(
            verify_inclusion_proof(&tb, &proof, &transfer, REFERENCE_TIME),
            Err(VerificationError::TransactionHashMismatch)
        );
    }

    #[test]
    fn rule_path_invalid() {
        let (tb, node, _o, transfer, mut proof) = transfer_case();
        // Point the inclusion proof at a different state-tree root.
        proof.unicity_certificate.input_record.hash = alloc::vec![0xCDu8; 32];
        reseal(&mut proof, &node); // keep the seal consistent so PATH fails first
        assert_eq!(
            verify_inclusion_proof(&tb, &proof, &transfer, REFERENCE_TIME),
            Err(VerificationError::PathInvalid)
        );
    }

    #[test]
    fn rule_shard_mismatch() {
        let (tb, _n, _o, transfer, mut proof) = transfer_case();
        // A 256-bit all-zero shard cannot be a prefix of a real state id.
        let mut encoded = alloc::vec![0u8; 32];
        encoded.push(0b1000_0000);
        proof.unicity_certificate.shard_tree_certificate.shard = ShardId::decode(&encoded).unwrap();
        assert_eq!(
            verify_inclusion_proof(&tb, &proof, &transfer, REFERENCE_TIME),
            Err(VerificationError::ShardMismatch)
        );
    }

    #[test]
    fn rule_seal_network_mismatch() {
        let (tb, _n, _o, transfer, mut proof) = transfer_case();
        proof.unicity_certificate.unicity_seal.network_id = NetworkId::MAINNET;
        assert_eq!(
            verify_inclusion_proof(&tb, &proof, &transfer, REFERENCE_TIME),
            Err(VerificationError::SealNetworkMismatch)
        );
    }

    #[test]
    fn rule_seal_root_mismatch() {
        let (tb, _n, _o, transfer, mut proof) = transfer_case();
        proof.unicity_certificate.unicity_seal.hash = alloc::vec![0u8; 32];
        assert_eq!(
            verify_inclusion_proof(&tb, &proof, &transfer, REFERENCE_TIME),
            Err(VerificationError::SealRootMismatch)
        );
    }

    #[test]
    fn rule_quorum_not_met_without_signatures() {
        let (tb, _n, _o, transfer, mut proof) = transfer_case();
        proof.unicity_certificate.unicity_seal.signatures = Vec::new();
        assert_eq!(
            verify_inclusion_proof(&tb, &proof, &transfer, REFERENCE_TIME),
            Err(VerificationError::QuorumNotMet)
        );
    }

    #[test]
    fn rule_quorum_not_met_with_untrusted_signer() {
        let (tb, _n, owner, transfer, _p) = transfer_case();
        // Seal signed by a key that is not in the trust base.
        let rogue = signer(0xEE);
        let proof = valid_proof(&transfer, &owner, &rogue);
        assert_eq!(
            verify_inclusion_proof(&tb, &proof, &transfer, REFERENCE_TIME),
            Err(VerificationError::QuorumNotMet)
        );
    }

    #[test]
    fn rule_not_authenticated_on_bad_unlock() {
        let (tb, _n, _o, transfer, mut proof) = transfer_case();
        let c = cert(&proof);
        let mut unlock = c.unlock_script().to_vec();
        unlock[0] ^= 0xff; // corrupt the signature (still 65 bytes)
        proof.certification_data = CertificationData::new(
            c.lock_script().clone(),
            c.source_state_hash().clone(),
            c.transaction_hash().clone(),
            unlock,
            Some(TIMEOUT),
        );
        assert_eq!(
            verify_inclusion_proof(&tb, &proof, &transfer, REFERENCE_TIME),
            Err(VerificationError::NotAuthenticated)
        );
    }

    #[test]
    fn rule_not_authenticated_when_signed_by_non_owner() {
        let (tb, node, _owner, transfer, _p) = transfer_case();
        // A valid signature, but from a key that is not the lock-script owner.
        let thief = signer(0x44);
        let proof = valid_proof(&transfer, &thief, &node);
        assert_eq!(
            verify_inclusion_proof(&tb, &proof, &transfer, REFERENCE_TIME),
            Err(VerificationError::NotAuthenticated)
        );
    }

    // --- genesis-only rules (full token) -----------------------------------

    /// Build a valid genesis-only token (and its trust base).
    fn genesis_token(
        node: &Secp256k1Signer,
        justification: Option<Vec<u8>>,
    ) -> (RootTrustBase, MintTransaction, InclusionProof) {
        let recipient = signer(0x55);
        let mint = MintTransaction::create(
            NetworkId::LOCAL,
            SignaturePredicate::new(recipient.public_key()).to_encoded(),
            TokenType::new(alloc::vec![0xAA; 32]),
            TokenSalt::from_bytes([0x66; 32]),
            None,
            justification,
            Some(TIMEOUT),
        )
        .unwrap();
        let minter = Minter::signer(mint.token_id()).unwrap();
        let proof = valid_proof(&mint, &minter, node);
        (trust_base(node), mint, proof)
    }

    #[test]
    fn baseline_genesis_token_verifies() {
        let node = signer(0x11);
        let (tb, mint, proof) = genesis_token(&node, None);
        let token = Token::new(CertifiedMintTransaction::new(mint, proof), Vec::new());
        assert_eq!(token.verify(&tb), Ok(()));
    }

    #[test]
    fn rule_network_mismatch() {
        let node = signer(0x11);
        let (_, mint, proof) = genesis_token(&node, None);
        let token = Token::new(CertifiedMintTransaction::new(mint, proof), Vec::new());
        // Mint is on LOCAL; verify against a (valid) MAINNET trust base.
        let mainnet = RootTrustBase::new(
            0,
            NetworkId::MAINNET,
            0,
            0,
            alloc::vec![node_info(&node, "NODE")],
            1,
        );
        assert_eq!(
            token.verify(&mainnet),
            Err(VerificationError::NetworkMismatch)
        );
    }

    #[test]
    fn rule_invalid_mint_lock_script() {
        let node = signer(0x11);
        let (tb, mint, mut proof) = genesis_token(&node, None);
        // Replace the certified lock script with one that is not the minter key.
        let stranger = signer(0x77);
        let c = cert(&proof);
        proof.certification_data = CertificationData::new(
            SignaturePredicate::new(stranger.public_key()).to_encoded(),
            c.source_state_hash().clone(),
            c.transaction_hash().clone(),
            c.unlock_script().to_vec(),
            Some(TIMEOUT),
        );
        let token = Token::new(CertifiedMintTransaction::new(mint, proof), Vec::new());
        assert_eq!(
            token.verify(&tb),
            Err(VerificationError::InvalidMintLockScript)
        );
    }

    #[test]
    fn rule_unsupported_mint_justification() {
        let node = signer(0x11);
        // A justified mint whose proof is otherwise fully valid reaches — and
        // fails at — the justification rule (no verifier is registered).
        let (tb, mint, proof) = genesis_token(&node, Some(alloc::vec![0xde, 0xad]));
        let token = Token::new(CertifiedMintTransaction::new(mint, proof), Vec::new());
        assert_eq!(
            token.verify(&tb),
            Err(VerificationError::UnsupportedMintJustification)
        );
    }

    // --- trust base rule ---------------------------------------------------

    #[test]
    fn rule_invalid_trust_base() {
        let node = signer(0x11);
        let (_, mint, proof) = genesis_token(&node, None);
        let token = Token::new(CertifiedMintTransaction::new(mint, proof), Vec::new());

        // Threshold of zero would accept an unsigned seal.
        let zero_threshold = RootTrustBase::new(
            0,
            NetworkId::LOCAL,
            0,
            0,
            alloc::vec![node_info(&node, "NODE")],
            0,
        );
        assert!(matches!(
            token.verify(&zero_threshold),
            Err(VerificationError::InvalidTrustBase(_))
        ));

        // Threshold exceeding the validator count is unattainable.
        let unattainable = RootTrustBase::new(
            0,
            NetworkId::LOCAL,
            0,
            0,
            alloc::vec![node_info(&node, "NODE")],
            2,
        );
        assert!(matches!(
            token.verify(&unattainable),
            Err(VerificationError::InvalidTrustBase(_))
        ));

        // Duplicate signing keys would let one signer satisfy the quorum twice.
        let duplicate = RootTrustBase::new(
            0,
            NetworkId::LOCAL,
            0,
            0,
            alloc::vec![node_info(&node, "NODE-A"), node_info(&node, "NODE-B")],
            2,
        );
        assert!(matches!(
            token.verify(&duplicate),
            Err(VerificationError::InvalidTrustBase(_))
        ));
    }

    // --- error wrapping ----------------------------------------------------

    #[test]
    fn genesis_failures_are_wrapped() {
        let node = signer(0x11);
        let (tb, mint, mut proof) = genesis_token(&node, None);
        proof.unicity_certificate.unicity_seal.hash = alloc::vec![0u8; 32]; // break seal root
        let token = Token::new(CertifiedMintTransaction::new(mint, proof), Vec::new());
        assert_eq!(
            token.verify(&tb),
            Err(VerificationError::Genesis(alloc::boxed::Box::new(
                VerificationError::SealRootMismatch
            )))
        );
    }

    #[test]
    fn transfer_failures_are_wrapped_with_index() {
        // A valid genesis followed by a transfer that spends the genesis output,
        // each with its own single-leaf proof; then break the transfer's seal.
        let node = signer(0x11);
        let owner = signer(0x55); // genesis recipient == transfer owner
        let (tb, mint, genesis_proof) = genesis_token(&node, None);
        let genesis = CertifiedMintTransaction::new(mint, genesis_proof);

        let recipient = signer(0x88);
        let transfer = TransferTransaction::new(
            genesis.result_state_hash(),
            genesis.recipient().clone(),
            SignaturePredicate::new(recipient.public_key()).to_encoded(),
            alloc::vec![9u8; 32],
            None,
            Some(TIMEOUT),
        );
        let mut transfer_proof = valid_proof(&transfer, &owner, &node);

        // Baseline: the whole chain verifies.
        let valid = Token::new(
            genesis.clone(),
            alloc::vec![CertifiedTransferTransaction::new(
                transfer.clone(),
                transfer_proof.clone()
            )],
        );
        assert_eq!(valid.verify(&tb), Ok(()));

        // Break the transfer's seal -> wrapped as Transfer { index: 0, .. }.
        transfer_proof.unicity_certificate.unicity_seal.hash = alloc::vec![0u8; 32];
        let tampered = Token::new(
            genesis,
            alloc::vec![CertifiedTransferTransaction::new(transfer, transfer_proof)],
        );
        assert_eq!(
            tampered.verify(&tb),
            Err(VerificationError::Transfer {
                index: 0,
                source: alloc::boxed::Box::new(VerificationError::SealRootMismatch),
            })
        );
    }

    // --- chain-of-custody (I1/I2): a swapped proof is rejected --------------

    #[test]
    fn transfer_with_foreign_proof_is_rejected() {
        // Give the transfer a proof certified for a *different* state (the
        // genesis state). On verification the state id is derived from the
        // transfer's own reconstructed fields, so the foreign proof no longer
        // matches and the transfer is rejected.
        let node = signer(0x11);
        let (tb, mint, genesis_proof) = genesis_token(&node, None);
        let genesis = CertifiedMintTransaction::new(mint, genesis_proof.clone());

        let recipient = signer(0x88);
        let transfer = TransferTransaction::new(
            genesis.result_state_hash(),
            genesis.recipient().clone(),
            SignaturePredicate::new(recipient.public_key()).to_encoded(),
            alloc::vec![9u8; 32],
            None,
            Some(TIMEOUT),
        );

        // The genesis proof does not attest to the transfer's transaction.
        let tampered = Token::new(
            genesis,
            alloc::vec![CertifiedTransferTransaction::new(transfer, genesis_proof)],
        );
        let result = tampered.verify(&tb);
        assert!(
            matches!(result, Err(VerificationError::Transfer { index: 0, .. })),
            "expected a wrapped transfer rejection, got {result:?}"
        );
    }
}
