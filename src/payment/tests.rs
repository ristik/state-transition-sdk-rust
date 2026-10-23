//! End-to-end token-split tests: build a payment-carrying token, split it into
//! per-asset RSMST allocations, mint each output with a [`SplitMintJustification`],
//! and verify the outputs against the trust base through the registered split
//! verifier. Negative cases confirm each split rule rejects its forgery.

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use num_bigint::BigUint;

use super::{
    split_output_commitment, verify_payment_token, Asset, AssetId, PaymentAssetCollection,
    PaymentDataVerifier, SplitManifest, SplitMintJustification, SplitMintJustificationVerifier,
    SplitOutputPayload, SplitTokenRequest, TokenSplit,
};
use crate::api::bft::{
    InputRecord, RootTrustBase, RootTrustBaseNodeInfo, ShardId, ShardTreeCertificate,
    UnicityCertificate, UnicitySeal, UnicityTreeCertificate,
};
use crate::api::calculate_leaf_value;
use crate::api::inclusion_proof::InclusionProof;
use crate::api::{CertificationData, InclusionCertificate, NetworkId, StateId};
use crate::crypto::hash::{sha256, DataHash};
use crate::crypto::signer::{Secp256k1Signer, Signer};
use crate::predicate::builtin::{BurnPredicate, SignaturePredicate};
use crate::predicate::unlock::sign_signature_unlock;
use crate::predicate::EncodedPredicate;
use crate::rsmst::build::Rsmst;
use crate::transaction::ids::{TokenId, TokenSalt, TokenType};
use crate::transaction::{
    CertifiedMintTransaction, CertifiedTransferTransaction, MintTransaction, Minter, Token,
    Transaction, TransferTransaction,
};
use crate::verify::{
    verify_token_with_policy, MintJustificationRegistry, VerificationError, VerificationLimits,
    VerificationPolicy,
};

/// Reference time every fixture in this module certifies under.
const REFERENCE_TIME: u64 = 1755000000;
/// Exclusive certification request timeout every fixture in this module uses.
const TIMEOUT: u64 = 1755003600;

// --- proof construction (mirrors the verify-engine test harness) -----------

fn signer(b: u8) -> Secp256k1Signer {
    Secp256k1Signer::from_bytes(&[b; 32]).unwrap()
}

fn sig_pred(s: &Secp256k1Signer) -> EncodedPredicate {
    SignaturePredicate::new(s.public_key()).to_encoded()
}

fn node_info(s: &Secp256k1Signer, id: &str) -> RootTrustBaseNodeInfo {
    RootTrustBaseNodeInfo {
        node_id: id.to_string(),
        signing_key: s.public_key(),
        stake: 1,
    }
}

fn trust_base(node: &Secp256k1Signer) -> RootTrustBase {
    RootTrustBase::new(0, NetworkId::LOCAL, 0, 0, vec![node_info(node, "NODE")], 1)
}

fn empty_shard() -> ShardId {
    ShardId::decode(&[0b1000_0000]).unwrap()
}

fn mk_seal(hash: Vec<u8>, signatures: Vec<(String, Vec<u8>)>) -> UnicitySeal {
    UnicitySeal {
        network_id: NetworkId::LOCAL,
        root_chain_round_number: 1,
        epoch: 0,
        timestamp: REFERENCE_TIME,
        previous_hash: None,
        hash,
        signatures,
    }
}

fn leaf_root(state_id: &StateId, tx_hash: &DataHash) -> [u8; 32] {
    let mut preimage = vec![0x00u8];
    preimage.extend_from_slice(state_id.bytes());
    preimage.extend_from_slice(tx_hash.data());
    let mut root = [0u8; 32];
    root.copy_from_slice(sha256(&preimage).data());
    root
}

fn signed_uc(node: &Secp256k1Signer, root: [u8; 32]) -> UnicityCertificate {
    let input_record = InputRecord {
        round_number: 0,
        epoch: 0,
        previous_hash: None,
        hash: Some(root.to_vec()),
        summary_value: Some(Vec::new()),
        timestamp: REFERENCE_TIME,
        block_hash: Some(vec![5; 32]),
        sum_of_earned_fees: 0,
        executed_transactions_hash: None,
    };
    let mut uc = UnicityCertificate {
        input_record,
        technical_record_hash: Some(vec![6; 32]),
        shard_configuration_hash: vec![0u8; 32],
        shard_tree_certificate: ShardTreeCertificate {
            shard: empty_shard(),
            sibling_hash_list: Vec::new(),
        },
        unicity_tree_certificate: UnicityTreeCertificate {
            partition_identifier: crate::api::AGGREGATION_PARTITION_ID,
            steps: Vec::new(),
        },
        unicity_seal: mk_seal(vec![0u8; 32], Vec::new()),
    };
    let seal_hash = uc.computed_seal_hash().unwrap().data().to_vec();
    let signature = node
        .sign(&mk_seal(seal_hash.clone(), Vec::new()).calculate_hash())
        .encode()
        .to_vec();
    uc.unicity_seal = mk_seal(seal_hash, vec![("NODE".to_string(), signature)]);
    uc
}

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

// --- scenario builders ------------------------------------------------------

/// Source/output token type. Splitting is never a type conversion, so the source
/// and every output share one coin token type.
fn coin_type() -> TokenType {
    TokenType::new(vec![0xC0; 32])
}

fn asset_a() -> AssetId {
    AssetId::new(vec![0xAA; 32])
}
fn asset_b() -> AssetId {
    AssetId::new(vec![0xBB; 32])
}

/// Mint a source token to `owner` carrying `payment`, fully certified.
fn source_token(node: &Secp256k1Signer, owner: &Secp256k1Signer) -> Token {
    let payment = PaymentAssetCollection::create([
        Asset::new(asset_a(), BigUint::from(100u32)),
        Asset::new(asset_b(), BigUint::from(50u32)),
    ])
    .unwrap();
    let mint = MintTransaction::create(
        NetworkId::LOCAL,
        sig_pred(owner),
        coin_type(),
        TokenSalt::from_bytes([0x01; 32]),
        Some(payment.to_cbor()),
        None,
        Some(TIMEOUT),
    )
    .unwrap();
    let minter = Minter::signer(mint.token_id()).unwrap();
    let proof = valid_proof(&mint, &minter, node);
    Token::new(CertifiedMintTransaction::new(mint, proof), Vec::new())
}

/// Wrap a burn transfer into a certified, burned source token.
fn burned_token(
    source: &Token,
    burn_tx: TransferTransaction,
    owner: &Secp256k1Signer,
    node: &Secp256k1Signer,
) -> Token {
    let proof = valid_proof(&burn_tx, owner, node);
    Token::new(
        source.genesis().clone(),
        vec![CertifiedTransferTransaction::new(burn_tx, proof)],
    )
}

/// Mint a split output token, certified, carrying its split justification.
fn mint_output(
    network: NetworkId,
    recipient: EncodedPredicate,
    token_type: TokenType,
    salt: TokenSalt,
    assets: &PaymentAssetCollection,
    justification: &SplitMintJustification,
    node: &Secp256k1Signer,
) -> Token {
    mint_output_bytes(
        network,
        recipient,
        token_type,
        salt,
        assets.to_cbor(),
        justification,
        node,
    )
}

/// Like [`mint_output`], minting exactly `data` as the payload.
fn mint_output_bytes(
    network: NetworkId,
    recipient: EncodedPredicate,
    token_type: TokenType,
    salt: TokenSalt,
    data: Vec<u8>,
    justification: &SplitMintJustification,
    node: &Secp256k1Signer,
) -> Token {
    let mint = MintTransaction::create(
        network,
        recipient,
        token_type,
        salt,
        Some(data),
        Some(justification.to_cbor()),
        Some(TIMEOUT),
    )
    .unwrap();
    let minter = Minter::signer(mint.token_id()).unwrap();
    let proof = valid_proof(&mint, &minter, node);
    Token::new(CertifiedMintTransaction::new(mint, proof), Vec::new())
}

fn registry() -> MintJustificationRegistry {
    let mut r = MintJustificationRegistry::new();
    r.register(Box::new(SplitMintJustificationVerifier::new()))
        .unwrap();
    r.register_token_data(Box::new(PaymentDataVerifier::new(
        coin_type(),
        authorize_test_payment,
    )))
    .unwrap();
    r
}

fn authorize_test_payment(
    _genesis: &CertifiedMintTransaction,
    _assets: &PaymentAssetCollection,
) -> Result<(), VerificationError> {
    Ok(())
}

/// Build the full positive scenario, returning everything needed by the tests.
struct Scenario {
    tb: RootTrustBase,
    node: Secp256k1Signer,
    source: Token,
    alice: Secp256k1Signer,
    requests: Vec<SplitTokenRequest>,
}

fn scenario() -> Scenario {
    let node = signer(0x11);
    let alice = signer(0x22);
    let bob = signer(0x33);
    let carol = signer(0x44);
    let source = source_token(&node, &alice);

    let req1 = SplitTokenRequest::create(
        sig_pred(&bob),
        PaymentAssetCollection::create([
            Asset::new(asset_a(), BigUint::from(60u32)),
            Asset::new(asset_b(), BigUint::from(50u32)),
        ])
        .unwrap(),
        coin_type(),
        TokenSalt::from_bytes([0x10; 32]),
    );
    let req2 = SplitTokenRequest::create(
        sig_pred(&carol),
        PaymentAssetCollection::create([Asset::new(asset_a(), BigUint::from(40u32))]).unwrap(),
        coin_type(),
        TokenSalt::from_bytes([0x20; 32]),
    );

    Scenario {
        tb: trust_base(&node),
        node,
        source,
        alice,
        requests: vec![req1, req2],
    }
}

/// Forge a single-asset output by hand-building an RSMST allocation that claims
/// `amount` of `asset_id`, then minting against it. The forged manifest carries
/// one root per source asset (the second is a dummy) so it passes the structural
/// length check and the relevant per-asset rule is reached.
fn forged_single_asset_output(s: &Scenario, asset_id: AssetId, amount: u32) -> Token {
    forged_output_with_type(s, asset_id, amount, coin_type())
}

fn forged_output_with_type(
    s: &Scenario,
    asset_id: AssetId,
    amount: u32,
    token_type: TokenType,
) -> Token {
    let recipient = sig_pred(&signer(0x55));
    let salt = TokenSalt::from_bytes([0x31; 32]);
    let token_id = TokenId::derive(NetworkId::LOCAL, &salt);
    let assets =
        PaymentAssetCollection::create([Asset::new(asset_id, BigUint::from(amount))]).unwrap();
    let commitment = split_output_commitment(
        s.source.id(),
        NetworkId::LOCAL,
        &recipient,
        &salt,
        &token_id,
        &token_type,
        &assets.to_cbor(),
    );

    let mut tree = Rsmst::new();
    tree.insert(*token_id.bytes(), commitment, BigUint::from(amount))
        .unwrap();
    let built = tree.build().unwrap();
    let proof = built.proof(token_id.bytes()).unwrap();

    // Source has two assets (asset_a, asset_b in canonical order); align the
    // forged root at index 0 and pad index 1 with a dummy root.
    let manifest = SplitManifest::create(vec![built.root_hash(), [0u8; 32]]).unwrap();
    let burn_predicate = BurnPredicate::new(manifest.reason_hash().to_vec());
    let (source_state_hash, lock_script) = s.source.latest_state();
    let burn = TransferTransaction::new(
        source_state_hash,
        lock_script,
        burn_predicate.to_encoded(),
        vec![9u8; 32],
        Some(manifest.to_cbor()),
        Some(TIMEOUT),
    );
    let burned = burned_token(&s.source, burn, &s.alice, &s.node);
    let justification = SplitMintJustification::create(burned, vec![proof]).unwrap();
    mint_output(
        NetworkId::LOCAL,
        recipient,
        token_type,
        salt,
        &assets,
        &justification,
        &s.node,
    )
}

// --- tests ------------------------------------------------------------------

#[test]
fn split_outputs_verify_end_to_end() {
    let s = scenario();
    assert_eq!(s.source.verify(&s.tb), Ok(()), "source token should verify");
    let registry = registry();
    assert_eq!(
        verify_payment_token(
            &s.source,
            &s.tb,
            &registry,
            PaymentAssetCollection::from_cbor_bytes,
        )
        .unwrap()
        .len(),
        2
    );

    let split = TokenSplit::split(
        &s.source,
        &s.tb,
        &registry,
        PaymentAssetCollection::from_cbor_bytes,
        s.requests,
        Some([7u8; 32]),
        Some(TIMEOUT),
    )
    .unwrap();

    let burned = burned_token(&s.source, split.burn.transaction.clone(), &s.alice, &s.node);
    assert_eq!(burned.verify(&s.tb), Ok(()), "burned token should verify");

    for out in &split.tokens {
        let just = SplitMintJustification::create(burned.clone(), out.proofs.clone()).unwrap();
        // Justification round-trips byte-for-byte.
        assert_eq!(
            SplitMintJustification::from_cbor(&just.to_cbor())
                .unwrap()
                .to_cbor(),
            just.to_cbor()
        );
        let token = mint_output(
            out.network_id,
            out.recipient.clone(),
            out.token_type.clone(),
            out.salt.clone(),
            &out.assets,
            &just,
            &s.node,
        );
        assert_eq!(
            token.verify_with(&s.tb, &registry),
            Ok(()),
            "split output should verify"
        );
        // Without the split verifier registered it is fail-closed.
        assert_eq!(
            token.verify(&s.tb),
            Err(VerificationError::UnsupportedMintJustification)
        );
    }
}

#[test]
fn payment_verification_requires_registered_payload_validator() {
    let s = scenario();
    assert_eq!(
        verify_payment_token(
            &s.source,
            &s.tb,
            &MintJustificationRegistry::new(),
            PaymentAssetCollection::from_cbor_bytes,
        ),
        Err(VerificationError::UnsupportedTokenData)
    );
}

#[test]
fn payment_verification_enforces_issuance_policy() {
    fn reject(
        _genesis: &CertifiedMintTransaction,
        _assets: &PaymentAssetCollection,
    ) -> Result<(), VerificationError> {
        Err(VerificationError::PaymentIssuanceRejected)
    }

    let s = scenario();
    let mut registry = MintJustificationRegistry::new();
    registry
        .register_token_data(Box::new(PaymentDataVerifier::new(coin_type(), reject)))
        .unwrap();
    assert_eq!(
        verify_payment_token(
            &s.source,
            &s.tb,
            &registry,
            PaymentAssetCollection::from_cbor_bytes,
        ),
        Err(VerificationError::PaymentIssuanceRejected)
    );
}

#[test]
fn recursive_split_verification_honors_shared_depth_limit() {
    let s = scenario();
    let split = TokenSplit::split(
        &s.source,
        &s.tb,
        &registry(),
        PaymentAssetCollection::from_cbor_bytes,
        s.requests,
        Some([7u8; 32]),
        Some(TIMEOUT),
    )
    .unwrap();
    let burned = burned_token(&s.source, split.burn.transaction.clone(), &s.alice, &s.node);
    let out = &split.tokens[0];
    let justification = SplitMintJustification::create(burned, out.proofs.clone()).unwrap();
    let token = mint_output(
        out.network_id,
        out.recipient.clone(),
        out.token_type.clone(),
        out.salt.clone(),
        &out.assets,
        &justification,
        &s.node,
    );
    let policy = VerificationPolicy {
        limits: VerificationLimits {
            max_embedded_token_depth: 0,
            ..VerificationLimits::default()
        },
        require_token_data_verifier: false,
    };

    assert_eq!(
        verify_token_with_policy(&token, &s.tb, &registry(), policy),
        Err(VerificationError::BurnTokenVerificationFailed(Box::new(
            VerificationError::VerificationLimitExceeded("embedded token depth")
        )))
    );
}

#[test]
fn rejects_inflated_allocation_built_without_split_builder() {
    let s = scenario();
    // Forge a tree claiming 1,000 units although the source owns only 100.
    let token = forged_single_asset_output(&s, asset_a(), 1_000);

    assert_eq!(
        token.verify_with(&s.tb, &registry()),
        Err(VerificationError::SplitSourceAmountMismatch)
    );
}

#[test]
fn rejects_asset_absent_from_burned_source() {
    let s = scenario();
    let token = forged_single_asset_output(&s, AssetId::new(vec![0xCC; 32]), 10);

    assert_eq!(
        token.verify_with(&s.tb, &registry()),
        Err(VerificationError::SplitSourceAssetMissing)
    );
}

#[test]
fn rejects_tampered_output_amount() {
    let s = scenario();
    let split = TokenSplit::split(
        &s.source,
        &s.tb,
        &registry(),
        PaymentAssetCollection::from_cbor_bytes,
        s.requests,
        Some([7u8; 32]),
        Some(TIMEOUT),
    )
    .unwrap();
    let burned = burned_token(&s.source, split.burn.transaction.clone(), &s.alice, &s.node);
    let registry = registry();

    let out = &split.tokens[0];
    let just = SplitMintJustification::create(burned, out.proofs.clone()).unwrap();
    // Declare a different amount of asset A than the proof (and commitment) cover.
    let inflated = PaymentAssetCollection::create([
        Asset::new(asset_a(), BigUint::from(61u32)),
        Asset::new(asset_b(), BigUint::from(50u32)),
    ])
    .unwrap();
    let token = mint_output(
        out.network_id,
        out.recipient.clone(),
        out.token_type.clone(),
        out.salt.clone(),
        &inflated,
        &just,
        &s.node,
    );
    assert_eq!(
        token.verify_with(&s.tb, &registry),
        Err(VerificationError::SplitAllocationProofInvalid)
    );
}

#[test]
fn rejects_dropped_proof() {
    let s = scenario();
    let split = TokenSplit::split(
        &s.source,
        &s.tb,
        &registry(),
        PaymentAssetCollection::from_cbor_bytes,
        s.requests,
        Some([7u8; 32]),
        Some(TIMEOUT),
    )
    .unwrap();
    let burned = burned_token(&s.source, split.burn.transaction.clone(), &s.alice, &s.node);
    let registry = registry();

    let out = &split.tokens[0]; // has two assets / two proofs
    let mut proofs = out.proofs.clone();
    proofs.pop(); // drop one proof while payment still declares two assets
    let just = SplitMintJustification::create(burned, proofs).unwrap();
    let token = mint_output(
        out.network_id,
        out.recipient.clone(),
        out.token_type.clone(),
        out.salt.clone(),
        &out.assets,
        &just,
        &s.node,
    );
    assert_eq!(
        token.verify_with(&s.tb, &registry),
        Err(VerificationError::SplitProofCountMismatch)
    );
}

#[test]
fn rejects_wrong_burn_predicate() {
    let s = scenario();
    let split = TokenSplit::split(
        &s.source,
        &s.tb,
        &registry(),
        PaymentAssetCollection::from_cbor_bytes,
        s.requests,
        Some([7u8; 32]),
        Some(TIMEOUT),
    )
    .unwrap();
    let registry = registry();

    // Burn the source carrying the real manifest, but locked to an unrelated burn
    // predicate (not SHA-256 of the manifest).
    let (source_state_hash, lock_script) = s.source.latest_state();
    let wrong_burn = TransferTransaction::new(
        source_state_hash,
        lock_script,
        BurnPredicate::new(b"not-the-manifest-hash".to_vec()).to_encoded(),
        vec![7u8; 32],
        Some(split.burn.manifest.clone()),
        Some(TIMEOUT),
    );
    let burned = burned_token(&s.source, wrong_burn, &s.alice, &s.node);
    assert_eq!(
        burned.verify(&s.tb),
        Ok(()),
        "the wrong burn still verifies on its own"
    );

    let out = &split.tokens[0];
    let just = SplitMintJustification::create(burned, out.proofs.clone()).unwrap();
    let token = mint_output(
        out.network_id,
        out.recipient.clone(),
        out.token_type.clone(),
        out.salt.clone(),
        &out.assets,
        &just,
        &s.node,
    );
    assert_eq!(
        token.verify_with(&s.tb, &registry),
        Err(VerificationError::SplitBurnPredicateMismatch)
    );
}

#[test]
fn rejects_output_token_type_mismatch_at_verify() {
    let s = scenario();
    // A self-consistent forged output whose token type differs from the source:
    // construction-time checks are bypassed, but the verifier still rejects it.
    let token = forged_output_with_type(&s, asset_a(), 100, TokenType::new(vec![0xC9; 32]));
    assert_eq!(
        token.verify_with(&s.tb, &registry()),
        Err(VerificationError::SplitTokenTypeMismatch)
    );
}

#[test]
fn rejects_missing_manifest() {
    let s = scenario();
    let split = TokenSplit::split(
        &s.source,
        &s.tb,
        &registry(),
        PaymentAssetCollection::from_cbor_bytes,
        s.requests,
        Some([7u8; 32]),
        Some(TIMEOUT),
    )
    .unwrap();
    // Burn with no auxiliary manifest data at all.
    let (source_state_hash, lock_script) = s.source.latest_state();
    let burn = TransferTransaction::new(
        source_state_hash,
        lock_script,
        BurnPredicate::new(b"x".to_vec()).to_encoded(),
        vec![3u8; 32],
        None,
        Some(TIMEOUT),
    );
    let burned = burned_token(&s.source, burn, &s.alice, &s.node);
    let out = &split.tokens[0];
    let just = SplitMintJustification::create(burned, out.proofs.clone()).unwrap();
    let token = mint_output(
        out.network_id,
        out.recipient.clone(),
        out.token_type.clone(),
        out.salt.clone(),
        &out.assets,
        &just,
        &s.node,
    );
    assert_eq!(
        token.verify_with(&s.tb, &registry()),
        Err(VerificationError::SplitManifestMissing)
    );
}

#[test]
fn rejects_manifest_length_mismatch() {
    let s = scenario();
    let split = TokenSplit::split(
        &s.source,
        &s.tb,
        &registry(),
        PaymentAssetCollection::from_cbor_bytes,
        s.requests,
        Some([7u8; 32]),
        Some(TIMEOUT),
    )
    .unwrap();
    // A self-consistent burn whose manifest has one root, although the source
    // carries two assets.
    let short = SplitManifest::create(vec![[0u8; 32]]).unwrap();
    let (source_state_hash, lock_script) = s.source.latest_state();
    let burn = TransferTransaction::new(
        source_state_hash,
        lock_script,
        BurnPredicate::new(short.reason_hash().to_vec()).to_encoded(),
        vec![4u8; 32],
        Some(short.to_cbor()),
        Some(TIMEOUT),
    );
    let burned = burned_token(&s.source, burn, &s.alice, &s.node);
    let out = &split.tokens[0];
    let just = SplitMintJustification::create(burned, out.proofs.clone()).unwrap();
    let token = mint_output(
        out.network_id,
        out.recipient.clone(),
        out.token_type.clone(),
        out.salt.clone(),
        &out.assets,
        &just,
        &s.node,
    );
    assert_eq!(
        token.verify_with(&s.tb, &registry()),
        Err(VerificationError::SplitManifestLengthMismatch)
    );
}

#[test]
fn rejects_wrong_output_token_type() {
    let s = scenario();
    // A split request whose output type differs from the source is rejected at
    // construction (splitting is not a token-type conversion).
    let bad = vec![SplitTokenRequest::create(
        sig_pred(&signer(0x33)),
        PaymentAssetCollection::create([
            Asset::new(asset_a(), BigUint::from(100u32)),
            Asset::new(asset_b(), BigUint::from(50u32)),
        ])
        .unwrap(),
        TokenType::new(vec![0xC9; 32]),
        TokenSalt::from_bytes([0x10; 32]),
    )];
    assert!(TokenSplit::split_unchecked(
        &s.source,
        PaymentAssetCollection::from_cbor_bytes,
        bad,
        Some([7u8; 32]),
        Some(TIMEOUT)
    )
    .is_err());
}

#[test]
fn rejects_unbalanced_split_at_build_time() {
    let s = scenario();
    let bob = signer(0x33);
    // Asset A totals 99, not the source's 100 -> value conservation fails.
    let bad = vec![SplitTokenRequest::create(
        sig_pred(&bob),
        PaymentAssetCollection::create([
            Asset::new(asset_a(), BigUint::from(99u32)),
            Asset::new(asset_b(), BigUint::from(50u32)),
        ])
        .unwrap(),
        coin_type(),
        TokenSalt::from_bytes([0x10; 32]),
    )];
    assert!(TokenSplit::split_unchecked(
        &s.source,
        PaymentAssetCollection::from_cbor_bytes,
        bad,
        Some([7u8; 32]),
        Some(TIMEOUT)
    )
    .is_err());
}

// --- application-specific output payloads -----------------------------------

/// Test-local application envelope `tag(39050, [1, assets, ext])`; the SDK
/// itself knows nothing of it. `ext` is `null` as encoded here.
fn wrap(assets: &PaymentAssetCollection, ext: &[u8]) -> Vec<u8> {
    crate::cbor::encode_tag(
        39050,
        &crate::cbor::encode_array(&[&crate::cbor::encode_uint(1), &assets.to_cbor(), ext]),
    )
}

/// Decoder for [`wrap`]. Deliberately ignores `ext`, so the envelope carries
/// bytes the decoded assets do not reflect.
fn unwrap(bytes: &[u8]) -> Result<PaymentAssetCollection, crate::Error> {
    let d = crate::cbor::Decoder::new(bytes);
    d.finish()?;
    let items = d.expect_tag(39050)?.array(Some(3))?;
    if items[0].uint()? != 1 {
        return Err(crate::Error::UnexpectedValue("bad envelope version"));
    }
    PaymentAssetCollection::from_cbor_bytes(items[1].bytes())
}

const NULL: [u8; 1] = [0xf6];

fn wrapped_registry() -> MintJustificationRegistry {
    let mut r = MintJustificationRegistry::new();
    r.register(Box::new(
        SplitMintJustificationVerifier::with_payment_decoder(unwrap),
    ))
    .unwrap();
    r.register_token_data(Box::new(PaymentDataVerifier::with_payment_decoder(
        coin_type(),
        unwrap,
        authorize_test_payment,
    )))
    .unwrap();
    r
}

fn one_asset(n: u32) -> PaymentAssetCollection {
    PaymentAssetCollection::create([Asset::new(asset_a(), BigUint::from(n))]).unwrap()
}

fn wrapped_request(owner: &Secp256k1Signer, amount: u32, salt: u8) -> SplitTokenRequest {
    let assets = one_asset(amount);
    let bytes = wrap(&assets, &NULL);
    SplitTokenRequest::create_with_payload(
        sig_pred(owner),
        SplitOutputPayload::new(assets, bytes, unwrap).unwrap(),
        coin_type(),
        TokenSalt::from_bytes([salt; 32]),
    )
}

/// Mint a wrapped source token of `amount` to `owner`.
fn wrapped_source(node: &Secp256k1Signer, owner: &Secp256k1Signer, amount: u32) -> Token {
    let mint = MintTransaction::create(
        NetworkId::LOCAL,
        sig_pred(owner),
        coin_type(),
        TokenSalt::from_bytes([0x02; 32]),
        Some(wrap(&one_asset(amount), &NULL)),
        None,
        Some(TIMEOUT),
    )
    .unwrap();
    let minter = Minter::signer(mint.token_id()).unwrap();
    let proof = valid_proof(&mint, &minter, node);
    Token::new(CertifiedMintTransaction::new(mint, proof), Vec::new())
}

/// Split `source` (owned by `owner`) and mint every output with exactly the
/// bytes the split returned.
fn split_and_mint(
    tb: &RootTrustBase,
    node: &Secp256k1Signer,
    owner: &Secp256k1Signer,
    source: &Token,
    requests: Vec<SplitTokenRequest>,
) -> Vec<Token> {
    let registry = wrapped_registry();
    let split = TokenSplit::split(
        source,
        tb,
        &registry,
        unwrap,
        requests,
        Some([7u8; 32]),
        Some(TIMEOUT),
    )
    .unwrap();
    let burned = burned_token(source, split.burn.transaction.clone(), owner, node);
    split
        .tokens
        .iter()
        .map(|out| {
            let just = SplitMintJustification::create(burned.clone(), out.proofs.clone()).unwrap();
            mint_output_bytes(
                out.network_id,
                out.recipient.clone(),
                out.token_type.clone(),
                out.salt.clone(),
                out.payload.clone(),
                &just,
                node,
            )
        })
        .collect()
}

#[test]
fn wrapped_payload_split_and_resplit_verify() {
    let node = signer(0x11);
    let alice = signer(0x22);
    let bob = signer(0x33);
    let carol = signer(0x44);
    let tb = trust_base(&node);
    let registry = wrapped_registry();

    let source = wrapped_source(&node, &alice, 10);
    let outputs = split_and_mint(
        &tb,
        &node,
        &alice,
        &source,
        vec![
            wrapped_request(&bob, 3, 0x10),
            wrapped_request(&carol, 7, 0x20),
        ],
    );
    for token in &outputs {
        assert_eq!(token.verify_with(&tb, &registry), Ok(()));
        // The minted bytes are the envelope, not the bare collection.
        let data = token.genesis().transaction().data().unwrap();
        assert_eq!(unwrap(data).unwrap().len(), 1);
        assert_ne!(data, unwrap(data).unwrap().to_cbor().as_slice());
    }

    // Split the 7-unit child again and verify the whole ancestry.
    let grandchildren = split_and_mint(
        &tb,
        &node,
        &carol,
        &outputs[1],
        vec![
            wrapped_request(&alice, 2, 0x30),
            wrapped_request(&bob, 5, 0x40),
        ],
    );
    for token in &grandchildren {
        assert_eq!(token.verify_with(&tb, &registry), Ok(()));
    }
}

#[test]
fn bare_request_payload_is_the_bare_encoding() {
    let s = scenario();
    let split = TokenSplit::split_unchecked(
        &s.source,
        PaymentAssetCollection::from_cbor_bytes,
        s.requests,
        Some([7u8; 32]),
        Some(TIMEOUT),
    )
    .unwrap();
    for out in &split.tokens {
        assert_eq!(out.payload, out.assets.to_cbor());
    }
}

#[test]
fn rejects_declared_assets_that_do_not_match_payload() {
    let bytes = wrap(&one_asset(3), &NULL);
    // Different amount, different asset, bare bytes under the envelope decoder,
    // and garbage all fail before any request (hence any burn) exists.
    assert!(SplitOutputPayload::new(one_asset(4), bytes.clone(), unwrap).is_err());
    let other =
        PaymentAssetCollection::create([Asset::new(asset_b(), BigUint::from(3u32))]).unwrap();
    assert!(SplitOutputPayload::new(other, bytes.clone(), unwrap).is_err());
    assert!(SplitOutputPayload::new(one_asset(3), one_asset(3).to_cbor(), unwrap).is_err());
    assert!(SplitOutputPayload::new(one_asset(3), vec![0xff], unwrap).is_err());
    // Trailing bytes are not a valid encoding either.
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(SplitOutputPayload::new(one_asset(3), trailing, unwrap).is_err());
    // The matching payload is accepted and keeps its exact bytes.
    let ok = SplitOutputPayload::new(one_asset(3), bytes.clone(), unwrap).unwrap();
    assert_eq!(ok.bytes(), bytes.as_slice());
    assert_eq!(ok.assets(), &one_asset(3));
}

#[test]
fn rejects_payload_tampering_that_preserves_decoded_amounts() {
    let node = signer(0x11);
    let alice = signer(0x22);
    let bob = signer(0x33);
    let carol = signer(0x44);
    let tb = trust_base(&node);
    let registry = wrapped_registry();
    let source = wrapped_source(&node, &alice, 10);

    let split = TokenSplit::split(
        &source,
        &tb,
        &registry,
        unwrap,
        vec![
            wrapped_request(&bob, 3, 0x10),
            wrapped_request(&carol, 7, 0x20),
        ],
        Some([7u8; 32]),
        Some(TIMEOUT),
    )
    .unwrap();
    let burned = burned_token(&source, split.burn.transaction.clone(), &alice, &node);
    let out = &split.tokens[0];
    let just = SplitMintJustification::create(burned, out.proofs.clone()).unwrap();

    let mint = |data: Vec<u8>| {
        mint_output_bytes(
            out.network_id,
            out.recipient.clone(),
            out.token_type.clone(),
            out.salt.clone(),
            data,
            &just,
            &node,
        )
    };
    // Untampered bytes verify.
    assert_eq!(
        mint(out.payload.clone()).verify_with(&tb, &registry),
        Ok(())
    );
    // Same decoded assets, different envelope bytes (ext field): rejected.
    let tampered = wrap(&one_asset(3), &[0x00]);
    assert_eq!(unwrap(&tampered).unwrap(), out.assets);
    assert_ne!(tampered, out.payload);
    assert_eq!(
        mint(tampered).verify_with(&tb, &registry),
        Err(VerificationError::SplitAllocationProofInvalid)
    );
}
