//! Token split against a live aggregator — the Rust equivalent of the reference
//! SDKs' `tests/examples/split`.
//!
//! Mints a coin token carrying a fungible payment payload (300 EUR + 500 USD),
//! splits it into three new coins (150 EUR, 150 EUR, 500 USD), burns the
//! original to its split-manifest burn predicate, mints each output with a
//! `SplitMintJustification`, and verifies the outputs **fail-closed** via
//! [`payment::verify_payment_token`]. Each minted output's CBOR is printed as
//! hex, like the model example.
//!
//! Connection parameters come from `e2e/.env` (see `e2e/.env.example`).
//!
//! Run with:
//!   cargo run --example split --features http
//!
//! [`payment::verify_payment_token`]: unicity_token::payment::verify_payment_token

use std::path::Path;
use std::time::Duration;

use num_bigint::BigUint;

use unicity_token::api::bft::RootTrustBase;
use unicity_token::api::StateId;
use unicity_token::client::{self, AggregatorClient, HttpAggregatorClient};
use unicity_token::crypto::signer::{Secp256k1Signer, Signer};
use unicity_token::payment::{
    verify_payment_token, Asset, AssetId, PaymentAssetCollection, PaymentDataVerifier,
    SplitMintJustification, SplitToken, SplitTokenRequest, TokenSplit,
};
use unicity_token::predicate::builtin::SignaturePredicate;
use unicity_token::transaction::ids::{StateMask, TokenSalt, TokenType};
use unicity_token::transaction::{
    CertifiedMintTransaction, MintTransaction, Minter, Token, Transaction,
};
use unicity_token::verify::{MintJustificationRegistry, VerificationError};

const DEFAULT_GATEWAY: &str = "https://gateway.testnet2.unicity.network/";
const DEFAULT_TRUSTBASE: &str = "bft-trustbase.testnet2.json";

/// A fixed burn state mask so the split's burn transfer can be re-submitted
/// through `client::transfer` and reproduced byte-for-byte.
const BURN_STATE_MASK: [u8; 32] = [0x42; 32];

/// Build an aggregator client and its trust base from `e2e/.env`.
fn load() -> (HttpAggregatorClient, RootTrustBase) {
    dotenvy::from_path("e2e/.env").ok();

    let gateway = std::env::var("UNICITY_GATEWAY").unwrap_or_else(|_| DEFAULT_GATEWAY.to_string());
    let trustbase =
        std::env::var("UNICITY_TRUSTBASE").unwrap_or_else(|_| DEFAULT_TRUSTBASE.to_string());
    let trustbase_path = if Path::new(&trustbase).is_absolute() {
        trustbase
    } else {
        format!("e2e/{trustbase}")
    };

    let trust_base = RootTrustBase::from_json(
        &std::fs::read_to_string(&trustbase_path)
            .unwrap_or_else(|e| panic!("read trust base {trustbase_path}: {e}")),
    )
    .expect("parse trust base");

    let mut aggregator =
        HttpAggregatorClient::new(gateway).with_polling(Duration::from_secs(2), 90);
    if let Ok(key) = std::env::var("UNICITY_API_KEY") {
        aggregator = aggregator.with_api_key(key);
    }

    (aggregator, trust_base)
}

/// Application issuance policy for the coin token type. Cryptographic validity is
/// necessary but never sufficient: a real consumer authorizes the *issuer* here
/// (e.g. checks the minter key against an allow-list, or caps total supply).
/// This demo trusts any issuer.
fn authorize_issuance(
    _genesis: &CertifiedMintTransaction,
    _assets: &PaymentAssetCollection,
) -> Result<(), VerificationError> {
    Ok(())
}

/// Mint one split output token (carrying its `SplitMintJustification`) and verify
/// it fail-closed with the payment verifier set. `client::mint` cannot be used
/// here: its internal verification is the bare `Token::verify`, which rejects any
/// mint justification.
fn mint_split_output(
    aggregator: &HttpAggregatorClient,
    trust_base: &RootTrustBase,
    registry: &MintJustificationRegistry,
    burnt: &Token,
    out: &SplitToken,
) -> Token {
    let justification = SplitMintJustification::create(burnt.clone(), out.proofs.clone())
        .expect("build split mint justification");

    let transaction = MintTransaction::create(
        out.network_id,
        out.recipient.clone(),
        out.token_type.clone(),
        out.salt.clone(),
        Some(out.assets.to_cbor()),
        Some(justification.to_cbor()),
        /* expires_at */ None,
    )
    .expect("build split output mint");

    // The genesis is unlocked by the deterministic minter key for the token id.
    let signer = Minter::signer(transaction.token_id()).expect("minter signer");
    let certification_data = client::certification_data_for(&transaction, &signer);
    aggregator
        .submit_certification_request(&certification_data)
        .expect("submit split output certification");

    let state_id = StateId::derive(transaction.lock_script(), transaction.source_state_hash());
    let proof = aggregator
        .get_inclusion_proof(&state_id)
        .expect("split output inclusion proof");
    let token = Token::new(
        CertifiedMintTransaction::new(transaction, proof),
        Vec::new(),
    );

    // Fail-closed payment verification: requires the registered split verifier
    // and the coin token-data verifier; returns the validated assets.
    let assets = verify_payment_token(
        &token,
        trust_base,
        registry,
        PaymentAssetCollection::from_cbor_bytes,
    )
    .expect("verify split output");
    assert_eq!(assets, out.assets, "verified assets must match the output");

    token
}

fn main() {
    let (aggregator, trust_base) = load();

    // One shared "coin" token type for the source and every split output, so a
    // single payment data verifier covers the whole chain.
    let coin_type = TokenType::random().expect("token type");

    // The verifier set a consumer trusts: accept split-minted coins, and run the
    // issuance policy for the coin token type. Without this, payment tokens are
    // rejected (cryptographic certification alone does not authorize an issuer).
    let mut registry = MintJustificationRegistry::new();
    registry
        .register(Box::new(
            unicity_token::payment::SplitMintJustificationVerifier::new(),
        ))
        .expect("register split verifier")
        .register_token_data(Box::new(PaymentDataVerifier::new(
            coin_type.clone(),
            authorize_issuance,
        )))
        .expect("register coin data verifier");

    // Alice mints a coin carrying 300 EUR + 500 USD.
    let alice = Secp256k1Signer::generate().expect("alice key");
    let eur = AssetId::new(*b"EUR");
    let usd = AssetId::new(*b"USD");
    let source_payment = PaymentAssetCollection::create([
        Asset::new(eur.clone(), BigUint::from(300u32)),
        Asset::new(usd.clone(), BigUint::from(500u32)),
    ])
    .expect("source payment");

    let source = client::mint(
        &aggregator,
        &trust_base,
        trust_base.network_id,
        &SignaturePredicate::new(alice.public_key()),
        coin_type.clone(),
        TokenSalt::random().expect("salt"),
        Some(source_payment.to_cbor()),
        None,
        /* expires_at */ None,
    )
    .expect("mint source coin");

    // Split into three coins: 150 EUR, 150 EUR, 500 USD (value is conserved).
    let owner_predicate = SignaturePredicate::new(alice.public_key()).to_encoded();
    let requests = vec![
        SplitTokenRequest::create(
            owner_predicate.clone(),
            PaymentAssetCollection::create([Asset::new(eur.clone(), BigUint::from(150u32))])
                .unwrap(),
            coin_type.clone(),
            TokenSalt::random().expect("salt"),
        ),
        SplitTokenRequest::create(
            owner_predicate.clone(),
            PaymentAssetCollection::create([Asset::new(eur, BigUint::from(150u32))]).unwrap(),
            coin_type.clone(),
            TokenSalt::random().expect("salt"),
        ),
        SplitTokenRequest::create(
            owner_predicate,
            PaymentAssetCollection::create([Asset::new(usd, BigUint::from(500u32))]).unwrap(),
            coin_type,
            TokenSalt::random().expect("salt"),
        ),
    ];

    // `split` verifies the source token (history, embedded chain, issuance
    // policy) before constructing the irreversible burn.
    let split = TokenSplit::split(
        &source,
        &trust_base,
        &registry,
        PaymentAssetCollection::from_cbor_bytes,
        requests,
        Some(BURN_STATE_MASK),
        /* expires_at */ None,
    )
    .expect("build split");

    // Burn the source coin to the split's manifest burn predicate, storing the
    // exact manifest bytes as the burn transfer's auxiliary data and reusing the
    // same state mask so the certified burn matches the split proofs.
    let burnt = client::transfer(
        &aggregator,
        &trust_base,
        &source,
        &split.burn.owner_predicate,
        &alice,
        StateMask::from_bytes(BURN_STATE_MASK),
        Some(split.burn.manifest.clone()),
        /* expires_at */ None,
    )
    .expect("burn source coin");

    // Mint and verify each output coin.
    for (i, out) in split.tokens.iter().enumerate() {
        let token = mint_split_output(&aggregator, &trust_base, &registry, &burnt, out);
        println!("Token[{}]: {}", i + 1, hex::encode(token.to_cbor()));
    }
}
