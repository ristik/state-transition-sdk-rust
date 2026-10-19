//! Token minting against a live aggregator — the Rust equivalent of the
//! reference SDKs' `tests/examples/mint`.
//!
//! Connection parameters come from `e2e/.env` (see `e2e/.env.example`); the
//! example talks to the gateway via [`HttpAggregatorClient`] and prints the
//! minted token's CBOR, just like the model example.
//!
//! Run with:
//!   cargo run --example mint --features http

use std::path::Path;
use std::time::Duration;

use unicity_token::api::bft::TrustBaseHistory;
use unicity_token::cbor::encode_text_string;
use unicity_token::client::{self, HttpAggregatorClient};
use unicity_token::crypto::signer::{Secp256k1Signer, Signer};
use unicity_token::predicate::builtin::SignaturePredicate;
use unicity_token::transaction::ids::{TokenSalt, TokenType};

/// Build an aggregator client and its trust base from `e2e/.env`.
fn load() -> (HttpAggregatorClient, TrustBaseHistory) {
    // Load e2e/.env (values already in the process environment win).
    dotenvy::from_path("e2e/.env").ok();

    let gateway = std::env::var("UNICITY_GATEWAY").unwrap_or_else(|_| {
        panic!("set UNICITY_GATEWAY to your deployment's aggregator URL (testnet2's V1 trust base is not supported by this major version)")
    });
    let trustbase =
        std::env::var("UNICITY_TRUSTBASE").unwrap_or_else(|_| {
        panic!("set UNICITY_TRUSTBASE to your deployment's V2 genesis (JSON or CBOR) or release bundle; e2e/dev has a development fixture")
    });
    let trustbase_path = if Path::new(&trustbase).is_absolute() {
        trustbase
    } else {
        format!("e2e/{trustbase}")
    };

    let trust_base = TrustBaseHistory::from_file(
        &std::fs::read(&trustbase_path)
            .unwrap_or_else(|e| panic!("read trust base {trustbase_path}: {e}")),
        None,
    )
    .expect("parse trust base");

    let mut aggregator =
        HttpAggregatorClient::new(gateway).with_polling(Duration::from_secs(2), 90);
    if let Ok(key) = std::env::var("UNICITY_API_KEY") {
        aggregator = aggregator.with_api_key(key);
    }

    (aggregator, trust_base)
}

fn main() {
    let (aggregator, trust_base) = load();

    // A fresh in-memory owner wallet.
    let owner = Secp256k1Signer::generate().expect("generate owner key");
    let owner_predicate = SignaturePredicate::new(owner.public_key());

    // `client::mint` submits the certification request, waits for the inclusion
    // proof, assembles the token, and verifies it before returning.
    let token = client::mint(
        &aggregator,
        &trust_base,
        trust_base.network_id(),
        &owner_predicate,
        TokenType::random().expect("token type"),
        TokenSalt::random().expect("salt"),
        Some(encode_text_string("My custom data")),
        None,
        /* expires_at */ None,
    )
    .expect("mint");

    println!("{}", hex::encode(token.to_cbor()));
}
