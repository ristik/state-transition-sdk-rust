//! Live end-to-end test against the testnet2 gateway.
//!
//! Reads connection parameters from `e2e/.env` (see `e2e/.env.example`), the
//! same source the examples and the `e2e/` demo crate use, then mints and
//! transfers a token through the real aggregator and verifies the result.
//!
//! Ignored by default (it requires network access and live infra). Run with:
//!   cargo test --features http --test e2e -- --ignored --nocapture
#![cfg(feature = "http")]

use std::path::Path;
use std::time::Duration;

use unicity_token::api::bft::RootTrustBase;
use unicity_token::client::{self, HttpAggregatorClient};
use unicity_token::crypto::signer::{Secp256k1Signer, Signer};
use unicity_token::predicate::builtin::SignaturePredicate;
use unicity_token::transaction::ids::{StateMask, TokenSalt, TokenType};

const DEFAULT_GATEWAY: &str = "https://gateway.testnet2.unicity.network/";
const DEFAULT_TRUSTBASE: &str = "bft-trustbase.testnet2.json";

/// Read connection parameters from `e2e/.env`, matching the examples and the
/// `e2e/` demo crate. Values already in the process environment take
/// precedence, so CI can supply the key without writing a file.
fn read_service() -> (String, Option<String>, String) {
    dotenvy::from_path("e2e/.env").ok();

    let gateway = std::env::var("UNICITY_GATEWAY").unwrap_or_else(|_| DEFAULT_GATEWAY.to_string());
    let api_key = std::env::var("UNICITY_API_KEY")
        .ok()
        .filter(|k| !k.is_empty());
    let trustbase =
        std::env::var("UNICITY_TRUSTBASE").unwrap_or_else(|_| DEFAULT_TRUSTBASE.to_string());
    let trustbase_path = if Path::new(&trustbase).is_absolute() {
        trustbase
    } else {
        format!("e2e/{trustbase}")
    };
    (gateway, api_key, trustbase_path)
}

#[test]
#[ignore = "hits the live testnet2 gateway"]
fn e2e_mint_transfer_verify() {
    let timeout = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_secs()
        + 3600;
    let (gateway, api_key, trustbase_path) = read_service();
    let trust_json = std::fs::read_to_string(&trustbase_path)
        .unwrap_or_else(|e| panic!("read trust base {trustbase_path}: {e}"));
    let trust_base = RootTrustBase::from_json(&trust_json).expect("parse trust base");

    let mut aggregator =
        HttpAggregatorClient::new(gateway).with_polling(Duration::from_secs(2), 90);
    if let Some(key) = api_key {
        aggregator = aggregator.with_api_key(key);
    }

    let alice = Secp256k1Signer::generate().unwrap();
    let bob = Secp256k1Signer::generate().unwrap();

    let token = client::mint(
        &aggregator,
        &trust_base,
        trust_base.network_id,
        &SignaturePredicate::new(alice.public_key()),
        TokenType::random().unwrap(),
        TokenSalt::random().unwrap(),
        None,
        None,
        Some(timeout),
    )
    .expect("mint");
    token.verify(&trust_base).expect("verify minted token");

    let transferred = client::transfer(
        &aggregator,
        &trust_base,
        &token,
        &SignaturePredicate::new(bob.public_key()),
        &alice,
        StateMask::random().unwrap(),
        None,
        Some(timeout),
    )
    .expect("transfer");
    transferred
        .verify(&trust_base)
        .expect("verify transferred token");

    println!(
        "transferred token CBOR: {}",
        hex::encode(transferred.to_cbor())
    );
}
