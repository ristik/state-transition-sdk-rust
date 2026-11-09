//! Token transfer against a live aggregator — the Rust equivalent of the
//! reference SDKs' `tests/examples/transfer`.
//!
//! Mints a token to Alice, re-decodes it from CBOR (as a recipient would),
//! verifies it, transfers it to Bob, and prints the resulting token's CBOR.
//! Connection parameters come from `e2e/.env` (see `e2e/.env.example`).
//!
//! Run with:
//!   cargo run --example transfer --features http

use std::path::Path;
use std::time::Duration;

use unicity_token::api::bft::RootTrustBase;
use unicity_token::cbor::encode_text_string;
use unicity_token::client::{self, HttpAggregatorClient};
use unicity_token::crypto::signer::{Secp256k1Signer, Signer};
use unicity_token::predicate::builtin::SignaturePredicate;
use unicity_token::transaction::ids::{StateMask, TokenSalt, TokenType};
use unicity_token::transaction::Token;

const DEFAULT_GATEWAY: &str = "https://gateway.testnet2.unicity.network/";
const DEFAULT_TRUSTBASE: &str = "bft-trustbase.testnet2.json";

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

fn main() {
    let (aggregator, trust_base) = load();

    // Alice mints a token.
    let alice = Secp256k1Signer::generate().expect("alice key");
    let alice_token = client::mint(
        &aggregator,
        &trust_base,
        trust_base.network_id,
        &SignaturePredicate::new(alice.public_key()),
        TokenType::random().expect("token type"),
        TokenSalt::random().expect("salt"),
        Some(encode_text_string("My custom data")),
        None,
        /* expires_at */ None,
    )
    .expect("mint");

    // Serialize and hand off; the recipient decodes and verifies before use.
    let serialized = alice_token.to_cbor();
    let token = Token::from_cbor(&serialized).expect("decode");
    token.verify(&trust_base).expect("verify received token");

    // Alice transfers the token to Bob, authorising the spend with her key.
    let bob = Secp256k1Signer::generate().expect("bob key");
    let transferred = client::transfer(
        &aggregator,
        &trust_base,
        &token,
        &SignaturePredicate::new(bob.public_key()),
        &alice,
        StateMask::random().expect("state mask"),
        Some(encode_text_string("My custom transfer data")),
        /* expires_at */ None,
    )
    .expect("transfer");

    println!("{}", hex::encode(transferred.to_cbor()));
}
