# Unicity State Transition SDK — Rust

Build applications that mint, transfer, and verify digital assets on the Unicity Network. This Rust SDK gives you control over tokens, ownership rules, and payments, with cryptographic verification built in.

Unicity combines private, off-chain token transactions with network-backed protection against double-spending. Token data stays with the parties you share it with, while unicity proofs let recipients verify that assets are spent only once. The network is designed to scale horizontally as demand grows.

- **Create digital assets:** mint tokens with your own types and application data payload.
- **Move value:** transfer tokens and split fungible tokens for payments.
- **Verify locally:** validate token history and unicity proofs against the compact trust base.
- **Integrate with your application:** choose ownership predicates, issuance policies, storage, and delivery channels.
- **Use Rust across environments:** use the HTTP client in host applications or the `no_std` verification core in WASM and zkVM guests.

## Installation

Requires Rust 1.81 or later. Add the SDK with its HTTP client to your `Cargo.toml`:

```toml
[dependencies]
unicity-token = { version = "0.1", features = ["http"] }
```

## Unicity Network

Version 4 of this crate verifies **V2 trust bases** (a signed entry per epoch, see [Trust base history](./docs/api-reference.md)). A network that publishes only the V1 trust base record is not supported by this major version: **testnet2's V1 trust base is not supported** (testnet2 stays V1), and neither is any other V1-only network. Use the 3.x releases for those, or point version 4 at a deployment that publishes a V2 genesis (JSON or CBOR) or a release bundle.

Pass your gateway API key through `HttpAggregatorClient::with_api_key` and keep it secure. For a deployment of your own, take its aggregator URL and its V2 trust base file from the operator; `e2e/dev/` holds a development fixture (public test keys) that shows the formats.

### Client setup

Put your deployment's trust base file (a release bundle, a genesis entry, or a V2 genesis JSON) in your working directory as `bft-trustbase.json`. Configure the client and load the trust base history:

```rust
use std::time::Duration;
use unicity_token::api::bft::TrustBaseHistory;
use unicity_token::client::HttpAggregatorClient;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let trust_base = TrustBaseHistory::from_file(
        &std::fs::read("bft-trustbase.json")?,
        None, // the deployment's genesis identity, when it has one
    )?;
    let _aggregator = HttpAggregatorClient::new("https://your-aggregator.example")
        .with_api_key("your-api-key")
        .with_polling(Duration::from_secs(2), 90);

    println!("Network ID: {}", trust_base.network_id().id());
    Ok(())
}
```

The trust base history identifies the Consensus Layer (BFT Core) instance and holds one signed entry per epoch. Ship the complete history known at release time with your application: the latest held entry is effectively the pin, held entries are never replaced, and newer entries are verified from it (see `docs/api-reference.md` §6). Use `trust_base.network_id()` when creating tokens so they match your gateway; take the network ID from the history (`trust_base.network_id()`).

`HttpAggregatorClient` provides a blocking HTTP transport. Applications can implement the `AggregatorClient` trait to supply their own transport.

## Working with tokens

The SDK handles cryptography and token encoding. Your application manages keys, stores tokens, and delivers them to recipients over your chosen transport.

| Task | SDK entry points | Example |
| --- | --- | --- |
| Mint a token | `client::mint` | [Mint](./examples/mint.rs) |
| Transfer ownership | `client::transfer` | [Transfer](./examples/transfer.rs) |
| Split a fungible token | `payment::TokenSplit::split` | [Split](./examples/split.rs) |
| Verify a payment token | `payment::verify_payment_token` | [Payment verification](./examples/split.rs) |

`client::mint` and `client::transfer` submit the transaction, wait for its unicity proof (`InclusionProof` in the API), and return the verified token. The [split example](./examples/split.rs) includes payment verifier setup.

While waiting, the client stops early with `HttpError::StateExpired` or `HttpError::StateUnknown` when the aggregator reports that it dropped the request or does not know it. The same signed request can then be submitted again. The wait uses long polling by default: the aggregator holds each request open while the state is pending, so the proof arrives soon after certification. Servers without long polling are polled at the configured interval. See the [API reference](./docs/api-reference.md#1-waiting-for-inclusion-proofs).

### Store, send, and receive

Serialize with `token.to_cbor()` to save or send a token, and deserialize with `Token::from_cbor(bytes)` to load it. Verify received tokens before accepting them:

```rust
use unicity_token::Token;

// `token_bytes` comes from your storage or transport.
let token = Token::from_cbor(&token_bytes)?;
token.verify(&trust_base)?;
```

`Token::verify` checks cryptographic history; application data remains opaque. Use `Token::verify_with` for registered mint justifications and `payment::verify_payment_token` for payments.

### Proof consolidation

Each transaction in a token's history has its own unicity proof, usually certified in a different round. Verifying the history in a constrained environment, such as a smart contract or a zkVM guest, means authenticating every one of those certificates. `client::ProofClient::consolidate` fetches new proofs for the token's history so that they share one unicity certificate, which then has to be authenticated only once. It is optional and the SDK never calls it on its own. See the [API reference](./docs/api-reference.md#4-proof-consolidation) and [`examples/consolidate_for_zkvm.rs`](./examples/consolidate_for_zkvm.rs).

### Non-inclusion proofs

A non-inclusion proof shows that a state ID was absent from the aggregator's state tree at one certified snapshot. It does not show that the state is absent now or that a token can be spent. `AggregatorClient::get_non_inclusion_proof` fetches the proof, and `NonInclusionProof::verify_at_snapshot` verifies it and returns the authenticated snapshot. Before relying on the result, compare the snapshot's network and round with a checkpoint your application trusts independently. See the [API reference](./docs/api-reference.md#5-non-inclusion-proofs).

### Run the examples

From a repository checkout, point the examples at your deployment and run a flow:

```bash
export UNICITY_GATEWAY=https://your-aggregator.example/
export UNICITY_API_KEY=your-api-key
export UNICITY_TRUSTBASE=/path/to/bft-trustbase.bundle.cbor
cargo run --example mint --features http
cargo run --example transfer --features http
cargo run --example split --features http
```

The examples have no network defaults: set `UNICITY_GATEWAY`, `UNICITY_API_KEY`, and `UNICITY_TRUSTBASE` through your environment or `e2e/.env`; relative trust-base paths resolve under `e2e/`. Example keys are discarded on exit. See [example configuration](./examples/README.md).

## Security

Unicity proofs provide independently verifiable evidence of certified state transitions being unique, backed by the network's Byzantine fault tolerant consensus. Together with ownership verification, they protect against double-spending without publishing token contents to a public ledger.

Verify tokens against the correct trust base and configure accepted issuers through `PaymentDataVerifier` and `MintJustificationRegistry`. Cryptographic validity does not authorize an issuer. Keep private keys and token backups secure, and check that received tokens belong to the intended recipient.

## Feature flags

| Feature | Default | Purpose |
| --- | --- | --- |
| `alloc` | Via `std` and `client` | Allocated structures used by the verification core. |
| `std` | Yes | Standard library integration, key generation, and the V2 genesis JSON loader. |
| `client` | Yes | Transaction construction, signing, minting, transfers, and split construction. |
| `http` | No | Blocking HTTP client for host applications. Enables `std` and `client`. |

For verification in a `no_std` environment, including WASM and zkVM guests:

```toml
[dependencies]
unicity-token = { version = "0.1", default-features = false, features = ["alloc"] }
```

Token and payment verification remain available in this configuration. Build the history from a release bundle (`TrustBaseHistory::from_bundle`) or a genesis entry (`TrustBaseEntry::from_cbor`, `TrustBaseHistory::from_genesis`); the file and JSON loaders require `std`.

## Development

```bash
cargo test
cargo test --all-features
cargo test --no-default-features --features alloc
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
```

The [live end-to-end test](./tests/e2e.rs) is ignored by default. It reads the gateway, key and trust base from `e2e/.env` or the environment (see `e2e/.env.example`):

```bash
cargo test --features http --test e2e -- --ignored --nocapture
```

## Resources

- [Unicity Network](https://github.com/unicitynetwork/)
- [API reference](./docs/api-reference.md)
- [Examples](./examples) and [standalone demo](./e2e/README.md)
- [Report an issue](https://github.com/unicitynetwork/state-transition-sdk-rust/issues)

## License

MIT OR Apache-2.0.
