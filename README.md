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

Mainnet is live. Start with testnet2; for production, use the mainnet gateway and matching trust base.

| Network | Gateway | Network ID | Trust base |
| --- | --- | --- | --- |
| Mainnet | `https://gateway.mainnet.unicity.network` | `1` | [JSON](https://raw.githubusercontent.com/unicitynetwork/unicity-ids/main/bft-trustbase.mainnet.json) |
| Testnet2 | `https://gateway.testnet2.unicity.network` | `4` | [JSON](https://raw.githubusercontent.com/unicitynetwork/unicity-ids/main/bft-trustbase.testnet2.json) |

Pass your gateway API key through `HttpAggregatorClient::with_api_key`. The public testnet2 key is `sk_ddc3cfcc001e4a28ac3fad7407f99590`. Use your own mainnet key obtained from [Sphere](https://sphere.unicity.network/) and keep it secure.

### Client setup

Download the testnet2 trust base above as `bft-trustbase.testnet2.json` in your working directory. Configure the client and load the trust base:

```rust
use std::time::Duration;
use unicity_token::api::bft::RootTrustBase;
use unicity_token::client::HttpAggregatorClient;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let trust_base = RootTrustBase::from_json(
        &std::fs::read_to_string("bft-trustbase.testnet2.json")?,
    )?;
    let _aggregator = HttpAggregatorClient::new(
        "https://gateway.testnet2.unicity.network",
    )
    .with_api_key("sk_ddc3cfcc001e4a28ac3fad7407f99590") // Public testnet2 key
    .with_polling(Duration::from_secs(2), 90);

    println!("Network ID: {}", trust_base.network_id.id());
    Ok(())
}
```

The trust base identifies the Consensus Layer (BFT Core) instance. Pin a trusted copy in your application for production. Use `trust_base.network_id` when creating tokens so they match your gateway; testnet2 is network ID `4` (`NetworkId::TESTNET` is `2`).

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

### Store, send, and receive

Serialize with `token.to_cbor()` to save or send a token, and deserialize with `Token::from_cbor(bytes)` to load it. Verify received tokens before accepting them:

```rust
use unicity_token::Token;

// `token_bytes` comes from your storage or transport.
let token = Token::from_cbor(&token_bytes)?;
token.verify(&trust_base)?;
```

`Token::verify` checks cryptographic history; application data remains opaque. Use `Token::verify_with` for registered mint justifications and `payment::verify_payment_token` for payments.

### Run the examples

From a repository checkout, set the public testnet2 key and run a flow:

```bash
export UNICITY_API_KEY=sk_ddc3cfcc001e4a28ac3fad7407f99590
cargo run --example mint --features http
cargo run --example transfer --features http
cargo run --example split --features http
```

The examples default to testnet2 with its bundled trust base. Configure `UNICITY_GATEWAY`, `UNICITY_API_KEY`, and `UNICITY_TRUSTBASE` through your environment or `e2e/.env`; relative trust-base paths resolve under `e2e/`. Example keys are discarded on exit. See [example configuration](./examples/README.md).

## Security

Unicity proofs provide independently verifiable evidence of certified state transitions being unique, backed by the network's Byzantine fault tolerant consensus. Together with ownership verification, they protect against double-spending without publishing token contents to a public ledger.

Verify tokens against the correct trust base and configure accepted issuers through `PaymentDataVerifier` and `MintJustificationRegistry`. Cryptographic validity does not authorize an issuer. Keep private keys and token backups secure, and check that received tokens belong to the intended recipient.

## Feature flags

| Feature | Default | Purpose |
| --- | --- | --- |
| `alloc` | Via `std` and `client` | Allocated structures used by the verification core. |
| `std` | Yes | Standard library integration, key generation, and JSON trust-base parsing. |
| `client` | Yes | Transaction construction, signing, minting, transfers, and split construction. |
| `http` | No | Blocking HTTP client for host applications. Enables `std` and `client`. |

For verification in a `no_std` environment, including WASM and zkVM guests:

```toml
[dependencies]
unicity-token = { version = "0.1", default-features = false, features = ["alloc"] }
```

Token and payment verification remain available in this configuration. Construct the trust base with `RootTrustBase::try_new`; JSON parsing requires `std`.

## Proof status hints (unauthenticated)

`HttpAggregatorClient` asks aggregators for a status hint (`includeStatus` on `get_inclusion_proof.v2`; aggregator-go issue #209). While waiting for a proof, `pending` keeps polling at the configured cadence, `expired` stops at once with `HttpError::StateExpired` (the same signed request may be resubmitted) and `unknown` stops with `HttpError::StateUnknown` after a short grace (`with_unknown_grace`, default 2 answers: right after a submission another replica may not have seen the request yet). `lookup_inclusion_proof` returns the hint next to the response without waiting. Servers that predate the hint answer with a plain string and everything behaves as before, as it does for status values this version does not know.

The status is **only a hint for control flow and user feedback**. It is not a proof of anything: `unknown` does not show a state was never certified or is unspent, `expired` does not show it is unspent, and an `included` hint is worth nothing without a proof that verifies. A certified proof is returned whatever the hint says, and no token, proof or certificate verification ever depends on it. In batch consolidation the details `state_pending` (retryable), `state_expired`, `state_unknown` and `state_not_in_root` (not retryable) map to `UnavailableReason::{StatePending, StateExpired, StateUnknown, StateNotInRoot}`.

**Resubmitting after `unknown`/`expired`.** A request is signed and deterministic, so sending it again is the same request: the aggregator never creates a second leaf. `resubmit_certification_request` is the idempotent form of the submission: it returns `SubmitOutcome::AlreadySubmitted` instead of an error when the aggregator already holds a record for the state id, which the server reports in two ways (by state id alone, so a *different* request for the same state, such as a conflicting spend, is reported the same way): the Mongo-backed queue refuses the copy of a still-pending request with an internal error (code -32603) whose data names a *duplicate key* (recognized by that text, as the server has no machine code for it; the Redis-backed queue silently accepts and drops the copy), and `STATE_ID_EXISTS` when it is already certified. Every other rejection, such as `REQUEST_EXPIRED`, stays an error, and the plain `submit_certification_request` keeps reporting both duplicate responses as errors. `submit_and_wait(data, max_resubmits)` combines submission, waiting and at most `max_resubmits` resubmissions after `StateUnknown`/`StateExpired`, and requires the proof to certify exactly the submitted data: if the state id was certified with another request it fails with `HttpError::ProofOfOtherData` (an unauthenticated hint, no resubmission) instead of returning the other transaction's proof; `submit_and_wait_verified(data, max_resubmits, &trust_base)` authenticates that proof first and reports `HttpError::StateCertifiedWithOtherData` (the race is really lost) only if it verifies. With several aggregator instances behind a load balancer a node that did not admit the request may answer `unknown`; after a restart the in-memory status is empty, so queued requests answer `unknown` until a round pulls them.

## Partition views and seal reuse (building blocks)

`unicity_token::consolidation` (pure `no_std + alloc`, no network) decodes the frozen `PartitionViewV1` — the complete shard-leaf vector of a partition under one unicity seal — as an *untrusted candidate*. `PartitionView::authenticate` validates its structure, rebuilds the native shard tree, follows the enclosing certificate's partition path to the seal hash, matches the enclosing leaf exactly and authenticates the complete seal under *your* anchored `RootTrustBase` (network, exact epoch, round ≥ epoch start, quorum); only then it returns an immutable `AuthenticatedView`, the sole input of `certificates()` (ordinary unicity certificates of every shard, all carrying the identical master seal). No peer configuration list is needed: the seal commits to every leaf's configuration hash. Independently pinned shard configuration hashes (`Some(&PartitionTopology)`) are an optional stricter policy and are part of `AuthenticatedView::identity()`. The authority is never taken from a response.

Verification of tokens authenticates each distinct complete seal once per operation (`verify::SealSession`, a bounded memo of successful quorum checks bound to one trust base). Only the quorum-signature check is reused; paths, reference times, predicates and application rules run for every proof. `verify::verify_token_with_seal_stats` reports the signature work performed. This does not shrink tokens or change their format, and nested proofs that carry other seals still need their own check. Nothing here contacts an aggregator or consolidates a token automatically.

## Explicit proof consolidation (opt-in)

With the `client` feature, `client::ProofClient::consolidate(&token, &options)` returns a *new*, fully verified token whose replaceable outer-history proofs share one unicity seal — useful before EVM / bridge-back or zkVM verification, where a verifier that reuses a successful quorum check pays for the signatures once. It is never automatic (nothing in mint, transfer, receive, import, serialization or `Token::verify` calls it), needs no signing key, and never submits or resubmits a transaction. The token format and size do not change, and proofs nested in signed mint justifications or split/burn dependencies stay byte-identical (they may still need their own seals; the summary reports outer-history and whole-verification quorum checks separately).

An attempt asks the *master* shard (the one with the newest authenticated evidence) for its latest batch and partition view, authenticates it under your trust base and configured topology, then fetches the exact roots the authenticated view names from the other participating shards (bounded parallel on a host), all under one deadline and one `CancelToken`. The batch call is the optional `client::BatchAggregatorClient` capability (`get_inclusion_proofs.v1`), implemented by `HttpAggregatorClient`; it is never emulated from single-proof calls. Results are typed: `Consolidated`, or `Unavailable { reason, retryable }` for missing capability / unretained or not-yet-published views / busy (the original token is untouched), versus errors for integrity failures, transport and server failures, timeouts and cancellation. See `examples/consolidate_for_bridge.rs` and `examples/consolidate_for_zkvm.rs`. Pure planning and checked reconstruction (`consolidation::{ShardRouter, outer_proofs, rebuild_token, ..}`) are `no_std + alloc`.

## Development

```bash
cargo test
cargo test --all-features
cargo test --no-default-features --features alloc
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
```

The [live end-to-end test](./tests/e2e.rs) is ignored by default. It reads gateway credentials from `e2e/unicity-service` and uses `e2e/bft-trustbase.testnet2.json`:

```bash
cargo test --features http --test e2e -- --ignored --nocapture
```

## Resources

- [Unicity Network](https://github.com/unicitynetwork/)
- [Examples](./examples) and [standalone demo](./e2e/README.md)
- [Report an issue](https://github.com/unicitynetwork/state-transition-sdk-rust/issues)

## License

MIT OR Apache-2.0.
