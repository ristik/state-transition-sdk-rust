# Live end-to-end demo

This standalone program exercises the Rust State Transition SDK against the
gateway of your own deployment. This major version verifies **V2** trust bases only; testnet2's V1 trust base is not supported. It:

1. Generates fresh Alice and Bob secp256k1 wallets in memory.
2. Mints a token to Alice and waits for its inclusion proof.
3. Saves, reloads, and verifies `artifacts/token-minted.cbor`.
4. Transfers the token from Alice to Bob and waits for its inclusion proof.
5. Saves, reloads, and verifies `artifacts/token-transferred.cbor`.
6. Confirms the final state is locked to Bob and contains one transfer.

## Run

From this directory:

```sh
cp .env.example .env
# Edit .env: UNICITY_GATEWAY, UNICITY_API_KEY and UNICITY_TRUSTBASE (your deployment's V2 genesis or bundle).
cargo run --release
```

The program loads `.env` with `dotenvy`. Values already present in the process
environment take precedence, which keeps it suitable for CI and deployed
environments. `.env` is git-ignored and the credential is never written to the
generated token files. Mint and transfer requests set an exclusive
`expiresAt` deadline one hour ahead of the current Unix time.

Configuration (no network defaults: the demo talks to your deployment):

- `UNICITY_GATEWAY` (required): the aggregator URL.
- `UNICITY_API_KEY` (required).
- `UNICITY_TRUSTBASE` (required): the deployment's V2 genesis (JSON or CBOR) or release bundle.
  [`dev/`](./dev) holds a development fixture (public test keys) that shows the formats; it only
  verifies against an aggregator whose validators use those keys.
- `UNICITY_OUTPUT_DIR` (optional): default `./artifacts`.

The generated wallets are intentionally ephemeral. Their private keys remain
in process memory and are discarded when the demo exits.
