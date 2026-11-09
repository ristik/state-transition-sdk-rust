# Live testnet2 end-to-end demo

This standalone program exercises the Rust State Transition SDK against the
Unicity testnet2 gateway. It:

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
# Edit .env and set UNICITY_API_KEY.
cargo run --release
```

The program loads `.env` with `dotenvy`. Values already present in the process
environment take precedence, which keeps it suitable for CI and deployed
environments. `.env` is git-ignored and the credential is never written to the
generated token files. Mint and transfer requests set an exclusive
`expiresAt` deadline one hour ahead of the current Unix time.

Defaults:

- Gateway: `https://gateway.testnet2.unicity.network/`
- Trustbase: `./bft-trustbase.testnet2.json`
- Output directory: `./artifacts`

Configure or override these with `UNICITY_GATEWAY`, `UNICITY_API_KEY`,
`UNICITY_TRUSTBASE`, and `UNICITY_OUTPUT_DIR`.

The generated wallets are intentionally ephemeral. Their private keys remain
in process memory and are discarded when the demo exits.
