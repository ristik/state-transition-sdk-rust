# Examples

Runnable example flows, talking to a
**live aggregator** through [`HttpAggregatorClient`].

| Example | Reference | Run |
|---------|-----------|-----|
| `mint` | `state-transition-sdk-js/tests/examples/mint` | `cargo run --example mint --features http` |
| `transfer` | `.../tests/examples/transfer` | `cargo run --example transfer --features http` |
| `split` | `.../tests/examples/split` | `cargo run --example split --features http` |
| `consolidate_for_bridge` | explicit proof consolidation before EVM / bridge-back | `cargo run --example consolidate_for_bridge --features http -- token.hex out.hex` |
| `consolidate_for_zkvm` | host consolidation, guest verifies from scratch | `cargo run --example consolidate_for_zkvm --features http -- token.hex` |

The two consolidation examples need `UNICITY_SHARD_ENDPOINTS` (the partition is the fixed `AGGREGATION_PARTITION_ID`, 7) (see `examples/common/consolidation.rs`) and are never run automatically.

Each example prints the resulting token's CBOR as hex, exactly like the model
examples (`console.log(HexConverter.encode(token.toCBOR()))`). `split` mints a
coin carrying a fungible payload, splits it into several coins (burning the
original), and prints each minted output after verifying it fail-closed with
`payment::verify_payment_token`.

## Configuration

Connection parameters are read from `e2e/.env` (copy `e2e/.env.example` and set
your key):

```
UNICITY_GATEWAY=https://your-aggregator.example/
UNICITY_API_KEY=sk_…
UNICITY_TRUSTBASE=/path/to/bft-trustbase.bundle.cbor  # your deployment's V2 genesis (JSON or CBOR) or release bundle
```

Values already present in the process environment take precedence. The examples
require the `http` feature (a blocking TLS HTTP stack); they generate ephemeral
in-memory wallets and never persist keys. Each submitted transaction uses an
service-assigned deadline derived from consensus time, so the examples do not require a valid system clock.

For a fuller standalone demo (mint → save → reload → transfer → verify), see the
`e2e/` crate.
