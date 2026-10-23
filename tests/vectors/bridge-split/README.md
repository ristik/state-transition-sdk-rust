# Bridge split cross-SDK vectors

`bridge_split.json` is a byte-identical copy of the JS SDK's
`tests/fixtures/bridge-split/v1/bridge_split.json` (ristik/state-transition-sdk-js, commit
`a0e97b7cb2e51eac7fe25b21b7fae58580f60cb4`, written by
`tests/functional/payment/BridgeSplitVectorTest.ts`; its README lists the fixed inputs).

The payment data is the native bridge's wallet value envelope
`tag(39050, [1, [[b(aid32), b(amount)]], null])`. A source of 100 (units of 10^15 wei) is split
into 40 + 60, and the minted 40 is split again into 15 + 25; `leaves` are the two minted
second-generation tokens. `tests/split_bridge_vectors.rs` rebuilds both splits from the recorded
sources with the verifying `TokenSplit::split` and checks that the second generation verifies
with its whole ancestry under a fail-closed issuance policy.

To refresh: regenerate in the JS SDK, then copy the file here unchanged.
