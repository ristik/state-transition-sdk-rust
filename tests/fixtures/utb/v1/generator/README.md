# UTB vector generator

Writes `../utb-vectors-v1.json`, the signed trust-base (record version 2) vector set shared by the JS and Rust SDKs.

Every expected outcome is computed by the Go reference code. Nothing is written by hand:
- entry cases by bft-core `utbstore.Append`;
- genesis cases by `utbstore.Open`;
- bundle cases by `gettrustbase.DecodeBundle`, `VerifyBundle` and `InstallBundle`.

Keys are fixed and signatures follow RFC 6979, so a rerun reproduces the file byte for byte. The `reason` strings are diagnostic only; signer IDs and recovery bytes in them are normalized.

    cd tests/fixtures/utb/v1/generator && go run . -out ../utb-vectors-v1.json && cd .. && shasum -a 256 -c manifest.sha256

Pinned inputs are in `go.mod`: ristik/bft-core `a20708b64a1c` and ristik/bft-go-base `6174434eeb99`. The latter has the strict 65-byte recoverable witness rule from bft-go-base#2.

The interface is each case's result: `appended`, `noop`, `gap`, `conflict` or `refused`, plus `tipAfter`, plus `heldBytesAfter` for replays. For genesis cases it is `valid`; for bundle cases it is `decodes`, `verifies`, `install` and `tipAfter`.
