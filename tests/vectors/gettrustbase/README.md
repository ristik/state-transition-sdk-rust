# Shared GetTrustBase response vectors

`vectors.json` is vendored byte for byte, not generated here:

- source: `ristik/bft-core`, branch `integration/enshrined-evm`, squash commit `5d9a8eaa211b480fc37227d41eebd912ef1440c5` (PR #928), `gettrustbase/testdata/v1/vectors.json`, 45 cases (reference codec: `gettrustbase/codec.go`); the same bytes as the JS SDK's copy.
- sha256: `3f9732fa5d5bed202d326f452f732d625040dbfac81857e19574df25bde3734c`
- never edit this copy; regenerate at the source.

Layout: `{spec[], entries[3], network, cases[]}`. An accept case names the decoded fields (`status`, `fromEpoch`, `effectiveEnd`, `endEntryId`, `entryEpochs`, `nextEpoch`); a reject case names the class (`encoding`: not a well-formed deterministic response; `response`: a consistency rule). Used by `tests/gettrustbase_vectors.rs`. The three entries are those of `tests/vectors/trust-base-v2` (epochs 1..3 of network 5).
