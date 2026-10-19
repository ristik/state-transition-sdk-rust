# Development trust base fixture

`bft-trustbase.dev.genesis.json` (a V2 genesis entry, JSON form), `bft-trustbase.dev.bundle.cbor`
(the history of epochs 1 to 4 as one release bundle, tag 39015) and `bft-trustbase.dev.genesis.entryid`
(the genesis identity, the pin) are the shared UTB test chain (`tests/fixtures/utb/v1`, generated from
Go): network 3, four validators with public test keys. All three files are emitted by the Go
generator (`json.MarshalIndent` of bft-go-base `RootTrustBaseV2`, whose absent hashes are `""`;
`TrustBaseEntry::from_json` reads `""` and `null` as absent) and are byte-identical in the JS SDK
(`tests/fixtures/utb/dev`).

They authenticate **nothing real**: use them to see the file formats, to run offline checks, and with a
development aggregator whose validators use these keys. For a real deployment, give
`UNICITY_TRUSTBASE` the genesis (JSON or CBOR) or the release bundle of that deployment.
