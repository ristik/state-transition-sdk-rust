# B1 seal vector generator

Derives `../b1-seal-vectors-v1.json` from the B1 any-age corpus, bft-core `b1ref/testdata/b1-vectors-anyage.json`. The corpus is pinned by the
`source.sha256` field and was taken at bft-core `8f828ce97`.

The corpus works at precompile level: a registry pre-state plus `CERT_BATCH_V2` request bytes. Each derived case carries:
- the unicity-certificate bytes taken from the request;
- every registry epoch as a committee, with its root-round interval and threshold;
- the claim's partition and the network;
- B1's own verdict. Nothing is re-judged.

Only cases whose verdict depends on the certificate or its seal are kept. `excluded` lists the others with the reason.

    cd tests/fixtures/b1-seals/v1/generator && go run . -corpus <bft-core>/b1ref/testdata/b1-vectors-anyage.json -out ../b1-seal-vectors-v1.json
    cd .. && shasum -a 256 -c manifest.sha256

The interface for each case:
- `verdict`: `valid`, `invalid` (B1 false) or `malformed` (B1 status error);
- the inputs `uc`, `epochs`, `network` and `expectedPartition`.

`b1Sentinel` is diagnostic. The seal rule each SDK must apply is in the file's `notes`.
