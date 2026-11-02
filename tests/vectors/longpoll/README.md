Frozen long-poll fixtures, copied byte-for-byte from aggregator-go
(`testdata/longpoll/`). `params.json` and `capability.json` come from PR #225
(branch `lp/A0-wire-contract`) and are unchanged. `echo.json` is revision 4
(invalid-`waitMs` echo ruling of 2026-11-02, aggregator-go PR
`fix/longpoll-invalid-wait-echo-202611020739` @ 09ed2d5c0f88500e004473c9d3e581a762246241):
an invalid or duplicate `waitMs` is a recognized wait, so its validation error echoes
`waitedMs:0`; a preflight rejection (request bytes, params bytes, RPC ID) has no echo.
sha256:

- params.json     4558bd8047b6fb5f0a00c84a167a0fa8f678c4dd325880e3036c3b033b48cb5e
- echo.json       a9dad238857c6953b3f65b5c8680cd8dda2786bccb85a6c633b47644b6c4cd86
- capability.json b00701917858d6e2671bec24b9f917de5bb53f4303bdeb6e6795b343ca379c35

Their proof bytes are synthetic Go fixtures; `tests/long_poll_wire.rs` swaps in this
SDK's own decodable proofs and checks envelope, echo placement and retry behaviour.
Echo cases whose exact bytes a parsed object cannot express (duplicates, escaped member
names) carry `rawParams`/`rawRequest`; this SDK rejects invalid waits locally, so those
cases are used only as injected server replies to a valid wait request.
