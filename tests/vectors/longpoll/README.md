Frozen long-poll fixtures, copied byte-for-byte from aggregator-go PR #225
(`testdata/longpoll/`, branch `lp/A0-wire-contract`). sha256:

- params.json     4558bd8047b6fb5f0a00c84a167a0fa8f678c4dd325880e3036c3b033b48cb5e
- echo.json       a287d35cdad196c55d1661430e6547b5cb730d3baf6b87549cdb5d5247289e4e
- capability.json b00701917858d6e2671bec24b9f917de5bb53f4303bdeb6e6795b343ca379c35

Their proof bytes are synthetic Go fixtures; `tests/long_poll_wire.rs` swaps in this
SDK's own decodable proofs and checks envelope, echo placement and retry behaviour.
