Frozen long-poll fixtures, copied byte-for-byte from aggregator-go PR #225
(`testdata/longpoll/`, branch `lp/A0-wire-contract`). sha256:

- params.json     4558bd8047b6fb5f0a00c84a167a0fa8f678c4dd325880e3036c3b033b48cb5e
- echo.json       eece0ee9b8839d5f13ecf72be0d19ecb65e737a6aa1514f4949064a5ce228f23
- capability.json f11f2341a0e5aadaba504133e8940cb4f0809d5f163a87e9ad4b95240b827578

Their proof bytes are synthetic Go fixtures; `tests/long_poll_wire.rs` swaps in this
SDK's own decodable proofs and checks envelope, echo placement and retry behaviour.
