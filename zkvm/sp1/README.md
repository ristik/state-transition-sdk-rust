# SP1 zkVM: precompile-accelerated verification

This directory is **outside the default build** (each crate carries its own empty
`[workspace]`); nothing here is compiled by `cargo build` / `cargo test` of the SDK.

* `guest/` - SP1 guest verifying a token or a native unicity certificate (UC quorum
  signatures, tree path, inclusion paths, unlock signatures, SHA-256), built **with** the
  patches.
* `guest-unpatched/` - the same source built without the patches (baseline).
* `host/` - executes (does not prove) both guests on the same inputs and prints the
  instruction and syscall counts. Needs the SP1 toolchain (`sp1up`, rustup toolchain
  `succinct`):

```sh
cd zkvm/sp1/host && cargo run --release
```

## Using the SDK in your own SP1 guest

Depend on the SDK with `default-features = false, features = ["alloc"]` and add this to the
**guest's** (workspace root) `Cargo.toml`:

```toml
[patch.crates-io]
sha2 = { git = "https://github.com/sp1-patches/RustCrypto-hashes", package = "sha2", tag = "patch-sha2-0.10.9-sp1-6.0.0" }
k256 = { git = "https://github.com/sp1-patches/elliptic-curves", tag = "patch-k256-13.4-sp1-6.0.0" }
```

The SDK code is identical on every target; precompiles come only from these patched
libraries. Version coupling: the lock must resolve `k256 0.13.4` and `sha2 0.10.9`
(the SDK requires `k256 0.13`, `sha2 0.10`); newer SP1 releases publish tags with the
same names for their version (for example `...-sp1-6.2.0`). The SDK has no direct
dependency on the `ecdsa` or `elliptic-curve` crates: the patched `k256` brings its
own patched `ecdsa` and the SDK uses the `k256::ecdsa` / `k256::elliptic_curve`
re-exports only.

## What is accelerated (read from `patch-k256-13.4-sp1-6.0.0` and `sp1-lib 6.0.0`)

On `target_os = "zkvm"` the patched `k256` replaces its arithmetic layer:

| k256 entry point used by the SDK | in the zkVM |
|---|---|
| `ProjectivePoint::lincomb(P, a, Q, b)` | `sp1_lib` `multi_scalar_multiplication`: SECP256K1 ADD/DOUBLE syscalls |
| `AffinePoint::decompress(x, parity)` | hinted square root (`FD_FP_SQRT`) checked with constrained field multiplications |
| `Scalar::invert`, `FieldElement::invert/sqrt` | hinted (`FD_FP_INV`), checked with one constrained multiplication |
| `ProjectivePoint::to_affine`, `to_encoded_point` | no inversion (points are affine in the syscall representation) |
| `VerifyingKey::recover_from_prehash` | patched `ecdsa` (`sp1-skip-verify-on-recovery`): decompress + one `lincomb`, **without** the library's internal re-verification (on the host, crates.io `ecdsa` still re-verifies) |
| SHA-256 (`sha2`) | SHA_EXTEND / SHA_COMPRESS syscalls |

## Signature verification (`crypto::signature::Signature::verify`)

One recover-and-compare, the same code on the host, in `no_std`/wasm and in SP1
(arch-o3 §4): scalar coefficients `a = s·r⁻¹`, `b = -z·r⁻¹` first, one two-term
`lincomb(R, a, G, b)` with `R = decompress(r + (v>>1)·n, v&1)`, accept iff the result is the
trusted key. It does not call `recover_from_prehash` (recover-then-verify on the host)
or any separate ECDSA verification, so there is no double work anywhere.
Hashing everywhere on the verification path goes through the `sha2` crate
(`crypto::hash`); there is no other hash dependency.

## Measured (executor, not proving; `EVIDENCE-execution.txt`, `EVIDENCE-cargo-tree.txt`)

| input | instructions, no patches | instructions, patches | syscalls with patches |
|---|---|---|---|
| token, mint + 2 transfers | 11,467,641 | 966,928 (11.9x fewer) | SECP256K1_ADD 1808, DOUBLE 3584, SHA_COMPRESS/EXTEND 77 |
| token, mint only | 5,039,017 | 373,287 (13.5x) | ADD 768, DOUBLE 1536, SHA 29 |
| native UC, 3-of-4 quorum | 4,735,108 | 266,954 (17.7x) | ADD 751, DOUBLE 1536, SHA 20 |

One two-term `lincomb` is 512 SECP256K1_DOUBLE syscalls in `sp1-lib`
(UC: 1536 = 3 recoveries for the 3 signatures of the quorum; no extra verification passes).

The single-pass formulation also roughly halves the unpatched (pure software) cost relative to the
earlier `recover_from_prehash` version (carol 19.3M -> 11.5M), because the library's
internal re-verification no longer runs; with the patches both formulations cost the
same (972,080 vs 966,928), as the patched library already skips it.
