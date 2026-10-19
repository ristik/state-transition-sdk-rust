//! # Unicity token state-transition SDK
//!
//! Clean-room Rust implementation of the Unicity token state-transition
//! protocol, binary-compatible (byte-for-byte CBOR) with the reference Java and
//! TypeScript SDKs.
//!
//! The crate is `no_std`-first. The default build (`std` + `client`) gives the
//! full SDK; building with `--no-default-features` yields the pure `no_std`
//! verification + decoding core intended for zkVM guests (SP1 / RISC0) and
//! `wasm32` targets.
//!
//! ## Security model
//!
//! Decoding a structure proves *nothing* about its validity. Trust is
//! established exclusively by [`Token::verify`], which walks an unbroken chain
//! of cryptographic checks from a caller-supplied root of trust
//! ([`TrustBaseHistory`]) down to every state in the token's history. See the
//! `verify` module for the enforced invariants.
//!
//! Application `data` and mint *justifications* are treated as opaque by
//! [`Token::verify`] and rejected unless a verifier is registered for them. The
//! [`payment`] module adds the fungible-asset payload and token-split subsystem:
//! verify such tokens fail-closed (policy-gated) with
//! [`payment::verify_payment_token`], and construct splits (under the `client`
//! feature) with `payment::TokenSplit`. The split inclusion proofs use the radix
//! sparse Merkle sum trees in [`rsmst`].
//!
//! [`Token::verify`]: crate::transaction::Token::verify
//! [`TrustBaseHistory`]: crate::api::bft::TrustBaseHistory

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

extern crate alloc;

pub mod api;
pub mod cbor;
#[cfg(feature = "client")]
pub mod client;
pub mod consolidation;
pub mod crypto;
pub mod error;
mod fifo_index;
pub mod payment;
pub mod predicate;
mod radix;
pub mod rsmst;
pub mod transaction;
pub mod verify;

pub use api::AGGREGATION_PARTITION_ID;
pub use error::{Error, Result};
pub use transaction::Token;
pub use verify::VerificationError;

// Convenience re-export of the workhorse hash.
pub use crypto::hash::{DataHash, DataHasher, HashAlgorithm};
