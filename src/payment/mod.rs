//! Payment / asset / token-split subsystem.
//!
//! A token can carry a [`PaymentAssetCollection`] in its mint `data`: a non-empty
//! canonical set of fungible [`Asset`]s (the yellowpaper `Assets(ty, auxd')`
//! function). `TokenSplit` (client only) burns such a token and produces several
//! new ones whose per-asset allocations sum to the original, each accompanied by
//! [`RsmstInclusionProof`]s. The burn commits to a [`SplitManifest`] (tag 39046)
//! stored as its auxiliary data; each split-minted token's genesis carries a
//! [`SplitMintJustification`] (tag 39044), which [`SplitMintJustificationVerifier`]
//! re-checks during [`Token::verify_with`](crate::transaction::Token::verify_with).
//!
//! The allocation proofs ride on the radix sparse Merkle sum trees in
//! [`rsmst`](crate::rsmst): one tree per asset, keyed by output token id.

pub mod asset;
pub mod commitment;
pub mod justification;
pub mod manifest;
pub mod verifier;

#[cfg(any(feature = "client", test))]
pub mod split;

#[cfg(test)]
mod tests;

pub use asset::{Asset, AssetId, PaymentAssetCollection};
pub use commitment::{split_output_commitment, SPLIT_OUTPUT};
pub use justification::{SplitMintJustification, SPLIT_MINT_JUSTIFICATION_TAG};
pub use manifest::{SplitManifest, SPLIT_MANIFEST_TAG};
pub use verifier::{
    verify_payment_token, PaymentDataDecoder, PaymentDataVerifier, PaymentIssuancePolicy,
    SplitMintJustificationVerifier,
};

/// Re-export of the allocation proof type carried by a split mint reason.
pub use crate::rsmst::RsmstInclusionProof;

#[cfg(any(feature = "client", test))]
pub use split::{
    Split, SplitBurn, SplitError, SplitOutputPayload, SplitToken, SplitTokenRequest, TokenSplit,
};
