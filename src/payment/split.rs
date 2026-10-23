//! Client-side token splitting (`client` feature).
//!
//! [`TokenSplit::split`] burns a payment-carrying token and produces everything
//! needed to mint several new tokens whose per-asset allocations sum to the
//! original. For every source asset it builds one radix sparse Merkle sum tree
//! ([`Rsmst`]) keyed by output token id; the per-asset root hashes form the
//! *split manifest*, whose hash becomes the burn predicate's reason and whose
//! exact bytes are stored as the burn transfer's auxiliary data. Each output
//! carries one [`RsmstInclusionProof`] per asset it receives. The result is
//! exactly what [`SplitMintJustificationVerifier`] re-checks.
//!
//! [`SplitMintJustificationVerifier`]: super::verifier::SplitMintJustificationVerifier

use alloc::vec::Vec;
use core::fmt;

use super::asset::PaymentAssetCollection;
use super::commitment::split_output_commitment;
use super::manifest::SplitManifest;
use super::verifier::{verify_payment_token, PaymentDataDecoder};
use crate::api::bft::RootTrustBase;
use crate::api::network_id::NetworkId;
use crate::error::Error;
use crate::predicate::builtin::BurnPredicate;
use crate::predicate::EncodedPredicate;
use crate::rsmst::build::Rsmst;
use crate::rsmst::RsmstInclusionProof;
use crate::transaction::ids::{TokenId, TokenSalt, TokenType};
use crate::transaction::{Token, TransferTransaction};
use crate::verify::MintJustificationRegistry;
use crate::VerificationError;

/// The payment payload of one split output: the assets it is allocated plus the
/// exact bytes minted as its auxiliary data (the Rust counterpart of the
/// TypeScript `IPaymentData`).
///
/// The bytes are what the allocation commitment `d_j` hashes, so they may wrap
/// the asset collection in an application envelope. Fields are private and the
/// only constructors are [`bare`](Self::bare) and the checked
/// [`new`](Self::new), so a payload whose bytes disagree with its assets cannot
/// exist. The bytes are owned and immutable once frozen here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitOutputPayload {
    assets: PaymentAssetCollection,
    bytes: Vec<u8>,
}

impl SplitOutputPayload {
    /// Bare payload: the bytes are exactly the canonical encoding of `assets`.
    pub fn bare(assets: PaymentAssetCollection) -> Self {
        let bytes = assets.to_cbor();
        SplitOutputPayload { assets, bytes }
    }

    /// Checked constructor for an application-specific payload. `bytes` is
    /// decoded with `decode_payment_data` (the decoder the verifier will use)
    /// and the decoded assets must equal `assets`; otherwise nothing is built.
    pub fn new(
        assets: PaymentAssetCollection,
        bytes: Vec<u8>,
        decode_payment_data: PaymentDataDecoder,
    ) -> Result<Self, Error> {
        let decoded = decode_payment_data(&bytes)?;
        if decoded != assets {
            return Err(Error::UnexpectedValue(
                "split output payload does not decode to the declared assets",
            ));
        }
        Ok(SplitOutputPayload { assets, bytes })
    }

    /// The assets allocated to the output.
    pub fn assets(&self) -> &PaymentAssetCollection {
        &self.assets
    }

    /// The exact bytes to mint and to commit to.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// A request to mint one new token as part of a split.
#[derive(Debug, Clone)]
pub struct SplitTokenRequest {
    recipient: EncodedPredicate,
    token_type: TokenType,
    payload: SplitOutputPayload,
    salt: TokenSalt,
}

impl SplitTokenRequest {
    /// Create a request: `recipient` locks the new token, which receives
    /// `assets` (minted as their bare canonical encoding) and is identified by
    /// `token_type` and `salt`. `token_type` must equal the source token type
    /// (splitting is not a type-conversion).
    pub fn create(
        recipient: EncodedPredicate,
        assets: PaymentAssetCollection,
        token_type: TokenType,
        salt: TokenSalt,
    ) -> Self {
        Self::create_with_payload(
            recipient,
            SplitOutputPayload::bare(assets),
            token_type,
            salt,
        )
    }

    /// Like [`create`](Self::create), for an output whose mint data is an
    /// application-specific payload (see [`SplitOutputPayload::new`]).
    pub fn create_with_payload(
        recipient: EncodedPredicate,
        payload: SplitOutputPayload,
        token_type: TokenType,
        salt: TokenSalt,
    ) -> Self {
        SplitTokenRequest {
            recipient,
            token_type,
            payload,
            salt,
        }
    }
}

/// A realized split output: everything needed to mint the new token.
#[derive(Debug, Clone)]
pub struct SplitToken {
    /// Network of the new token (inherited from the source token).
    pub network_id: NetworkId,
    /// Predicate that will lock the new token.
    pub recipient: EncodedPredicate,
    /// Token type of the new token.
    pub token_type: TokenType,
    /// Salt of the new token.
    pub salt: TokenSalt,
    /// Assets the new token receives (canonical order).
    pub assets: PaymentAssetCollection,
    /// The exact bytes to mint as the new token's data: the bytes the allocation
    /// proofs commit to (the bare encoding of `assets` for a bare request).
    pub payload: Vec<u8>,
    /// One allocation proof per asset, in canonical output-asset order.
    pub proofs: Vec<RsmstInclusionProof>,
}

/// The burn side of a split: the predicate and transfer that destroy the source.
#[derive(Debug, Clone)]
pub struct SplitBurn {
    /// The burn predicate (reason = `SHA-256(b_M)`).
    pub owner_predicate: BurnPredicate,
    /// The transfer that burns the source token (auxiliary data = `b_M`).
    pub transaction: TransferTransaction,
    /// The exact canonical manifest encoding `b_M` stored by the burn transfer.
    pub manifest: Vec<u8>,
}

/// The result of [`TokenSplit::split`].
#[derive(Debug, Clone)]
pub struct Split {
    /// The burn of the source token.
    pub burn: SplitBurn,
    /// The new tokens to mint.
    pub tokens: Vec<SplitToken>,
}

/// Why a split could not be produced (see [`TokenSplit::split`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SplitError {
    /// The source token failed verification, so no burn was constructed. The
    /// caller's value is untouched.
    Verification(VerificationError),
    /// The source verified, but the requested split could not be built (e.g. a
    /// per-asset total does not equal the source amount, or a duplicate output
    /// id). No burn was constructed.
    Build(Error),
}

impl fmt::Display for SplitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SplitError::Verification(e) => write!(f, "source token verification failed: {e}"),
            SplitError::Build(e) => write!(f, "split construction failed: {e}"),
        }
    }
}

impl core::error::Error for SplitError {}

/// Token splitting.
#[derive(Debug)]
pub struct TokenSplit;

impl TokenSplit {
    /// Split `token` into the outputs described by `requests`, after fully
    /// verifying the source token.
    ///
    /// The source token is verified with [`verify_payment_token`] — its whole
    /// cryptographic history, any embedded split chain, and the registered
    /// issuance policy for its token type — **before** the irreversible burn
    /// transfer is constructed. If verification fails, no burn is produced and
    /// the caller's value is untouched. `registry` must therefore hold the
    /// payment-data verifier for the source token type (and the split verifier if
    /// the source is itself a split output).
    ///
    /// `decode_payment_data` extracts the source token's [`PaymentAssetCollection`]
    /// from its mint `data`. `burn_state_mask` sets the burn transfer's state
    /// mask; pass `None` for a random mask (requires the `std` RNG) or a fixed
    /// value for a reproducible, crash-resumable burn.
    ///
    /// To split a token whose validity you have already established by other
    /// means, use [`TokenSplit::split_unchecked`].
    pub fn split(
        token: &Token,
        trust_base: &RootTrustBase,
        registry: &MintJustificationRegistry,
        decode_payment_data: PaymentDataDecoder,
        requests: Vec<SplitTokenRequest>,
        burn_state_mask: Option<[u8; 32]>,
        burn_expires_at: Option<u64>,
    ) -> Result<Split, SplitError> {
        let assets = verify_payment_token(token, trust_base, registry, decode_payment_data)
            .map_err(SplitError::Verification)?;
        Self::build_split(token, assets, requests, burn_state_mask, burn_expires_at)
            .map_err(SplitError::Build)
    }

    /// Split `token` **without verifying it first**.
    ///
    /// This constructs an irreversible burn transfer from an unverified source
    /// token. Only use it when the source token's validity (and ownership of its
    /// current state) is already established; otherwise prefer
    /// [`TokenSplit::split`], which verifies before burning. The split outputs
    /// are still independently checked by the verifier when later minted, but an
    /// invalid source can only be discovered *after* value has been burned.
    pub fn split_unchecked(
        token: &Token,
        decode_payment_data: PaymentDataDecoder,
        requests: Vec<SplitTokenRequest>,
        burn_state_mask: Option<[u8; 32]>,
        burn_expires_at: Option<u64>,
    ) -> Result<Split, Error> {
        let source_bytes = token
            .genesis()
            .transaction()
            .data()
            .ok_or(Error::UnexpectedValue("source token has no payment data"))?;
        let assets = decode_payment_data(source_bytes)?;
        Self::build_split(token, assets, requests, burn_state_mask, burn_expires_at)
    }

    /// Construct the split from the source token's already-decoded canonical
    /// asset collection. Shared by [`split`](Self::split) and
    /// [`split_unchecked`](Self::split_unchecked).
    fn build_split(
        token: &Token,
        assets: PaymentAssetCollection,
        requests: Vec<SplitTokenRequest>,
        burn_state_mask: Option<[u8; 32]>,
        burn_expires_at: Option<u64>,
    ) -> Result<Split, Error> {
        let network_id = token.genesis().transaction().network_id();
        let source_token_type = token.token_type().clone();

        // Validate each request and derive its token id and output commitment.
        let mut entries: Vec<(SplitTokenRequest, TokenId, [u8; 32])> = Vec::new();
        for request in requests {
            if request.token_type != source_token_type {
                return Err(Error::UnexpectedValue(
                    "split output token type must equal source token type",
                ));
            }
            for asset in request.payload.assets.as_slice() {
                if assets.get(asset.id()).is_none() {
                    return Err(Error::UnexpectedValue(
                        "split output asset is absent from source token",
                    ));
                }
            }
            let token_id = TokenId::derive(network_id, &request.salt);
            if entries.iter().any(|(_, id, _)| id == &token_id) {
                return Err(Error::UnexpectedValue("duplicate split token id"));
            }
            let commitment = split_output_commitment(
                token.id(),
                network_id,
                &request.recipient,
                &request.salt,
                &token_id,
                &request.token_type,
                request.payload.bytes(),
            );
            entries.push((request, token_id, commitment));
        }

        // One RSMST per source asset, in canonical asset order, checking value
        // conservation. The per-asset root hashes form the manifest.
        let mut roots: Vec<[u8; 32]> = Vec::new();
        let mut built_trees: Vec<(super::asset::AssetId, crate::rsmst::build::BuiltRsmst)> =
            Vec::new();
        for source_asset in assets.as_slice() {
            let mut tree = Rsmst::new();
            for (request, token_id, commitment) in &entries {
                if let Some(output_asset) = request.payload.assets.get(source_asset.id()) {
                    tree.insert(*token_id.bytes(), *commitment, output_asset.value().clone())?;
                }
            }
            let built = tree.build().map_err(|_| {
                Error::UnexpectedValue("source asset is not allocated to any output")
            })?;
            if built.root_sum() != source_asset.value() {
                return Err(Error::UnexpectedValue(
                    "split asset total does not match source amount",
                ));
            }
            roots.push(built.root_hash());
            built_trees.push((source_asset.id().clone(), built));
        }

        let manifest = SplitManifest::create(roots)?;
        let manifest_bytes = manifest.to_cbor();
        let burn_predicate = BurnPredicate::new(manifest.reason_hash().to_vec());

        let mask = match burn_state_mask {
            Some(m) => m,
            None => random_mask()?,
        };
        let (source_state_hash, lock_script) = token.latest_state();
        let recipient = burn_predicate.to_encoded();
        let burn_transaction = TransferTransaction::new(
            source_state_hash,
            lock_script,
            recipient,
            mask.to_vec(),
            Some(manifest_bytes.clone()),
            burn_expires_at,
        );

        // Build each output with its per-asset proofs (canonical output order).
        let mut tokens = Vec::new();
        for (request, token_id, _commitment) in entries {
            let mut proofs = Vec::new();
            for asset in request.payload.assets.as_slice() {
                let (_, built) = built_trees
                    .iter()
                    .find(|(id, _)| id == asset.id())
                    .expect("a tree is built for every source asset");
                let proof = built.proof(token_id.bytes()).ok_or(Error::UnexpectedValue(
                    "missing allocation proof for output",
                ))?;
                proofs.push(proof);
            }
            tokens.push(SplitToken {
                network_id,
                recipient: request.recipient,
                token_type: request.token_type,
                salt: request.salt,
                assets: request.payload.assets,
                payload: request.payload.bytes,
                proofs,
            });
        }

        Ok(Split {
            burn: SplitBurn {
                owner_predicate: burn_predicate,
                transaction: burn_transaction,
                manifest: manifest_bytes,
            },
            tokens,
        })
    }
}

#[cfg(feature = "std")]
fn random_mask() -> Result<[u8; 32], Error> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| Error::Crypto("RNG failure"))?;
    Ok(bytes)
}

#[cfg(not(feature = "std"))]
fn random_mask() -> Result<[u8; 32], Error> {
    Err(Error::Crypto(
        "burn_state_mask must be supplied without the std RNG",
    ))
}
