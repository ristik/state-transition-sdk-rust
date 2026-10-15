//! [`SplitMintJustificationVerifier`]: the security-critical check that a
//! split-minted token is a legitimate output of burning a real source token.
//!
//! The chain of evidence it enforces (yellowpaper "Split Mint-Reason
//! Verification"):
//!
//! 1. the output declares a **non-empty canonical asset collection** as its
//!    payload;
//! 2. the burned **source token fully verifies** against the trust base
//!    (recursively, so a split of a split is checked end to end), on the same
//!    network as the output;
//! 3. the source ends in a certified **burn transfer** whose auxiliary data is
//!    the exact split manifest `b_M` and whose recipient is
//!    `burn(SHA-256(b_M))` — binding the burn to *exactly* this ordered vector
//!    of per-asset allocation roots;
//! 4. the output **token type equals the source token type**, byte for byte;
//! 5. the source payload is canonical and has exactly one manifest root per
//!    asset; and
//! 6. for every output asset, in canonical order, its **RSMST allocation proof**
//!    verifies against the matching manifest root using the recomputed output
//!    commitment `d_j`, and the proof's reconstructed **root sum equals the
//!    source amount** for that asset (the verifier-side value-conservation rule).
//!
//! Any deviation rejects the mint, so a forged or over-issued split cannot pass.

use alloc::boxed::Box;

use super::asset::PaymentAssetCollection;
use super::commitment::commitment_for_mint;
use super::justification::{SplitMintJustification, SPLIT_MINT_JUSTIFICATION_TAG};
use super::manifest::SplitManifest;
use crate::error::Error;
use crate::predicate::builtin::BurnPredicate;
use crate::predicate::EncodedPredicate;
use crate::transaction::ids::TokenType;
use crate::transaction::{CertifiedMintTransaction, Token};
use crate::verify::{
    verify_token_with_policy, MintJustificationRegistry, MintJustificationVerifier,
    TokenDataVerifier, VerificationContext, VerificationPolicy,
};
use crate::VerificationError;

/// Decoder from a token's mint `data` bytes to its [`PaymentAssetCollection`]
/// (the `Assets(ty, auxd')` function).
///
/// The default ([`PaymentAssetCollection::from_cbor_bytes`]) treats the mint
/// `data` as exactly the encoded collection; supply a custom decoder if the
/// payment data is wrapped in an application envelope.
pub type PaymentDataDecoder = fn(&[u8]) -> Result<PaymentAssetCollection, Error>;

/// Application policy authorizing issuance of a payment payload.
pub type PaymentIssuancePolicy =
    fn(&CertifiedMintTransaction, &PaymentAssetCollection) -> Result<(), VerificationError>;

/// Verifier for [`SplitMintJustification`] mint justifications.
#[derive(Debug, Clone)]
pub struct SplitMintJustificationVerifier {
    decode_payment_data: PaymentDataDecoder,
}

impl SplitMintJustificationVerifier {
    /// Create a verifier using the default payment-data decoder.
    pub fn new() -> Self {
        SplitMintJustificationVerifier {
            decode_payment_data: PaymentAssetCollection::from_cbor_bytes,
        }
    }

    /// Create a verifier with a custom payment-data decoder.
    pub fn with_payment_decoder(decoder: PaymentDataDecoder) -> Self {
        SplitMintJustificationVerifier {
            decode_payment_data: decoder,
        }
    }
}

impl Default for SplitMintJustificationVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Payment-data and mandatory issuance-policy verifier for one token type.
#[derive(Debug, Clone)]
pub struct PaymentDataVerifier {
    token_type: TokenType,
    decode_payment_data: PaymentDataDecoder,
    authorize_issuance: PaymentIssuancePolicy,
}

impl PaymentDataVerifier {
    /// Validate bare [`PaymentAssetCollection`] data and invoke the issuance
    /// policy for `token_type`.
    pub fn new(token_type: TokenType, authorize_issuance: PaymentIssuancePolicy) -> Self {
        Self {
            token_type,
            decode_payment_data: PaymentAssetCollection::from_cbor_bytes,
            authorize_issuance,
        }
    }

    /// Validate custom payment-data envelopes and invoke the issuance policy.
    pub fn with_payment_decoder(
        token_type: TokenType,
        decoder: PaymentDataDecoder,
        authorize_issuance: PaymentIssuancePolicy,
    ) -> Self {
        Self {
            token_type,
            decode_payment_data: decoder,
            authorize_issuance,
        }
    }
}

impl TokenDataVerifier for PaymentDataVerifier {
    fn token_type(&self) -> &TokenType {
        &self.token_type
    }

    fn verify(
        &self,
        genesis: &CertifiedMintTransaction,
        _context: &mut VerificationContext<'_>,
    ) -> Result<(), VerificationError> {
        let bytes = genesis
            .transaction()
            .data()
            .ok_or(VerificationError::MalformedTokenData)?;
        let assets =
            (self.decode_payment_data)(bytes).map_err(|_| VerificationError::MalformedTokenData)?;
        (self.authorize_issuance)(genesis, &assets)
    }
}

/// Verify cryptographic history, all registered payloads, and return the
/// validated payment carried by `token`.
pub fn verify_payment_token(
    token: &Token,
    trust_base: &crate::api::bft::RootTrustBase,
    registry: &MintJustificationRegistry,
    decode_payment_data: PaymentDataDecoder,
) -> Result<PaymentAssetCollection, VerificationError> {
    let policy = VerificationPolicy {
        require_token_data_verifier: true,
        ..VerificationPolicy::default()
    };
    verify_token_with_policy(token, trust_base, registry, policy)?;
    let bytes = token
        .genesis()
        .transaction()
        .data()
        .ok_or(VerificationError::PaymentDataMissing)?;
    decode_payment_data(bytes).map_err(|_| VerificationError::MalformedTokenData)
}

impl MintJustificationVerifier for SplitMintJustificationVerifier {
    fn tag(&self) -> u64 {
        SPLIT_MINT_JUSTIFICATION_TAG
    }

    fn verify(
        &self,
        genesis: &CertifiedMintTransaction,
        context: &mut VerificationContext<'_>,
    ) -> Result<(), VerificationError> {
        let mint = genesis.transaction();
        let limits = context.policy().limits.decode;

        let justification_bytes = mint
            .justification()
            .ok_or(VerificationError::MalformedMintJustification)?;
        let justification = SplitMintJustification::from_cbor_interned(
            justification_bytes,
            limits,
            context.interner(),
        )
        .map_err(|_| VerificationError::MalformedMintJustification)?;

        // (1) The minted token must declare a non-empty canonical asset payload.
        let output_payment_bytes = mint.data().ok_or(VerificationError::PaymentDataMissing)?;
        if output_payment_bytes.len() > limits.max_input_bytes {
            return Err(VerificationError::VerificationLimitExceeded(
                "payment data bytes",
            ));
        }
        let output_assets = (self.decode_payment_data)(output_payment_bytes)
            .map_err(|_| VerificationError::MalformedTokenData)?;

        let burned = justification.token();

        // Mint and source token must live on the same network.
        if mint.network_id() != burned.genesis().transaction().network_id() {
            return Err(VerificationError::SplitNetworkMismatch);
        }

        // (2) The burned source token must itself fully verify (recursively, so
        // a split of a split is checked end to end) under the same context.
        context
            .verify_embedded_token(burned, justification.encoded_token_len())
            .map_err(|e| VerificationError::BurnTokenVerificationFailed(Box::new(e)))?;

        // (3) The source must end in a certified burn transfer carrying the exact
        // manifest, locked to burn(SHA-256(b_M)).
        let burn_transfer = burned
            .transactions()
            .last()
            .ok_or(VerificationError::SplitBurnTransferMissing)?;
        let manifest_bytes = burn_transfer
            .transaction()
            .data()
            .ok_or(VerificationError::SplitManifestMissing)?;
        if manifest_bytes.len() > limits.max_input_bytes {
            return Err(VerificationError::VerificationLimitExceeded(
                "split manifest bytes",
            ));
        }
        let manifest = SplitManifest::from_cbor_bytes(manifest_bytes, limits)
            .map_err(|_| VerificationError::SplitManifestMalformed)?;
        let expected_burn =
            EncodedPredicate::from_predicate(&BurnPredicate::new(manifest.reason_hash().to_vec()));
        if burn_transfer.recipient() != &expected_burn {
            return Err(VerificationError::SplitBurnPredicateMismatch);
        }

        // (4) Output token type must be byte-identical to the source token type.
        let source = burned.genesis().transaction();
        if mint.token_type() != source.token_type() {
            return Err(VerificationError::SplitTokenTypeMismatch);
        }

        // (5) The source payload must be canonical with one manifest root each.
        let source_payment_bytes = source
            .data()
            .ok_or(VerificationError::SplitSourcePaymentDataMissing)?;
        if source_payment_bytes.len() > limits.max_input_bytes {
            return Err(VerificationError::VerificationLimitExceeded(
                "source payment data bytes",
            ));
        }
        let source_assets = (self.decode_payment_data)(source_payment_bytes)
            .map_err(|_| VerificationError::SplitSourcePaymentDataMissing)?;
        if source_assets.len() != manifest.len() {
            return Err(VerificationError::SplitManifestLengthMismatch);
        }

        // The number of proofs must equal the number of output assets; proofs are
        // associated with assets purely by canonical order.
        if justification.proofs().len() != output_assets.len() {
            return Err(VerificationError::SplitProofCountMismatch);
        }

        // (6) Verify each allocation proof against its manifest root, and require
        // the reconstructed root sum to equal the authenticated source amount.
        let output_id = mint.token_id();
        let commitment = commitment_for_mint(burned.id(), mint)
            .map_err(|_| VerificationError::PaymentDataMissing)?;

        for (asset, proof) in output_assets.as_slice().iter().zip(justification.proofs()) {
            let index = source_assets
                .as_slice()
                .iter()
                .position(|source_asset| source_asset.id() == asset.id())
                .ok_or(VerificationError::SplitSourceAssetMissing)?;
            let root = &manifest.roots()[index];
            let root_sum = proof
                .verify(output_id.bytes(), &commitment, asset.value(), root)
                .ok_or(VerificationError::SplitAllocationProofInvalid)?;
            if &root_sum != source_assets.as_slice()[index].value() {
                return Err(VerificationError::SplitSourceAmountMismatch);
            }
        }

        Ok(())
    }
}
