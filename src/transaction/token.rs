//! The self-contained token: a certified genesis plus an ordered transfer
//! history. Decoding reconstructs each transfer's source state and lock script
//! from its predecessor, so the chain of custody is structurally bound before
//! [`Token::verify`] ever runs.

use alloc::vec::Vec;

use super::certified::{CertifiedMintTransaction, CertifiedTransferTransaction};
use super::ids::{TokenId, TokenType};
use crate::api::bft::{DecodeStats, TrustBaseHistory, UcInterner};
use crate::cbor::{encode_array, encode_uint, DecodeLimits, Decoder};
use crate::error::Error;
use crate::verify::VerificationError;

/// CBOR tag for [`Token`].
pub const TOKEN_TAG: u64 = 39040;
const VERSION: u64 = 2;

/// A token: its genesis mint and the chain of certified transfers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    genesis: CertifiedMintTransaction,
    transactions: Vec<CertifiedTransferTransaction>,
}

impl Token {
    /// Bundle a genesis and transfers without verifying (use [`Token::verify`]).
    pub fn new(
        genesis: CertifiedMintTransaction,
        transactions: Vec<CertifiedTransferTransaction>,
    ) -> Self {
        Token {
            genesis,
            transactions,
        }
    }

    /// The genesis (mint) transaction.
    pub fn genesis(&self) -> &CertifiedMintTransaction {
        &self.genesis
    }

    /// The ordered transfer history.
    pub fn transactions(&self) -> &[CertifiedTransferTransaction] {
        &self.transactions
    }

    /// The current state: the `(resulting state hash, lock script)` of the
    /// latest transaction (the genesis if there are no transfers). These are
    /// the values a new transfer must spend.
    pub fn latest_state(
        &self,
    ) -> (
        crate::crypto::hash::DataHash,
        crate::predicate::EncodedPredicate,
    ) {
        match self.transactions.last() {
            Some(t) => (t.result_state_hash(), t.recipient().clone()),
            None => (
                self.genesis.result_state_hash(),
                self.genesis.recipient().clone(),
            ),
        }
    }

    /// The token id (from the genesis).
    pub fn id(&self) -> &TokenId {
        self.genesis.transaction().token_id()
    }

    /// The token type (from the genesis).
    pub fn token_type(&self) -> &TokenType {
        self.genesis.transaction().token_type()
    }

    /// Decode a token from CBOR, reconstructing every transfer's source state
    /// hash and lock script from its predecessor (the chain linkage).
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_cbor_with_limits(bytes, DecodeLimits::DEFAULT)
    }

    /// Decode a token with explicit resource limits.
    pub fn from_cbor_with_limits(bytes: &[u8], limits: DecodeLimits) -> Result<Self, Error> {
        Self::from_cbor_interned(bytes, limits, &mut UcInterner::new())
    }

    /// Decode a token and report the certificate decode work: each distinct
    /// complete certificate encoding is parsed once, however many proofs carry it.
    pub fn from_cbor_stats(bytes: &[u8]) -> Result<(Self, DecodeStats), Error> {
        let mut interner = UcInterner::new();
        let token = Self::from_cbor_interned(bytes, DecodeLimits::DEFAULT, &mut interner)?;
        Ok((token, interner.stats()))
    }

    /// Decode a token through a caller-owned interner, so several tokens decoded
    /// in one operation (for example a token and the source token embedded in its
    /// mint justification) share certificate decodes.
    pub fn from_cbor_interned(
        bytes: &[u8],
        limits: DecodeLimits,
        interner: &mut UcInterner,
    ) -> Result<Self, Error> {
        let d = Decoder::with_limits(bytes, limits);
        d.finish()?;
        let inner = d.expect_tag(TOKEN_TAG)?;
        let items = inner.array(Some(3))?;
        if items[0].uint()? != VERSION {
            return Err(Error::UnexpectedValue("unsupported Token version"));
        }

        let genesis = CertifiedMintTransaction::from_cbor_interned(items[1], interner)?;

        let mut prev_state_hash = genesis.result_state_hash();
        let mut prev_lock_script = genesis.recipient().clone();

        let mut transactions = Vec::new();
        for t in items[2].array(None)? {
            let ct = CertifiedTransferTransaction::from_cbor_interned(
                t,
                prev_state_hash.clone(),
                prev_lock_script.clone(),
                interner,
            )?;
            prev_state_hash = ct.result_state_hash();
            prev_lock_script = ct.recipient().clone();
            transactions.push(ct);
        }

        Ok(Token {
            genesis,
            transactions,
        })
    }

    /// Encode the token to CBOR.
    pub fn to_cbor(&self) -> Vec<u8> {
        let transfers: Vec<Vec<u8>> = self.transactions.iter().map(|t| t.to_cbor()).collect();
        let transfer_refs: Vec<&[u8]> = transfers.iter().map(|v| v.as_slice()).collect();
        crate::cbor::encode_tag(
            TOKEN_TAG,
            &encode_array(&[
                &encode_uint(VERSION),
                &self.genesis.to_cbor(),
                &encode_array(&transfer_refs),
            ]),
        )
    }

    /// Cryptographically verify the entire token history against the root of
    /// trust. Application data remains opaque; payment consumers must use
    /// [`verify_payment_token`](crate::payment::verify_payment_token) or an
    /// explicit [`VerificationPolicy`](crate::verify::VerificationPolicy).
    pub fn verify(&self, history: &TrustBaseHistory) -> Result<(), VerificationError> {
        crate::verify::verify_token(self, history)
    }

    /// Like [`Token::verify`], but dispatches any mint justification through
    /// `registry` (e.g. to accept split-minted tokens). See
    /// [`verify_token_with`](crate::verify::verify_token_with).
    pub fn verify_with(
        &self,
        history: &TrustBaseHistory,
        registry: &crate::verify::MintJustificationRegistry,
    ) -> Result<(), VerificationError> {
        crate::verify::verify_token_with(self, history, registry)
    }
}
