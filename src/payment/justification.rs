//! [`SplitMintJustification`] (CBOR tag 39044): the split *mint reason* proving a
//! token was minted as an output of splitting a (now burned) source token.
//!
//! It carries the complete certified burned source token `L_burn` — including
//! its manifest-bearing burn transfer — and, in canonical output-asset order,
//! one [`RsmstInclusionProof`] per asset the new token receives. The proofs hold
//! only sibling entries; the asset id, output id, output commitment, leaf amount
//! and root hash are all derived by the verifier from the output payload, mint
//! transaction and manifest, so they never appear on the wire here.

use alloc::vec::Vec;

use super::asset::MAX_PAYMENT_ASSETS;
use crate::api::bft::UcInterner;
use crate::cbor::{encode_array, encode_tag, DecodeLimits, Decoder};
use crate::error::Error;
use crate::rsmst::RsmstInclusionProof;
use crate::transaction::Token;

/// CBOR tag for [`SplitMintJustification`].
pub const SPLIT_MINT_JUSTIFICATION_TAG: u64 = 39044;

/// The split mint reason: the burned source token plus one RSMST allocation
/// proof per asset the new token receives (canonical output-asset order).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitMintJustification {
    token: Token,
    proofs: Vec<RsmstInclusionProof>,
    encoded_token_len: usize,
}

impl SplitMintJustification {
    /// Construct from the burned source token and its allocation proofs.
    /// `proofs` must be a non-empty, at-most-256 vector.
    pub fn create(token: Token, proofs: Vec<RsmstInclusionProof>) -> Result<Self, Error> {
        if proofs.is_empty() {
            return Err(Error::UnexpectedValue(
                "split mint justification needs at least one proof",
            ));
        }
        if proofs.len() > MAX_PAYMENT_ASSETS {
            return Err(Error::OutOfRange(
                "split proof count exceeds protocol limit",
            ));
        }
        let encoded_token_len = token.to_cbor().len();
        Ok(SplitMintJustification {
            token,
            proofs,
            encoded_token_len,
        })
    }

    /// The burned source token.
    pub fn token(&self) -> &Token {
        &self.token
    }

    /// The per-asset allocation proofs, in canonical output-asset order.
    pub fn proofs(&self) -> &[RsmstInclusionProof] {
        &self.proofs
    }

    pub(crate) fn encoded_token_len(&self) -> usize {
        self.encoded_token_len
    }

    /// Decode from CBOR (tag 39044): `[token, [proofs...]]`.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_cbor_with_limits(bytes, DecodeLimits::DEFAULT)
    }

    /// Decode with explicit limits, including the embedded source token.
    pub fn from_cbor_with_limits(bytes: &[u8], limits: DecodeLimits) -> Result<Self, Error> {
        Self::from_cbor_interned(bytes, limits, &mut UcInterner::new())
    }

    /// Decode through a caller-owned interner (the verification operation's), so the
    /// embedded source token shares certificate decodes with the token embedding it.
    pub fn from_cbor_interned(
        bytes: &[u8],
        limits: DecodeLimits,
        interner: &mut UcInterner,
    ) -> Result<Self, Error> {
        let inner = Decoder::with_limits(bytes, limits).expect_tag(SPLIT_MINT_JUSTIFICATION_TAG)?;
        let items = inner.array(Some(2))?;
        let encoded_token_len = items[0].bytes().len();
        let token = Token::from_cbor_interned(items[0].bytes(), limits, interner)?;
        let encoded_proofs = items[1].array(None)?;
        if encoded_proofs.len() > MAX_PAYMENT_ASSETS {
            return Err(Error::OutOfRange(
                "split proof count exceeds protocol limit",
            ));
        }
        let mut proofs = Vec::with_capacity(encoded_proofs.len());
        for proof in encoded_proofs {
            proofs.push(RsmstInclusionProof::from_cbor(proof)?);
        }
        let mut justification = SplitMintJustification::create(token, proofs)?;
        justification.encoded_token_len = encoded_token_len;
        Ok(justification)
    }

    /// Encode to CBOR (tag 39044): `[token, [proofs...]]`.
    pub fn to_cbor(&self) -> Vec<u8> {
        let proof_bytes: Vec<Vec<u8>> = self
            .proofs
            .iter()
            .map(RsmstInclusionProof::to_cbor)
            .collect();
        let proof_refs: Vec<&[u8]> = proof_bytes.iter().map(Vec::as_slice).collect();
        encode_tag(
            SPLIT_MINT_JUSTIFICATION_TAG,
            &encode_array(&[&self.token.to_cbor(), &encode_array(&proof_refs)]),
        )
    }
}
