//! Certified transactions: a transaction bundled with its inclusion proof.
//!
//! These wrap [`MintTransaction`] / [`TransferTransaction`] and are *not* tagged.
//! On the wire each value is a 2-element array `[transaction, inclusionProof]`.
//!
//! The reference time is fixed when the transaction is first bound to a proof
//! and carried from then on: the tree is append-only, so a proof fetched later
//! is issued against a later root and its input record carries a later time.

use super::mint::MintTransaction;
use super::transfer::TransferTransaction;
use super::Transaction;
use crate::api::bft::UcInterner;
use crate::api::inclusion_proof::InclusionProof;
use crate::cbor::{encode_array, Decoder};
use crate::crypto::hash::DataHash;
use crate::error::Error;
use crate::predicate::EncodedPredicate;

/// A mint transaction with its inclusion proof (a token's genesis).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertifiedMintTransaction {
    transaction: MintTransaction,
    inclusion_proof: InclusionProof,
}

impl CertifiedMintTransaction {
    /// Bundle a transaction with a proof (no verification — see
    /// [`Token::verify`](super::token::Token::verify)).
    pub fn new(transaction: MintTransaction, inclusion_proof: InclusionProof) -> Self {
        CertifiedMintTransaction {
            transaction,
            inclusion_proof,
        }
    }

    /// The inner mint transaction.
    pub fn transaction(&self) -> &MintTransaction {
        &self.transaction
    }
    /// The inclusion proof.
    pub fn inclusion_proof(&self) -> &InclusionProof {
        &self.inclusion_proof
    }
    /// The reference time this transition was validated under.
    ///
    /// Read off the inclusion proof rather than stored beside it: the proof is
    /// the only thing consensus certified, so a second copy could only ever
    /// disagree with it.
    pub fn reference_time(&self) -> u64 {
        self.inclusion_proof.reference_time
    }
    /// The recipient predicate (lock script of the next state).
    pub fn recipient(&self) -> &EncodedPredicate {
        self.transaction.recipient()
    }
    /// The hash of the state this genesis produces.
    pub fn result_state_hash(&self) -> DataHash {
        self.transaction.calculate_state_hash()
    }

    /// Decode from CBOR (2-element array).
    pub fn from_cbor(d: Decoder<'_>) -> Result<Self, Error> {
        let items = d.array(Some(2))?;
        Ok(CertifiedMintTransaction {
            transaction: MintTransaction::from_cbor(items[0])?,
            inclusion_proof: InclusionProof::from_cbor(items[1])?,
        })
    }

    /// Like [`from_cbor`](Self::from_cbor), interning the proof's certificate.
    pub fn from_cbor_interned(d: Decoder<'_>, interner: &mut UcInterner) -> Result<Self, Error> {
        let items = d.array(Some(2))?;
        Ok(CertifiedMintTransaction {
            transaction: MintTransaction::from_cbor(items[0])?,
            inclusion_proof: InclusionProof::from_cbor_interned(items[1], interner)?,
        })
    }

    /// Encode to CBOR (2-element array).
    pub fn to_cbor(&self) -> alloc::vec::Vec<u8> {
        encode_array(&[&self.transaction.to_cbor(), &self.inclusion_proof.to_cbor()])
    }
}

/// A transfer transaction with its inclusion proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertifiedTransferTransaction {
    transaction: TransferTransaction,
    inclusion_proof: InclusionProof,
}

impl CertifiedTransferTransaction {
    /// Bundle a transaction with a proof (no verification).
    pub fn new(transaction: TransferTransaction, inclusion_proof: InclusionProof) -> Self {
        CertifiedTransferTransaction {
            transaction,
            inclusion_proof,
        }
    }

    /// The inner transfer transaction.
    pub fn transaction(&self) -> &TransferTransaction {
        &self.transaction
    }
    /// The inclusion proof.
    pub fn inclusion_proof(&self) -> &InclusionProof {
        &self.inclusion_proof
    }
    /// The reference time this transition was validated under.
    ///
    /// Read off the inclusion proof, for the same reason as on the genesis.
    pub fn reference_time(&self) -> u64 {
        self.inclusion_proof.reference_time
    }
    /// The recipient predicate (lock script of the next state).
    pub fn recipient(&self) -> &EncodedPredicate {
        self.transaction.recipient()
    }
    /// The hash of the state this transfer produces.
    pub fn result_state_hash(&self) -> DataHash {
        self.transaction.calculate_state_hash()
    }

    /// Decode from CBOR (2-element array), reconstructing the transfer's source
    /// state hash and lock script from the previous transaction.
    pub fn from_cbor(
        d: Decoder<'_>,
        source_state_hash: DataHash,
        lock_script: EncodedPredicate,
    ) -> Result<Self, Error> {
        let items = d.array(Some(2))?;
        Ok(CertifiedTransferTransaction {
            transaction: TransferTransaction::from_cbor(items[0], source_state_hash, lock_script)?,
            inclusion_proof: InclusionProof::from_cbor(items[1])?,
        })
    }

    /// Like [`from_cbor`](Self::from_cbor), interning the proof's certificate.
    pub fn from_cbor_interned(
        d: Decoder<'_>,
        source_state_hash: DataHash,
        lock_script: EncodedPredicate,
        interner: &mut UcInterner,
    ) -> Result<Self, Error> {
        let items = d.array(Some(2))?;
        Ok(CertifiedTransferTransaction {
            transaction: TransferTransaction::from_cbor(items[0], source_state_hash, lock_script)?,
            inclusion_proof: InclusionProof::from_cbor_interned(items[1], interner)?,
        })
    }

    /// Encode to CBOR (2-element array).
    pub fn to_cbor(&self) -> alloc::vec::Vec<u8> {
        encode_array(&[&self.transaction.to_cbor(), &self.inclusion_proof.to_cbor()])
    }
}
