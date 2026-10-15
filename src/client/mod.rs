//! Transaction construction and the mint/transfer flow (`client` feature).
//!
//! This layer is transport-agnostic: callers implement the synchronous
//! [`AggregatorClient`] trait over whatever transport they like (an HTTP
//! JSON-RPC client, an in-process aggregator, a test double). The [`mint`] and
//! [`transfer`] helpers drive the full flow — build the transaction, sign its
//! unlock script, submit the certification request, fetch the inclusion proof,
//! assemble the token, and **verify it** before returning.

mod batch;
mod consolidate;
#[cfg(feature = "http")]
mod http;
#[cfg(feature = "http")]
pub use http::{HttpAggregatorClient, HttpError};

pub use batch::{
    detail, rpc_code, BatchAggregatorClient, BatchFailure, BatchProof, BatchRequest,
    InclusionProofBatch, RequestOptions, StateRoot, MAX_BATCH_STATE_IDS, UNCLASSIFIED,
};
pub use consolidate::{
    AdmissionWork, BundleOutcome, CancelToken, Clock, ConsolidateOptions, ConsolidationError,
    ConsolidationOutcome, ConsolidationSummary, IntegrityError, ProofBundle, ProofClient,
    ProofClientConfig, ProofItem, SequentialExecutor, UnavailableReason, WaveExecutor,
    DEFAULT_TIMEOUT_MS,
};
#[cfg(feature = "std")]
pub use consolidate::{SystemClock, ThreadedExecutor};

use alloc::vec::Vec;
use core::fmt;

use crate::api::bft::RootTrustBase;
use crate::api::inclusion_proof::InclusionProof;
use crate::api::{CertificationData, NetworkId, NonInclusionProof, StateId};
use crate::crypto::signer::Signer;
use crate::predicate::unlock::sign_signature_unlock;
use crate::predicate::{EncodedPredicate, Predicate};
use crate::transaction::ids::{StateMask, TokenSalt, TokenType};
use crate::transaction::{
    CertifiedMintTransaction, CertifiedTransferTransaction, MintTransaction, Minter, Token,
    Transaction, TransferTransaction,
};
use crate::verify::VerificationError;
use crate::Error;

/// A synchronous aggregator transport.
///
/// Implementations submit certification requests and fetch inclusion proofs.
/// They need not perform any verification — the [`mint`]/[`transfer`] helpers
/// verify the resulting token against the trust base.
pub trait AggregatorClient {
    /// Transport-specific error type.
    type Error;

    /// Submit a certification request for a state transition.
    fn submit_certification_request(&self, data: &CertificationData) -> Result<(), Self::Error>;

    /// Fetch the inclusion proof for a state id.
    fn get_inclusion_proof(&self, state_id: &StateId) -> Result<InclusionProof, Self::Error>;
}

/// Optional aggregator capability for relation-specific non-inclusion proofs.
///
/// Keeping this separate from [`AggregatorClient`] makes the new API additive:
/// existing transports and test doubles do not need a meaningless unsupported
/// method. Implementations should bind successful results with
/// [`NonInclusionProof::for_state`] so callers can use its one-argument
/// verification method safely.
pub trait NonInclusionAggregatorClient: AggregatorClient {
    /// Fetch a snapshot proof that a state id is absent from the latest
    /// certified root known to the aggregator.
    fn get_non_inclusion_proof(&self, state_id: &StateId)
        -> Result<NonInclusionProof, Self::Error>;
}

/// Proof-carrying relation returned by a membership-status lookup.
///
/// Callers must still verify the contained proof against their trust base.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MembershipStatus {
    /// The requested state is claimed present at the root carried by this proof.
    Included(InclusionProof),
    /// The requested state is claimed absent at the root carried by this bound proof.
    Absent(NonInclusionProof),
}

/// Errors from a construction flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientError<E> {
    /// Transaction construction failed (e.g. invalid key).
    Build(Error),
    /// The aggregator transport failed.
    Aggregator(E),
    /// The assembled token failed verification.
    Verification(VerificationError),
}

impl<E> From<Error> for ClientError<E> {
    fn from(e: Error) -> Self {
        ClientError::Build(e)
    }
}
impl<E> From<VerificationError> for ClientError<E> {
    fn from(e: VerificationError) -> Self {
        ClientError::Verification(e)
    }
}

impl<E: fmt::Display> fmt::Display for ClientError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientError::Build(e) => write!(f, "build error: {e}"),
            ClientError::Aggregator(e) => write!(f, "aggregator error: {e}"),
            ClientError::Verification(e) => write!(f, "verification error: {e}"),
        }
    }
}

#[cfg(feature = "std")]
impl<E: fmt::Display + fmt::Debug> core::error::Error for ClientError<E> {}

/// Build the certification data for `transaction`, signing the unlock script
/// with `signer`.
pub fn certification_data_for(
    transaction: &impl Transaction,
    signer: &impl Signer,
) -> CertificationData {
    let tx_hash = transaction.calculate_transaction_hash();
    let unlock = sign_signature_unlock(signer, transaction.source_state_hash(), &tx_hash);
    CertificationData::from_transaction(transaction, unlock)
}

/// Mint a new token and return the verified [`Token`].
#[allow(clippy::too_many_arguments)]
pub fn mint<A: AggregatorClient>(
    aggregator: &A,
    trust_base: &RootTrustBase,
    network: NetworkId,
    recipient: &impl Predicate,
    token_type: TokenType,
    salt: TokenSalt,
    data: Option<Vec<u8>>,
    justification: Option<Vec<u8>>,
    expires_at: Option<u64>,
) -> Result<Token, ClientError<A::Error>> {
    trust_base
        .validate()
        .map_err(VerificationError::InvalidTrustBase)?;
    if network != trust_base.network_id {
        return Err(VerificationError::NetworkMismatch.into());
    }
    let transaction = MintTransaction::create(
        network,
        EncodedPredicate::from_predicate(recipient),
        token_type,
        salt,
        data,
        justification,
        expires_at,
    )?;

    // The genesis is unlocked by the deterministic minter key for the token id.
    let signer = Minter::signer(transaction.token_id())?;
    let certification_data = certification_data_for(&transaction, &signer);
    aggregator
        .submit_certification_request(&certification_data)
        .map_err(ClientError::Aggregator)?;

    let state_id = StateId::derive(transaction.lock_script(), transaction.source_state_hash());
    let proof = aggregator
        .get_inclusion_proof(&state_id)
        .map_err(ClientError::Aggregator)?;
    let token = Token::new(
        CertifiedMintTransaction::new(transaction, proof),
        Vec::new(),
    );
    token.verify(trust_base)?;
    Ok(token)
}

/// Transfer `token` to `recipient`, authorised by `signer` (the current
/// owner's key), and return the verified successor [`Token`].
#[allow(clippy::too_many_arguments)]
pub fn transfer<A: AggregatorClient>(
    aggregator: &A,
    trust_base: &RootTrustBase,
    token: &Token,
    recipient: &impl Predicate,
    signer: &impl Signer,
    state_mask: StateMask,
    data: Option<Vec<u8>>,
    expires_at: Option<u64>,
) -> Result<Token, ClientError<A::Error>> {
    // Reject an untrusted or stale input before causing any aggregator side
    // effect. The successor is verified again below as defense in depth.
    token.verify(trust_base)?;
    let (source_state_hash, lock_script) = token.latest_state();
    let transaction = TransferTransaction::new(
        source_state_hash,
        lock_script,
        EncodedPredicate::from_predicate(recipient),
        state_mask.bytes().to_vec(),
        data,
        expires_at,
    );

    let certification_data = certification_data_for(&transaction, signer);
    aggregator
        .submit_certification_request(&certification_data)
        .map_err(ClientError::Aggregator)?;

    let state_id = StateId::derive(transaction.lock_script(), transaction.source_state_hash());
    let proof = aggregator
        .get_inclusion_proof(&state_id)
        .map_err(ClientError::Aggregator)?;
    let mut transactions = token.transactions().to_vec();
    transactions.push(CertifiedTransferTransaction::new(transaction, proof));
    let next = Token::new(token.genesis().clone(), transactions);
    next.verify(trust_base)?;
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exclusive certification request deadline used by these tests.
    const TIMEOUT: u64 = 1755000000;
    use crate::crypto::signature::PublicKey;
    use crate::predicate::builtin::SignaturePredicate;
    use core::cell::RefCell;
    use hex_literal::hex;

    /// Mock aggregator that captures the submitted certification data and then
    /// refuses to return a proof — enough to validate the *construction* path
    /// (the certification request bytes) without needing a real SMT proof.
    struct CapturingAggregator {
        captured: RefCell<Option<Vec<u8>>>,
    }

    impl AggregatorClient for CapturingAggregator {
        type Error = &'static str;

        fn submit_certification_request(
            &self,
            data: &CertificationData,
        ) -> Result<(), Self::Error> {
            *self.captured.borrow_mut() = Some(data.to_cbor());
            Ok(())
        }

        fn get_inclusion_proof(&self, _state_id: &StateId) -> Result<InclusionProof, Self::Error> {
            Err("no proof in mock")
        }
    }

    // The mint flow must build exactly the CertificationData golden vector from
    // the reference TS SDK before submitting it.
    #[test]
    fn mint_builds_golden_certification_data() {
        let agg = CapturingAggregator {
            captured: RefCell::new(None),
        };
        let recipient = SignaturePredicate::new(
            PublicKey::from_bytes(&hex!(
                "02ce9f22e51333c97a8fb1f807a229ece3a8765a16af5fc1a13e30834be3280026"
            ))
            .unwrap(),
        );
        let trust_base = RootTrustBase::new(
            1,
            NetworkId::MAINNET,
            0,
            0,
            alloc::vec![crate::api::bft::root_trust_base::RootTrustBaseNodeInfo {
                node_id: "NODE".into(),
                signing_key: recipient.public_key().clone(),
                stake: 1,
            }],
            1,
        );

        // Fetching the proof fails in the mock, so the flow stops there.
        let err = mint(
            &agg,
            &trust_base,
            NetworkId::MAINNET,
            &recipient,
            TokenType::new([0u8; 32]),
            TokenSalt::from_bytes([0u8; 32]),
            None,
            None,
            Some(TIMEOUT),
        )
        .unwrap_err();
        assert_eq!(err, ClientError::Aggregator("no proof in mock"));

        let captured = agg.captured.borrow().clone().expect("submitted");
        assert_eq!(
            captured,
            hex!(
                "d998778602d9987883014101582103a19eef04b8856f50bf2d688b0d8804575115e53d2a7780da363628343f9635075820e4b183ff6b7a399983cee26e4feea85d517dede0142def5c838e593a9e6152415820ed275ff0a0694d1b61ec22f13914a431569220ba7f2f043d7940aac78d02c2f91a689b2cc0584111f0f7929d70e0e32db9159b7e23b6e0043502bc36609728e9dc0353251c241a7b1adb047c9234cd77ed519c409048a6c8bc247f0262c1f161b03d6fee49426e00"
            )
        );
    }
}
