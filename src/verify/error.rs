//! Verification failure reasons.

use alloc::boxed::Box;
use core::fmt;

use crate::Error;

/// Why a token (or one of its transactions) failed verification.
///
/// Distinct variants make it possible to test that each rule rejects the
/// forgery it is meant to catch.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerificationError {
    /// The supplied root trust base is structurally unsafe.
    InvalidTrustBase(Error),
    /// The genesis network id does not match the trust base.
    NetworkMismatch,
    /// The genesis lock script is not the deterministic minter key for the token id.
    InvalidMintLockScript,
    /// A mint justification was present but no verifier supports it.
    UnsupportedMintJustification,
    /// Token application data required validation but no verifier was registered.
    UnsupportedTokenData,
    /// A registered token-data verifier rejected malformed application data.
    MalformedTokenData,
    /// Application policy did not authorize this payment issuance.
    PaymentIssuanceRejected,
    /// A cumulative verification resource limit was exceeded.
    VerificationLimitExceeded(&'static str),
    /// A mint justification (or its embedded payment data) failed to decode.
    MalformedMintJustification,
    /// A split-minted token's genesis carried no payment (asset) data.
    PaymentDataMissing,
    /// A split mint is on a different network than its burned source token.
    SplitNetworkMismatch,
    /// The burned source token in a split justification failed verification.
    BurnTokenVerificationFailed(Box<VerificationError>),
    /// The output token type is not byte-identical to the source token type.
    SplitTokenTypeMismatch,
    /// The burned source token did not end in a (burn) transfer.
    SplitBurnTransferMissing,
    /// The burn transfer carried no auxiliary split-manifest data.
    SplitManifestMissing,
    /// The split manifest failed to decode (wrong tag, length, or structure).
    SplitManifestMalformed,
    /// The manifest root count does not equal the source asset count.
    SplitManifestLengthMismatch,
    /// The proof count does not equal the number of output assets.
    SplitProofCountMismatch,
    /// An RSMST allocation proof did not verify against its manifest root.
    SplitAllocationProofInvalid,
    /// The burned source token carried no decodable payment data.
    SplitSourcePaymentDataMissing,
    /// An output asset did not exist in the burned source token.
    SplitSourceAssetMissing,
    /// A proof's reconstructed root sum did not equal the burned source amount.
    SplitSourceAmountMismatch,
    /// The burned token was not locked to the split manifest's burn predicate.
    SplitBurnPredicateMismatch,
    /// Certification fields do not match the reconstructed transaction state.
    CertificationDataMismatch,
    /// The certified transaction hash does not match the recomputed one.
    TransactionHashMismatch,
    /// The inclusion proof's reference time differs from the one the transition carries.
    ReferenceTimeMismatch,
    /// The leaf claims a reference time later than the round that certified it.
    ReferenceTimeAfterRound,
    /// The round's reference time had already reached the request's timeout.
    RequestExpired,
    /// The sparse-Merkle-tree path did not reproduce the expected root.
    PathInvalid,
    /// The non-inclusion certificate did not authenticate against the certified root.
    NonInclusionCertificateInvalid,
    /// A directly decoded non-inclusion proof has no requested state id attached.
    NonInclusionTargetMissing,
    /// An explicit target differs from the state id attached by the client.
    NonInclusionTargetMismatch,
    /// The requested state was present at the certified root.
    StateIncluded,
    /// The certified shard does not contain the state id.
    ShardMismatch,
    /// The unicity seal's network id does not match the trust base.
    SealNetworkMismatch,
    /// The unicity seal's epoch is not the epoch of the authority's trust base.
    SealEpochMismatch,
    /// The unicity seal predates the start of the trust base's epoch.
    SealBeforeEpochStart,
    /// The unicity seal is structurally unusable (no signatures, zero round, ...).
    SealMalformed,
    /// The recomputed unicity-tree root does not match the signed seal hash.
    SealRootMismatch,
    /// Fewer than `quorumThreshold` distinct root-node signatures were valid.
    QuorumNotMet,
    /// The unlock script does not satisfy the lock script.
    NotAuthenticated,
    /// The genesis failed verification (wraps the underlying cause).
    Genesis(Box<VerificationError>),
    /// Transfer at `index` failed verification (wraps the underlying cause).
    Transfer {
        /// Position in the transfer history.
        index: usize,
        /// The underlying failure.
        source: Box<VerificationError>,
    },
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerificationError::InvalidTrustBase(e) => write!(f, "{e}"),
            VerificationError::NetworkMismatch => write!(f, "network id does not match trust base"),
            VerificationError::InvalidMintLockScript => {
                write!(
                    f,
                    "genesis lock script is not the minter key for the token id"
                )
            }
            VerificationError::UnsupportedMintJustification => {
                write!(f, "unsupported mint justification")
            }
            VerificationError::UnsupportedTokenData => {
                write!(f, "token data has no registered verifier")
            }
            VerificationError::MalformedTokenData => write!(f, "malformed token data"),
            VerificationError::PaymentIssuanceRejected => {
                write!(f, "payment issuance rejected by application policy")
            }
            VerificationError::VerificationLimitExceeded(resource) => {
                write!(f, "verification resource limit exceeded: {resource}")
            }
            VerificationError::MalformedMintJustification => {
                write!(f, "malformed mint justification")
            }
            VerificationError::PaymentDataMissing => write!(f, "payment data missing"),
            VerificationError::SplitNetworkMismatch => {
                write!(f, "split mint network does not match source token")
            }
            VerificationError::BurnTokenVerificationFailed(e) => {
                write!(f, "burned source token verification failed: {e}")
            }
            VerificationError::SplitTokenTypeMismatch => {
                write!(f, "output token type does not match source token type")
            }
            VerificationError::SplitBurnTransferMissing => {
                write!(f, "burned source token has no burn transfer")
            }
            VerificationError::SplitManifestMissing => {
                write!(f, "burn transfer carries no split manifest")
            }
            VerificationError::SplitManifestMalformed => write!(f, "split manifest malformed"),
            VerificationError::SplitManifestLengthMismatch => {
                write!(f, "manifest root count does not match source asset count")
            }
            VerificationError::SplitProofCountMismatch => {
                write!(f, "proof count does not match output asset count")
            }
            VerificationError::SplitAllocationProofInvalid => {
                write!(f, "RSMST allocation proof did not verify")
            }
            VerificationError::SplitSourcePaymentDataMissing => {
                write!(f, "burned source token has no valid payment data")
            }
            VerificationError::SplitSourceAssetMissing => {
                write!(f, "split asset is absent from burned source token")
            }
            VerificationError::SplitSourceAmountMismatch => {
                write!(
                    f,
                    "reconstructed root sum does not match burned source amount"
                )
            }
            VerificationError::SplitBurnPredicateMismatch => {
                write!(
                    f,
                    "burned token not locked to split manifest burn predicate"
                )
            }
            VerificationError::CertificationDataMismatch => {
                write!(f, "certification data does not match transaction state")
            }
            VerificationError::TransactionHashMismatch => write!(f, "transaction hash mismatch"),
            VerificationError::ReferenceTimeMismatch => {
                write!(f, "inclusion proof reference time mismatch")
            }
            VerificationError::ReferenceTimeAfterRound => {
                write!(
                    f,
                    "inclusion proof reference time is after its certified round"
                )
            }
            VerificationError::RequestExpired => write!(f, "certification request expired"),
            VerificationError::PathInvalid => write!(f, "inclusion path invalid"),
            VerificationError::NonInclusionCertificateInvalid => {
                write!(f, "non-inclusion certificate invalid")
            }
            VerificationError::NonInclusionTargetMissing => {
                write!(
                    f,
                    "non-inclusion proof is not bound to a requested state id"
                )
            }
            VerificationError::NonInclusionTargetMismatch => {
                write!(
                    f,
                    "non-inclusion proof target differs from the requested state id"
                )
            }
            VerificationError::StateIncluded => {
                write!(f, "state is included at the certified root")
            }
            VerificationError::ShardMismatch => write!(f, "shard does not contain state id"),
            VerificationError::SealNetworkMismatch => {
                write!(f, "unicity seal network does not match trust base")
            }
            VerificationError::SealEpochMismatch => {
                write!(f, "unicity seal epoch does not match trust base")
            }
            VerificationError::SealBeforeEpochStart => {
                write!(f, "unicity seal predates the trust base epoch")
            }
            VerificationError::SealMalformed => write!(f, "malformed unicity seal"),
            VerificationError::SealRootMismatch => {
                write!(f, "unicity tree root does not match seal hash")
            }
            VerificationError::QuorumNotMet => write!(f, "quorum of root-node signatures not met"),
            VerificationError::NotAuthenticated => {
                write!(f, "unlock script does not satisfy lock script")
            }
            VerificationError::Genesis(e) => write!(f, "genesis verification failed: {e}"),
            VerificationError::Transfer { index, source } => {
                write!(f, "transfer[{index}] verification failed: {source}")
            }
        }
    }
}

impl core::error::Error for VerificationError {}
