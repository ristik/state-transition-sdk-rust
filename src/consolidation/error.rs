//! Typed failures of partition view decoding, validation and assembly.

use core::fmt;

use crate::error::Error;
use crate::verify::VerificationError;

/// Why a partition view was rejected or could not be turned into certificates.
///
/// The variants are stable, typed reasons; match on them rather than on the
/// display text.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PartitionViewError {
    /// The bytes are not a well-formed (bounded, definite-length) CBOR view.
    Decode(Error),
    /// The encoded view exceeds the admission limit.
    TooLarge {
        /// Limit in bytes.
        limit: usize,
        /// Actual size in bytes.
        actual: usize,
    },
    /// The explicit version is not 1 (a zero is never defaulted).
    UnsupportedVersion(u64),
    /// The bytes decode but are not the canonical encoding of the value.
    NotCanonical,
    /// A structural bound or per-leaf rule of the view is violated.
    Bounds(&'static str),
    /// The trusted topology is not a complete prefix-free sharding scheme.
    InvalidTopology(&'static str),
    /// The view is of another partition than expected.
    PartitionMismatch,
    /// The leaves are not exactly the topology's shards in canonical order.
    LeafSetMismatch(&'static str),
    /// A leaf's configuration hash differs from the admitted one.
    ConfigHashMismatch,
    /// Assembly needs an admitted configuration hash for every shard.
    ConfigHashRequired,
    /// The rebuilt shard tree does not hash into the enclosing seal.
    TreeRootMismatch,
    /// The enclosing certificate is inconsistent with the view.
    EnclosingCertificate(&'static str),
    /// The master seal was not authenticated by the trusted authority.
    Seal(VerificationError),
}

impl From<Error> for PartitionViewError {
    fn from(e: Error) -> Self {
        PartitionViewError::Decode(e)
    }
}

impl From<crate::error::CborError> for PartitionViewError {
    fn from(e: crate::error::CborError) -> Self {
        PartitionViewError::Decode(Error::Cbor(e))
    }
}

impl fmt::Display for PartitionViewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PartitionViewError::Decode(e) => write!(f, "malformed partition view: {e}"),
            PartitionViewError::TooLarge { limit, actual } => {
                write!(f, "partition view is {actual} bytes, limit is {limit}")
            }
            PartitionViewError::UnsupportedVersion(v) => {
                write!(f, "unsupported partition view version {v}")
            }
            PartitionViewError::NotCanonical => {
                write!(f, "partition view is not canonically encoded")
            }
            PartitionViewError::Bounds(m) => write!(f, "invalid partition view: {m}"),
            PartitionViewError::InvalidTopology(m) => write!(f, "invalid sharding scheme: {m}"),
            PartitionViewError::PartitionMismatch => {
                write!(f, "partition view is of another partition")
            }
            PartitionViewError::LeafSetMismatch(m) => {
                write!(f, "partition view does not match the topology: {m}")
            }
            PartitionViewError::ConfigHashMismatch => {
                write!(
                    f,
                    "shard configuration hash does not match the admitted configuration"
                )
            }
            PartitionViewError::ConfigHashRequired => {
                write!(
                    f,
                    "an admitted configuration hash is required for every shard"
                )
            }
            PartitionViewError::TreeRootMismatch => {
                write!(f, "partition view does not hash into the unicity seal")
            }
            PartitionViewError::EnclosingCertificate(m) => {
                write!(f, "enclosing unicity certificate: {m}")
            }
            PartitionViewError::Seal(e) => write!(f, "unicity seal not authenticated: {e}"),
        }
    }
}

impl core::error::Error for PartitionViewError {}
