//! Aggregator-facing API types: identifiers, certification data, proofs, and
//! the BFT trust structures.

pub mod bft;
pub mod certification;
pub mod certification_request;
pub mod inclusion_certificate;
pub mod inclusion_proof;
pub mod inclusion_proof_response;
pub mod leaf_value;
pub mod network_id;
pub mod non_inclusion_certificate;
pub mod non_inclusion_proof;
pub mod proof_status;
pub mod state_id;

/// The aggregation partition every Unicity network uses (`7`).
///
/// This is a fixed protocol constant, not configuration: a proof never selects
/// its own expected partition. Every application verification path (inclusion,
/// token including nested proofs, non-inclusion, consolidation and partition
/// views) rejects an authenticated certificate of any other partition. Generic
/// BFT codecs stay partition-agnostic and cannot confer verification success.
pub const AGGREGATION_PARTITION_ID: u32 = 7;

/// Leaf-value width in the Unicity aggregation profile.
///
/// The generic RSMT certificate format permits arbitrary byte-string values;
/// Unicity restricts each value to one raw SHA-256 digest.
pub const AGGREGATION_TREE_VALUE_SIZE: usize = 32;

pub use certification::CertificationData;
pub use certification_request::CertificationRequest;
pub use inclusion_certificate::InclusionCertificate;
pub use inclusion_proof::InclusionProof;
pub use inclusion_proof_response::InclusionProofResponse;
pub use leaf_value::calculate_leaf_value;
pub use network_id::NetworkId;
pub use non_inclusion_certificate::{NonInclusionCertificate, PathRelation};
pub use non_inclusion_proof::NonInclusionProof;
pub use proof_status::ProofStatus;
pub use state_id::StateId;
