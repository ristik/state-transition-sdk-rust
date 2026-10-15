//! BFT consensus structures: the unicity certificate chain and the root trust
//! base that anchors it.

pub mod input_record;
pub mod root_trust_base;
pub mod shard_id;
pub mod shard_tree;
pub mod uc_interner;
pub mod unicity_certificate;
pub mod unicity_seal;
pub mod unicity_tree;

pub use input_record::InputRecord;
pub use root_trust_base::{RootTrustBase, RootTrustBaseNodeInfo};
pub use shard_id::ShardId;
pub use shard_tree::ShardTreeCertificate;
pub use uc_interner::{DecodeStats, UcInterner};
pub use unicity_certificate::UnicityCertificate;
pub use unicity_seal::UnicitySeal;
pub use unicity_tree::{HashStep, UnicityTreeCertificate};
