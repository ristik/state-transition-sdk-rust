//! BFT consensus structures: the unicity certificate chain and the root trust
//! base that anchors it.

pub mod input_record;
pub mod shard_id;
pub mod shard_tree;
pub mod trust_base_entry;
pub mod trust_base_fetch;
pub mod trust_base_history;
pub mod uc_interner;
pub mod unicity_certificate;
pub mod unicity_seal;
pub mod unicity_tree;

pub use input_record::InputRecord;
pub use shard_id::ShardId;
pub use shard_tree::ShardTreeCertificate;
pub use trust_base_entry::{TrustBaseEntry, TrustBaseError, TrustBaseMember};
pub use trust_base_fetch::{
    PageError, TrustBasePage, TrustBaseRequest, TrustBaseStatus, MAX_PAGE_ENTRIES,
};
pub use trust_base_history::{Appended, HistoryError, TrustBaseHistory};
pub use uc_interner::{DecodeStats, UcInterner};
pub use unicity_certificate::UnicityCertificate;
pub use unicity_seal::UnicitySeal;
pub use unicity_tree::{HashStep, UnicityTreeCertificate};
