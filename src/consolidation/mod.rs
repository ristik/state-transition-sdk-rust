//! Pure (`no_std + alloc`) building blocks of proof consolidation: the strict
//! [`PartitionView`] codec, native shard-tree reconstruction and authenticated
//! assembly of ordinary unicity certificates under a master seal.
//!
//! A partition view is the complete vector of shard-tree leaves of one
//! partition as committed by a single unicity seal. Given the enclosing
//! certificate of one shard, the trusted topology and an authority, every other
//! shard's ordinary version-1 unicity certificate can be derived; all of them
//! carry the identical master seal, so a verifier authenticates that seal once.
//!
//! Nothing here performs I/O. A decoded view or a rebuilt tree is **not**
//! trusted: [`PartitionView::authenticate`] checks it against an anchored authority
//! and yields an immutable [`AuthenticatedView`], the only input of certificate
//! assembly.
//!
//! The wire format is the frozen `PartitionViewV1` of the reference
//! implementation (bft-go-base `types/partition_view.go`):
//! `[1, partitionId, [[shardId, inputRecord, trHash, shardConfHash], ...]]`.
//!

mod assemble;
mod error;
mod partition_view;
mod plan;
mod shard_tree;
mod topology;

pub(crate) use assemble::view_policy;
pub use assemble::{AuthenticatedView, ShardCertificate};
pub use error::PartitionViewError;
pub use partition_view::{
    PartitionView, PartitionViewInputRecord, PartitionViewLeaf, MAX_PARTITION_VIEW_BYTES,
    MAX_PARTITION_VIEW_IR_BYTES, MAX_PARTITION_VIEW_LEAVES, MAX_PARTITION_VIEW_SHARD_ID_BITS,
    MAX_PARTITION_VIEW_SUMMARY_VALUE_BYTES, PARTITION_VIEW_VERSION,
};
pub use plan::{distinct_seals, outer_proofs, OuterProof, RootRoundBound, ShardRouter};
pub(crate) use plan::{rebuild_token, replacement_proof};
pub use shard_tree::ShardTree;
pub use topology::PartitionTopology;
