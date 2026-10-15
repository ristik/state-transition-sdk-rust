//! The trusted description of a partition a view is validated against.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::error::PartitionViewError;
use super::partition_view::{MAX_PARTITION_VIEW_LEAVES, MAX_PARTITION_VIEW_SHARD_ID_BITS};
use crate::api::bft::ShardId;

/// The sharding scheme of a partition plus the admitted shard configuration
/// hashes.
///
/// It must come from the verifier's own configuration, never from the response
/// carrying the view: a response does not establish trust in a topology.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionTopology {
    scheme: Vec<ShardId>,
    conf_hashes: BTreeMap<Vec<u8>, [u8; 32]>,
}

impl PartitionTopology {
    /// Topology of an unsharded partition (the single empty shard id).
    pub fn single_shard() -> Self {
        Self {
            scheme: Vec::new(),
            conf_hashes: BTreeMap::new(),
        }
    }

    /// Topology with the given shard ids. An empty scheme is the single shard;
    /// completeness and prefix-freeness are checked by [`Self::canonical_order`].
    pub fn new(scheme: Vec<ShardId>) -> Self {
        Self {
            scheme,
            conf_hashes: BTreeMap::new(),
        }
    }

    /// Admit the configuration hash of `shard`.
    pub fn with_shard_conf_hash(mut self, shard: &ShardId, hash: [u8; 32]) -> Self {
        self.conf_hashes.insert(shard.encode(), hash);
        self
    }

    /// The admitted configuration hash of `shard`, if any.
    pub fn shard_conf_hash(&self, shard: &ShardId) -> Option<&[u8; 32]> {
        self.conf_hashes.get(&shard.encode())
    }

    /// Digest of the scheme and pinned hashes, for inclusion in cache/session
    /// identities of anything derived under this policy.
    pub fn digest(&self) -> [u8; 32] {
        use crate::crypto::hash::{DataHasher, HashAlgorithm};
        let mut h = DataHasher::new(HashAlgorithm::Sha256)
            .expect("sha256")
            .update(b"unicity-token/topology/v1")
            .update(&(self.scheme.len() as u64).to_be_bytes());
        let mut scheme: Vec<Vec<u8>> = self.scheme.iter().map(ShardId::encode).collect();
        scheme.sort();
        for id in &scheme {
            h = h.update(&(id.len() as u64).to_be_bytes()).update(id);
        }
        h = h.update(&(self.conf_hashes.len() as u64).to_be_bytes());
        for (id, hash) in &self.conf_hashes {
            h = h
                .update(&(id.len() as u64).to_be_bytes())
                .update(id)
                .update(hash);
        }
        let mut d = [0u8; 32];
        d.copy_from_slice(h.finalize().data());
        d
    }

    /// The shard ids of the (complete, prefix-free) scheme in binary tree
    /// left-to-right order: lexicographic bit strings, `0` before `1`. The empty
    /// scheme yields the single empty shard id.
    pub fn canonical_order(&self) -> Result<Vec<ShardId>, PartitionViewError> {
        let scheme = &self.scheme;
        if scheme.len() > MAX_PARTITION_VIEW_LEAVES {
            return Err(PartitionViewError::InvalidTopology("too many shards"));
        }
        if scheme.is_empty() {
            return Ok(alloc::vec![ShardId::root()]);
        }
        if scheme.len() == 1 {
            return Err(PartitionViewError::InvalidTopology(
                "a scheme can not hold a single shard",
            ));
        }
        for id in scheme {
            if id.length() == 0 {
                return Err(PartitionViewError::InvalidTopology(
                    "a scheme can not contain the empty shard id",
                ));
            }
            if id.length() > MAX_PARTITION_VIEW_SHARD_ID_BITS {
                return Err(PartitionViewError::InvalidTopology("shard id is too long"));
            }
        }
        for (i, a) in scheme.iter().enumerate() {
            for (j, b) in scheme.iter().enumerate() {
                if i != j && a.is_prefix_of_shard(b) {
                    return Err(PartitionViewError::InvalidTopology(
                        "scheme is not prefix-free",
                    ));
                }
            }
        }
        // a prefix-free set covers the whole shard tree iff every internal node
        // it implies has both children covered
        if !covers(scheme, &ShardId::root()) {
            return Err(PartitionViewError::InvalidTopology(
                "scheme does not cover the whole shard tree",
            ));
        }
        let mut ids = scheme.clone();
        ids.sort_by(|a, b| a.canonical_cmp(b));
        Ok(ids)
    }
}

/// Whether the shards below `node` are completely covered by `scheme`.
/// Descends only along prefixes of scheme members, so it is bounded by
/// `scheme.len() * MAX_PARTITION_VIEW_SHARD_ID_BITS` steps.
fn covers(scheme: &[ShardId], node: &ShardId) -> bool {
    if scheme.iter().any(|s| s == node) {
        return true;
    }
    if !scheme.iter().any(|s| node.is_prefix_of_shard(s)) {
        return false;
    }
    let (zero, one) = node.split();
    covers(scheme, &zero) && covers(scheme, &one)
}
