//! The native shard tree: leaf hashes of every shard and the binary hash tree
//! above them, from which shard tree certificates are read.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::error::PartitionViewError;
use crate::api::bft::{ShardId, ShardTreeCertificate};
use crate::cbor::encode_byte_string;
use crate::crypto::hash::{DataHasher, HashAlgorithm};

/// Hash tree over the shard leaves `H(inputRecord, trHash, shardConfHash)`.
///
/// Node keys are the encoded shard ids; the root is the empty shard id. A
/// single-shard tree is just its leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardTree {
    nodes: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl ShardTree {
    /// Build the tree from the leaf hashes of a complete, prefix-free scheme.
    pub(crate) fn build(leaves: Vec<(ShardId, Vec<u8>)>) -> Result<Self, PartitionViewError> {
        let mut nodes = BTreeMap::new();
        for (shard, hash) in leaves {
            if nodes.insert(shard.encode(), hash).is_some() {
                return Err(PartitionViewError::LeafSetMismatch("duplicate shard"));
            }
        }
        let mut tree = ShardTree { nodes };
        if tree.nodes.len() > 1 {
            tree.generate(&ShardId::root())?;
        }
        Ok(tree)
    }

    /// Generates the inner nodes; every leaf exists before this is called, and
    /// the scheme was checked complete, so the recursion ends at the leaves.
    fn generate(&mut self, id: &ShardId) -> Result<Vec<u8>, PartitionViewError> {
        if let Some(h) = self.nodes.get(&id.encode()) {
            return Ok(h.clone());
        }
        if id.length() > super::MAX_PARTITION_VIEW_SHARD_ID_BITS {
            return Err(PartitionViewError::InvalidTopology(
                "shard tree is too deep",
            ));
        }
        let (zero, one) = id.split();
        let left = self.generate(&zero)?;
        let right = self.generate(&one)?;
        let hash = DataHasher::new(HashAlgorithm::Sha256)
            .expect("sha256")
            .update(&encode_byte_string(&left))
            .update(&encode_byte_string(&right))
            .finalize()
            .data()
            .to_vec();
        self.nodes.insert(id.encode(), hash.clone());
        Ok(hash)
    }

    /// Root hash of the tree.
    pub fn root_hash(&self) -> &[u8] {
        self.nodes
            .get(&ShardId::root().encode())
            .map_or(&[], Vec::as_slice)
    }

    /// The shard tree certificate (sibling hashes from the leaf up) of `shard`.
    pub fn certificate(&self, shard: &ShardId) -> Result<ShardTreeCertificate, PartitionViewError> {
        if !self.nodes.contains_key(&shard.encode()) {
            return Err(PartitionViewError::LeafSetMismatch(
                "shard is not in the tree",
            ));
        }
        let mut sibling_hash_list = Vec::with_capacity(shard.length());
        for len in (1..=shard.length()).rev() {
            let sibling = shard.prefix(len).and_then(|p| p.sibling()).ok_or(
                PartitionViewError::LeafSetMismatch("shard is not in the tree"),
            )?;
            let hash =
                self.nodes
                    .get(&sibling.encode())
                    .ok_or(PartitionViewError::LeafSetMismatch(
                        "shard is not in the tree",
                    ))?;
            sibling_hash_list.push(hash.clone());
        }
        Ok(ShardTreeCertificate {
            shard: shard.clone(),
            sibling_hash_list,
        })
    }
}
