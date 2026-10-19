//! The native shard tree: leaf hashes of every shard and the binary hash tree
//! above them, from which shard tree certificates are read.
//!
//! The tree is a flat arena. Leaves arrive in canonical (left-to-right) order, so
//! the inner nodes are produced by one stack pass - each leaf is pushed once and
//! each inner node is hashed exactly once (`S - 1` hashes), O(S) in total for a
//! canonical scheme, with no ordered-map lookups. A certificate is read by
//! climbing parent links: O(depth) node visits after locating the leaf.

use alloc::vec::Vec;

use super::error::PartitionViewError;
use crate::api::bft::{ShardId, ShardTreeCertificate};
use crate::cbor::encode_byte_string;
use crate::crypto::hash::{DataHasher, HashAlgorithm};

const NONE: u32 = u32::MAX;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Node {
    hash: Vec<u8>,
    parent: u32,
    /// `[zero child, one child]` of an inner node; `NONE` for leaves.
    children: [u32; 2],
}

/// Counted work of building and reading a tree (the metric of its O(S) bound).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ShardTreeWork {
    /// Inner-node hashes computed.
    pub inner_hashes: u64,
    /// Leaves consumed.
    pub leaves: u64,
    /// Nodes visited reading certificates.
    pub path_visits: u64,
}

/// Hash tree over the shard leaves `H(inputRecord, trHash, shardConfHash)`.
///
/// A single-shard tree is just its leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardTree {
    nodes: Vec<Node>,
    /// `(shard, node index)` of every leaf, in canonical order.
    leaves: Vec<(ShardId, u32)>,
    root: u32,
}

impl ShardTree {
    /// Build the tree from the leaf hashes of a complete, prefix-free scheme
    /// given in canonical order.
    pub(crate) fn build(leaves: Vec<(ShardId, Vec<u8>)>) -> Result<Self, PartitionViewError> {
        Self::build_counted(leaves, &mut ShardTreeWork::default())
    }

    pub(crate) fn build_counted(
        leaves: Vec<(ShardId, Vec<u8>)>,
        work: &mut ShardTreeWork,
    ) -> Result<Self, PartitionViewError> {
        let invalid = |m| PartitionViewError::InvalidTopology(m);
        if leaves.is_empty() {
            return Err(invalid("a shard tree needs at least one leaf"));
        }
        let mut nodes: Vec<Node> = Vec::with_capacity(2 * leaves.len());
        let mut index: Vec<(ShardId, u32)> = Vec::with_capacity(leaves.len());
        // pending subtrees: (id of the subtree's root in the shard tree, node index)
        let mut stack: Vec<(ShardId, u32)> = Vec::new();
        for (shard, hash) in leaves {
            if let Some((prev, _)) = index.last() {
                if prev.canonical_cmp(&shard).is_ge() {
                    return Err(PartitionViewError::LeafSetMismatch(
                        "shards are duplicated or not in canonical order",
                    ));
                }
            }
            work.leaves += 1;
            let node = nodes.len() as u32;
            nodes.push(Node {
                hash,
                parent: NONE,
                children: [NONE, NONE],
            });
            index.push((shard.clone(), node));
            stack.push((shard, node));
            // merge while the top two are the zero and one child of one parent
            while stack.len() >= 2 {
                let (right_id, right) = &stack[stack.len() - 1];
                let (left_id, left) = &stack[stack.len() - 2];
                let siblings = right_id.sibling().as_ref() == Some(left_id)
                    && left_id.get_bit(left_id.length() - 1) == Ok(0);
                if !siblings {
                    break;
                }
                let (parent_id, left, right) = (
                    left_id
                        .prefix(left_id.length() - 1)
                        .expect("shorter prefix"),
                    *left,
                    *right,
                );
                let hash = DataHasher::new(HashAlgorithm::Sha256)
                    .expect("sha256")
                    .update(&encode_byte_string(&nodes[left as usize].hash))
                    .update(&encode_byte_string(&nodes[right as usize].hash))
                    .finalize()
                    .data()
                    .to_vec();
                work.inner_hashes += 1;
                let parent = nodes.len() as u32;
                nodes.push(Node {
                    hash,
                    parent: NONE,
                    children: [left, right],
                });
                nodes[left as usize].parent = parent;
                nodes[right as usize].parent = parent;
                stack.truncate(stack.len() - 2);
                stack.push((parent_id, parent));
            }
        }
        // a complete scheme collapses to exactly the root
        match stack.as_slice() {
            [(id, root)] if id.length() == 0 => Ok(ShardTree {
                root: *root,
                nodes,
                leaves: index,
            }),
            _ => Err(invalid("scheme does not cover the whole shard tree")),
        }
    }

    /// Root hash of the tree.
    pub fn root_hash(&self) -> &[u8] {
        &self.nodes[self.root as usize].hash
    }

    /// The shard tree certificate (sibling hashes from the leaf up) of `shard`.
    pub fn certificate(&self, shard: &ShardId) -> Result<ShardTreeCertificate, PartitionViewError> {
        self.certificate_counted(shard, &mut ShardTreeWork::default())
    }

    pub(crate) fn certificate_counted(
        &self,
        shard: &ShardId,
        work: &mut ShardTreeWork,
    ) -> Result<ShardTreeCertificate, PartitionViewError> {
        let missing = || PartitionViewError::LeafSetMismatch("shard is not in the tree");
        let at = self
            .leaves
            .binary_search_by(|(s, _)| s.canonical_cmp(shard))
            .map_err(|_| missing())?;
        let mut node = self.leaves[at].1;
        let mut sibling_hash_list = Vec::with_capacity(shard.length());
        while self.nodes[node as usize].parent != NONE {
            work.path_visits += 1;
            let parent = &self.nodes[self.nodes[node as usize].parent as usize];
            let sibling = if parent.children[0] == node {
                parent.children[1]
            } else {
                parent.children[0]
            };
            sibling_hash_list.push(self.nodes[sibling as usize].hash.clone());
            node = self.nodes[node as usize].parent;
        }
        Ok(ShardTreeCertificate {
            shard: shard.clone(),
            sibling_hash_list,
            empty_as_null: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use alloc::vec;

    /// The previous ordered-map implementation: the slow reference model.
    struct Reference {
        nodes: BTreeMap<Vec<u8>, Vec<u8>>,
    }

    impl Reference {
        fn build(leaves: &[(ShardId, Vec<u8>)]) -> Self {
            let mut r = Reference {
                nodes: leaves
                    .iter()
                    .map(|(s, h)| (s.encode(), h.clone()))
                    .collect(),
            };
            if r.nodes.len() > 1 {
                r.generate(&ShardId::root());
            }
            r
        }
        fn generate(&mut self, id: &ShardId) -> Vec<u8> {
            if let Some(h) = self.nodes.get(&id.encode()) {
                return h.clone();
            }
            let (z, o) = id.split();
            let (l, r) = (self.generate(&z), self.generate(&o));
            let h = DataHasher::new(HashAlgorithm::Sha256)
                .unwrap()
                .update(&encode_byte_string(&l))
                .update(&encode_byte_string(&r))
                .finalize()
                .data()
                .to_vec();
            self.nodes.insert(id.encode(), h.clone());
            h
        }
        fn certificate(&self, shard: &ShardId) -> Vec<Vec<u8>> {
            (1..=shard.length())
                .rev()
                .map(|len| {
                    let s = shard.prefix(len).unwrap().sibling().unwrap();
                    self.nodes[&s.encode()].clone()
                })
                .collect()
        }
    }

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }
    }

    /// Canonical leaves of a random complete scheme of `n` shards.
    fn scheme(n: usize, rng: &mut Rng) -> Vec<(ShardId, Vec<u8>)> {
        let mut ids = vec![ShardId::root()];
        while ids.len() < n {
            let i = (rng.next() as usize) % ids.len();
            let (z, o) = ids[i].split();
            ids.splice(i..=i, [z, o]);
        }
        ids.into_iter()
            .enumerate()
            .map(|(i, id)| (id, vec![i as u8; 32]))
            .collect()
    }

    #[test]
    fn equals_the_ordered_map_reference_on_random_schemes() {
        let mut rng = Rng(11);
        for n in 1..=40 {
            for _ in 0..10 {
                let leaves = scheme(n, &mut rng);
                let tree = ShardTree::build(leaves.clone()).unwrap();
                let reference = Reference::build(&leaves);
                assert_eq!(tree.root_hash(), reference.nodes[&ShardId::root().encode()]);
                for (shard, _) in &leaves {
                    assert_eq!(
                        tree.certificate(shard).unwrap().sibling_hash_list,
                        reference.certificate(shard),
                        "n={n} shard={}",
                        shard.to_bit_string()
                    );
                }
                assert!(
                    tree.certificate(&leaves[0].0.split().0).is_err(),
                    "a shard below a leaf is not in the tree"
                );
            }
        }
    }

    #[test]
    fn rejects_unsorted_duplicate_and_incomplete_leaves() {
        let mut rng = Rng(5);
        let leaves = scheme(6, &mut rng);
        let mut swapped = leaves.clone();
        swapped.swap(1, 2);
        assert!(ShardTree::build(swapped).is_err());
        let mut dup = leaves.clone();
        dup[3] = dup[2].clone();
        assert!(ShardTree::build(dup).is_err());
        let mut missing = leaves.clone();
        missing.remove(2);
        assert!(ShardTree::build(missing).is_err());
        assert!(ShardTree::build(Vec::new()).is_err());
        // a deeper leaf where a sibling subtree is missing
        let a = ShardId::root().split().0;
        assert!(
            ShardTree::build(vec![(a.split().0, vec![0; 32]), (a.split().1, vec![0; 32])]).is_err()
        );
    }

    /// One hash per inner node (`S - 1`) and one visit per level of the path: linear
    /// build, logarithmic (balanced) certificate reads, independent of S for a leaf's depth.
    #[test]
    fn build_and_lookup_work_is_linear_not_log_linear() {
        let mut rng = Rng(3);
        let mut build_ratio = Vec::new();
        for k in 1..=11u32 {
            let s = 1usize << k;
            // balanced complete scheme in canonical order
            let mut ids = vec![ShardId::root()];
            for _ in 0..k {
                ids = ids
                    .iter()
                    .flat_map(|x| {
                        let (z, o) = x.split();
                        [z, o]
                    })
                    .collect();
            }
            let leaves: Vec<_> = ids
                .iter()
                .map(|id| (id.clone(), vec![rng.next() as u8; 32]))
                .collect();
            let mut work = ShardTreeWork::default();
            let tree = ShardTree::build_counted(leaves, &mut work).unwrap();
            assert_eq!(work.leaves, s as u64);
            assert_eq!(work.inner_hashes, s as u64 - 1, "one hash per inner node");
            build_ratio.push(work.inner_hashes as f64 / s as f64);
            let mut reads = ShardTreeWork::default();
            for id in &ids {
                tree.certificate_counted(id, &mut reads).unwrap();
            }
            assert_eq!(
                reads.path_visits,
                s as u64 * u64::from(k),
                "depth visits per certificate"
            );
        }
        assert!(
            build_ratio.iter().all(|r| *r < 1.0),
            "hashes per leaf stay below one"
        );
    }

    /// A maximally skewed (depth S-1) scheme still costs one hash per inner node.
    #[test]
    fn skewed_schemes_stay_linear() {
        for s in [4usize, 16, 64, 256] {
            let mut leaves = Vec::new();
            let mut node = ShardId::root();
            for i in 0..s - 1 {
                let (z, o) = node.split();
                leaves.push((z, vec![i as u8; 32]));
                node = o;
            }
            leaves.push((node, vec![0xff; 32]));
            let mut work = ShardTreeWork::default();
            ShardTree::build_counted(leaves, &mut work).unwrap();
            assert_eq!(work.inner_hashes, s as u64 - 1);
        }
    }
}
