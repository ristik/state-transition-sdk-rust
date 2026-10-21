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
    ///
    /// Cost: O(S log S) shard-id comparisons for an arbitrary order and O(S) for
    /// an already canonical one (sort, then adjacent-pair prefix check, then a
    /// single descent that visits each internal node once).
    pub fn canonical_order(&self) -> Result<Vec<ShardId>, PartitionViewError> {
        self.canonical_order_with(MAX_PARTITION_VIEW_LEAVES, &mut 0)
    }

    /// [`canonical_order`](Self::canonical_order) with an explicit shard limit
    /// (the view admission cap by default; raised in scaling tests) and a count
    /// of shard-id comparisons.
    pub(crate) fn canonical_order_with(
        &self,
        max_shards: usize,
        comparisons: &mut u64,
    ) -> Result<Vec<ShardId>, PartitionViewError> {
        let scheme = &self.scheme;
        if scheme.len() > max_shards {
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
        let mut ids = scheme.clone();
        ids.sort_by(|a, b| {
            *comparisons += 1;
            a.canonical_cmp(b)
        });
        // in lexicographic order a prefix is followed by everything it prefixes, so
        // an overlap (or duplicate) is always visible between neighbors
        for pair in ids.windows(2) {
            *comparisons += 1;
            if pair[0].is_prefix_of_shard(&pair[1]) {
                return Err(PartitionViewError::InvalidTopology(
                    "scheme is not prefix-free",
                ));
            }
        }
        if !covers(&ids, 0, comparisons) {
            return Err(PartitionViewError::InvalidTopology(
                "scheme does not cover the whole shard tree",
            ));
        }
        Ok(ids)
    }
}

/// Whether the sorted, prefix-free `shards` (all sharing their first `depth`
/// bits) exactly tile the subtree at `depth`. Each internal node is visited once.
fn covers(shards: &[ShardId], depth: usize, comparisons: &mut u64) -> bool {
    if shards.len() == 1 {
        return shards[0].length() == depth;
    }
    // prefix-free: no member ends here while others continue below, so every bit is defined
    let split = shards.partition_point(|s| {
        *comparisons += 1;
        s.get_bit(depth) == Ok(0)
    });
    split != 0
        && split != shards.len()
        && covers(&shards[..split], depth + 1, comparisons)
        && covers(&shards[split..], depth + 1, comparisons)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

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

    /// The previous quadratic algorithm, kept as the slow reference model.
    fn reference(scheme: &[ShardId], max: usize) -> Result<Vec<ShardId>, ()> {
        if scheme.len() > max {
            return Err(());
        }
        if scheme.is_empty() {
            return Ok(vec![ShardId::root()]);
        }
        if scheme.len() == 1 || scheme.iter().any(|s| s.length() == 0) {
            return Err(());
        }
        for (i, a) in scheme.iter().enumerate() {
            for (j, b) in scheme.iter().enumerate() {
                if i != j && a.is_prefix_of_shard(b) {
                    return Err(());
                }
            }
        }
        fn covers(scheme: &[ShardId], node: &ShardId) -> bool {
            if scheme.iter().any(|s| s == node) {
                return true;
            }
            if !scheme.iter().any(|s| node.is_prefix_of_shard(s)) {
                return false;
            }
            let (z, o) = node.split();
            covers(scheme, &z) && covers(scheme, &o)
        }
        if !covers(scheme, &ShardId::root()) {
            return Err(());
        }
        let mut ids = scheme.to_vec();
        ids.sort_by(|a, b| a.canonical_cmp(b));
        Ok(ids)
    }

    /// A random complete scheme of exactly `n >= 2` shards, in canonical order.
    fn random_scheme(n: usize, rng: &mut Rng) -> Vec<ShardId> {
        let mut leaves = vec![ShardId::root()];
        while leaves.len() < n {
            let i = (rng.next() as usize) % leaves.len();
            let (z, o) = leaves[i].split();
            leaves.splice(i..=i, [z, o]);
        }
        leaves
    }

    fn shuffle(v: &mut [ShardId], rng: &mut Rng) {
        for i in (1..v.len()).rev() {
            v.swap(i, (rng.next() as usize) % (i + 1));
        }
    }

    fn run(scheme: &[ShardId], max: usize) -> (Result<Vec<ShardId>, ()>, u64) {
        let mut cmps = 0;
        let r = PartitionTopology::new(scheme.to_vec())
            .canonical_order_with(max, &mut cmps)
            .map_err(|_| ());
        (r, cmps)
    }

    #[test]
    fn agrees_with_the_quadratic_reference_on_valid_and_broken_schemes() {
        let mut rng = Rng(42);
        for n in 2..=24 {
            for _ in 0..40 {
                let mut scheme = random_scheme(n, &mut rng);
                let canonical = scheme.clone();
                shuffle(&mut scheme, &mut rng);
                let (got, _) = run(&scheme, 64);
                assert_eq!(got, reference(&scheme, 64));
                assert_eq!(got.as_ref().unwrap(), &canonical);

                // break it: drop a leaf / duplicate one / add an overlapping child / lengthen one
                let mut broken = scheme.clone();
                match rng.next() % 4 {
                    0 => {
                        broken.remove((rng.next() as usize) % broken.len());
                    }
                    1 => {
                        let d = broken[(rng.next() as usize) % broken.len()].clone();
                        broken.push(d);
                    }
                    2 => {
                        let d = broken[(rng.next() as usize) % broken.len()].split().0;
                        broken.push(d);
                    }
                    _ => {
                        let i = (rng.next() as usize) % broken.len();
                        broken[i] = broken[i].split().1;
                    }
                }
                let (got, _) = run(&broken, 64);
                assert_eq!(got, reference(&broken, 64), "{broken:?}");
            }
        }
        // the empty id, a single shard, the shard limit
        assert_eq!(run(&[], 8).0, reference(&[], 8));
        assert_eq!(run(&[ShardId::root()], 8).0, Err(()));
        let nine = random_scheme(9, &mut rng);
        assert_eq!(run(&nine, 8).0, Err(()));
        assert!(run(&nine, 9).0.is_ok());
    }

    #[test]
    fn comparison_count_is_s_log_s_not_s_squared() {
        let mut rng = Rng(7);
        let mut sorted_cmps = Vec::new();
        let mut shuffled_cmps = Vec::new();
        let mut reference_pairs = Vec::new();
        for k in 1..=11u32 {
            let s = 1usize << k;
            // balanced complete scheme
            let mut scheme = alloc::vec![ShardId::root()];
            for _ in 0..k {
                scheme = scheme
                    .iter()
                    .flat_map(|x| {
                        let (z, o) = x.split();
                        [z, o]
                    })
                    .collect();
            }
            let (ok, canonical_cmps) = run(&scheme, usize::MAX);
            assert!(ok.is_ok());
            sorted_cmps.push((s, canonical_cmps));
            shuffle(&mut scheme, &mut rng);
            let (ok, c) = run(&scheme, usize::MAX);
            assert!(ok.is_ok());
            shuffled_cmps.push((s, c));
            reference_pairs.push((s, (s * s) as u64));
        }
        for &(s, c) in &sorted_cmps {
            // already canonical: sort detects the run, then neighbors and one descent
            assert!(c <= 6 * s as u64, "sorted S={s}: {c} comparisons");
        }
        for &(s, c) in &shuffled_cmps {
            let log = u64::from(s.ilog2()).max(1);
            assert!(c <= 4 * s as u64 * log, "shuffled S={s}: {c} comparisons");
        }
        // growth: doubling S at most ~doubles (plus log factor) the count; the quadratic
        // reference would quadruple it
        let (s_small, c_small) = shuffled_cmps[4];
        let (s_big, c_big) = shuffled_cmps[10];
        let growth = c_big as f64 / c_small as f64;
        let size = (s_big / s_small) as f64; // 64x
        assert!(
            growth < size * 2.0,
            "shuffled growth {growth} for {size}x shards"
        );
        assert!(growth < 0.1 * size * size, "far below quadratic");
    }
}
