//! A bounded FIFO set with O(1) expected indexed lookup, in `no_std + alloc`.
//!
//! Operation-scoped verification memos need membership by key, bounded memory
//! and eviction of the oldest entry. A `Vec` makes lookup and eviction linear in
//! the capacity; `std`'s `HashMap` is unavailable under `no_std`. This is a
//! chained hash table over a power-of-two bucket array plus a FIFO queue of
//! `(sequence, bucket)` pairs: lookup scans one bucket (expected O(1) for
//! well-mixed hashes, at most `capacity` for adversarial ones), insertion and
//! eviction touch one bucket and one queue end.
//!
//! The hash is supplied by the caller and is **not** a security boundary: entries
//! are confirmed by full equality, so a collision can only cost time inside the
//! configured capacity, never a wrong answer.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

struct Slot<T> {
    seq: u64,
    hash: u64,
    value: T,
}

pub(crate) struct FifoIndex<T> {
    capacity: usize,
    buckets: Vec<Vec<Slot<T>>>,
    order: VecDeque<(u64, usize)>,
    next_seq: u64,
    probes: u64,
}

impl<T> core::fmt::Debug for FifoIndex<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FifoIndex")
            .field("capacity", &self.capacity)
            .field("len", &self.order.len())
            .finish()
    }
}

impl<T> FifoIndex<T> {
    /// An index holding at most `capacity` entries (`0` stores nothing).
    pub(crate) fn new(capacity: usize) -> Self {
        let buckets = if capacity == 0 {
            0
        } else {
            capacity.next_power_of_two()
        };
        Self {
            capacity,
            buckets: (0..buckets).map(|_| Vec::new()).collect(),
            order: VecDeque::new(),
            next_seq: 0,
            probes: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.order.len()
    }

    /// Slots examined by lookups and evictions so far (the metric the O(1)
    /// claim is tested with).
    pub(crate) fn probes(&self) -> u64 {
        self.probes
    }

    fn bucket(&self, hash: u64) -> usize {
        (hash as usize) & (self.buckets.len() - 1)
    }

    /// Whether an entry with this hash satisfies `eq`.
    pub(crate) fn contains(&mut self, hash: u64, mut eq: impl FnMut(&T) -> bool) -> bool {
        if self.capacity == 0 {
            return false;
        }
        let b = self.bucket(hash);
        let mut probes = 0;
        let mut found = false;
        for slot in &self.buckets[b] {
            probes += 1;
            if slot.hash == hash && eq(&slot.value) {
                found = true;
                break;
            }
        }
        self.probes += probes;
        found
    }

    /// Insert, evicting the oldest entry when full. The caller checks
    /// [`contains`](Self::contains) first; duplicates are not detected here.
    pub(crate) fn insert(&mut self, hash: u64, value: T) {
        if self.capacity == 0 {
            return;
        }
        if self.order.len() == self.capacity {
            if let Some((seq, bucket)) = self.order.pop_front() {
                let slots = &mut self.buckets[bucket];
                let mut probes = 0;
                if let Some(i) = slots.iter().position(|s| {
                    probes += 1;
                    s.seq == seq
                }) {
                    slots.swap_remove(i);
                }
                self.probes += probes;
            }
        }
        let b = self.bucket(hash);
        let seq = self.next_seq;
        self.next_seq += 1;
        self.buckets[b].push(Slot { seq, hash, value });
        self.order.push_back((seq, b));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic well-mixed 64-bit sequence (splitmix64).
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

    /// The slow reference: a vector with linear lookup and `remove(0)` eviction.
    struct Model {
        cap: usize,
        keys: Vec<u64>,
    }
    impl Model {
        fn contains(&self, k: u64) -> bool {
            self.keys.contains(&k)
        }
        fn insert(&mut self, k: u64) {
            if self.cap == 0 {
                return;
            }
            if self.keys.len() == self.cap {
                self.keys.remove(0);
            }
            self.keys.push(k);
        }
    }

    #[test]
    fn behaves_like_the_linear_reference_model() {
        for cap in [0usize, 1, 2, 3, 7, 64, 100] {
            for key_space in [3u64, 50, 5_000] {
                let mut rng = Rng(cap as u64 * 31 + key_space);
                let mut index = FifoIndex::<u64>::new(cap);
                let mut model = Model {
                    cap,
                    keys: Vec::new(),
                };
                for _ in 0..5_000 {
                    let k = rng.next() % key_space;
                    // use a deliberately poor hash half of the time: collisions must not matter
                    let h = if k % 2 == 0 { k } else { k % 4 };
                    let hit = index.contains(h, |v| *v == k);
                    assert_eq!(hit, model.contains(k), "cap {cap} key {k}");
                    if !hit {
                        index.insert(h, k);
                        model.insert(k);
                    }
                    assert_eq!(index.len(), model.keys.len());
                }
            }
        }
    }

    /// Mean slots examined per operation with uniformly distributed hashes.
    fn mean_probes(cap: usize) -> f64 {
        let mut rng = Rng(7);
        let mut index = FifoIndex::<u64>::new(cap);
        let ops = 4 * cap.max(64);
        for _ in 0..ops {
            let k = rng.next();
            if !index.contains(k, |v| *v == k) {
                index.insert(k, k);
            }
        }
        index.probes() as f64 / ops as f64
    }

    #[test]
    fn operation_cost_does_not_grow_with_the_capacity() {
        // a Vec memo would examine ~cap/2 entries per operation: slope 1 in cap
        let sweep: Vec<(usize, f64)> = [64usize, 256, 1_024, 4_096, 16_384]
            .iter()
            .map(|&c| (c, mean_probes(c)))
            .collect();
        for (cap, probes) in &sweep {
            assert!(
                *probes < 4.0,
                "capacity {cap}: {probes} probes per operation"
            );
        }
        let (first, last) = (sweep[0].1, sweep[sweep.len() - 1].1);
        assert!(last < 2.0 * first + 1.0, "flat in capacity: {sweep:?}");
    }

    #[test]
    fn adversarial_hashes_cost_at_most_the_configured_capacity() {
        let cap = 64;
        let mut index = FifoIndex::<u64>::new(cap);
        for k in 0..1_000u64 {
            // every key collides: the worst case is the capacity bound, never more
            let before = index.probes();
            assert!(!index.contains(0, |v| *v == k));
            index.insert(0, k);
            assert!(index.probes() - before <= 2 * cap as u64 + 1);
        }
        assert_eq!(index.len(), cap);
    }
}
