//! Decode-scope interning of unicity certificates by their complete wire bytes.
//!
//! A token (and every token nested in it) carries one unicity certificate per
//! proof, but proofs of one consolidated history share a handful of distinct
//! certificates. Decoding each copy again is `O(L * C)` parsing work for `m`
//! distinct bodies. A [`UcInterner`] remembers the decoded certificate of every
//! distinct complete encoding seen during one decode/verification operation, so
//! each distinct certificate is parsed once and its repeats are clones.
//!
//! The key is the **complete** encoding (signature witness included), compared by
//! equality; the hash only selects a bucket. Reading the repeated wire bytes is
//! still `Ω(L * C)` - interning removes parsing, not input inspection.
//! Failed decodes are never remembered. Memory is bounded by the capacity.

use alloc::vec::Vec;

use super::unicity_certificate::UnicityCertificate;
use crate::cbor::Decoder;
use crate::error::Error;
use crate::fifo_index::FifoIndex;

/// Default number of distinct certificates remembered per operation.
pub const DEFAULT_UC_INTERNER_CAPACITY: usize = 256;

/// Counters of a decode operation: the metric of the interning bound.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DecodeStats {
    /// Certificates actually parsed (one per distinct complete encoding while resident).
    pub uc_decodes: u64,
    /// Certificates served from a previously decoded identical encoding.
    pub uc_hits: u64,
}

/// Bounded interner of decoded unicity certificates (see the module docs).
#[derive(Debug)]
pub struct UcInterner {
    index: FifoIndex<(Vec<u8>, UnicityCertificate)>,
    stats: DecodeStats,
}

impl Default for UcInterner {
    fn default() -> Self {
        Self::new()
    }
}

impl UcInterner {
    /// Interner with the [`DEFAULT_UC_INTERNER_CAPACITY`].
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_UC_INTERNER_CAPACITY)
    }

    /// Interner remembering at most `capacity` encodings; `0` disables reuse.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            index: FifoIndex::new(capacity),
            stats: DecodeStats::default(),
        }
    }

    /// Work done so far.
    pub fn stats(&self) -> DecodeStats {
        self.stats
    }

    /// Decode the certificate item `d` (strictly, exactly like
    /// [`UnicityCertificate::from_cbor`]), reusing an identical earlier decode.
    pub fn decode(&mut self, d: Decoder<'_>) -> Result<UnicityCertificate, Error> {
        let bytes = d.bytes();
        let hash = fingerprint(bytes);
        let mut found: Option<UnicityCertificate> = None;
        self.index.contains(hash, |(b, uc)| {
            let hit = b.as_slice() == bytes;
            if hit {
                found = Some(uc.clone());
            }
            hit
        });
        if let Some(uc) = found {
            self.stats.uc_hits += 1;
            return Ok(uc);
        }
        self.stats.uc_decodes += 1;
        let uc = UnicityCertificate::from_cbor(d)?;
        self.index.insert(hash, (bytes.to_vec(), uc.clone()));
        Ok(uc)
    }
}

/// FNV-1a over the encoding: a bucket selector only, never an identity.
fn fingerprint(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}
