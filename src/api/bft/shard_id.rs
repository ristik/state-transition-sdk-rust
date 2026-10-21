//! Shard identifier: a variable-length bit string with an end-marker byte
//! encoding, ported exactly from the reference SDKs.

use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;

use crate::error::Error;

/// A shard identifier (a bit string of `length` bits stored MSB-first).
#[derive(Clone, PartialEq, Eq)]
pub struct ShardId {
    bits: Vec<u8>,
    length: usize,
}

impl ShardId {
    /// Number of bits in the shard id.
    pub fn length(&self) -> usize {
        self.length
    }

    /// The empty shard id (the single shard of an unsharded partition).
    pub fn root() -> Self {
        ShardId {
            bits: Vec::new(),
            length: 0,
        }
    }

    /// The first `length` bits of this shard id.
    ///
    /// Returns `None` when `length` exceeds the id's own length.
    pub fn prefix(&self, length: usize) -> Option<Self> {
        if length > self.length {
            return None;
        }
        let mut bits = self.bits[..length.div_ceil(8)].to_vec();
        if length % 8 != 0 {
            if let Some(last) = bits.last_mut() {
                *last &= 0xffu8 << (8 - length % 8);
            }
        }
        Some(ShardId { bits, length })
    }

    /// The two child shard ids, one bit longer (`0` child first).
    pub fn split(&self) -> (Self, Self) {
        let length = self.length + 1;
        let mut zero = self.bits.clone();
        if self.length % 8 == 0 {
            zero.push(0);
        }
        let mut one = zero.clone();
        if let Some(last) = one.last_mut() {
            *last |= 1 << (7 - self.length % 8);
        }
        (
            ShardId { bits: zero, length },
            ShardId { bits: one, length },
        )
    }

    /// The id differing from this one in the last bit only (`None` for the
    /// empty id).
    pub fn sibling(&self) -> Option<Self> {
        if self.length == 0 {
            return None;
        }
        let mut bits = self.bits.clone();
        let last = (self.length - 1) / 8;
        bits[last] ^= 1 << (7 - (self.length - 1) % 8);
        Some(ShardId {
            bits,
            length: self.length,
        })
    }

    /// Whether this id is a bit-prefix of (or equal to) `other`.
    pub fn is_prefix_of_shard(&self, other: &ShardId) -> bool {
        self.length <= other.length && self.is_prefix_of(&other.bits)
    }

    /// Order of the bit strings `"0"`/`"1"` as text: lexicographic, a proper
    /// prefix sorts first. For a complete prefix-free scheme this is the binary
    /// tree left-to-right order.
    pub fn canonical_cmp(&self, other: &ShardId) -> Ordering {
        for i in 0..self.length.min(other.length) {
            let (a, b) = (
                (self.bits[i / 8] >> (7 - i % 8)) & 1,
                (other.bits[i / 8] >> (7 - i % 8)) & 1,
            );
            if a != b {
                return a.cmp(&b);
            }
        }
        self.length.cmp(&other.length)
    }

    /// Where this shard's bit prefix lies relative to the first bits of `key`:
    /// `Equal` iff this id is a bit-prefix of `key`. Over a sorted prefix-free
    /// scheme this is monotone, so it supports binary search.
    pub fn cmp_prefix_of_key(&self, key: &[u8]) -> Ordering {
        for i in 0..self.length {
            let (a, b) = (
                (self.bits[i / 8] >> (7 - i % 8)) & 1,
                key.get(i / 8).map_or(0, |k| (k >> (7 - i % 8)) & 1),
            );
            if a != b {
                return a.cmp(&b);
            }
        }
        Ordering::Equal
    }

    /// The bit string as text, e.g. `"010"` (empty for the empty id).
    pub fn to_bit_string(&self) -> String {
        (0..self.length)
            .map(|i| {
                if (self.bits[i / 8] >> (7 - i % 8)) & 1 == 1 {
                    '1'
                } else {
                    '0'
                }
            })
            .collect()
    }

    /// The bit at `index` (MSB-first within each byte).
    pub fn get_bit(&self, index: usize) -> Result<u8, Error> {
        if index >= self.length {
            return Err(Error::OutOfRange("ShardId bit index out of bounds"));
        }
        Ok((self.bits[index / 8] >> (7 - (index % 8))) & 1)
    }

    /// Whether this shard id is a bit-prefix of `data`.
    pub fn is_prefix_of(&self, data: &[u8]) -> bool {
        let full_bytes = self.length / 8;
        let remaining_bits = self.length % 8;
        if data.len() < full_bytes {
            return false;
        }
        if self.bits[..full_bytes] != data[..full_bytes] {
            return false;
        }
        if remaining_bits > 0 {
            let Some(&db) = data.get(full_bytes) else {
                return false;
            };
            let mask = 0xffu8.wrapping_shl(8 - remaining_bits as u32);
            if (self.bits[full_bytes] & mask) != (db & mask) {
                return false;
            }
        }
        true
    }

    /// Decode from the end-marker byte encoding.
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let mut last_byte = *data.last().ok_or(Error::UnexpectedValue("empty ShardId"))?;
        for i in (1..=8usize).rev() {
            if last_byte & 1 == 1 {
                if i == 1 {
                    return Ok(ShardId {
                        bits: data[..data.len() - 1].to_vec(),
                        length: (data.len() - 1) * 8,
                    });
                }
                let mut bits = data[..data.len() - 1].to_vec();
                bits.push((last_byte >> 1) << (8 - i + 1));
                return Ok(ShardId {
                    bits,
                    length: (data.len() - 1) * 8 + i - 1,
                });
            }
            last_byte >>= 1;
        }
        Err(Error::UnexpectedValue("ShardId missing end marker"))
    }

    /// Encode to the end-marker byte form.
    pub fn encode(&self) -> Vec<u8> {
        let byte_count = self.length / 8;
        let bit_count = self.length % 8;
        let mut result = alloc::vec![0u8; byte_count + 1];
        result[..byte_count].copy_from_slice(&self.bits[..byte_count]);
        if bit_count == 0 {
            result[byte_count] = 0b1000_0000;
        } else {
            let v = self.bits[byte_count] & !(0xffu8 >> bit_count);
            result[byte_count] = v | (1 << (7 - bit_count));
        }
        result
    }
}

impl core::fmt::Debug for ShardId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "ShardId(len={}, {})",
            self.length,
            hex::encode(&self.bits)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_shard_roundtrip() {
        let s = ShardId::decode(&[0x80]).unwrap();
        assert_eq!(s.length(), 0);
        assert_eq!(s.encode(), alloc::vec![0x80]);
    }
}
