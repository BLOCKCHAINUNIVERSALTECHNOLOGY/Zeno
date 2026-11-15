// bloom.rs — a small Bloom filter.
//
// A Bloom filter answers "is this key DEFINITELY NOT in this SSTable?"
// with certainty, and "maybe yes" with a small chance of a false positive.
// That lets the read path skip SSTable files that cannot contain the key.
//
// Honest note: this is a small, teaching-grade Bloom filter (fixed size,
// 3 hash functions, no tuning for a target false-positive rate). It is NOT
// a production Bloom filter. It is good enough to demonstrate the idea.

const FILTER_BITS: usize = 8192; // 1 KiB of bits
const NUM_HASHES: usize = 3;

/// A tiny Bloom filter over string keys.
#[derive(Debug, Clone)]
pub struct BloomFilter {
    bits: Vec<u8>, // FILTER_BITS bits, packed
}

impl Default for BloomFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl BloomFilter {
    pub fn new() -> Self {
        Self {
            bits: vec![0; FILTER_BITS / 8],
        }
    }

    /// Build a filter from a list of keys.
    pub fn from_keys(keys: &[String]) -> Self {
        let mut filter = Self::new();
        for key in keys {
            filter.add(key);
        }
        filter
    }

    pub fn add(&mut self, key: &str) {
        for i in 0..NUM_HASHES {
            let bit = hash(key, i as u64) % (FILTER_BITS as u64);
            self.bits[(bit / 8) as usize] |= 1 << (bit % 8);
        }
    }

    /// Returns false only when the key is DEFINITELY absent.
    /// Returns true when the key MIGHT be present.
    pub fn may_contain(&self, key: &str) -> bool {
        for i in 0..NUM_HASHES {
            let bit = hash(key, i as u64) % (FILTER_BITS as u64);
            if self.bits[(bit / 8) as usize] & (1 << (bit % 8)) == 0 {
                return false;
            }
        }
        true
    }

    /// Serialise the bitset as a hex string (for storing next to an SSTable).
    pub fn to_hex(&self) -> String {
        self.bits.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Deserialise from a hex string produced by `to_hex`.
    pub fn from_hex(hex: &str) -> Option<Self> {
        if hex.len() != FILTER_BITS / 4 {
            return None;
        }
        let mut bits = Vec::with_capacity(FILTER_BITS / 8);
        let bytes = hex.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let hi = hex_val(bytes[i])?;
            let lo = hex_val(bytes[i + 1])?;
            bits.push((hi << 4) | lo);
            i += 2;
        }
        Some(Self { bits })
    }
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// FNV-1a hash with a per-function seed. Not cryptographic — only used to
/// spread keys across the filter's bits.
fn hash(key: &str, seed: u64) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325 ^ seed.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    for b in key.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_finds_added_keys() {
        let filter = BloomFilter::from_keys(&["a".to_string(), "b".to_string()]);
        assert!(filter.may_contain("a"));
        assert!(filter.may_contain("b"));
    }

    #[test]
    fn filter_never_has_false_negatives() {
        // 500 keys in, all 500 must report "maybe present".
        let keys: Vec<String> = (0..500).map(|i| format!("key-{i}")).collect();
        let filter = BloomFilter::from_keys(&keys);
        for key in &keys {
            assert!(filter.may_contain(key), "false negative for {key}");
        }
    }

    #[test]
    fn filter_skips_most_absent_keys() {
        let keys: Vec<String> = (0..100).map(|i| format!("key-{i}")).collect();
        let filter = BloomFilter::from_keys(&keys);
        // Most keys that were never added should be reported absent.
        let absent = (1000..1100)
            .filter(|i| !filter.may_contain(&format!("key-{i}")))
            .count();
        assert!(
            absent > 80,
            "filter barely filters: only {absent}/100 skipped"
        );
    }

    #[test]
    fn hex_round_trip() {
        let filter = BloomFilter::from_keys(&["x".to_string(), "y".to_string()]);
        let hex = filter.to_hex();
        let back = BloomFilter::from_hex(&hex).expect("valid hex");
        assert!(back.may_contain("x"));
        assert!(!back.may_contain("definitely-not-there-zzzz"));
    }
}
