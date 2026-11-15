// bloom.rs — a Bloom filter that scales with the number of entries.
//
// A Bloom filter answers "is this key DEFINITELY NOT in this SSTable?"
// with certainty, and "maybe yes" with a small chance of a false positive.
// That lets the read path skip SSTable files that cannot contain the key.
//
// V0.2 sizing (was: fixed 1 KiB, 3 hashes, in V0.1): the filter now
// targets 16 bits per key, with a minimum of 1 KiB (8192 bits), and
// still uses 3 hash functions. At 16 bits/key and 3 hashes the
// theoretical false-positive rate stays near 0.5% no matter how many
// keys the SSTable holds — a fixed 1 KiB filter, by contrast, degrades
// badly once a table holds thousands of keys (at 5000 keys its rate is
// roughly 60%, i.e. it barely filters at all). False negatives are
// still impossible: every added key sets all its bits, and `may_contain`
// only returns false when at least one of those bits is clear.
// The size is stored implicitly in the hex string (see `to_hex` /
// `from_hex`), so old V0.1 SSTables (1 KiB filters) still open fine.

/// Bits per key for a newly built filter.
const BITS_PER_KEY: usize = 16;
/// Minimum filter size, in bits (1 KiB) — small tables keep the V0.1 size.
const MIN_BITS: usize = 8192;
const NUM_HASHES: usize = 3;

/// A Bloom filter over string keys, with a size chosen at build time.
#[derive(Debug, Clone)]
pub struct BloomFilter {
    bits: Vec<u8>,
}

impl Default for BloomFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl BloomFilter {
    /// An empty filter at the minimum size.
    pub fn new() -> Self {
        Self {
            bits: vec![0; MIN_BITS / 8],
        }
    }

    /// Build a filter sized for `expected_keys` entries.
    /// Size = max(1 KiB, expected_keys * 16 bits), rounded up to a
    /// whole number of bytes.
    pub fn with_capacity(expected_keys: usize) -> Self {
        let wanted = expected_keys.saturating_mul(BITS_PER_KEY).max(MIN_BITS);
        // Round up to a multiple of 8 bits (one byte).
        let bits = wanted.div_ceil(8) * 8;
        Self {
            bits: vec![0; bits / 8],
        }
    }

    /// Build a filter from a list of keys, sized for that many keys.
    pub fn from_keys(keys: &[String]) -> Self {
        let mut filter = Self::with_capacity(keys.len());
        for key in keys {
            filter.add(key);
        }
        filter
    }

    /// Number of bits in this filter.
    pub fn num_bits(&self) -> usize {
        self.bits.len() * 8
    }

    fn num_bits_u64(&self) -> u64 {
        self.num_bits() as u64
    }

    pub fn add(&mut self, key: &str) {
        let n = self.num_bits_u64();
        for i in 0..NUM_HASHES {
            let bit = hash(key, i as u64) % n;
            self.bits[(bit / 8) as usize] |= 1 << (bit % 8);
        }
    }

    /// Returns false only when the key is DEFINITELY absent.
    /// Returns true when the key MIGHT be present.
    pub fn may_contain(&self, key: &str) -> bool {
        let n = self.num_bits_u64();
        for i in 0..NUM_HASHES {
            let bit = hash(key, i as u64) % n;
            if self.bits[(bit / 8) as usize] & (1 << (bit % 8)) == 0 {
                return false;
            }
        }
        true
    }

    /// Serialise the bitset as a hex string (for storing next to an SSTable).
    /// The length encodes the size, so `from_hex` accepts any size.
    pub fn to_hex(&self) -> String {
        self.bits.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Deserialise from a hex string produced by `to_hex`. Accepts any
    /// (even, non-empty) length, so both V0.1 fixed-size filters and
    /// V0.2 scaled filters load. Returns `None` on bad hex.
    pub fn from_hex(hex: &str) -> Option<Self> {
        if hex.is_empty() || !hex.len().is_multiple_of(2) {
            return None;
        }
        let mut bits = Vec::with_capacity(hex.len() / 2);
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

    #[test]
    fn small_filter_stays_at_minimum_size() {
        let filter = BloomFilter::from_keys(&["only".to_string()]);
        assert_eq!(filter.num_bits(), 8192, "small tables keep the 1 KiB floor");
    }

    #[test]
    fn large_filter_grows_with_entry_count() {
        let keys: Vec<String> = (0..5000).map(|i| format!("key-{i}")).collect();
        let filter = BloomFilter::from_keys(&keys);
        // 5000 keys * 16 bits/key = 80_000 bits, far above the 1 KiB floor.
        assert!(
            filter.num_bits() >= 80_000,
            "filter did not scale: {} bits for 5000 keys",
            filter.num_bits()
        );
        // No false negatives at scale either.
        for key in &keys {
            assert!(filter.may_contain(key), "false negative for {key}");
        }
    }

    #[test]
    fn large_filter_stays_accurate_where_fixed_filter_fails() {
        // A fixed 1 KiB filter holding 5000 keys has a false-positive
        // rate near 60% (it barely filters). The scaled filter must
        // stay near its ~0.5% design rate: under 2% here.
        let keys: Vec<String> = (0..5000).map(|i| format!("key-{i}")).collect();
        let filter = BloomFilter::from_keys(&keys);
        let false_positives = (100_000..102_000)
            .filter(|i| filter.may_contain(&format!("key-{i}")))
            .count();
        assert!(
            false_positives < 40, // < 2% of 2000 absent keys
            "scaled filter too weak: {false_positives}/2000 false positives"
        );
        // And the hex round-trip keeps the scaled size and the accuracy.
        let back = BloomFilter::from_hex(&filter.to_hex()).expect("valid hex");
        assert_eq!(back.num_bits(), filter.num_bits());
        for key in &keys {
            assert!(back.may_contain(key), "false negative after round-trip");
        }
    }

    #[test]
    fn old_fixed_size_hex_still_loads() {
        // A V0.1 filter was exactly 1 KiB (2048 hex chars).
        let old = BloomFilter::from_keys(&["a".to_string()]);
        assert_eq!(old.to_hex().len(), 2048);
        let back = BloomFilter::from_hex(&old.to_hex()).expect("V0.1 hex must load");
        assert_eq!(back.num_bits(), 8192);
        assert!(back.may_contain("a"));
    }
}
