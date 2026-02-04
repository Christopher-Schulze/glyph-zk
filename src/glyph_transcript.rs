//! GLYPH-PROVER Transcript: Keccak256-based Fiat-Shamir transcript.
//!
//! Implements deterministic transcript for GLYPH-PROVER per Prover-Blueprint.md Section 3.
//! All challenges are derived via domain-separated Keccak256 hashing.

#![allow(clippy::needless_range_loop)]

use tiny_keccak::{Hasher, Keccak};
use crate::glyph_field_simd::{
    Goldilocks,
    GOLDILOCKS_MODULUS,
    prefetch_read,
    ensure_two_thread_pool,
    cuda_keccak256_batch_64,
};
use rayon::prelude::*;

const TRANSCRIPT_INIT_LABEL: &[u8] = b"GLYPH_TRANSCRIPT";

// ============================================================
//                    DOMAIN SEPARATION TAGS (Blueprint 3.1)
// ============================================================

/// Domain tag for UCIR absorption
pub const DOMAIN_UCIR: &[u8] = b"UCIR";

/// Domain tag for lookup absorption
pub const DOMAIN_LOOKUP: &[u8] = b"LOOKUP";

/// Domain tag for sumcheck absorption
pub const DOMAIN_SUMCHECK: &[u8] = b"SUMCHECK";
pub const DOMAIN_SUMCHECK_MIX: &[u8] = b"SUMCHECK_MIX";

/// Domain tag for PCS absorption
pub const DOMAIN_PCS: &[u8] = b"PCS";
/// Domain tag for BaseFold PCS commitments
pub const DOMAIN_PCS_BASEFOLD_COMMIT: &[u8] = b"PCS_BASEFOLD_COMMIT";
/// Domain tag for BaseFold PCS openings
pub const DOMAIN_PCS_BASEFOLD_OPEN: &[u8] = b"PCS_BASEFOLD_OPEN";
/// Domain tag for ring-switch binding
pub const DOMAIN_PCS_RING_SWITCH: &[u8] = b"PCS_RING_SWITCH";
/// Domain tag for BaseFold ZK masks
pub const DOMAIN_PCS_ZK_MASK: &[u8] = b"PCS_ZK_MASK";

/// Domain tag for artifact derivation
pub const DOMAIN_ARTIFACT: &[u8] = b"ARTIFACT";

// ============================================================
//                    KECCAK256 HELPER
// ============================================================

/// Compute Keccak256 hash using tiny_keccak
fn keccak256_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(data);
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    output
}

/// Compute Keccak256 hash of multiple slices
fn keccak256_multi(slices: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    for slice in slices {
        hasher.update(slice);
    }
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    output
}

// ============================================================
//                    TRANSCRIPT STRUCTURE
// ============================================================

/// Keccak256-based transcript for Fiat-Shamir transform.
/// 
/// Per Blueprint Section 3:
/// - Domain separation via tags
/// - Absorb format: tag || length (u64 LE) || data
/// - Challenges via Keccak256 with rejection sampling
#[derive(Clone, Debug)]
pub struct Transcript {
    /// Current state (32-byte hash seed)
    state: [u8; 32],
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new()
    }
}

impl Transcript {
    /// Create a new transcript with zero initial state
    pub fn new() -> Self {
        Self {
            state: keccak256_hash(TRANSCRIPT_INIT_LABEL),
        }
    }

    /// Create a transcript with a custom label/seed
    pub fn with_label(label: &[u8]) -> Self {
        let mut t = Self::new();
        t.absorb_raw(label);
        t
    }

    /// Raw absorb without domain tag (internal use)
    fn absorb_raw(&mut self, data: &[u8]) {
        self.state = keccak256_multi(&[&self.state, data]);
    }

    /// Absorb data with domain tag per Blueprint Section 3.2
    /// Format: tag || length (u64 LE) || data
    pub fn absorb(&mut self, domain: &[u8], data: &[u8]) {
        let len_bytes = (data.len() as u64).to_le_bytes();
        self.state = keccak256_multi(&[&self.state, domain, &len_bytes, data]);
    }

    /// Absorb a single Goldilocks element
    pub fn absorb_goldilocks(&mut self, domain: &[u8], val: Goldilocks) {
        self.absorb(domain, &val.0.to_le_bytes());
    }

    /// Absorb a vector of Goldilocks elements
    pub fn absorb_goldilocks_vec(&mut self, domain: &[u8], vals: &[Goldilocks]) {
        let len_bytes = ((vals.len() as u64).saturating_mul(8)).to_le_bytes();
        let mut hasher = Keccak::v256();
        hasher.update(&self.state);
        hasher.update(domain);
        hasher.update(&len_bytes);
        for v in vals {
            hasher.update(&v.0.to_le_bytes());
        }
        hasher.finalize(&mut self.state);
    }

    /// Absorb one sumcheck round with XOR compression.
    pub fn absorb_sumcheck_round(
        &mut self,
        c0: Goldilocks,
        c1: Goldilocks,
        c2: Goldilocks,
        c3: Goldilocks,
    ) {
        let compressed = Goldilocks(c0.0 ^ c1.0 ^ c2.0 ^ c3.0);
        self.absorb_goldilocks(DOMAIN_SUMCHECK, compressed);
    }

    /// Absorb a 32-byte hash/commitment
    pub fn absorb_bytes32(&mut self, domain: &[u8], bytes: &[u8; 32]) {
        self.absorb(domain, bytes);
    }

    /// Derive a Goldilocks field challenge per Blueprint Section 3.3
    ///
    /// Optimized: XOR-fold 256-bit hash into 64 bits for lower rejection rate
    /// Then rejection sample if >= p (rate: ~2^-32 instead of ~50%)
    pub fn challenge_goldilocks(&mut self) -> Goldilocks {
        let mut counter: u64 = 0;
        loop {
            let counter_bytes = counter.to_le_bytes();
            let hash = if counter == 0 {
                keccak256_hash(&self.state)
            } else {
                keccak256_multi(&[&self.state, &counter_bytes])
            };

            let mut b0 = [0u8; 8];
            b0.copy_from_slice(&hash[0..8]);
            let candidate = u64::from_le_bytes(b0);

            if candidate < GOLDILOCKS_MODULUS {
                self.state = hash;
                return Goldilocks(candidate);
            }

            counter = counter.wrapping_add(1);
        }
    }

    /// Derive multiple Goldilocks challenges
    pub fn challenge_goldilocks_n(&mut self, n: usize) -> Vec<Goldilocks> {
        (0..n).map(|_| self.challenge_goldilocks()).collect()
    }

    /// Derive a bounded usize challenge
    pub fn challenge_usize(&mut self, bound: usize) -> usize {
        if bound <= 1 {
            return 0;
        }

        let bound_u128 = bound as u128;
        let limit = u128::MAX - (u128::MAX % bound_u128);

        let mut counter: u64 = 0;
        loop {
            let counter_bytes = counter.to_le_bytes();
            let hash = if counter == 0 {
                keccak256_hash(&self.state)
            } else {
                keccak256_multi(&[&self.state, &counter_bytes])
            };

            let mut b0 = [0u8; 16];
            b0.copy_from_slice(&hash[0..16]);
            let candidate = u128::from_le_bytes(b0);

            if candidate < limit {
                self.state = hash;
                return (candidate % bound_u128) as usize;
            }

            counter = counter.wrapping_add(1);
        }
    }

    /// Derive a 256-bit challenge as raw bytes
    pub fn challenge_bytes32(&mut self) -> [u8; 32] {
        self.state = keccak256_hash(&self.state);
        self.state
    }

    /// Get current state hash (for debugging/verification)
    pub fn state(&self) -> [u8; 32] {
        self.state
    }

    /// Fork the transcript (create independent copy)
    pub fn fork(&self) -> Self {
        self.clone()
    }
}

// ============================================================
//                    PUBLIC HELPER FUNCTIONS
// ============================================================

/// Compute Keccak256 hash of arbitrary data
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    keccak256_hash(data)
}

/// Compute Keccak256 hashes in parallel for a batch of slices
pub fn keccak256_batch(inputs: &[Vec<u8>]) -> Vec<[u8; 32]> {
    if !inputs.is_empty() && inputs.iter().all(|data| data.len() == 64) {
        let mut fixed = Vec::with_capacity(inputs.len());
        for data in inputs {
            let mut block = [0u8; 64];
            block.copy_from_slice(data);
            fixed.push(block);
        }
        if let Some(out) = cuda_keccak256_batch_64(&fixed) {
            return out;
        }
    }
    if inputs.len() < 128 {
        return inputs.iter().map(|data| keccak256_hash(data)).collect();
    }

    ensure_two_thread_pool();
    inputs.par_iter().map(|data| keccak256_hash(data)).collect()
}

/// Parallel Keccak256 hashing for fixed-size 64-byte inputs (AVX-friendly layout)
pub fn keccak256_batch_64(inputs: &[[u8; 64]]) -> Vec<[u8; 32]> {
    if let Some(out) = cuda_keccak256_batch_64(inputs) {
        return out;
    }
    if inputs.len() >= 1024 {
        ensure_two_thread_pool();
        return inputs
            .par_iter()
            .map(|data| keccak256_hash(data))
            .collect();
    }

    let use_x4 = std::env::var("GLYPH_KECCAK_X4")
        .ok()
        .as_deref()
        .map(|v| v != "0")
        .unwrap_or(true);

    let mut out = Vec::with_capacity(inputs.len());
    if use_x4 {
        let mut i = 0usize;
        while i + 4 <= inputs.len() {
            let mut block = [[0u8; 64]; 4];
            block[0].copy_from_slice(&inputs[i]);
            block[1].copy_from_slice(&inputs[i + 1]);
            block[2].copy_from_slice(&inputs[i + 2]);
            block[3].copy_from_slice(&inputs[i + 3]);
            let hashes = keccak256_64_x4(&block);
            out.push(hashes[0]);
            out.push(hashes[1]);
            out.push(hashes[2]);
            out.push(hashes[3]);
            i += 4;
        }
        for j in i..inputs.len() {
            out.push(keccak256_hash(&inputs[j]));
        }
        return out;
    }

    let prefetch_dist = 4usize;
    for i in 0..inputs.len() {
        if i + prefetch_dist < inputs.len() {
            let ptr = inputs[i + prefetch_dist].as_ptr();
            prefetch_read(ptr);
        }
        out.push(keccak256_hash(&inputs[i]));
    }
    out
}

const KECCAKF_ROUNDS: usize = 24;
const KECCAKF_RNDC: [u64; KECCAKF_ROUNDS] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];
const KECCAKF_ROTC: [u32; KECCAKF_ROUNDS] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];
const KECCAKF_PILN: [usize; KECCAKF_ROUNDS] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

#[inline(always)]
fn rotl4(v: [u64; 4], r: u32) -> [u64; 4] {
    if r == 0 {
        return v;
    }
    let r = r as u64;
    [
        (v[0] << r) | (v[0] >> (64 - r)),
        (v[1] << r) | (v[1] >> (64 - r)),
        (v[2] << r) | (v[2] >> (64 - r)),
        (v[3] << r) | (v[3] >> (64 - r)),
    ]
}

#[inline(always)]
fn xor4(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]]
}

#[inline(always)]
fn and4(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    [a[0] & b[0], a[1] & b[1], a[2] & b[2], a[3] & b[3]]
}

#[inline(always)]
fn not4(a: [u64; 4]) -> [u64; 4] {
    [!a[0], !a[1], !a[2], !a[3]]
}

fn keccakf_x4(state: &mut [[u64; 4]; 25]) {
    let mut bc = [[0u64; 4]; 5];
    for round in 0..KECCAKF_ROUNDS {
        for i in 0..5 {
            bc[i] = xor4(
                xor4(state[i], state[i + 5]),
                xor4(state[i + 10], xor4(state[i + 15], state[i + 20])),
            );
        }
        for i in 0..5 {
            let t = xor4(bc[(i + 4) % 5], rotl4(bc[(i + 1) % 5], 1));
            for j in (0..25).step_by(5) {
                state[j + i] = xor4(state[j + i], t);
            }
        }

        let mut t = state[1];
        for i in 0..KECCAKF_ROUNDS {
            let j = KECCAKF_PILN[i];
            let tmp = state[j];
            state[j] = rotl4(t, KECCAKF_ROTC[i]);
            t = tmp;
        }

        for j in (0..25).step_by(5) {
            let b0 = state[j];
            let b1 = state[j + 1];
            let b2 = state[j + 2];
            let b3 = state[j + 3];
            let b4 = state[j + 4];
            state[j] = xor4(b0, and4(not4(b1), b2));
            state[j + 1] = xor4(b1, and4(not4(b2), b3));
            state[j + 2] = xor4(b2, and4(not4(b3), b4));
            state[j + 3] = xor4(b3, and4(not4(b4), b0));
            state[j + 4] = xor4(b4, and4(not4(b0), b1));
        }

        let rc = KECCAKF_RNDC[round];
        state[0][0] ^= rc;
        state[0][1] ^= rc;
        state[0][2] ^= rc;
        state[0][3] ^= rc;
    }
}

fn keccak256_64_x4(inputs: &[[u8; 64]; 4]) -> [[u8; 32]; 4] {
    let mut state = [[0u64; 4]; 25];
    for lane in 0..4 {
        for i in 0..8 {
            let start = i * 8;
            let mut word_bytes = [0u8; 8];
            word_bytes.copy_from_slice(&inputs[lane][start..start + 8]);
            let word = u64::from_le_bytes(word_bytes);
            state[i][lane] ^= word;
        }
        state[8][lane] ^= 0x01;
        state[16][lane] ^= 0x80u64 << 56;
    }

    keccakf_x4(&mut state);

    let mut out = [[0u8; 32]; 4];
    for lane in 0..4 {
        for i in 0..4 {
            out[lane][i * 8..(i + 1) * 8].copy_from_slice(&state[i][lane].to_le_bytes());
        }
    }
    out
}

/// Compute domain-separated Keccak256 hash
pub fn keccak256_domain(domain: &[u8], data: &[u8]) -> [u8; 32] {
    let len_bytes = (data.len() as u64).to_le_bytes();
    keccak256_multi(&[domain, &len_bytes, data])
}

// ============================================================
//                    TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transcript_determinism() {
        // Same inputs must produce same outputs
        let mut t1 = Transcript::new();
        let mut t2 = Transcript::new();

        t1.absorb(DOMAIN_UCIR, b"test data");
        t2.absorb(DOMAIN_UCIR, b"test data");

        let c1 = t1.challenge_goldilocks();
        let c2 = t2.challenge_goldilocks();

        assert_eq!(c1, c2, "Transcript must be deterministic");
        println!("Transcript determinism test passed.");
    }

    #[test]
    fn test_transcript_domain_separation() {
        // Different domains must produce different outputs
        let mut t1 = Transcript::new();
        let mut t2 = Transcript::new();

        t1.absorb(DOMAIN_UCIR, b"same data");
        t2.absorb(DOMAIN_SUMCHECK, b"same data");

        let c1 = t1.challenge_goldilocks();
        let c2 = t2.challenge_goldilocks();

        assert_ne!(c1, c2, "Different domains must yield different challenges");
        println!("Transcript domain separation test passed.");
    }

    #[test]
    fn test_keccak256_x4_matches_scalar() {
        let mut inputs = [[0u8; 64]; 4];
        for lane in 0..4 {
            for i in 0..64 {
                inputs[lane][i] = (lane as u8).wrapping_mul(31).wrapping_add(i as u8);
            }
        }

        let expected = [
            keccak256_hash(&inputs[0]),
            keccak256_hash(&inputs[1]),
            keccak256_hash(&inputs[2]),
            keccak256_hash(&inputs[3]),
        ];
        let got = keccak256_64_x4(&inputs);

        assert_eq!(got, expected, "x4 keccak must match scalar");
        println!("Keccak x4 test passed.");
    }

    #[test]
    fn test_challenge_canonical() {
        let mut t = Transcript::new();
        t.absorb(DOMAIN_PCS, b"some commitment");

        for _ in 0..100 {
            let c = t.challenge_goldilocks();
            assert!(c.0 < GOLDILOCKS_MODULUS, "Challenge must be canonical");
        }
        println!("Transcript challenge canonical test passed.");
    }

    #[test]
    fn test_transcript_ordering() {
        // Absorb order must matter
        let mut t1 = Transcript::new();
        let mut t2 = Transcript::new();

        t1.absorb(DOMAIN_UCIR, b"A");
        t1.absorb(DOMAIN_UCIR, b"B");

        t2.absorb(DOMAIN_UCIR, b"B");
        t2.absorb(DOMAIN_UCIR, b"A");

        let c1 = t1.challenge_goldilocks();
        let c2 = t2.challenge_goldilocks();

        assert_ne!(c1, c2, "Absorb order must affect output");
        println!("Transcript ordering test passed.");
    }

    #[test]
    fn test_transcript_fork() {
        let mut t = Transcript::new();
        t.absorb(DOMAIN_SUMCHECK, b"round 1");

        let mut fork1 = t.fork();
        let mut fork2 = t.fork();

        fork1.absorb(DOMAIN_SUMCHECK, b"branch A");
        fork2.absorb(DOMAIN_SUMCHECK, b"branch B");

        let c1 = fork1.challenge_goldilocks();
        let c2 = fork2.challenge_goldilocks();

        assert_ne!(c1, c2, "Forked transcripts must diverge");
        println!("Transcript fork test passed.");
    }

    #[test]
    fn test_transcript_is_domain_initialized() {
        let t = Transcript::new();
        assert_eq!(t.state(), keccak256_hash(TRANSCRIPT_INIT_LABEL));
    }

    #[test]
    fn test_challenge_usize_within_bound_and_deterministic() {
        let mut t1 = Transcript::new();
        t1.absorb(DOMAIN_LOOKUP, b"seed");
        let mut t2 = t1.fork();

        for bound in [2usize, 3, 7, 64, 1024, 1 << 20] {
            let a = t1.challenge_usize(bound);
            let b = t2.challenge_usize(bound);
            assert!(a < bound);
            assert_eq!(a, b);
        }
    }

    #[test]
    fn test_keccak256_helper() {
        let hash = keccak256(b"hello");
        assert_eq!(hash.len(), 32);

        // Verify against known Keccak256 value for "hello"
        // Note: This is the actual Keccak256 output, not SHA3-256
        let expected_hex = "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8";
        let expected: Vec<u8> = (0..32)
            .map(|i| {
                match u8::from_str_radix(&expected_hex[i * 2..i * 2 + 2], 16) {
                    Ok(value) => value,
                    Err(_) => {
                        assert!(false, "valid keccak hex");
                        0u8
                    }
                }
            })
            .collect();
        assert_eq!(&hash[..], &expected[..], "Keccak256 hash mismatch");
        println!("Keccak256 helper test passed.");
    }
}
