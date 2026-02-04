//! Shared PCS constants and helpers for the BaseFold PCS path.

use crate::glyph_field_simd::Goldilocks;
use crate::glyph_transcript::keccak256;
use rand::{rngs::OsRng, RngCore};
use tiny_keccak::{Hasher, Keccak};

/// PCS commitment domain.
pub const PCS_COMMIT_DOMAIN: &[u8] = b"GLYPH_PCS_COMMIT";

/// PCS point tag domain.
pub const PCS_POINT_TAG_DOMAIN: &[u8] = b"GLYPH_PCS_POINT_TAG";

/// PCS salt domain (ZK mode).
pub const PCS_SALT_DOMAIN: &[u8] = b"GLYPH_PCS_SALT";

/// ZK PCS configuration.
#[derive(Clone, Debug)]
pub struct ZkPcsConfig {
    /// 256-bit salt for hiding.
    pub salt: [u8; 32],
    /// Salt commitment hash.
    pub salt_commitment: [u8; 32],
}

impl ZkPcsConfig {
    /// Create ZK config with random salt.
    pub fn new_random() -> Self {
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        let salt_commitment = pcs_salt_commitment(&salt);
        Self {
            salt,
            salt_commitment,
        }
    }

    /// Create deterministic ZK config for testing.
    pub fn deterministic(seed: u8) -> Self {
        let mut salt = [0u8; 32];
        salt[0] = seed;
        let salt_commitment = pcs_salt_commitment(&salt);
        Self { salt, salt_commitment }
    }

    /// Create deterministic ZK config from full 32-byte seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let salt_commitment = pcs_salt_commitment(&seed);
        Self { salt: seed, salt_commitment }
    }
}

/// Compute salt commitment.
pub fn pcs_salt_commitment(salt: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(PCS_SALT_DOMAIN);
    hasher.update(salt);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

/// Derive point tag for GLYPH artifact.
pub fn derive_point_tag(commitment_tag: &[u8; 32], eval_point: &[Goldilocks]) -> [u8; 32] {
    let mut input = Vec::new();
    input.extend_from_slice(PCS_POINT_TAG_DOMAIN);
    input.extend_from_slice(commitment_tag);
    for p in eval_point {
        // u128_be format: upper 64 bits zero, lower 64 bits are the value.
        input.extend_from_slice(&[0u8; 8]);
        input.extend_from_slice(&p.0.to_be_bytes());
    }
    keccak256(&input)
}
