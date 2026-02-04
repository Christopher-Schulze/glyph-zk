//! BN254 to Goldilocks Embedding and helpers.
//!
//! Provides deterministic conversion utilities and BN254 modular arithmetic
//! for use in adapter compilation and binding.

use crate::glyph_field_simd::Goldilocks;
use crate::bn254_field::{bn254_add_mod, bn254_sub_mod, bn254_mul_mod};
use crate::bn254_field::is_canonical_limbs;

// ============================================================
//                    CONSTANTS
// ============================================================

/// BN254 Fq modulus (254 bits)
/// q = 21888242871839275222246405745257275088696311157297823662689037894645226208583
pub const BN254_MODULUS_LIMBS: [u64; 4] = [
    0x3C208C16D87CFD47,
    0x97816A916871CA8D,
    0xB85045B68181585D,
    0x30644E72E131A029,
];

/// Number of Goldilocks limbs per Fq element
pub const LIMBS_PER_FQ: usize = 4;

/// Number of 16-bit chunks per limb
pub const CHUNKS_PER_LIMB: usize = 4;

// ============================================================
//                    FQ EMBEDDING (Blueprint 5.1)
// ============================================================

/// Embedded Fq element as 4 Goldilocks limbs (little-endian u64 limbs)
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EmbeddedFq {
    pub limbs: [Goldilocks; 4],
}

impl EmbeddedFq {
    /// Create from raw bytes (32 bytes, little-endian)
    pub fn from_bytes(data: &[u8; 32]) -> Self {
        let mut limbs = [Goldilocks::ZERO; 4];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let start = i * 8;
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&data[start..start + 8]);
            *limb = Goldilocks(u64::from_le_bytes(bytes));
        }
        Self { limbs }
    }

    /// Convert to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, limb) in self.limbs.iter().enumerate() {
            out[i * 8..(i + 1) * 8].copy_from_slice(&limb.0.to_le_bytes());
        }
        out
    }

    /// Convert to raw BN254 limbs
    pub fn to_limbs_u64(&self) -> [u64; 4] {
        [
            self.limbs[0].0,
            self.limbs[1].0,
            self.limbs[2].0,
            self.limbs[3].0,
        ]
    }

    pub fn is_canonical(&self) -> bool {
        is_canonical_limbs(self.to_limbs_u64())
    }

    /// Add two Fq elements modulo BN254
    pub fn add_mod(&self, other: &Self) -> Option<Self> {
        if !self.is_canonical() || !other.is_canonical() {
            return None;
        }
        let out = bn254_add_mod(self.to_limbs_u64(), other.to_limbs_u64())?;
        Some(Self::from_limbs_u64(out))
    }

    /// Subtract two Fq elements modulo BN254
    pub fn sub_mod(&self, other: &Self) -> Option<Self> {
        if !self.is_canonical() || !other.is_canonical() {
            return None;
        }
        let out = bn254_sub_mod(self.to_limbs_u64(), other.to_limbs_u64())?;
        Some(Self::from_limbs_u64(out))
    }

    /// Multiply two Fq elements modulo BN254
    pub fn mul_mod(&self, other: &Self) -> Option<Self> {
        if !self.is_canonical() || !other.is_canonical() {
            return None;
        }
        let out = bn254_mul_mod(self.to_limbs_u64(), other.to_limbs_u64())?;
        Some(Self::from_limbs_u64(out))
    }

    /// Create from raw BN254 limbs
    pub fn from_limbs_u64(limbs: [u64; 4]) -> Self {
        Self {
            limbs: [
                Goldilocks(limbs[0]),
                Goldilocks(limbs[1]),
                Goldilocks(limbs[2]),
                Goldilocks(limbs[3]),
            ],
        }
    }
}

// ============================================================
//                    TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_embedded_fq_roundtrip() {
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        bytes[8] = 2;
        bytes[16] = 3;
        bytes[24] = 4;

        let fq = EmbeddedFq::from_bytes(&bytes);
        assert_eq!(fq.limbs[0].0, 1);
        assert_eq!(fq.limbs[1].0, 2);
        assert_eq!(fq.limbs[2].0, 3);
        assert_eq!(fq.limbs[3].0, 4);

        let recovered = fq.to_bytes();
        assert_eq!(bytes, recovered);

        println!("Embedded Fq roundtrip test passed.");
    }

    #[test]
    fn test_embedded_fq_add() {
        let a = EmbeddedFq {
            limbs: [Goldilocks(1), Goldilocks(2), Goldilocks(3), Goldilocks(4)],
        };
        let b = EmbeddedFq {
            limbs: [Goldilocks(10), Goldilocks(20), Goldilocks(30), Goldilocks(40)],
        };

        let c = match a.add_mod(&b) {
            Some(value) => value,
            None => {
                assert!(false, "add_mod");
                return;
            }
        };
        assert_eq!(c.limbs[0].0, 11);
        assert_eq!(c.limbs[1].0, 22);
        assert_eq!(c.limbs[2].0, 33);
        assert_eq!(c.limbs[3].0, 44);

        println!("Embedded Fq add test passed.");
    }

    #[test]
    fn test_embedded_fq_mul() {
        let a = EmbeddedFq {
            limbs: [Goldilocks(1), Goldilocks(0), Goldilocks(0), Goldilocks(0)],
        };
        let b = EmbeddedFq {
            limbs: [Goldilocks(5), Goldilocks(0), Goldilocks(0), Goldilocks(0)],
        };

        let c = match a.mul_mod(&b) {
            Some(value) => value,
            None => {
                assert!(false, "mul_mod");
                return;
            }
        };
        assert_eq!(c.limbs[0].0, 5);

        println!("Embedded Fq mul test passed.");
    }

    #[test]
    fn test_embedded_fq_rejects_non_canonical_inputs() {
        let a = EmbeddedFq::from_limbs_u64(BN254_MODULUS_LIMBS);
        let one = EmbeddedFq::from_limbs_u64([1u64, 0, 0, 0]);
        assert!(a.add_mod(&one).is_none());
        assert!(one.sub_mod(&a).is_none());
        assert!(a.mul_mod(&one).is_none());
    }

    #[test]
    fn test_embedded_fq_outputs_are_canonical() {
        let mut state = 0x1337_4242_dead_beefu64;
        for _ in 0..128 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let a_limbs = [
                state,
                state.rotate_left(17),
                state.rotate_left(33),
                state.rotate_left(49),
            ];
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let b_limbs = [
                state,
                state.rotate_left(9),
                state.rotate_left(27),
                state.rotate_left(45),
            ];
            if !is_canonical_limbs(a_limbs) || !is_canonical_limbs(b_limbs) {
                continue;
            }
            let a = EmbeddedFq::from_limbs_u64(a_limbs);
            let b = EmbeddedFq::from_limbs_u64(b_limbs);
            let add = match a.add_mod(&b) {
                Some(value) => value,
                None => {
                    assert!(false, "add_mod");
                    return;
                }
            };
            let mul = match a.mul_mod(&b) {
                Some(value) => value,
                None => {
                    assert!(false, "mul_mod");
                    return;
                }
            };
            assert!(add.is_canonical());
            assert!(mul.is_canonical());
        }
    }
}
