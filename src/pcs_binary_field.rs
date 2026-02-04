
//! Binary tower field encoding helpers for PCS work.

use binius_field::{
    BinaryField128b,
    Field,
    PackedBinaryField1x128b,
    PackedField,
    underlier::WithUnderlier,
};
use binius_math::{Error as BiniusMathError, MultilinearExtension};
use crate::glyph_field_simd::Goldilocks;
use rayon::prelude::*;

fn basefold_par_min() -> usize {
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let default_min = (2048usize.saturating_mul(threads)).clamp(2048, 1 << 20);
    std::env::var("GLYPH_PCS_BASEFOLD_PAR_MIN")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(default_min)
        .max(1)
}

/// Map a Goldilocks element into a binary tower element using the canonical
/// 128-bit little-endian representation.
pub fn b128_from_goldilocks_le(value: Goldilocks) -> BinaryField128b {
    BinaryField128b::from_underlier(u128::from(u64::from_le_bytes(value.0.to_le_bytes())))
}

/// Convert a binary tower element into a Goldilocks value (lower 64 bits).
pub fn goldilocks_from_b128_le(value: BinaryField128b) -> Goldilocks {
    let bytes = value.to_underlier().to_le_bytes();
    let mut low = [0u8; 8];
    low.copy_from_slice(&bytes[..8]);
    Goldilocks(u64::from_le_bytes(low))
}

/// Encode a 16-byte little-endian value into a binary tower element.
pub fn b128_from_bytes_le(bytes: [u8; 16]) -> BinaryField128b {
    BinaryField128b::from_underlier(u128::from_le_bytes(bytes))
}

/// Decode a binary tower element into 16 little-endian bytes.
pub fn b128_to_bytes_le(value: BinaryField128b) -> [u8; 16] {
    value.to_underlier().to_le_bytes()
}

/// Convert a Goldilocks slice into binary tower elements using the canonical mapping.
pub fn b128_vec_from_goldilocks_le(values: &[Goldilocks]) -> Vec<BinaryField128b> {
    let mut out = Vec::with_capacity(values.len());
    b128_vec_from_goldilocks_le_into(values, &mut out);
    out
}

/// Convert Goldilocks values into binary tower elements reusing a caller-owned buffer.
pub fn b128_vec_from_goldilocks_le_into(
    values: &[Goldilocks],
    out: &mut Vec<BinaryField128b>,
) {
    out.clear();
    if values.len() >= basefold_par_min() {
        out.resize(values.len(), BinaryField128b::ZERO);
        out.par_iter_mut()
            .zip(values.par_iter())
            .for_each(|(dst, v)| {
                *dst = b128_from_goldilocks_le(*v);
            });
    } else {
        out.reserve(values.len());
        for v in values.iter().copied() {
            out.push(b128_from_goldilocks_le(v));
        }
    }
}

/// Pad binary field evaluations to the next power-of-two length.
pub fn pad_b128_to_pow2(values: &[BinaryField128b]) -> Result<Vec<BinaryField128b>, String> {
    if values.is_empty() {
        return Err("binary field evals must be non-empty".to_string());
    }
    let target_len = values.len().next_power_of_two();
    let mut out = vec![BinaryField128b::ZERO; target_len];
    out[..values.len()].copy_from_slice(values);
    Ok(out)
}

pub type BasefoldPackedBinaryField = PackedBinaryField1x128b;

/// Pack BinaryField128b scalars into width-1 packed field elements.
pub fn pack_b128_scalars(values: &[BinaryField128b]) -> Result<Vec<BasefoldPackedBinaryField>, String> {
    if values.is_empty() {
        return Err("binary field evals must be non-empty".to_string());
    }
    let width = BasefoldPackedBinaryField::WIDTH;
    if !values.len().is_multiple_of(width) {
        return Err("binary field evals length must be divisible by packed width".to_string());
    }
    let pack_chunk = |chunk: &[BinaryField128b]| BasefoldPackedBinaryField::from_scalars(chunk.iter().copied());
    if values.len() >= basefold_par_min() {
        Ok(values.par_chunks(width).map(pack_chunk).collect())
    } else {
        let mut out = Vec::with_capacity(values.len() / width);
        for chunk in values.chunks(width) {
            out.push(pack_chunk(chunk));
        }
        Ok(out)
    }
}

/// Build a multilinear extension from BinaryField128b evaluations.
pub fn b128_evals_to_multilinear(
    evals: &[BinaryField128b],
    n_vars: usize,
) -> Result<MultilinearExtension<BasefoldPackedBinaryField>, String> {
    if evals.is_empty() {
        return Err("binary field evals must be non-empty".to_string());
    }
    let expected = 1usize
        .checked_shl(n_vars as u32)
        .ok_or_else(|| "n_vars too large".to_string())?;
    if evals.len() != expected {
        return Err("binary field evals length does not match 2^n_vars".to_string());
    }
    let packed = pack_b128_scalars(evals)?;
    MultilinearExtension::new(n_vars, packed)
        .map_err(|err: BiniusMathError| err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use binius_field::PackedField;

    #[test]
    fn test_goldilocks_roundtrip_le() {
        let values = [
            Goldilocks::ZERO,
            Goldilocks::ONE,
            Goldilocks::new(0x1122_3344_5566_7788),
            Goldilocks::new(u64::MAX),
        ];
        for v in values {
            let b = b128_from_goldilocks_le(v);
            let back = goldilocks_from_b128_le(b);
            assert_eq!(back, v);
        }
    }

    #[test]
    fn test_b128_bytes_roundtrip_le() {
        let bytes = [
            0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        ];
        let b = b128_from_bytes_le(bytes);
        let back = b128_to_bytes_le(b);
        assert_eq!(back, bytes);
    }

    #[test]
    fn test_pad_b128_to_pow2() {
        let values = vec![BinaryField128b::ONE; 3];
        let padded = match pad_b128_to_pow2(&values) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "pad");
                return;
            }
        };
        assert_eq!(padded.len(), 4);
        assert_eq!(padded[0], BinaryField128b::ONE);
        assert_eq!(padded[3], BinaryField128b::ZERO);
    }

    #[test]
    fn test_pack_b128_scalars_roundtrip() {
        let values = vec![
            BinaryField128b::ZERO,
            BinaryField128b::ONE,
            BinaryField128b::from_underlier(42),
            BinaryField128b::from_underlier(7),
        ];
        let packed = match pack_b128_scalars(&values) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "pack");
                return;
            }
        };
        let width = BasefoldPackedBinaryField::WIDTH;
        assert_eq!(packed.len(), values.len() / width);
        for (chunk_idx, packed_val) in packed.iter().enumerate() {
            let base = chunk_idx * width;
            assert_eq!(packed_val.get(0), values[base]);
            if width > 1 {
                assert_eq!(packed_val.get(1), values[base + 1]);
            }
        }
    }

    #[test]
    fn test_b128_evals_to_multilinear_roundtrip_shape() {
        let evals = vec![
            BinaryField128b::ZERO,
            BinaryField128b::ONE,
            BinaryField128b::from_underlier(2),
            BinaryField128b::from_underlier(3),
        ];
        let mle = match b128_evals_to_multilinear(&evals, 2) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "mle");
                return;
            }
        };
        assert_eq!(mle.n_vars(), 2);
        assert_eq!(mle.size(), 4);
    }
}
