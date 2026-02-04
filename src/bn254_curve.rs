//! BN254 curve parsing helpers for adapter kernels.
//!
//! Provides strict, canonical parsing for G1 and G2 points using big-endian
//! encodings compatible with EVM precompile expectations.

use ark_bn254::{Fq, Fq2, G1Affine, G2Affine};
use crate::bn254_field::{be_bytes_from_limbs, fq_from_limbs, is_canonical_be, limbs_from_be_bytes, limbs_from_fq};

pub fn fq_from_be_bytes_strict(bytes: [u8; 32]) -> Option<Fq> {
    if !is_canonical_be(bytes) {
        return None;
    }
    fq_from_limbs(limbs_from_be_bytes(bytes))
}

pub fn fq_to_be_bytes(x: Fq) -> [u8; 32] {
    be_bytes_from_limbs(limbs_from_fq(x))
}

pub fn g1_from_be_bytes_strict(x_bytes: [u8; 32], y_bytes: [u8; 32]) -> Result<G1Affine, String> {
    let x = fq_from_be_bytes_strict(x_bytes).ok_or_else(|| "g1 x not canonical".to_string())?;
    let y = fq_from_be_bytes_strict(y_bytes).ok_or_else(|| "g1 y not canonical".to_string())?;
    let p = G1Affine::new_unchecked(x, y);
    if !p.is_on_curve() {
        return Err("g1 point not on curve".to_string());
    }
    if !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err("g1 point not in subgroup".to_string());
    }
    Ok(p)
}

/// G2 encoding uses the EVM precompile layout:
///   x_im || x_re || y_im || y_re (each 32 bytes, big-endian).
pub fn g2_from_be_bytes_strict(
    x_im: [u8; 32],
    x_re: [u8; 32],
    y_im: [u8; 32],
    y_re: [u8; 32],
) -> Result<G2Affine, String> {
    let x_c0 = fq_from_be_bytes_strict(x_re).ok_or_else(|| "g2 x_re not canonical".to_string())?;
    let x_c1 = fq_from_be_bytes_strict(x_im).ok_or_else(|| "g2 x_im not canonical".to_string())?;
    let y_c0 = fq_from_be_bytes_strict(y_re).ok_or_else(|| "g2 y_re not canonical".to_string())?;
    let y_c1 = fq_from_be_bytes_strict(y_im).ok_or_else(|| "g2 y_im not canonical".to_string())?;
    let x = Fq2::new(x_c0, x_c1);
    let y = Fq2::new(y_c0, y_c1);
    let p = G2Affine::new_unchecked(x, y);
    if !p.is_on_curve() {
        return Err("g2 point not on curve".to_string());
    }
    if !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err("g2 point not in subgroup".to_string());
    }
    Ok(p)
}

pub fn g1_to_be_bytes(p: &G1Affine) -> ([u8; 32], [u8; 32]) {
    (fq_to_be_bytes(p.x), fq_to_be_bytes(p.y))
}

pub fn g2_to_be_bytes(p: &G2Affine) -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
    let x = p.x;
    let y = p.y;
    let x_re = fq_to_be_bytes(x.c0);
    let x_im = fq_to_be_bytes(x.c1);
    let y_re = fq_to_be_bytes(y.c0);
    let y_im = fq_to_be_bytes(y.c1);
    (x_im, x_re, y_im, y_re)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::AffineRepr;

    #[test]
    fn test_g1_roundtrip_generator() {
        let g = G1Affine::generator();
        let (x, y) = g1_to_be_bytes(&g);
        let parsed = match g1_from_be_bytes_strict(x, y) {
            Ok(point) => point,
            Err(_) => {
                assert!(false, "g1 parse");
                return;
            }
        };
        assert_eq!(g, parsed);
    }

    #[test]
    fn test_g2_roundtrip_generator() {
        let g = G2Affine::generator();
        let (x_im, x_re, y_im, y_re) = g2_to_be_bytes(&g);
        let parsed = match g2_from_be_bytes_strict(x_im, x_re, y_im, y_re) {
            Ok(point) => point,
            Err(_) => {
                assert!(false, "g2 parse");
                return;
            }
        };
        assert_eq!(g, parsed);
    }

    #[test]
    fn test_g1_tamper_fails() {
        let g = G1Affine::generator();
        let (mut x, y) = g1_to_be_bytes(&g);
        x[0] ^= 1;
        assert!(g1_from_be_bytes_strict(x, y).is_err());
    }

    #[test]
    fn test_g2_tamper_fails() {
        let g = G2Affine::generator();
        let (mut x_im, x_re, y_im, y_re) = g2_to_be_bytes(&g);
        x_im[0] ^= 1;
        assert!(g2_from_be_bytes_strict(x_im, x_re, y_im, y_re).is_err());
    }

    #[test]
    fn test_g1_zero_rejected() {
        let zero = [0u8; 32];
        assert!(g1_from_be_bytes_strict(zero, zero).is_err());
    }

    #[test]
    fn test_g2_zero_rejected() {
        let zero = [0u8; 32];
        assert!(g2_from_be_bytes_strict(zero, zero, zero, zero).is_err());
    }
}
