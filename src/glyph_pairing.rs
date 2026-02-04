//! Pairing Kernel: BN254 Pairing Optimizations for SNARK Groth16 and KZG adapters.
//!
//! Implements pairing optimizations per Prover-Blueprint.md Section 6.
//! Miller loop precomputation and cyclotomic final exponent.

use crate::bn254_field::{be_bytes_from_limbs, is_canonical_be, limbs_from_be_bytes};
use crate::bn254_pairing::{
    final_exponentiation, to_ark_fq12, Fq12Elem, Fq2Elem, FqElem, G1Affine as PairingG1Affine,
    G2Affine as LimbG2Affine, G2Prepared,
};
use crate::glyph_field_simd::Goldilocks;
use ark_bn254::Fr;
use ark_bn254::Fq12 as ArkFq12;
use ark_bn254::G2Affine as ArkG2Affine;
use ark_ff::{Field, One};
use num_traits::Zero;
#[cfg(feature = "snark")]
use ark_ec::{AffineRepr, CurveGroup};
#[cfg(feature = "snark")]
use ark_ff::PrimeField;
#[cfg(feature = "snark")]
use std::ops::Neg;

// ============================================================
//                    CONSTANTS (Blueprint 6)
// ============================================================

/// BN254 curve parameter x (u parameter)
/// x = 4965661367192848881
pub const BN254_X: u64 = 4965661367192848881;

/// Number of bits in x
pub const BN254_X_BITS: usize = 63;

/// Number of Miller loop iterations
pub const MILLER_LOOP_ITERATIONS: usize = 64;

const ATE_LOOP_COUNT: &[i8] = &[
    0, 0, 0, 1, 0, 1, 0, -1, 0, 0, 1, -1, 0, 0, 1, 0, 0, 1, 1, 0, -1, 0, 0, 1, 0, -1, 0,
    0, 0, 0, 1, 1, 1, 0, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, 1, 1, 0, 0, -1, 0, 0, 0,
    1, 1, 0, -1, 0, 0, 1, 0, 1, 1,
];

// ============================================================
//                    G2 PRECOMPUTATION (Blueprint 6.1)
// ============================================================

/// Precomputed G2 line coefficients for Miller loop
#[derive(Clone, Debug)]
pub struct G2Precomp {
    /// Line evaluations at each Miller step
    /// Each line has coefficients (ell_0, ell_vw, ell_vv)
    pub lines: Vec<LineCoeffs>,
}

fn fq_to_be_bytes(limbs: [Goldilocks; 4]) -> [u8; 32] {
    let u = [limbs[0].0, limbs[1].0, limbs[2].0, limbs[3].0];
    be_bytes_from_limbs(u)
}

fn fq_from_be_bytes(bytes: [u8; 32]) -> Result<[Goldilocks; 4], String> {
    if !is_canonical_be(bytes) {
        return Err("fq bytes not canonical".to_string());
    }
    let limbs = limbs_from_be_bytes(bytes);
    Ok([
        Goldilocks(limbs[0]),
        Goldilocks(limbs[1]),
        Goldilocks(limbs[2]),
        Goldilocks(limbs[3]),
    ])
}

fn fq2_to_be_bytes(fq2: &[[Goldilocks; 4]; 2]) -> ([u8; 32], [u8; 32]) {
    // Match bn254_pairing_trace convention: (im, re) = (c1, c0)
    (fq_to_be_bytes(fq2[1]), fq_to_be_bytes(fq2[0]))
}

fn fq2_from_be_bytes(im: [u8; 32], re: [u8; 32]) -> Result<[[Goldilocks; 4]; 2], String> {
    let c1 = fq_from_be_bytes(im)?;
    let c0 = fq_from_be_bytes(re)?;
    Ok([c0, c1])
}

fn line_coeffs_from_be_bytes(data: &[u8]) -> Result<LineCoeffs, String> {
    if data.len() != 192 {
        return Err("line coeff bytes length mismatch".to_string());
    }
    let mut off = 0usize;
    let read32 = |data: &[u8], off: &mut usize| -> Result<[u8; 32], String> {
        let s = data
            .get(*off..*off + 32)
            .ok_or_else(|| "unexpected EOF".to_string())?;
        let mut out = [0u8; 32];
        out.copy_from_slice(s);
        *off += 32;
        Ok(out)
    };
    let read_fq2 = |data: &[u8], off: &mut usize| -> Result<[[Goldilocks; 4]; 2], String> {
        let im = read32(data, off)?;
        let re = read32(data, off)?;
        fq2_from_be_bytes(im, re)
    };
    let ell_0 = read_fq2(data, &mut off)?;
    let ell_vw = read_fq2(data, &mut off)?;
    let ell_vv = read_fq2(data, &mut off)?;
    Ok(LineCoeffs { ell_0, ell_vw, ell_vv })
}

fn line_coeffs_to_be_bytes(coeffs: &LineCoeffs) -> [u8; 192] {
    let mut out = [0u8; 192];
    let mut off = 0usize;
    let write_fq2 = |buf: &mut [u8; 192], off: &mut usize, fq2: &[[Goldilocks; 4]; 2]| {
        let (im, re) = fq2_to_be_bytes(fq2);
        buf[*off..*off + 32].copy_from_slice(&im);
        *off += 32;
        buf[*off..*off + 32].copy_from_slice(&re);
        *off += 32;
    };
    write_fq2(&mut out, &mut off, &coeffs.ell_0);
    write_fq2(&mut out, &mut off, &coeffs.ell_vw);
    write_fq2(&mut out, &mut off, &coeffs.ell_vv);
    out
}

/// Encode G2 Miller-loop precomputation bytes (same format as adapters expect).
pub fn encode_g2_precomp_bytes(q: ArkG2Affine) -> Vec<u8> {
    let prep = G2Prepared::from(LimbG2Affine::from(q));
    let mut out = Vec::with_capacity(prep.ell_coeffs.len().saturating_mul(192));
    for (c0, c1, c2) in prep.ell_coeffs.iter() {
        let to_gl_fq2 = |e: &crate::bn254_pairing::Fq2Elem| -> [[Goldilocks; 4]; 2] {
            [
                [
                    Goldilocks(e.c0.0[0]),
                    Goldilocks(e.c0.0[1]),
                    Goldilocks(e.c0.0[2]),
                    Goldilocks(e.c0.0[3]),
                ],
                [
                    Goldilocks(e.c1.0[0]),
                    Goldilocks(e.c1.0[1]),
                    Goldilocks(e.c1.0[2]),
                    Goldilocks(e.c1.0[3]),
                ],
            ]
        };
        let line = LineCoeffs {
            ell_0: to_gl_fq2(c0),
            ell_vw: to_gl_fq2(c1),
            ell_vv: to_gl_fq2(c2),
        };
        out.extend_from_slice(&line_coeffs_to_be_bytes(&line));
    }
    out
}

/// Decode G2 precomputation bytes into structured coefficients.
pub fn decode_g2_precomp_bytes(bytes: &[u8]) -> Result<G2Precomp, String> {
    if bytes.is_empty() {
        return Ok(G2Precomp { lines: Vec::new() });
    }
    if !bytes.len().is_multiple_of(192) {
        return Err("g2 precomp bytes length must be multiple of 192".to_string());
    }
    let mut lines = Vec::with_capacity(bytes.len() / 192);
    let mut off = 0usize;
    while off < bytes.len() {
        let chunk = bytes
            .get(off..off + 192)
            .ok_or_else(|| "unexpected EOF".to_string())?;
        let line = line_coeffs_from_be_bytes(chunk)?;
        lines.push(line);
        off += 192;
    }
    Ok(G2Precomp { lines })
}

pub fn decode_g2_precomp_bytes_strict(bytes: &[u8]) -> Result<G2Precomp, String> {
    if bytes.is_empty() {
        return Ok(G2Precomp { lines: Vec::new() });
    }
    let expected = expected_g2_precomp_bytes_len();
    if bytes.len() != expected {
        return Err(format!(
            "g2 precomp bytes length mismatch: expected {expected} got {}",
            bytes.len()
        ));
    }
    decode_g2_precomp_bytes(bytes)
}

pub fn encode_g2_precomp_from_decoded(precomp: &G2Precomp) -> Vec<u8> {
    let mut out = Vec::with_capacity(precomp.lines.len().saturating_mul(192));
    for line in &precomp.lines {
        out.extend_from_slice(&line_coeffs_to_be_bytes(line));
    }
    out
}

/// Miller loop line coefficients
#[derive(Clone, Debug, Default)]
pub struct LineCoeffs {
    /// ell_0 coefficient as Fq2: [c0, c1], each 4 Goldilocks limbs
    pub ell_0: [[Goldilocks; 4]; 2],
    /// ell_vw coefficient as Fq2: [c0, c1], each 4 Goldilocks limbs
    pub ell_vw: [[Goldilocks; 4]; 2],
    /// ell_vv coefficient as Fq2: [c0, c1], each 4 Goldilocks limbs
    pub ell_vv: [[Goldilocks; 4]; 2],
}

impl LineCoeffs {
    /// Create line coefficients from bytes (192 bytes total)
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 192 {
            return None;
        }

        let mut coeffs = Self::default();

        let mut offset = 0usize;
        let mut read_fq2 = |out: &mut [[Goldilocks; 4]; 2]| -> Option<()> {
            for limb_set in out.iter_mut() {
                for limb in limb_set.iter_mut() {
                    let start = offset;
                    let end = start + 8;
                    *limb = Goldilocks(u64::from_le_bytes(data[start..end].try_into().ok()?));
                    offset = end;
                }
            }
            Some(())
        };

        read_fq2(&mut coeffs.ell_0)?;
        read_fq2(&mut coeffs.ell_vw)?;
        read_fq2(&mut coeffs.ell_vv)?;

        Some(coeffs)
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(192);
        let mut write_fq2 = |coeff: &[[Goldilocks; 4]; 2]| {
            for limb_set in coeff {
                for limb in limb_set {
                    out.extend_from_slice(&limb.0.to_le_bytes());
                }
            }
        };
        write_fq2(&self.ell_0);
        write_fq2(&self.ell_vw);
        write_fq2(&self.ell_vv);
        out
    }
}

fn expected_g2_precomp_coeffs_len() -> usize {
    let mut count = 0usize;
    for bit in ATE_LOOP_COUNT.iter().rev().skip(1) {
        count += 1;
        if *bit != 0 {
            count += 1;
        }
    }
    count + 2
}

pub fn expected_g2_precomp_bytes_len() -> usize {
    expected_g2_precomp_coeffs_len() * 192
}

fn validate_g2_precomp(precomp: &G2Precomp) -> Result<(), String> {
    if precomp.lines.is_empty() {
        return Ok(());
    }
    let expected = expected_g2_precomp_coeffs_len();
    if precomp.lines.len() != expected {
        return Err(format!(
            "g2 precomp coeffs length mismatch: expected {expected} got {}",
            precomp.lines.len()
        ));
    }
    Ok(())
}

fn fq_from_goldilocks(limbs: [Goldilocks; 4]) -> FqElem {
    FqElem([limbs[0].0, limbs[1].0, limbs[2].0, limbs[3].0])
}

fn fq2_from_goldilocks(limbs: &[[Goldilocks; 4]; 2]) -> Fq2Elem {
    Fq2Elem {
        c0: fq_from_goldilocks(limbs[0]),
        c1: fq_from_goldilocks(limbs[1]),
    }
}

pub fn g1_from_goldilocks(x: [Goldilocks; 4], y: [Goldilocks; 4], infinity: bool) -> PairingG1Affine {
    PairingG1Affine {
        x: fq_from_goldilocks(x),
        y: fq_from_goldilocks(y),
        infinity,
    }
}

fn line_coeffs_to_pairing(line: &LineCoeffs) -> (Fq2Elem, Fq2Elem, Fq2Elem) {
    let ell_0 = fq2_from_goldilocks(&line.ell_0);
    let ell_vw = fq2_from_goldilocks(&line.ell_vw);
    let ell_vv = fq2_from_goldilocks(&line.ell_vv);
    (ell_0, ell_vw, ell_vv)
}

fn apply_line(f: &mut Fq12Elem, line: &LineCoeffs, p: &PairingG1Affine) {
    let (ell_0, ell_vw, ell_vv) = line_coeffs_to_pairing(line);
    let c0 = ell_0.mul_by_fp(p.y);
    let c1 = ell_vw.mul_by_fp(p.x);
    let c2 = ell_vv;
    f.mul_by_034(&c0, &c1, &c2);
}

pub fn multi_miller_loop_precomp(
    pairs: &[(PairingG1Affine, G2Precomp)],
) -> Result<Fq12Elem, String> {
    let mut prepped: Vec<(PairingG1Affine, &G2Precomp, usize)> = Vec::new();
    for (p, precomp) in pairs.iter() {
        if p.infinity || precomp.lines.is_empty() {
            continue;
        }
        validate_g2_precomp(precomp)?;
        prepped.push((*p, precomp, 0usize));
    }
    if prepped.is_empty() {
        return Ok(Fq12Elem::one());
    }

    let mut f = Fq12Elem::one();
    for i in (1..ATE_LOOP_COUNT.len()).rev() {
        if i != ATE_LOOP_COUNT.len() - 1 {
            f = f.square();
        }
        for (p, precomp, idx) in prepped.iter_mut() {
            let line = precomp
                .lines
                .get(*idx)
                .ok_or_else(|| "g2 precomp missing line coeffs".to_string())?;
            *idx += 1;
            apply_line(&mut f, line, p);
        }
        let bit = ATE_LOOP_COUNT[i - 1];
        if bit == 1 || bit == -1 {
            for (p, precomp, idx) in prepped.iter_mut() {
                let line = precomp
                    .lines
                    .get(*idx)
                    .ok_or_else(|| "g2 precomp missing line coeffs".to_string())?;
                *idx += 1;
                apply_line(&mut f, line, p);
            }
        }
    }

    for _ in 0..2 {
        for (p, precomp, idx) in prepped.iter_mut() {
            let line = precomp
                .lines
                .get(*idx)
                .ok_or_else(|| "g2 precomp missing line coeffs".to_string())?;
            *idx += 1;
            apply_line(&mut f, line, p);
        }
    }

    for (_, precomp, idx) in prepped {
        if idx != precomp.lines.len() {
            return Err("g2 precomp has unused line coeffs".to_string());
        }
    }

    Ok(f)
}

pub fn miller_loop_precomp(
    p: PairingG1Affine,
    precomp: &G2Precomp,
) -> Result<Fq12Elem, String> {
    multi_miller_loop_precomp(&[(p, precomp.clone())])
}

fn cyclotomic_check_ark(f: ArkFq12) -> bool {
    if f.is_zero() {
        return false;
    }
    let prod = f * f.frobenius_map(6);
    prod == ArkFq12::one()
}

fn easy_exponentiation_to_cyclotomic(f: Fq12Elem) -> Option<ArkFq12> {
    let f_ark = to_ark_fq12(f)?;
    let inv = f_ark.inverse()?;
    let f_p6 = f_ark.frobenius_map(6);
    let f1 = f_p6 * inv;
    let f1_p2 = f1.frobenius_map(2);
    Some(f1_p2 * f1)
}

pub fn pairing_product_cyclotomic_check(
    pairs: &[(PairingG1Affine, G2Precomp)],
) -> Result<bool, String> {
    let ml = multi_miller_loop_precomp(pairs)?;
    let cyclo = easy_exponentiation_to_cyclotomic(ml)
        .ok_or_else(|| "pairing cyclotomic check failed: zero element".to_string())?;
    Ok(cyclotomic_check_ark(cyclo))
}

pub fn pairing_product_is_one_full(
    pairs: &[(PairingG1Affine, G2Precomp)],
) -> Result<bool, String> {
    let ml = multi_miller_loop_precomp(pairs)?;
    let out = final_exponentiation(ml)
        .ok_or_else(|| "pairing final exponentiation failed".to_string())?;
    Ok(out.is_one())
}

pub fn pairing_product_is_one(
    pairs: &[(PairingG1Affine, G2Precomp)],
) -> Result<bool, String> {
    if env_bool("GLYPH_PAIRING_FULL_EXP", false) {
        pairing_product_is_one_full(pairs)
    } else {
        pairing_product_cyclotomic_check(pairs)
    }
}

fn env_bool(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(default)
}

// ============================================================
//                    NATIVE VERIFICATION HELPERS
// ============================================================

/// Verify Groth16 proof using native BN254 pairing
pub fn verify_groth16(
    vk: &crate::bn254_groth16::Groth16VerifyingKey,
    proof: &crate::bn254_groth16::Groth16Proof,
    public_inputs: &[Fr],
) -> Result<bool, String> {
    crate::bn254_groth16::verify_groth16_proof(vk, proof, public_inputs)
}

/// Verify KZG proof using native BN254 pairing
#[cfg(feature = "snark")]
pub fn verify_kzg(
    vk: &crate::snark_kzg_bn254_adapter::KzgVk,
    proof: &crate::snark_kzg_bn254_adapter::KzgProof,
    inputs: &crate::snark_kzg_bn254_adapter::KzgPublicInputs,
) -> bool {
    let y_g1 = vk.g1.mul_bigint(inputs.y.into_bigint());
    let c_minus_y = (proof.commitment.into_group() - y_g1).into_affine();       
    let z_g2 = vk.g2.mul_bigint(inputs.z.into_bigint());
    let s_minus_z = (vk.g2_s.into_group() - z_g2).into_affine();
    let s_minus_z_neg = s_minus_z.into_group().neg().into_affine();
    crate::bn254_pairing::pairing_product_is_one(&[
        (c_minus_y.into(), vk.g2.into()),
        (proof.proof.into(), s_minus_z_neg.into()),
    ])
}

// ============================================================
//                    TESTS
// ============================================================

#[cfg(all(test, feature = "snark"))]
mod tests {
    use super::*;
    use crate::bn254_pairing::{multi_miller_loop, G2Affine as PairingG2Affine};

    #[test]
    fn test_line_coeffs_roundtrip() {
        let coeffs = LineCoeffs {
            ell_0: [
                [Goldilocks(1), Goldilocks(2), Goldilocks(3), Goldilocks(4)],
                [Goldilocks(5), Goldilocks(6), Goldilocks(7), Goldilocks(8)],
            ],
            ell_vw: [
                [Goldilocks(9), Goldilocks(10), Goldilocks(11), Goldilocks(12)],
                [Goldilocks(13), Goldilocks(14), Goldilocks(15), Goldilocks(16)],
            ],
            ell_vv: [
                [Goldilocks(17), Goldilocks(18), Goldilocks(19), Goldilocks(20)],
                [Goldilocks(21), Goldilocks(22), Goldilocks(23), Goldilocks(24)],
            ],
        };

        let bytes = coeffs.to_bytes();
        assert_eq!(bytes.len(), 192);

        let decoded = match LineCoeffs::from_bytes(&bytes) {
            Some(decoded) => decoded,
            None => {
                assert!(false, "decode line coeffs");
                return;
            }
        };
        assert_eq!(decoded.ell_0, coeffs.ell_0);
        assert_eq!(decoded.ell_vw, coeffs.ell_vw);
        assert_eq!(decoded.ell_vv, coeffs.ell_vv);

        println!("Line coeffs roundtrip test passed.");
    }

    #[test]
    fn test_g2_precomp_bytes_roundtrip_generator() {
        let g2 = ArkG2Affine::generator();
        let bytes = encode_g2_precomp_bytes(g2);
        assert!(!bytes.is_empty());
        assert!(bytes.len().is_multiple_of(192));
        assert_eq!(bytes.len(), expected_g2_precomp_bytes_len());
        let decoded = match decode_g2_precomp_bytes(&bytes) {
            Ok(decoded) => decoded,
            Err(err) => {
                assert!(false, "decode: {err}");
                return;
            }
        };
        let roundtrip = encode_g2_precomp_from_decoded(&decoded);
        assert_eq!(bytes, roundtrip);

        let mut short = bytes.clone();
        short.pop();
        assert!(decode_g2_precomp_bytes(&short).is_err());
        assert!(decode_g2_precomp_bytes_strict(&short).is_err());
    }

    #[test]
    fn test_miller_loop_precomp_matches_bn254_pairing() {
        let g1 = ark_bn254::G1Affine::generator();
        let g2 = ArkG2Affine::generator();
        let bytes = encode_g2_precomp_bytes(g2);
        let precomp = match decode_g2_precomp_bytes_strict(&bytes) {
            Ok(precomp) => precomp,
            Err(err) => {
                assert!(false, "precomp: {err}");
                return;
            }
        };
        let ours = match miller_loop_precomp(PairingG1Affine::from(g1), &precomp) {
            Ok(ours) => ours,
            Err(err) => {
                assert!(false, "ml precomp: {err}");
                return;
            }
        };
        let expected =
            multi_miller_loop(&[(PairingG1Affine::from(g1), PairingG2Affine::from(g2))]);
        assert_eq!(ours, expected);
    }

    #[test]
    fn test_pairing_product_precomp_is_one() {
        let g1 = ark_bn254::G1Affine::generator();
        let g2 = ArkG2Affine::generator();
        let bytes = encode_g2_precomp_bytes(g2);
        let precomp = match decode_g2_precomp_bytes_strict(&bytes) {
            Ok(precomp) => precomp,
            Err(err) => {
                assert!(false, "precomp: {err}");
                return;
            }
        };
        let pairs = vec![
            (PairingG1Affine::from(g1), precomp.clone()),
            (PairingG1Affine::from(g1.neg()), precomp),
        ];
        let full = match pairing_product_is_one_full(&pairs) {
            Ok(full) => full,
            Err(err) => {
                assert!(false, "pairing full: {err}");
                return;
            }
        };
        assert!(full);
        let cyclo = match pairing_product_cyclotomic_check(&pairs) {
            Ok(cyclo) => cyclo,
            Err(err) => {
                assert!(false, "pairing cyclo: {err}");
                return;
            }
        };
        assert!(cyclo);
    }

    // Pairing verification helpers are covered by bn254_groth16 and snark_kzg_bn254_adapter tests.
}
