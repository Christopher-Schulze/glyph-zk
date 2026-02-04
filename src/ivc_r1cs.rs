//! Transparent R1CS receipt format for IVC verification.
//!
//! This module defines a canonical R1CS encoding and a strict verifier for
//! relaxed R1CS instances used by internal IVC proof types.

use ark_bn254::Fr;
use ark_ff::{BigInt, Field, PrimeField};
use rayon::prelude::*;

pub const IVC_R1CS_DOMAIN: &[u8] = b"GLYPH_IVC_R1CS";
pub const IVC_R1CS_VERSION: u16 = 1;
const IVC_R1CS_PAR_THRESHOLD: usize = 256;

#[derive(Clone, Debug)]
pub struct R1csTerm {
    pub var_idx: u32,
    pub coeff: Fr,
}

#[derive(Clone, Debug)]
pub struct R1csLinearCombination {
    pub terms: Vec<R1csTerm>,
}

#[derive(Clone, Debug)]
pub struct R1csConstraint {
    pub a: R1csLinearCombination,
    pub b: R1csLinearCombination,
    pub c: R1csLinearCombination,
}

#[derive(Clone, Debug)]
pub struct R1csReceipt {
    pub num_vars: u32,
    pub num_constraints: u32,
    pub constraints: Vec<R1csConstraint>,
    pub witness: Vec<Fr>,
    pub u: Fr,
    pub error: Vec<Fr>,
}

fn read_u16_be(bytes: &[u8], off: &mut usize) -> Result<u16, String> {
    let s = bytes
        .get(*off..*off + 2)
        .ok_or_else(|| "unexpected EOF".to_string())?;
    *off += 2;
    Ok(u16::from_be_bytes([s[0], s[1]]))
}

fn read_u32_be(bytes: &[u8], off: &mut usize) -> Result<u32, String> {
    let s = bytes
        .get(*off..*off + 4)
        .ok_or_else(|| "unexpected EOF".to_string())?;
    *off += 4;
    Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_bytes(bytes: &[u8], off: &mut usize, len: usize) -> Result<Vec<u8>, String> {
    let s = bytes
        .get(*off..*off + len)
        .ok_or_else(|| "unexpected EOF".to_string())?;
    *off += len;
    Ok(s.to_vec())
}

fn fr_from_be(bytes: [u8; 32]) -> Result<Fr, String> {
    let mut limbs = [0u64; 4];
    for (i, limb) in limbs.iter_mut().enumerate() {
        let start = 32 - (i + 1) * 8;
        let end = start + 8;
        let mut limb_bytes = [0u8; 8];
        limb_bytes.copy_from_slice(&bytes[start..end]);
        *limb = u64::from_be_bytes(limb_bytes);
    }
    let bigint = BigInt(limbs);
    if bigint >= Fr::MODULUS {
        return Err("r1cs field element not canonical".to_string());
    }
    Fr::from_bigint(bigint).ok_or_else(|| "r1cs field decode failed".to_string())
}

fn fr_to_be(value: Fr) -> [u8; 32] {
    let limbs = value.into_bigint().0;
    let mut out = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        let start = 32 - (i + 1) * 8;
        let end = start + 8;
        out[start..end].copy_from_slice(&limb.to_be_bytes());
    }
    out
}

fn decode_lc(
    bytes: &[u8],
    off: &mut usize,
    num_vars: u32,
) -> Result<R1csLinearCombination, String> {
    let term_len = read_u32_be(bytes, off)? as usize;
    let mut terms = Vec::with_capacity(term_len);
    for _ in 0..term_len {
        let idx = read_u32_be(bytes, off)?;
        if idx >= num_vars {
            return Err("r1cs term index out of bounds".to_string());
        }
        let coeff_bytes = read_bytes(bytes, off, 32)?;
        let coeff = fr_from_be(
            coeff_bytes
                .as_slice()
                .try_into()
                .map_err(|_| "r1cs coeff length mismatch".to_string())?,
        )?;
        terms.push(R1csTerm { var_idx: idx, coeff });
    }
    Ok(R1csLinearCombination { terms })
}

fn encode_lc(out: &mut Vec<u8>, lc: &R1csLinearCombination) {
    out.extend_from_slice(&(lc.terms.len() as u32).to_be_bytes());
    for term in &lc.terms {
        out.extend_from_slice(&term.var_idx.to_be_bytes());
        out.extend_from_slice(&fr_to_be(term.coeff));
    }
}

pub fn decode_r1cs_receipt(bytes: &[u8]) -> Result<R1csReceipt, String> {
    if !bytes.starts_with(IVC_R1CS_DOMAIN) {
        return Err("r1cs receipt missing domain tag".to_string());
    }
    let mut off = IVC_R1CS_DOMAIN.len();
    let version = read_u16_be(bytes, &mut off)?;
    if version != IVC_R1CS_VERSION {
        return Err(format!("r1cs receipt unsupported version={version}"));
    }
    let num_vars = read_u32_be(bytes, &mut off)?;
    if num_vars == 0 {
        return Err("r1cs receipt num_vars must be > 0".to_string());
    }
    let num_constraints = read_u32_be(bytes, &mut off)?;
    if num_constraints == 0 {
        return Err("r1cs receipt num_constraints must be > 0".to_string());
    }
    let mut constraints = Vec::with_capacity(num_constraints as usize);
    for _ in 0..num_constraints {
        let a = decode_lc(bytes, &mut off, num_vars)?;
        let b = decode_lc(bytes, &mut off, num_vars)?;
        let c = decode_lc(bytes, &mut off, num_vars)?;
        constraints.push(R1csConstraint { a, b, c });
    }
    let witness_len = read_u32_be(bytes, &mut off)? as usize;
    if witness_len != num_vars as usize {
        return Err("r1cs witness length mismatch".to_string());
    }
    let mut witness = Vec::with_capacity(witness_len);
    for _ in 0..witness_len {
        let w = read_bytes(bytes, &mut off, 32)?;
        let w = fr_from_be(w.as_slice().try_into().map_err(|_| "r1cs witness length mismatch".to_string())?)?;
        witness.push(w);
    }
    if witness.is_empty() || witness[0] != Fr::ONE {
        return Err("r1cs witness[0] must be 1".to_string());
    }
    let u_bytes = read_bytes(bytes, &mut off, 32)?;
    let u = fr_from_be(u_bytes.as_slice().try_into().map_err(|_| "r1cs u length mismatch".to_string())?)?;
    let error_len = read_u32_be(bytes, &mut off)? as usize;
    if error_len != num_constraints as usize {
        return Err("r1cs error length mismatch".to_string());
    }
    let mut error = Vec::with_capacity(error_len);
    for _ in 0..error_len {
        let e = read_bytes(bytes, &mut off, 32)?;
        let e = fr_from_be(e.as_slice().try_into().map_err(|_| "r1cs error length mismatch".to_string())?)?;
        error.push(e);
    }
    if off != bytes.len() {
        return Err("r1cs receipt trailing data".to_string());
    }
    Ok(R1csReceipt {
        num_vars,
        num_constraints,
        constraints,
        witness,
        u,
        error,
    })
}

pub fn encode_r1cs_receipt(receipt: &R1csReceipt) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(IVC_R1CS_DOMAIN);
    out.extend_from_slice(&IVC_R1CS_VERSION.to_be_bytes());
    out.extend_from_slice(&receipt.num_vars.to_be_bytes());
    out.extend_from_slice(&receipt.num_constraints.to_be_bytes());
    for constraint in &receipt.constraints {
        encode_lc(&mut out, &constraint.a);
        encode_lc(&mut out, &constraint.b);
        encode_lc(&mut out, &constraint.c);
    }
    out.extend_from_slice(&(receipt.witness.len() as u32).to_be_bytes());
    for w in &receipt.witness {
        out.extend_from_slice(&fr_to_be(*w));
    }
    out.extend_from_slice(&fr_to_be(receipt.u));
    out.extend_from_slice(&(receipt.error.len() as u32).to_be_bytes());
    for e in &receipt.error {
        out.extend_from_slice(&fr_to_be(*e));
    }
    out
}

fn eval_lc(lc: &R1csLinearCombination, witness: &[Fr]) -> Result<Fr, String> {
    let mut acc = Fr::ZERO;
    for term in &lc.terms {
        let idx = term.var_idx as usize;
        let w = witness
            .get(idx)
            .ok_or_else(|| "r1cs term index out of bounds".to_string())?;
        acc += term.coeff * *w;
    }
    Ok(acc)
}

pub fn verify_relaxed_r1cs(receipt: &R1csReceipt) -> Result<(), String> {
    if receipt.witness.len() != receipt.num_vars as usize {
        return Err("r1cs witness length mismatch".to_string());
    }
    if receipt.error.len() != receipt.num_constraints as usize {
        return Err("r1cs error length mismatch".to_string());
    }
    if receipt.witness.is_empty() || receipt.witness[0] != Fr::ONE {
        return Err("r1cs witness[0] must be 1".to_string());
    }
    if receipt.constraints.len() >= IVC_R1CS_PAR_THRESHOLD && rayon::current_num_threads() > 1 {
        receipt
            .constraints
            .par_iter()
            .enumerate()
            .try_for_each(|(idx, constraint)| -> Result<(), String> {
                let a = eval_lc(&constraint.a, &receipt.witness)?;
                let b = eval_lc(&constraint.b, &receipt.witness)?;
                let c = eval_lc(&constraint.c, &receipt.witness)?;
                let expected = receipt.u * c + receipt.error[idx];
                if a * b != expected {
                    return Err(format!("r1cs constraint {idx} failed"));
                }
                Ok(())
            })?;
    } else {
        for (idx, constraint) in receipt.constraints.iter().enumerate() {
            let a = eval_lc(&constraint.a, &receipt.witness)?;
            let b = eval_lc(&constraint.b, &receipt.witness)?;
            let c = eval_lc(&constraint.c, &receipt.witness)?;
            let expected = receipt.u * c + receipt.error[idx];
            if a * b != expected {
                return Err(format!("r1cs constraint {idx} failed"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Field;

    #[test]
    fn test_r1cs_roundtrip_and_verify() {
        let one = Fr::ONE;
        let two = one + one;

        // Constraint: (x1 + 1) * (x2) = x3
        let constraint = R1csConstraint {
            a: R1csLinearCombination {
                terms: vec![
                    R1csTerm { var_idx: 0, coeff: one },
                    R1csTerm { var_idx: 1, coeff: one },
                ],
            },
            b: R1csLinearCombination {
                terms: vec![R1csTerm { var_idx: 2, coeff: one }],
            },
            c: R1csLinearCombination {
                terms: vec![R1csTerm { var_idx: 3, coeff: one }],
            },
        };
        let receipt = R1csReceipt {
            num_vars: 4,
            num_constraints: 1,
            constraints: vec![constraint],
            witness: vec![one, two, two, six()],
            u: Fr::ONE,
            error: vec![Fr::ZERO],
        };
        let bytes = encode_r1cs_receipt(&receipt);
        let decoded = match decode_r1cs_receipt(&bytes) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "decode");
                return;
            }
        };
        if let Err(_) = verify_relaxed_r1cs(&decoded) {
            assert!(false, "verify");
        }
    }

    fn six() -> Fr {
        let one = Fr::ONE;
        one + one + one + one + one + one
    }
}
