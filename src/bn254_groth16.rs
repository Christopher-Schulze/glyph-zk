//! BN254 Groth16 parsing and verification helpers for adapter kernels.
//!
//! This module provides strict parsing for Groth16 proofs and verification keys
//! in EVM-compatible uncompressed encoding.

use ark_bn254::{Fr, G1Affine as ArkG1Affine, G1Projective, G2Affine as ArkG2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use num_bigint::BigUint;

use crate::bn254_curve::{g1_from_be_bytes_strict, g2_from_be_bytes_strict};
use crate::bn254_pairing::{pairing_product_is_one, G1Affine, G2Affine};

pub const GROTH16_PROOF_BYTES_LEN: usize = 64 + 128 + 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Groth16Proof {
    pub a: ArkG1Affine,
    pub b: ArkG2Affine,
    pub c: ArkG1Affine,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Groth16VerifyingKey {
    pub alpha_g1: ArkG1Affine,
    pub beta_g2: ArkG2Affine,
    pub gamma_g2: ArkG2Affine,
    pub delta_g2: ArkG2Affine,
    pub ic: Vec<ArkG1Affine>,
}

pub fn decode_groth16_proof_bytes(bytes: &[u8]) -> Result<Groth16Proof, String> {
    if bytes.len() != GROTH16_PROOF_BYTES_LEN {
        return Err(format!(
            "groth16 proof bytes must be {GROTH16_PROOF_BYTES_LEN} bytes"
        ));
    }
    let mut off = 0usize;
    let a = decode_g1(&bytes[off..off + 64])?;
    off += 64;
    let b = decode_g2(&bytes[off..off + 128])?;
    off += 128;
    let c = decode_g1(&bytes[off..off + 64])?;
    Ok(Groth16Proof { a, b, c })
}

pub fn encode_groth16_proof_bytes(proof: &Groth16Proof) -> [u8; GROTH16_PROOF_BYTES_LEN] {
    let mut out = [0u8; GROTH16_PROOF_BYTES_LEN];
    let mut off = 0usize;
    let a = encode_g1(&proof.a);
    out[off..off + 64].copy_from_slice(&a);
    off += 64;
    let b = encode_g2(&proof.b);
    out[off..off + 128].copy_from_slice(&b);
    off += 128;
    let c = encode_g1(&proof.c);
    out[off..off + 64].copy_from_slice(&c);
    out
}

pub fn decode_groth16_vk_bytes(bytes: &[u8]) -> Result<Groth16VerifyingKey, String> {
    if bytes.len() < 64 + 128 * 3 + 4 {
        return Err("groth16 vk bytes too short".to_string());
    }
    let mut off = 0usize;
    let alpha_g1 = decode_g1(&bytes[off..off + 64])?;
    off += 64;
    let beta_g2 = decode_g2(&bytes[off..off + 128])?;
    off += 128;
    let gamma_g2 = decode_g2(&bytes[off..off + 128])?;
    off += 128;
    let delta_g2 = decode_g2(&bytes[off..off + 128])?;
    off += 128;

    let ic_len = read_u32_be(bytes, &mut off)? as usize;
    let expected = off + ic_len * 64;
    if expected != bytes.len() {
        return Err("groth16 vk bytes length mismatch".to_string());
    }
    let mut ic = Vec::with_capacity(ic_len);
    for _ in 0..ic_len {
        let g = decode_g1(&bytes[off..off + 64])?;
        off += 64;
        ic.push(g);
    }
    if ic.is_empty() {
        return Err("groth16 vk ic must contain at least one point".to_string());
    }

    Ok(Groth16VerifyingKey {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        ic,
    })
}

pub fn encode_groth16_vk_bytes(vk: &Groth16VerifyingKey) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&encode_g1(&vk.alpha_g1));
    out.extend_from_slice(&encode_g2(&vk.beta_g2));
    out.extend_from_slice(&encode_g2(&vk.gamma_g2));
    out.extend_from_slice(&encode_g2(&vk.delta_g2));
    out.extend_from_slice(&(vk.ic.len() as u32).to_be_bytes());
    for g in vk.ic.iter() {
        out.extend_from_slice(&encode_g1(g));
    }
    out
}

pub fn decode_groth16_public_inputs(bytes: &[u8]) -> Result<Vec<Fr>, String> {
    if !bytes.len().is_multiple_of(32) {
        return Err("groth16 public inputs must be 32-byte aligned".to_string());
    }
    let mut inputs = Vec::with_capacity(bytes.len() / 32);
    let modulus = BigUint::from_bytes_be(&Fr::MODULUS.to_bytes_be());
    for chunk in bytes.chunks(32) {
        let mut tmp = [0u8; 32];
        tmp.copy_from_slice(chunk);
        let big = BigUint::from_bytes_be(&tmp);
        if big >= modulus {
            return Err("groth16 public input not canonical".to_string());
        }
        let fr = Fr::from_be_bytes_mod_order(&tmp);
        inputs.push(fr);
    }
    Ok(inputs)
}

pub fn encode_groth16_public_inputs(inputs: &[Fr]) -> Vec<u8> {
    let mut out = Vec::with_capacity(inputs.len() * 32);
    for input in inputs {
        let mut bytes = input.into_bigint().to_bytes_be();
        if bytes.len() > 32 {
            bytes = bytes[bytes.len() - 32..].to_vec();
        }
        if bytes.len() < 32 {
            let mut padded = vec![0u8; 32 - bytes.len()];
            padded.extend_from_slice(&bytes);
            bytes = padded;
        }
        out.extend_from_slice(&bytes);
    }
    out
}

pub fn verify_groth16_proof(
    vk: &Groth16VerifyingKey,
    proof: &Groth16Proof,
    public_inputs: &[Fr],
) -> Result<bool, String> {
    if public_inputs.len() + 1 != vk.ic.len() {
        return Err("groth16 public input length mismatch".to_string());
    }

    let mut acc = G1Projective::from(vk.ic[0]);
    for (input, base) in public_inputs.iter().zip(vk.ic.iter().skip(1)) {
        acc += base.mul_bigint(input.into_bigint());
    }
    let acc_affine = acc.into_affine();

    let pairs = [
        (to_pairing_g1(&proof.a), to_pairing_g2(&proof.b)),
        (
            negate_g1(&to_pairing_g1(&vk.alpha_g1)),
            to_pairing_g2(&vk.beta_g2),
        ),
        (
            negate_g1(&to_pairing_g1(&acc_affine)),
            to_pairing_g2(&vk.gamma_g2),
        ),
        (
            negate_g1(&to_pairing_g1(&proof.c)),
            to_pairing_g2(&vk.delta_g2),
        ),
    ];

    Ok(pairing_product_is_one(&pairs))
}

fn decode_g1(bytes: &[u8]) -> Result<ArkG1Affine, String> {
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&bytes[0..32]);
    y.copy_from_slice(&bytes[32..64]);
    g1_from_be_bytes_strict(x, y)
}

fn decode_g2(bytes: &[u8]) -> Result<ArkG2Affine, String> {
    let mut x_im = [0u8; 32];
    let mut x_re = [0u8; 32];
    let mut y_im = [0u8; 32];
    let mut y_re = [0u8; 32];
    x_im.copy_from_slice(&bytes[0..32]);
    x_re.copy_from_slice(&bytes[32..64]);
    y_im.copy_from_slice(&bytes[64..96]);
    y_re.copy_from_slice(&bytes[96..128]);
    g2_from_be_bytes_strict(x_im, x_re, y_im, y_re)
}

fn encode_g1(p: &ArkG1Affine) -> [u8; 64] {
    let (x, y) = crate::bn254_curve::g1_to_be_bytes(p);
    let mut out = [0u8; 64];
    out[0..32].copy_from_slice(&x);
    out[32..64].copy_from_slice(&y);
    out
}

fn encode_g2(p: &ArkG2Affine) -> [u8; 128] {
    let (x_im, x_re, y_im, y_re) = crate::bn254_curve::g2_to_be_bytes(p);
    let mut out = [0u8; 128];
    out[0..32].copy_from_slice(&x_im);
    out[32..64].copy_from_slice(&x_re);
    out[64..96].copy_from_slice(&y_im);
    out[96..128].copy_from_slice(&y_re);
    out
}

fn to_pairing_g1(p: &ArkG1Affine) -> G1Affine {
    G1Affine::from(*p)
}

fn to_pairing_g2(p: &ArkG2Affine) -> G2Affine {
    G2Affine::from(*p)
}

fn negate_g1(p: &G1Affine) -> G1Affine {
    if p.infinity {
        *p
    } else {
        G1Affine {
            x: p.x,
            y: p.y.neg(),
            infinity: false,
        }
    }
}

fn read_u32_be(bytes: &[u8], off: &mut usize) -> Result<u32, String> {
    let s = bytes
        .get(*off..*off + 4)
        .ok_or_else(|| "unexpected EOF".to_string())?;
    *off += 4;
    Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_groth16::Groth16;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError};
    use ark_snark::SNARK;
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    #[derive(Clone)]
    struct MulCircuit {
        pub a: Fr,
        pub b: Fr,
        pub c: Fr,
    }

    impl ConstraintSynthesizer<Fr> for MulCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
            let a_var = cs.new_witness_variable(|| Ok(self.a))?;
            let b_var = cs.new_witness_variable(|| Ok(self.b))?;
            let c_var = cs.new_input_variable(|| Ok(self.c))?;

            let lc_a = LinearCombination::from(a_var);
            let lc_b = LinearCombination::from(b_var);
            let lc_c = LinearCombination::from(c_var);
            cs.enforce_constraint(lc_a, lc_b, lc_c)?;
            Ok(())
        }
    }

    #[test]
    fn test_groth16_roundtrip_and_verify() {
        let mut rng = StdRng::seed_from_u64(0xdecafbad);
        let a = Fr::from(3u64);
        let b = Fr::from(9u64);
        let c = a * b;
        let circuit = MulCircuit { a, b, c };
        let (pk, vk) = match Groth16::<ark_bn254::Bn254>::circuit_specific_setup(
            circuit.clone(),
            &mut rng,
        ) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "setup");
                return;
            }
        };
        let pvk = match Groth16::<ark_bn254::Bn254>::process_vk(&vk) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "pvk");
                return;
            }
        };
        let proof = match Groth16::<ark_bn254::Bn254>::prove(&pk, circuit, &mut rng) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "proof");
                return;
            }
        };

        let ok = match Groth16::<ark_bn254::Bn254>::verify_with_processed_vk(&pvk, &[c], &proof) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "verify");
                return;
            }
        };
        assert!(ok);

        let vk_bytes = encode_groth16_vk_bytes(&Groth16VerifyingKey {
            alpha_g1: vk.alpha_g1,
            beta_g2: vk.beta_g2,
            gamma_g2: vk.gamma_g2,
            delta_g2: vk.delta_g2,
            ic: vk.gamma_abc_g1.clone(),
        });
        let proof_bytes = encode_groth16_proof_bytes(&Groth16Proof {
            a: proof.a,
            b: proof.b,
            c: proof.c,
        });
        let parsed_vk = match decode_groth16_vk_bytes(&vk_bytes) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "vk decode");
                return;
            }
        };
        let parsed_proof = match decode_groth16_proof_bytes(&proof_bytes) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "proof decode");
                return;
            }
        };
        let inputs = match decode_groth16_public_inputs(&encode_groth16_public_inputs(&[c])) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "inputs");
                return;
            }
        };
        let ours = match verify_groth16_proof(&parsed_vk, &parsed_proof, &inputs) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "ours");
                return;
            }
        };
        assert!(ours);
    }
}
