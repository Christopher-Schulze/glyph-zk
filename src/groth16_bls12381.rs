//! BLS12-381 Groth16 receipt handling for SNARK Groth16.
//!
//! Verification is off-chain only. The receipt is bound to GLYPH artifacts and
//! later proven via GLYPH sumcheck.

use ark_bls12_381::{Bls12_381, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{prepare_verifying_key, Groth16, Proof as ArkProof, VerifyingKey};
use num_bigint::BigUint;

use crate::adapters::keccak256;
use crate::adapter_error::{wrap, wrap_stage};

pub const SNARK_GROTH16_BLS12381_RECEIPT_TAG: &[u8] = b"GLYPH_SNARK_GROTH16_BLS12381_RECEIPT";
pub const SNARK_GROTH16_BLS12381_DOMAIN: &[u8] = b"GLYPH_ADAPTER_SNARK_GROTH16_BLS12381";
pub const SNARK_GROTH16_BLS12381_VK_HASH_DOMAIN: &[u8] = b"GLYPH_SNARK_GROTH16_BLS12381_VK_HASH";

pub const GROTH16_BLS12381_PROOF_BYTES_LEN: usize = 96 + 192 + 96;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Groth16Proof {
    pub a: G1Affine,
    pub b: G2Affine,
    pub c: G1Affine,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Groth16VerifyingKey {
    pub alpha_g1: G1Affine,
    pub beta_g2: G2Affine,
    pub gamma_g2: G2Affine,
    pub delta_g2: G2Affine,
    pub ic: Vec<G1Affine>,
}

#[derive(Clone, Debug)]
pub struct Groth16Bls12381Receipt {
    pub vk_bytes: Vec<u8>,
    pub proof_bytes: Vec<u8>,
    pub pub_inputs_bytes: Vec<u8>,
}

pub fn encode_groth16_bls12381_receipt(receipt: &Groth16Bls12381Receipt) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(SNARK_GROTH16_BLS12381_RECEIPT_TAG);
    out.extend_from_slice(&(receipt.vk_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&(receipt.proof_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&(receipt.pub_inputs_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&receipt.vk_bytes);
    out.extend_from_slice(&receipt.proof_bytes);
    out.extend_from_slice(&receipt.pub_inputs_bytes);
    out
}

pub fn decode_groth16_bls12381_receipt(bytes: &[u8]) -> Result<Groth16Bls12381Receipt, String> {
    if !bytes.starts_with(SNARK_GROTH16_BLS12381_RECEIPT_TAG) {
        return Err("groth16 bls12381 receipt missing tag".to_string());
    }
    let mut off = SNARK_GROTH16_BLS12381_RECEIPT_TAG.len();
    let vk_len = read_u32_be(bytes, &mut off)? as usize;
    let proof_len = read_u32_be(bytes, &mut off)? as usize;
    let pub_len = read_u32_be(bytes, &mut off)? as usize;
    let vk_bytes = read_vec(bytes, &mut off, vk_len)?;
    let proof_bytes = read_vec(bytes, &mut off, proof_len)?;
    let pub_inputs_bytes = read_vec(bytes, &mut off, pub_len)?;
    if off != bytes.len() {
        return Err("groth16 bls12381 receipt trailing bytes".to_string());
    }
    Ok(Groth16Bls12381Receipt {
        vk_bytes,
        proof_bytes,
        pub_inputs_bytes,
    })
}

pub fn decode_groth16_proof_bytes(bytes: &[u8]) -> Result<Groth16Proof, String> {
    if bytes.len() != GROTH16_BLS12381_PROOF_BYTES_LEN {
        return Err(format!(
            "groth16 bls12381 proof bytes must be {GROTH16_BLS12381_PROOF_BYTES_LEN} bytes"
        ));
    }
    let mut off = 0usize;
    let a = decode_g1(&bytes[off..off + 96])?;
    off += 96;
    let b = decode_g2(&bytes[off..off + 192])?;
    off += 192;
    let c = decode_g1(&bytes[off..off + 96])?;
    Ok(Groth16Proof { a, b, c })
}

pub fn encode_groth16_proof_bytes(proof: &Groth16Proof) -> [u8; GROTH16_BLS12381_PROOF_BYTES_LEN] {
    let mut out = [0u8; GROTH16_BLS12381_PROOF_BYTES_LEN];
    let mut off = 0usize;
    let a = encode_g1(&proof.a);
    out[off..off + 96].copy_from_slice(&a);
    off += 96;
    let b = encode_g2(&proof.b);
    out[off..off + 192].copy_from_slice(&b);
    off += 192;
    let c = encode_g1(&proof.c);
    out[off..off + 96].copy_from_slice(&c);
    out
}

pub fn decode_groth16_vk_bytes(bytes: &[u8]) -> Result<Groth16VerifyingKey, String> {
    if bytes.len() < 96 + 192 * 3 + 4 {
        return Err("groth16 bls12381 vk bytes too short".to_string());
    }
    let mut off = 0usize;
    let alpha_g1 = decode_g1(&bytes[off..off + 96])?;
    off += 96;
    let beta_g2 = decode_g2(&bytes[off..off + 192])?;
    off += 192;
    let gamma_g2 = decode_g2(&bytes[off..off + 192])?;
    off += 192;
    let delta_g2 = decode_g2(&bytes[off..off + 192])?;
    off += 192;

    let ic_len = read_u32_be(bytes, &mut off)? as usize;
    let expected = off + ic_len * 96;
    if expected != bytes.len() {
        return Err("groth16 bls12381 vk bytes length mismatch".to_string());
    }
    let mut ic = Vec::with_capacity(ic_len);
    for _ in 0..ic_len {
        let g = decode_g1(&bytes[off..off + 96])?;
        off += 96;
        ic.push(g);
    }
    if ic.is_empty() {
        return Err("groth16 bls12381 vk ic must contain at least one point".to_string());
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
        return Err("groth16 bls12381 public inputs must be 32-byte aligned".to_string());
    }
    let mut inputs = Vec::with_capacity(bytes.len() / 32);
    let modulus = BigUint::from_bytes_be(&Fr::MODULUS.to_bytes_be());
    for chunk in bytes.chunks(32) {
        let mut tmp = [0u8; 32];
        tmp.copy_from_slice(chunk);
        let big = BigUint::from_bytes_be(&tmp);
        if big >= modulus {
            return Err("groth16 bls12381 public input not canonical".to_string());
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
        return Err("groth16 bls12381 public input length mismatch".to_string());
    }
    let ark_vk = VerifyingKey::<Bls12_381> {
        alpha_g1: vk.alpha_g1,
        beta_g2: vk.beta_g2,
        gamma_g2: vk.gamma_g2,
        delta_g2: vk.delta_g2,
        gamma_abc_g1: vk.ic.clone(),
    };
    let pvk = prepare_verifying_key(&ark_vk);
    let ark_proof = ArkProof::<Bls12_381> {
        a: proof.a,
        b: proof.b,
        c: proof.c,
    };
    Groth16::<Bls12_381>::verify_proof(&pvk, &ark_proof, public_inputs)
        .map_err(|e| format!("groth16 bls12381 verify error: {e:?}"))
}

pub fn verify_groth16_bls12381_receipt(receipt_bytes: &[u8]) -> Result<Groth16Bls12381Receipt, String> {
    let receipt = decode_groth16_bls12381_receipt(receipt_bytes)
        .map_err(|e| wrap_stage("groth16_bls12381", "decode", e))?;
    let vk = decode_groth16_vk_bytes(&receipt.vk_bytes)
        .map_err(|e| wrap_stage("groth16_bls12381", "vk decode", e))?;
    let proof = decode_groth16_proof_bytes(&receipt.proof_bytes)
        .map_err(|e| wrap_stage("groth16_bls12381", "proof decode", e))?;
    let inputs = decode_groth16_public_inputs(&receipt.pub_inputs_bytes)
        .map_err(|e| wrap_stage("groth16_bls12381", "inputs decode", e))?;
    let ok = verify_groth16_proof(&vk, &proof, &inputs)
        .map_err(|e| wrap_stage("groth16_bls12381", "verify", e))?;
    if !ok {
        return Err(wrap("groth16_bls12381", "verification failed"));
    }
    Ok(receipt)
}

pub fn derive_glyph_artifact_from_groth16_bls12381_receipt(
    receipt_bytes: &[u8],
) -> Result<([u8; 32], [u8; 32], u128), String> {
    let receipt = verify_groth16_bls12381_receipt(receipt_bytes)?;
    let vk_hash = keccak256_with_domain(SNARK_GROTH16_BLS12381_VK_HASH_DOMAIN, &receipt.vk_bytes);
    let proof_hash = keccak256(&receipt.proof_bytes);
    let pub_hash = keccak256(&receipt.pub_inputs_bytes);
    let commitment_tag = keccak256_concat_domain(SNARK_GROTH16_BLS12381_DOMAIN, &vk_hash, &proof_hash);
    let point_tag = keccak256_concat_domain(SNARK_GROTH16_BLS12381_DOMAIN, &vk_hash, &pub_hash);
    let claim_hash = keccak256_concat_domain(SNARK_GROTH16_BLS12381_DOMAIN, &commitment_tag, &point_tag);
    let mut claim_bytes = [0u8; 16];
    claim_bytes.copy_from_slice(&claim_hash[..16]);
    let claim128 = u128::from_be_bytes(claim_bytes);
    Ok((commitment_tag, point_tag, claim128))
}

fn fq_from_be_bytes_strict(bytes: [u8; 48]) -> Result<Fq, String> {
    let modulus = BigUint::from_bytes_be(&Fq::MODULUS.to_bytes_be());
    let big = BigUint::from_bytes_be(&bytes);
    if big >= modulus {
        return Err("bls12381 fq not canonical".to_string());
    }
    Ok(Fq::from_be_bytes_mod_order(&bytes))
}

fn g1_from_be_bytes_strict(x_bytes: [u8; 48], y_bytes: [u8; 48]) -> Result<G1Affine, String> {
    let x = fq_from_be_bytes_strict(x_bytes)?;
    let y = fq_from_be_bytes_strict(y_bytes)?;
    let p = G1Affine::new_unchecked(x, y);
    if !p.is_on_curve() {
        return Err("bls12381 g1 not on curve".to_string());
    }
    if !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err("bls12381 g1 not in subgroup".to_string());
    }
    if p.is_zero() {
        return Err("bls12381 g1 is zero".to_string());
    }
    Ok(p)
}

fn g2_from_be_bytes_strict(
    x_im: [u8; 48],
    x_re: [u8; 48],
    y_im: [u8; 48],
    y_re: [u8; 48],
) -> Result<G2Affine, String> {
    let x_c0 = fq_from_be_bytes_strict(x_re).map_err(|_| "bls12381 g2 x_re not canonical".to_string())?;
    let x_c1 = fq_from_be_bytes_strict(x_im).map_err(|_| "bls12381 g2 x_im not canonical".to_string())?;
    let y_c0 = fq_from_be_bytes_strict(y_re).map_err(|_| "bls12381 g2 y_re not canonical".to_string())?;
    let y_c1 = fq_from_be_bytes_strict(y_im).map_err(|_| "bls12381 g2 y_im not canonical".to_string())?;
    let x = Fq2::new(x_c0, x_c1);
    let y = Fq2::new(y_c0, y_c1);
    let p = G2Affine::new_unchecked(x, y);
    if !p.is_on_curve() {
        return Err("bls12381 g2 not on curve".to_string());
    }
    if !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err("bls12381 g2 not in subgroup".to_string());
    }
    if p.is_zero() {
        return Err("bls12381 g2 is zero".to_string());
    }
    Ok(p)
}

fn decode_g1(bytes: &[u8]) -> Result<G1Affine, String> {
    let mut x = [0u8; 48];
    let mut y = [0u8; 48];
    x.copy_from_slice(&bytes[0..48]);
    y.copy_from_slice(&bytes[48..96]);
    g1_from_be_bytes_strict(x, y)
}

fn decode_g2(bytes: &[u8]) -> Result<G2Affine, String> {
    let mut x_im = [0u8; 48];
    let mut x_re = [0u8; 48];
    let mut y_im = [0u8; 48];
    let mut y_re = [0u8; 48];
    x_im.copy_from_slice(&bytes[0..48]);
    x_re.copy_from_slice(&bytes[48..96]);
    y_im.copy_from_slice(&bytes[96..144]);
    y_re.copy_from_slice(&bytes[144..192]);
    g2_from_be_bytes_strict(x_im, x_re, y_im, y_re)
}

fn encode_g1(p: &G1Affine) -> [u8; 96] {
    let mut out = [0u8; 96];
    let x_bytes = p.x.into_bigint().to_bytes_be();
    let y_bytes = p.y.into_bigint().to_bytes_be();
    let x_pad = pad_be_48(&x_bytes);
    let y_pad = pad_be_48(&y_bytes);
    out[0..48].copy_from_slice(&x_pad);
    out[48..96].copy_from_slice(&y_pad);
    out
}

fn encode_g2(p: &G2Affine) -> [u8; 192] {
    let mut out = [0u8; 192];
    let x_re = pad_be_48(&p.x.c0.into_bigint().to_bytes_be());
    let x_im = pad_be_48(&p.x.c1.into_bigint().to_bytes_be());
    let y_re = pad_be_48(&p.y.c0.into_bigint().to_bytes_be());
    let y_im = pad_be_48(&p.y.c1.into_bigint().to_bytes_be());
    out[0..48].copy_from_slice(&x_im);
    out[48..96].copy_from_slice(&x_re);
    out[96..144].copy_from_slice(&y_im);
    out[144..192].copy_from_slice(&y_re);
    out
}

fn pad_be_48(bytes: &[u8]) -> [u8; 48] {
    let mut out = [0u8; 48];
    let start = 48 - bytes.len();
    out[start..].copy_from_slice(bytes);
    out
}

fn keccak256_with_domain(domain: &[u8], data: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(domain.len() + data.len());
    input.extend_from_slice(domain);
    input.extend_from_slice(data);
    keccak256(&input)
}

fn keccak256_concat_domain(domain: &[u8], left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut input = Vec::new();
    input.extend_from_slice(domain);
    input.extend_from_slice(left);
    input.extend_from_slice(right);
    keccak256(&input)
}

fn read_u32_be(bytes: &[u8], off: &mut usize) -> Result<u32, String> {
    let s = bytes
        .get(*off..*off + 4)
        .ok_or_else(|| "groth16 bls12381 receipt eof".to_string())?;
    *off += 4;
    Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_vec(bytes: &[u8], off: &mut usize, len: usize) -> Result<Vec<u8>, String> {
    let s = bytes
        .get(*off..*off + len)
        .ok_or_else(|| "groth16 bls12381 receipt eof".to_string())?;
    *off += len;
    Ok(s.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError};
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
    fn test_bls12381_receipt_roundtrip_and_artifact() {
        let mut rng = StdRng::seed_from_u64(0x1234_5678);
        let a = Fr::from(3u64);
        let b = Fr::from(9u64);
        let c = a * b;
        let circuit = MulCircuit { a, b, c };
        let params = match Groth16::<Bls12_381>::generate_random_parameters_with_reduction(
            circuit.clone(),
            &mut rng,
        ) {
            Ok(params) => params,
            Err(err) => {
                assert!(false, "params: {err:?}");
                return;
            }
        };
        let proof = match Groth16::<Bls12_381>::create_random_proof_with_reduction(
            circuit,
            &params,
            &mut rng,
        ) {
            Ok(proof) => proof,
            Err(err) => {
                assert!(false, "proof: {err:?}");
                return;
            }
        };
        let vk = params.vk;
        let public_inputs = vec![c];
        let ok = match Groth16::<Bls12_381>::verify_proof(
            &prepare_verifying_key(&vk),
            &proof,
            &public_inputs,
        ) {
            Ok(ok) => ok,
            Err(err) => {
                assert!(false, "verify: {err:?}");
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
        let pub_inputs_bytes = encode_groth16_public_inputs(&public_inputs);
        let receipt = Groth16Bls12381Receipt {
            vk_bytes: vk_bytes.clone(),
            proof_bytes: proof_bytes.to_vec(),
            pub_inputs_bytes: pub_inputs_bytes.clone(),
        };
        let receipt_bytes = encode_groth16_bls12381_receipt(&receipt);
        assert!(verify_groth16_bls12381_receipt(&receipt_bytes).is_ok());
        let (commitment_tag, point_tag, claim128) =
            match derive_glyph_artifact_from_groth16_bls12381_receipt(&receipt_bytes) {
                Ok(values) => values,
                Err(err) => {
                    assert!(false, "artifact: {err}");
                    return;
                }
            };
        assert_ne!(commitment_tag, [0u8; 32]);
        assert_ne!(point_tag, [0u8; 32]);
        assert_ne!(claim128, 0u128);
    }

    #[test]
    fn test_bls12381_fixture_emit() {
        let mut rng = StdRng::seed_from_u64(0x9876_5432);
        let a = Fr::from(7u64);
        let b = Fr::from(5u64);
        let c = a * b;
        let circuit = MulCircuit { a, b, c };
        let params = match Groth16::<Bls12_381>::generate_random_parameters_with_reduction(
            circuit.clone(),
            &mut rng,
        ) {
            Ok(params) => params,
            Err(err) => {
                assert!(false, "params: {err:?}");
                return;
            }
        };
        let proof = match Groth16::<Bls12_381>::create_random_proof_with_reduction(
            circuit,
            &params,
            &mut rng,
        ) {
            Ok(proof) => proof,
            Err(err) => {
                assert!(false, "proof: {err:?}");
                return;
            }
        };
        let vk = params.vk;
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
        let pub_inputs_bytes = encode_groth16_public_inputs(&[c]);
        let receipt = Groth16Bls12381Receipt {
            vk_bytes,
            proof_bytes: proof_bytes.to_vec(),
            pub_inputs_bytes,
        };
        let payload = format!("receipt_hex={}\n", hex::encode(encode_groth16_bls12381_receipt(&receipt)));
        let path = "scripts/tools/fixtures/groth16_bls12381_receipt.txt";
        let target = if std::path::Path::new(path).exists() {
            format!("{path}.candidate")
        } else {
            path.to_string()
        };
        if let Err(err) = std::fs::write(&target, payload) {
            assert!(false, "fixture write: {err}");
            return;
        }
    }
}
