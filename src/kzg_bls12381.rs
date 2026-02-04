//! BLS12-381 KZG receipt handling for SNARK KZG.
//!
//! Verification is off-chain only. The receipt is bound to GLYPH artifacts and
//! later proven via GLYPH sumcheck.

use ark_bls12_381::{Bls12_381, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ec::pairing::Pairing;
use ark_ff::{BigInteger, PrimeField};
use num_bigint::BigUint;

use crate::adapters::keccak256;
use crate::adapter_error::{wrap, wrap_stage};

pub const SNARK_KZG_BLS12381_RECEIPT_TAG: &[u8] = b"GLYPH_SNARK_KZG_BLS12381_RECEIPT";
pub const SNARK_KZG_BLS12381_DOMAIN: &[u8] = b"GLYPH_ADAPTER_SNARK_KZG_BLS12381";
pub const SNARK_KZG_BLS12381_VK_HASH_DOMAIN: &[u8] = b"GLYPH_SNARK_KZG_BLS12381_VK_HASH";

#[derive(Clone, Debug)]
pub struct KzgVk {
    pub g1: G1Affine,
    pub g2: G2Affine,
    pub g2_s: G2Affine,
}

#[derive(Clone, Debug)]
pub struct KzgProof {
    pub commitment: G1Affine,
    pub proof: G1Affine,
}

#[derive(Clone, Debug)]
pub struct KzgPublicInputs {
    pub z: Fr,
    pub y: Fr,
}

#[derive(Clone, Debug)]
pub struct KzgBls12381Receipt {
    pub vk_bytes: Vec<u8>,
    pub proof_bytes: Vec<u8>,
    pub pub_inputs_bytes: Vec<u8>,
}

pub fn encode_kzg_bls12381_receipt(receipt: &KzgBls12381Receipt) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(SNARK_KZG_BLS12381_RECEIPT_TAG);
    out.extend_from_slice(&(receipt.vk_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&(receipt.proof_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&(receipt.pub_inputs_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&receipt.vk_bytes);
    out.extend_from_slice(&receipt.proof_bytes);
    out.extend_from_slice(&receipt.pub_inputs_bytes);
    out
}

pub fn decode_kzg_bls12381_receipt(bytes: &[u8]) -> Result<KzgBls12381Receipt, String> {
    if !bytes.starts_with(SNARK_KZG_BLS12381_RECEIPT_TAG) {
        return Err("kzg bls12381 receipt missing tag".to_string());
    }
    let mut off = SNARK_KZG_BLS12381_RECEIPT_TAG.len();
    let vk_len = read_u32_be(bytes, &mut off)? as usize;
    let proof_len = read_u32_be(bytes, &mut off)? as usize;
    let pub_len = read_u32_be(bytes, &mut off)? as usize;
    let vk_bytes = read_vec(bytes, &mut off, vk_len)?;
    let proof_bytes = read_vec(bytes, &mut off, proof_len)?;
    let pub_inputs_bytes = read_vec(bytes, &mut off, pub_len)?;
    if off != bytes.len() {
        return Err("kzg bls12381 receipt trailing bytes".to_string());
    }
    Ok(KzgBls12381Receipt {
        vk_bytes,
        proof_bytes,
        pub_inputs_bytes,
    })
}

pub fn encode_kzg_vk_bytes(vk: &KzgVk) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&encode_g1(&vk.g1));
    out.extend_from_slice(&encode_g2(&vk.g2));
    out.extend_from_slice(&encode_g2(&vk.g2_s));
    out
}

pub fn decode_kzg_vk_bytes(bytes: &[u8]) -> Result<KzgVk, String> {
    if bytes.len() != 96 + 192 + 192 {
        return Err("kzg bls12381 vk length mismatch".to_string());
    }
    let mut off = 0usize;
    let g1 = decode_g1(&bytes[off..off + 96])?;
    off += 96;
    let g2 = decode_g2(&bytes[off..off + 192])?;
    off += 192;
    let g2_s = decode_g2(&bytes[off..off + 192])?;
    if g1 != G1Affine::generator() {
        return Err("kzg bls12381 vk g1 generator mismatch".to_string());
    }
    if g2 != G2Affine::generator() {
        return Err("kzg bls12381 vk g2 generator mismatch".to_string());
    }
    Ok(KzgVk { g1, g2, g2_s })
}

pub fn encode_kzg_proof_bytes(proof: &KzgProof) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&encode_g1(&proof.commitment));
    out.extend_from_slice(&encode_g1(&proof.proof));
    out
}

pub fn decode_kzg_proof_bytes(bytes: &[u8]) -> Result<KzgProof, String> {
    if bytes.len() != 96 + 96 {
        return Err("kzg bls12381 proof length mismatch".to_string());
    }
    let commitment = decode_g1(&bytes[0..96])?;
    let proof = decode_g1(&bytes[96..192])?;
    Ok(KzgProof { commitment, proof })
}

pub fn encode_kzg_public_inputs_bytes(inputs: &KzgPublicInputs) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&fr_to_be_bytes(inputs.z));
    out.extend_from_slice(&fr_to_be_bytes(inputs.y));
    out
}

pub fn decode_kzg_public_inputs_bytes(bytes: &[u8]) -> Result<KzgPublicInputs, String> {
    if bytes.len() != 64 {
        return Err("kzg bls12381 public inputs length mismatch".to_string());
    }
    let mut z_bytes = [0u8; 32];
    let mut y_bytes = [0u8; 32];
    z_bytes.copy_from_slice(&bytes[0..32]);
    y_bytes.copy_from_slice(&bytes[32..64]);
    let z = fr_from_be_bytes_strict(z_bytes)?;
    let y = fr_from_be_bytes_strict(y_bytes)?;
    Ok(KzgPublicInputs { z, y })
}

pub fn verify_kzg_proof(vk: &KzgVk, proof: &KzgProof, inputs: &KzgPublicInputs) -> Result<bool, String> {
    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();
    let y_g1 = g1.mul_bigint(inputs.y.into_bigint());
    let left = (G1Projective::from(proof.commitment) - y_g1).into_affine();
    let z_g2 = g2.mul_bigint(inputs.z.into_bigint());
    let right = (G2Projective::from(vk.g2_s) - z_g2).into_affine();

    let lhs = Bls12_381::pairing(left, g2);
    let rhs = Bls12_381::pairing(proof.proof, right);
    Ok(lhs == rhs)
}

pub fn verify_kzg_bls12381_receipt(receipt_bytes: &[u8]) -> Result<KzgBls12381Receipt, String> {
    let receipt = decode_kzg_bls12381_receipt(receipt_bytes)
        .map_err(|e| wrap_stage("kzg_bls12381", "decode", e))?;
    let vk = decode_kzg_vk_bytes(&receipt.vk_bytes)
        .map_err(|e| wrap_stage("kzg_bls12381", "vk decode", e))?;
    let proof = decode_kzg_proof_bytes(&receipt.proof_bytes)
        .map_err(|e| wrap_stage("kzg_bls12381", "proof decode", e))?;
    let inputs = decode_kzg_public_inputs_bytes(&receipt.pub_inputs_bytes)
        .map_err(|e| wrap_stage("kzg_bls12381", "inputs decode", e))?;
    let ok = verify_kzg_proof(&vk, &proof, &inputs)
        .map_err(|e| wrap_stage("kzg_bls12381", "verify", e))?;
    if !ok {
        return Err(wrap("kzg_bls12381", "verification failed"));
    }
    Ok(receipt)
}

pub fn derive_glyph_artifact_from_kzg_bls12381_receipt(
    receipt_bytes: &[u8],
) -> Result<([u8; 32], [u8; 32], u128), String> {
    let receipt = verify_kzg_bls12381_receipt(receipt_bytes)?;
    let vk_hash = keccak256_with_domain(SNARK_KZG_BLS12381_VK_HASH_DOMAIN, &receipt.vk_bytes);
    let proof_hash = keccak256(&receipt.proof_bytes);
    let pub_hash = keccak256(&receipt.pub_inputs_bytes);
    let commitment_tag = keccak256_concat_domain(SNARK_KZG_BLS12381_DOMAIN, &vk_hash, &proof_hash);
    let point_tag = keccak256_concat_domain(SNARK_KZG_BLS12381_DOMAIN, &vk_hash, &pub_hash);
    let claim_hash = keccak256_concat_domain(SNARK_KZG_BLS12381_DOMAIN, &commitment_tag, &point_tag);
    let mut claim_bytes = [0u8; 16];
    claim_bytes.copy_from_slice(&claim_hash[..16]);
    let claim128 = u128::from_be_bytes(claim_bytes);
    Ok((commitment_tag, point_tag, claim128))
}

fn fr_to_be_bytes(x: Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut bytes = x.into_bigint().to_bytes_be();
    if bytes.len() > 32 {
        bytes = bytes[bytes.len() - 32..].to_vec();
    }
    let start = 32 - bytes.len();
    out[start..].copy_from_slice(&bytes);
    out
}

fn fr_from_be_bytes_strict(bytes: [u8; 32]) -> Result<Fr, String> {
    let fr = Fr::from_be_bytes_mod_order(&bytes);
    if fr_to_be_bytes(fr) != bytes {
        return Err("bls12381 fr bytes not canonical".to_string());
    }
    Ok(fr)
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
        .ok_or_else(|| "kzg bls12381 receipt eof".to_string())?;
    *off += 4;
    Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_vec(bytes: &[u8], off: &mut usize, len: usize) -> Result<Vec<u8>, String> {
    let s = bytes
        .get(*off..*off + len)
        .ok_or_else(|| "kzg bls12381 receipt eof".to_string())?;
    *off += len;
    Ok(s.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Field;

    #[test]
    fn test_kzg_bls12381_roundtrip_and_artifact() {
        let s = Fr::from(5u64);
        let z = Fr::from(13u64);
        let coeffs = [Fr::from(3u64), Fr::from(11u64), Fr::from(7u64), Fr::from(24u64)];

        let eval_poly = |x: Fr| -> Fr {
            let mut pow = Fr::ONE;
            let mut acc = Fr::ZERO;
            for c in coeffs.iter() {
                acc += *c * pow;
                pow *= x;
            }
            acc
        };

        let y = eval_poly(z);
        let f_s = eval_poly(s);
        let denom = match (s - z).inverse() {
            Some(value) => value,
            None => {
                assert!(false, "s != z");
                return;
            }
        };
        let q_s = (f_s - y) * denom;

        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();
        let g2_s = g2.mul_bigint(s.into_bigint()).into_affine();
        let commitment = g1.mul_bigint(f_s.into_bigint()).into_affine();
        let proof = g1.mul_bigint(q_s.into_bigint()).into_affine();

        let vk = KzgVk { g1, g2, g2_s };
        let proof_data = KzgProof { commitment, proof };
        let inputs = KzgPublicInputs { z, y };
 
        let vk_bytes = encode_kzg_vk_bytes(&vk);
        let proof_bytes = encode_kzg_proof_bytes(&proof_data);
        let pub_bytes = encode_kzg_public_inputs_bytes(&inputs);
        let receipt = KzgBls12381Receipt {
            vk_bytes,
            proof_bytes,
            pub_inputs_bytes: pub_bytes,
        };
        let receipt_bytes = encode_kzg_bls12381_receipt(&receipt);
        assert!(verify_kzg_bls12381_receipt(&receipt_bytes).is_ok());
        let (commitment_tag, point_tag, claim128) =
            derive_glyph_artifact_from_kzg_bls12381_receipt(&receipt_bytes).unwrap_or_else(|_| {
                assert!(false, "artifact");
                ([0u8; 32], [0u8; 32], 0u128)
            });
        assert_ne!(commitment_tag, [0u8; 32]);
        assert_ne!(point_tag, [0u8; 32]);
        assert_ne!(claim128, 0u128);
    }

    #[test]
    fn test_kzg_bls12381_fixture_emit() {
        let s = Fr::from(9u64);
        let z = Fr::from(17u64);
        let coeffs = [Fr::from(2u64), Fr::from(5u64), Fr::from(19u64)];

        let eval_poly = |x: Fr| -> Fr {
            let mut pow = Fr::ONE;
            let mut acc = Fr::ZERO;
            for c in coeffs.iter() {
                acc += *c * pow;
                pow *= x;
            }
            acc
        };

        let y = eval_poly(z);
        let f_s = eval_poly(s);
        let denom = match (s - z).inverse() {
            Some(value) => value,
            None => {
                assert!(false, "s != z");
                return;
            }
        };
        let q_s = (f_s - y) * denom;

        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();
        let g2_s = g2.mul_bigint(s.into_bigint()).into_affine();
        let commitment = g1.mul_bigint(f_s.into_bigint()).into_affine();
        let proof = g1.mul_bigint(q_s.into_bigint()).into_affine();

        let vk = KzgVk { g1, g2, g2_s };
        let proof_data = KzgProof { commitment, proof };
        let inputs = KzgPublicInputs { z, y };
 
        let vk_bytes = encode_kzg_vk_bytes(&vk);
        let proof_bytes = encode_kzg_proof_bytes(&proof_data);
        let pub_bytes = encode_kzg_public_inputs_bytes(&inputs);
        let receipt = KzgBls12381Receipt {
            vk_bytes,
            proof_bytes,
            pub_inputs_bytes: pub_bytes,
        };
        let payload = format!("receipt_hex={}\n", hex::encode(encode_kzg_bls12381_receipt(&receipt)));
        let path = "scripts/tools/fixtures/kzg_bls12381_receipt.txt";
        let target = if std::path::Path::new(path).exists() {
            format!("{path}.candidate")
        } else {
            path.to_string()
        };
        if let Err(_) = std::fs::write(&target, payload) {
            assert!(false, "fixture write");
        }
    }
}
