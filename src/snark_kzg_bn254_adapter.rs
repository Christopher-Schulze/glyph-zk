//! Adapter KZG BN254 proof bridge into GLYPH artifacts.
//!
//! This module wires strict KZG opening parsing and verification into the GLYPH artifact boundary.

use ark_bn254::{Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};

use crate::adapter_ir::kernel_id;
use crate::adapters::keccak256;
use crate::bn254_curve::{g1_from_be_bytes_strict, g1_to_be_bytes, g2_from_be_bytes_strict, g2_to_be_bytes};

pub const KZG_BN254_VK_CANONICAL_DOMAIN: &[u8] = b"GLYPH_KZG_BN254_CANONICAL_VK";
pub const KZG_BN254_PARAMS_DOMAIN: &[u8] = b"GLYPH_KZG_BN254_PARAMS";
pub const KZG_BN254_PROOF_CANONICAL_DOMAIN: &[u8] = b"GLYPH_KZG_BN254_PROOF";
pub const KZG_BN254_PUBLIC_INPUTS_DOMAIN: &[u8] = b"GLYPH_KZG_BN254_PUBLIC_INPUTS";
pub const GLYPH_KZG_BN254_INSTANCE_DOMAIN: &[u8] = b"GLYPH_KZG_BN254_INSTANCE";

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
        return Err("fr bytes not canonical".to_string());
    }
    Ok(fr)
}

pub fn encode_kzg_vk_bytes(vk: &KzgVk) -> Vec<u8> {
    let (g1_x, g1_y) = g1_to_be_bytes(&vk.g1);
    let (g2_x_im, g2_x_re, g2_y_im, g2_y_re) = g2_to_be_bytes(&vk.g2);
    let (g2s_x_im, g2s_x_re, g2s_y_im, g2s_y_re) = g2_to_be_bytes(&vk.g2_s);

    let mut out = Vec::new();
    out.extend_from_slice(KZG_BN254_VK_CANONICAL_DOMAIN);
    out.extend_from_slice(&g1_x);
    out.extend_from_slice(&g1_y);
    out.extend_from_slice(&g2_x_im);
    out.extend_from_slice(&g2_x_re);
    out.extend_from_slice(&g2_y_im);
    out.extend_from_slice(&g2_y_re);
    out.extend_from_slice(&g2s_x_im);
    out.extend_from_slice(&g2s_x_re);
    out.extend_from_slice(&g2s_y_im);
    out.extend_from_slice(&g2s_y_re);
    out
}

pub fn encode_kzg_params_bytes(vk: &KzgVk) -> Vec<u8> {
    let (g1_x, g1_y) = g1_to_be_bytes(&vk.g1);
    let (g2_x_im, g2_x_re, g2_y_im, g2_y_re) = g2_to_be_bytes(&vk.g2);
    let (g2s_x_im, g2s_x_re, g2s_y_im, g2s_y_re) = g2_to_be_bytes(&vk.g2_s);

    let mut out = Vec::new();
    out.extend_from_slice(KZG_BN254_PARAMS_DOMAIN);
    out.extend_from_slice(&g1_x);
    out.extend_from_slice(&g1_y);
    out.extend_from_slice(&g2_x_im);
    out.extend_from_slice(&g2_x_re);
    out.extend_from_slice(&g2_y_im);
    out.extend_from_slice(&g2_y_re);
    out.extend_from_slice(&g2s_x_im);
    out.extend_from_slice(&g2s_x_re);
    out.extend_from_slice(&g2s_y_im);
    out.extend_from_slice(&g2s_y_re);
    out
}

#[allow(dead_code)]
fn kzg_params_hash_from_vk(vk: &KzgVk) -> [u8; 32] {
    keccak256(&encode_kzg_params_bytes(vk))
}

pub fn decode_kzg_vk_bytes(bytes: &[u8]) -> Result<KzgVk, String> {
    if !bytes.starts_with(KZG_BN254_VK_CANONICAL_DOMAIN) {
        return Err("kzg bn254 vk bytes missing domain tag".to_string());
    }
    let mut off = KZG_BN254_VK_CANONICAL_DOMAIN.len();

    let read32 = |bytes: &[u8], off: &mut usize| -> Result<[u8; 32], String> {
        let s = bytes
            .get(*off..*off + 32)
            .ok_or_else(|| "unexpected EOF".to_string())?;
        let mut out = [0u8; 32];
        out.copy_from_slice(s);
        *off += 32;
        Ok(out)
    };

    let g1_x = read32(bytes, &mut off)?;
    let g1_y = read32(bytes, &mut off)?;
    let g2_x_im = read32(bytes, &mut off)?;
    let g2_x_re = read32(bytes, &mut off)?;
    let g2_y_im = read32(bytes, &mut off)?;
    let g2_y_re = read32(bytes, &mut off)?;
    let g2s_x_im = read32(bytes, &mut off)?;
    let g2s_x_re = read32(bytes, &mut off)?;
    let g2s_y_im = read32(bytes, &mut off)?;
    let g2s_y_re = read32(bytes, &mut off)?;

    if off != bytes.len() {
        return Err("kzg bn254 vk bytes trailing data".to_string());
    }

    let g1 = g1_from_be_bytes_strict(g1_x, g1_y)?;
    let g2 = g2_from_be_bytes_strict(g2_x_im, g2_x_re, g2_y_im, g2_y_re)?;
    let g2_s = g2_from_be_bytes_strict(g2s_x_im, g2s_x_re, g2s_y_im, g2s_y_re)?;

    if g1 != G1Affine::generator() {
        return Err("kzg bn254 vk g1 generator mismatch".to_string());
    }
    if g2 != G2Affine::generator() {
        return Err("kzg bn254 vk g2 generator mismatch".to_string());
    }

    Ok(KzgVk { g1, g2, g2_s })
}

pub fn encode_kzg_proof_bytes(proof: &KzgProof) -> Vec<u8> {
    let (c_x, c_y) = g1_to_be_bytes(&proof.commitment);
    let (p_x, p_y) = g1_to_be_bytes(&proof.proof);
    let mut out = Vec::new();
    out.extend_from_slice(KZG_BN254_PROOF_CANONICAL_DOMAIN);
    out.extend_from_slice(&c_x);
    out.extend_from_slice(&c_y);
    out.extend_from_slice(&p_x);
    out.extend_from_slice(&p_y);
    out
}

pub fn decode_kzg_proof_bytes(bytes: &[u8]) -> Result<KzgProof, String> {
    if !bytes.starts_with(KZG_BN254_PROOF_CANONICAL_DOMAIN) {
        return Err("kzg bn254 proof bytes missing domain tag".to_string());
    }
    let mut off = KZG_BN254_PROOF_CANONICAL_DOMAIN.len();
    let read32 = |bytes: &[u8], off: &mut usize| -> Result<[u8; 32], String> {
        let s = bytes
            .get(*off..*off + 32)
            .ok_or_else(|| "unexpected EOF".to_string())?;
        let mut out = [0u8; 32];
        out.copy_from_slice(s);
        *off += 32;
        Ok(out)
    };

    let c_x = read32(bytes, &mut off)?;
    let c_y = read32(bytes, &mut off)?;
    let p_x = read32(bytes, &mut off)?;
    let p_y = read32(bytes, &mut off)?;
    if off != bytes.len() {
        return Err("kzg bn254 proof bytes trailing data".to_string());
    }

    let commitment = g1_from_be_bytes_strict(c_x, c_y)?;
    let proof = g1_from_be_bytes_strict(p_x, p_y)?;
    Ok(KzgProof { commitment, proof })
}

pub fn encode_kzg_public_inputs_bytes(inputs: &KzgPublicInputs) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(KZG_BN254_PUBLIC_INPUTS_DOMAIN);
    out.extend_from_slice(&fr_to_be_bytes(inputs.z));
    out.extend_from_slice(&fr_to_be_bytes(inputs.y));
    out
}

pub fn decode_kzg_public_inputs_bytes(bytes: &[u8]) -> Result<KzgPublicInputs, String> {
    if !bytes.starts_with(KZG_BN254_PUBLIC_INPUTS_DOMAIN) {
        return Err("kzg bn254 public inputs missing domain tag".to_string());
    }
    let mut off = KZG_BN254_PUBLIC_INPUTS_DOMAIN.len();
    let read32 = |bytes: &[u8], off: &mut usize| -> Result<[u8; 32], String> {
        let s = bytes
            .get(*off..*off + 32)
            .ok_or_else(|| "unexpected EOF".to_string())?;
        let mut out = [0u8; 32];
        out.copy_from_slice(s);
        *off += 32;
        Ok(out)
    };
    let z_bytes = read32(bytes, &mut off)?;
    let y_bytes = read32(bytes, &mut off)?;
    if off != bytes.len() {
        return Err("kzg bn254 public inputs trailing data".to_string());
    }
    let z = fr_from_be_bytes_strict(z_bytes)?;
    let y = fr_from_be_bytes_strict(y_bytes)?;
    Ok(KzgPublicInputs { z, y })
}

pub fn derive_glyph_artifact_from_kzg_bn254(
    adapter_vk_bytes: &[u8],
    adapter_statement_bytes: &[u8],
    raw_vk_bytes: &[u8],
    raw_proof_bytes: &[u8],
    raw_public_inputs_bytes: &[u8],
) -> Result<([u8; 32], [u8; 32], u128), String> {
    let ir = crate::adapter_ir::AdapterIr {
        version: 1,
        ops: vec![crate::adapter_ir::AdapterIrOp {
            kernel_id: kernel_id::KZG_BN254_VERIFY,
            args: Vec::new(),
        }],
    };
    crate::adapter_ir::derive_glyph_artifact_from_kzg_bn254_ir(
        &ir.encode(),
        adapter_vk_bytes,
        adapter_statement_bytes,
        raw_vk_bytes,
        raw_proof_bytes,
        raw_public_inputs_bytes,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::SNARK_KZG_PLONK_ID;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::Field;
    use std::ops::Neg;

    fn kzg_verify_native(vk: &KzgVk, proof: &KzgProof, inputs: &KzgPublicInputs) -> bool {
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

    #[test]
    fn test_kzg_bn254_vk_roundtrip() {
        let vk = KzgVk {
            g1: G1Affine::generator(),
            g2: G2Affine::generator(),
            g2_s: G2Affine::generator(),
        };
        let bytes = encode_kzg_vk_bytes(&vk);
        let parsed = match decode_kzg_vk_bytes(&bytes) {
            Ok(parsed) => parsed,
            Err(err) => {
                assert!(false, "kzg vk decode: {err}");
                return;
            }
        };
        assert_eq!(parsed.g1, vk.g1);
        assert_eq!(parsed.g2, vk.g2);
        assert_eq!(parsed.g2_s, vk.g2_s);

        let mut tampered = bytes.clone();
        tampered[0] ^= 1;
        assert!(decode_kzg_vk_bytes(&tampered).is_err());
    }

    #[test]
    fn test_kzg_bn254_public_inputs_roundtrip() {
        let inputs = KzgPublicInputs {
            z: Fr::from(7u64),
            y: Fr::from(11u64),
        };
        let bytes = encode_kzg_public_inputs_bytes(&inputs);
        let parsed = match decode_kzg_public_inputs_bytes(&bytes) {
            Ok(parsed) => parsed,
            Err(err) => {
                assert!(false, "kzg inputs decode: {err}");
                return;
            }
        };
        assert_eq!(parsed.z, inputs.z);
        assert_eq!(parsed.y, inputs.y);

        let mut tampered = bytes.clone();
        tampered[0] ^= 1;
        assert!(decode_kzg_public_inputs_bytes(&tampered).is_err());
    }

    #[test]
    fn test_kzg_bn254_trace_event_consistency() {
        let s = Fr::from(5u64);
        let z = Fr::from(13u64);
        let coeffs = [Fr::from(3u64), Fr::from(11u64), Fr::from(7u64), Fr::from(2u64)];

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
            Some(denom) => denom,
            None => {
                assert!(false, "s == z");
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

        let events = match crate::bn254_pairing_trace::record_kzg_pairing_ops(
            vk.g1,
            vk.g2,
            vk.g2_s,
            proof_data.commitment,
            proof_data.proof,
            inputs.z,
            inputs.y,
        )
        {
            Ok(events) => events,
            Err(err) => {
                assert!(false, "kzg trace: {err}");
                return;
            }
        };
        if let Err(err) = crate::bn254_ops::validate_bn254_op_trace_batch(&events) {
            assert!(false, "trace batch validate: {err}");
            return;
        }
    }

    #[test]
    fn test_kzg_bn254_adapter_binding_rejects_mismatch() {
        let s = Fr::from(5u64);
        let z = Fr::from(13u64);
        let coeffs = [Fr::from(3u64), Fr::from(11u64), Fr::from(7u64), Fr::from(2u64)];

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
            Some(denom) => denom,
            None => {
                assert!(false, "s == z");
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

        let raw_vk_bytes = encode_kzg_vk_bytes(&vk);
        let raw_proof_bytes = encode_kzg_proof_bytes(&proof_data);
        let raw_inputs_bytes = encode_kzg_public_inputs_bytes(&inputs);

        let input_layout_hash = keccak256(b"kzg-bn254-test-layout");
        let vk_hash = keccak256(&raw_vk_bytes);
        let pub_hash = keccak256(&raw_inputs_bytes);
        let params_hash = kzg_params_hash_from_vk(&vk);
        let g2_s_precomp = crate::bn254_pairing_trace::encode_g2_precomp_bytes(g2_s);
        let adapter_vk_bytes = crate::adapters::kzg_bn254_vk_bytes_g2s_precomp(
            SNARK_KZG_PLONK_ID,
            &params_hash,
            &vk_hash,
            &input_layout_hash,
            &g2_s_precomp,
        );
        let adapter_statement_bytes =
            crate::adapters::kzg_bn254_statement_bytes(&input_layout_hash, &pub_hash);

        let mut bad_statement = adapter_statement_bytes.clone();
        bad_statement[0] ^= 1;

        assert!(derive_glyph_artifact_from_kzg_bn254(
            &adapter_vk_bytes,
            &bad_statement,
            &raw_vk_bytes,
            &raw_proof_bytes,
            &raw_inputs_bytes,
        )
        .is_err());
    }

    #[test]
    fn test_kzg_bn254_native_verify_smoke() {
        let s = Fr::from(5u64);
        let z = Fr::from(13u64);
        let coeffs = [Fr::from(3u64), Fr::from(11u64), Fr::from(7u64), Fr::from(2u64)];

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
            Some(denom) => denom,
            None => {
                assert!(false, "s == z");
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

        assert!(kzg_verify_native(&vk, &proof_data, &inputs));

        let mut bad_inputs = inputs.clone();
        bad_inputs.y += Fr::ONE;
        assert!(!kzg_verify_native(&vk, &proof_data, &bad_inputs));
    }

    #[cfg(feature = "dev-tools")]
    #[test]
    fn test_kzg_bn254_trace_stats() {
        let _env_lock = crate::test_utils::lock_env();
        let _trace =
            crate::test_utils::EnvVarGuard::set("GLYPH_KZG_BN254_TRACE_STATS", "1");
        let s = Fr::from(5u64);
        let z = Fr::from(13u64);
        let coeffs = [Fr::from(3u64), Fr::from(11u64), Fr::from(7u64), Fr::from(2u64)];

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
            Some(denom) => denom,
            None => {
                assert!(false, "s == z");
                return;
            }
        };
        let q_s = (f_s - y) * denom;

        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();
        let g2_s = g2.mul_bigint(s.into_bigint()).into_affine();
        let commitment = g1.mul_bigint(f_s.into_bigint()).into_affine();
        let proof = g1.mul_bigint(q_s.into_bigint()).into_affine();

        let use_precomp = std::env::var("GLYPH_KZG_BN254_TRACE_G2S_PRECOMP")
            .ok()
            .as_deref()
            == Some("1");
        if use_precomp {
            let g2_s_precomp = crate::bn254_pairing_trace::encode_g2_precomp_bytes(g2_s);
            let _events = match crate::bn254_pairing_trace::record_kzg_pairing_ops_with_precomp(
                g1,
                g2,
                g2_s,
                commitment,
                proof,
                z,
                y,
                Some(&g2_s_precomp),
            )
            {
                Ok(events) => events,
                Err(err) => {
                    assert!(false, "kzg trace precomp: {err}");
                    return;
                }
            };
        } else {
            let _events = match crate::bn254_pairing_trace::record_kzg_pairing_ops(
                g1,
                g2,
                g2_s,
                commitment,
                proof,
                z,
                y,
            )
            {
                Ok(events) => events,
                Err(err) => {
                    assert!(false, "kzg trace: {err}");
                    return;
                }
            };
        }
    }
}
