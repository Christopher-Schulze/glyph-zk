//! PLONK receipt adapter (backend-agnostic with explicit backend ids).

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use dusk_bytes::Serializable;
use dusk_bls12_381::BlsScalar;
use dusk_plonk::prelude::{Proof, Verifier};

use crate::adapters::keccak256;
use crate::adapter_error::{wrap, wrap_stage};
use crate::halo2_receipt;

pub const PLONK_RECEIPT_TAG: &[u8] = b"GLYPH_PLONK_RECEIPT";

pub const PLONK_COMMITMENT_TAG_DOMAIN: &[u8] = b"GLYPH_PLONK_COMMITMENT_TAG";
pub const PLONK_POINT_TAG_DOMAIN: &[u8] = b"GLYPH_PLONK_POINT_TAG";
pub const PLONK_CLAIM_DOMAIN: &[u8] = b"GLYPH_PLONK_CLAIM";

pub const PLONK_CURVE_BN254: u8 = 0x01;
pub const PLONK_CURVE_BLS12381: u8 = 0x02;

pub const PLONK_BACKEND_GNARK: u8 = 0x01;
pub const PLONK_BACKEND_DUSK: u8 = 0x02;
pub const PLONK_BACKEND_GENERIC: u8 = 0x03;

pub const PLONK_ENCODING_BN254_BE: u8 = 0x01;
pub const PLONK_ENCODING_BLS_LE: u8 = 0x02;
pub const PLONK_ENCODING_HALO2_INSTANCES: u8 = 0x03;

pub const PLONK_PCS_KZG: u8 = 0x01;
pub const PLONK_PROTOCOL_PLONK: u8 = 0x01;
pub const PLONK_TRANSCRIPT_NATIVE: u8 = 0x01;
pub const PLONK_TRANSCRIPT_BLAKE2B: u8 = 0x02;

pub const PLONK_GENERIC_BACKEND_PARAMS_TAG: &[u8] = b"GLYPH_PLONK_GENERIC_PARAMS";
pub const PLONK_GENERIC_BACKEND_HALO2: u8 = 0x01;
pub const PLONK_GENERIC_BACKEND_GNARK: u8 = 0x02;
pub const PLONK_GENERIC_BACKEND_DUSK: u8 = 0x03;
pub const PLONK_HALO2_BACKEND_PARAMS_TAG: &[u8] = b"GLYPH_PLONK_HALO2_PARAMS";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlonkReceipt {
    pub backend_id: u8,
    pub curve_id: u8,
    pub encoding_id: u8,
    pub pcs_id: u8,
    pub protocol_id: u8,
    pub transcript_id: u8,
    pub backend_params_bytes: Vec<u8>,
    pub vk_bytes: Vec<u8>,
    pub public_inputs_bytes: Vec<u8>,
    pub proof_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlonkHalo2BackendParams {
    pub halo2_backend_id: u8,
    pub circuit_id: u8,
    pub compress_selectors: bool,
    pub circuit_params_bytes: Vec<u8>,
    pub params_bytes: Vec<u8>,
}

type PlonkVerifyFn = fn(&PlonkReceipt) -> Result<(), String>;

struct PlonkBackendSpec {
    expected_encoding: Option<u8>,
    expected_transcript: Option<u8>,
    allow_backend_params: bool,
    verify: PlonkVerifyFn,
}

fn plonk_backend_spec(backend_id: u8, curve_id: u8) -> Result<PlonkBackendSpec, String> {
    match (backend_id, curve_id) {
        (PLONK_BACKEND_GNARK, PLONK_CURVE_BN254) => Ok(PlonkBackendSpec {
            expected_encoding: Some(PLONK_ENCODING_BN254_BE),
            expected_transcript: Some(PLONK_TRANSCRIPT_NATIVE),
            allow_backend_params: false,
            verify: verify_plonk_gnark_bn254,
        }),
        (PLONK_BACKEND_DUSK, PLONK_CURVE_BLS12381) => Ok(PlonkBackendSpec {
            expected_encoding: Some(PLONK_ENCODING_BLS_LE),
            expected_transcript: Some(PLONK_TRANSCRIPT_NATIVE),
            allow_backend_params: false,
            verify: verify_plonk_dusk_bls12381,
        }),
        (PLONK_BACKEND_GENERIC, PLONK_CURVE_BN254)
        | (PLONK_BACKEND_GENERIC, PLONK_CURVE_BLS12381) => Ok(PlonkBackendSpec {
            expected_encoding: None,
            expected_transcript: None,
            allow_backend_params: true,
            verify: verify_plonk_generic_backend,
        }),
        _ => Err("unsupported plonk backend or curve".to_string()),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlonkGenericBackendParams {
    pub backend_kind: u8,
    pub payload: Vec<u8>,
}

pub fn encode_plonk_generic_backend_params(backend_kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        PLONK_GENERIC_BACKEND_PARAMS_TAG.len() + 1 + 4 + payload.len(),
    );
    out.extend_from_slice(PLONK_GENERIC_BACKEND_PARAMS_TAG);
    out.push(backend_kind);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

pub fn decode_plonk_generic_backend_params(
    bytes: &[u8],
) -> Result<PlonkGenericBackendParams, String> {
    if !bytes.starts_with(PLONK_GENERIC_BACKEND_PARAMS_TAG) {
        return Err("plonk generic backend params missing tag".to_string());
    }
    let mut off = PLONK_GENERIC_BACKEND_PARAMS_TAG.len();
    let backend_kind = read_u8(bytes, &mut off)?;
    let payload_len = read_u32_be(bytes, &mut off)? as usize;
    let payload = read_vec(bytes, &mut off, payload_len)?;
    if off != bytes.len() {
        return Err("plonk generic backend params trailing bytes".to_string());
    }
    Ok(PlonkGenericBackendParams {
        backend_kind,
        payload,
    })
}

pub fn encode_plonk_halo2_backend_params(params: &PlonkHalo2BackendParams) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        PLONK_HALO2_BACKEND_PARAMS_TAG.len()
            + 3
            + 4
            + params.params_bytes.len()
            + 4
            + params.circuit_params_bytes.len(),
    );
    out.extend_from_slice(PLONK_HALO2_BACKEND_PARAMS_TAG);
    out.push(params.halo2_backend_id);
    out.push(params.circuit_id);
    out.push(params.compress_selectors as u8);
    out.extend_from_slice(&(params.params_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&params.params_bytes);
    out.extend_from_slice(&(params.circuit_params_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&params.circuit_params_bytes);
    out
}

pub fn decode_plonk_halo2_backend_params(
    bytes: &[u8],
) -> Result<PlonkHalo2BackendParams, String> {
    if !bytes.starts_with(PLONK_HALO2_BACKEND_PARAMS_TAG) {
        return Err("plonk halo2 backend params missing tag".to_string());
    }
    let mut off = PLONK_HALO2_BACKEND_PARAMS_TAG.len();
    let halo2_backend_id = read_u8(bytes, &mut off)?;
    let circuit_id = read_u8(bytes, &mut off)?;
    let compress_selectors = read_u8(bytes, &mut off)? != 0;
    let params_len = read_u32_be(bytes, &mut off)? as usize;
    let params_bytes = read_vec(bytes, &mut off, params_len)?;
    let circuit_len = read_u32_be(bytes, &mut off)? as usize;
    let circuit_params_bytes = read_vec(bytes, &mut off, circuit_len)?;
    if off != bytes.len() {
        return Err("plonk halo2 backend params trailing bytes".to_string());
    }
    Ok(PlonkHalo2BackendParams {
        halo2_backend_id,
        circuit_id,
        compress_selectors,
        circuit_params_bytes,
        params_bytes,
    })
}

pub fn encode_plonk_receipt(receipt: &PlonkReceipt) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        PLONK_RECEIPT_TAG.len()
            + 6
            + 4
            + receipt.backend_params_bytes.len()
            + 4
            + receipt.vk_bytes.len()
            + 4
            + receipt.public_inputs_bytes.len()
            + 4
            + receipt.proof_bytes.len(),
    );
    out.extend_from_slice(PLONK_RECEIPT_TAG);
    out.push(receipt.curve_id);
    out.push(receipt.backend_id);
    out.push(receipt.encoding_id);
    out.push(receipt.pcs_id);
    out.push(receipt.protocol_id);
    out.push(receipt.transcript_id);
    out.extend_from_slice(&(receipt.backend_params_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&receipt.backend_params_bytes);
    out.extend_from_slice(&(receipt.vk_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&receipt.vk_bytes);
    out.extend_from_slice(&(receipt.public_inputs_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&receipt.public_inputs_bytes);
    out.extend_from_slice(&(receipt.proof_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&receipt.proof_bytes);
    out
}

pub fn decode_plonk_receipt(bytes: &[u8]) -> Result<PlonkReceipt, String> {
    if !bytes.starts_with(PLONK_RECEIPT_TAG) {
        return Err("plonk receipt missing tag".to_string());
    }
    let mut off = PLONK_RECEIPT_TAG.len();
    let curve_id = read_u8(bytes, &mut off)?;
    let backend_id = read_u8(bytes, &mut off)?;
    let encoding_id = read_u8(bytes, &mut off)?;
    let pcs_id = read_u8(bytes, &mut off)?;
    let protocol_id = read_u8(bytes, &mut off)?;
    let transcript_id = read_u8(bytes, &mut off)?;
    let params_len = read_u32_be(bytes, &mut off)? as usize;
    let backend_params_bytes = read_vec(bytes, &mut off, params_len)?;
    let vk_len = read_u32_be(bytes, &mut off)? as usize;
    let vk_bytes = read_vec(bytes, &mut off, vk_len)?;
    let pub_len = read_u32_be(bytes, &mut off)? as usize;
    let public_inputs_bytes = read_vec(bytes, &mut off, pub_len)?;
    let proof_len = read_u32_be(bytes, &mut off)? as usize;
    let proof_bytes = read_vec(bytes, &mut off, proof_len)?;
    if off != bytes.len() {
        return Err("plonk receipt has trailing bytes".to_string());
    }
    Ok(PlonkReceipt {
        backend_id,
        curve_id,
        encoding_id,
        pcs_id,
        protocol_id,
        transcript_id,
        backend_params_bytes,
        vk_bytes,
        public_inputs_bytes,
        proof_bytes,
    })
}

pub fn verify_plonk_receipt(bytes: &[u8]) -> Result<PlonkReceipt, String> {
    let receipt = decode_plonk_receipt(bytes).map_err(|e| wrap_stage("plonk", "decode", e))?;
    if receipt.vk_bytes.is_empty() {
        return Err(wrap("plonk", "vk bytes empty"));
    }
    if receipt.proof_bytes.is_empty() {
        return Err(wrap("plonk", "proof bytes empty"));
    }
    if receipt.pcs_id != PLONK_PCS_KZG {
        return Err(wrap("plonk", "pcs id unsupported"));
    }
    if receipt.protocol_id != PLONK_PROTOCOL_PLONK {
        return Err(wrap("plonk", "protocol id unsupported"));
    }
    let spec = plonk_backend_spec(receipt.backend_id, receipt.curve_id)
        .map_err(|e| wrap_stage("plonk", "backend", e))?;
    if let Some(expected_encoding) = spec.expected_encoding {
        if receipt.encoding_id != expected_encoding {
            return Err(wrap("plonk", "public input encoding mismatch"));
        }
    }
    if let Some(expected_transcript) = spec.expected_transcript {
        if receipt.transcript_id != expected_transcript {
            return Err(wrap("plonk", "transcript id unsupported"));
        }
    }
    if spec.allow_backend_params {
        if receipt.backend_params_bytes.is_empty() {
            return Err(wrap("plonk", "backend params missing"));
        }
    } else if !receipt.backend_params_bytes.is_empty() {
        return Err(wrap("plonk", "backend params unsupported"));
    }
    (spec.verify)(&receipt).map_err(|e| wrap_stage("plonk", "verify", e))?;
    Ok(receipt)
}

fn verify_plonk_gnark_bn254(receipt: &PlonkReceipt) -> Result<(), String> {
    if receipt.proof_bytes.len() < 64 {
        return Err("plonk bn254 proof bytes too short".to_string());
    }
    if receipt.vk_bytes.len() < 64 {
        return Err("plonk bn254 vk bytes too short".to_string());
    }
    let public_inputs = decode_bn254_public_inputs(&receipt.public_inputs_bytes)?;
    let ok = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        gnark_bn254_verifier::verify(
            &receipt.proof_bytes,
            &receipt.vk_bytes,
            &public_inputs,
            gnark_bn254_verifier::ProvingSystem::Plonk,
        )
    }))
    .map_err(|_| "plonk bn254 verifier panicked".to_string())?;
    if !ok {
        return Err("plonk bn254 verify failed".to_string());
    }
    Ok(())
}

fn verify_plonk_dusk_bls12381(receipt: &PlonkReceipt) -> Result<(), String> {
    let public_inputs = decode_bls_public_inputs(&receipt.public_inputs_bytes)?;
    let verifier = Verifier::try_from_bytes(&receipt.vk_bytes)
        .map_err(|e| format!("plonk bls verifier decode failed: {e:?}"))?;
    let proof_array: [u8; Proof::SIZE] = receipt
        .proof_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "plonk bls proof length mismatch".to_string())?;
    let proof =
        Proof::from_bytes(&proof_array).map_err(|e| format!("plonk bls proof decode failed: {e:?}"))?;
    verifier
        .verify(&proof, &public_inputs)
        .map_err(|e| format!("plonk bls verify failed: {e:?}"))?;
    Ok(())
}

pub fn derive_glyph_artifact_from_plonk_receipt(
    receipt_bytes: &[u8],
) -> Result<([u8; 32], [u8; 32], u128), String> {
    let receipt = verify_plonk_receipt(receipt_bytes)?;
    let proof_hash = keccak256(&receipt.proof_bytes);
    let pub_hash = keccak256(&receipt.public_inputs_bytes);
    let vk_hash = keccak256(&receipt.vk_bytes);
    let meta_hash = plonk_meta_hash(&receipt);
    let vk_binding = keccak256_concat(&vk_hash, &meta_hash);

    let commitment_tag =
        keccak256_concat_domain(PLONK_COMMITMENT_TAG_DOMAIN, &proof_hash, &vk_binding);
    let point_tag = keccak256_concat_domain(PLONK_POINT_TAG_DOMAIN, &pub_hash, &vk_binding);
    let claim_hash = keccak256_concat_domain(PLONK_CLAIM_DOMAIN, &commitment_tag, &point_tag);
    let mut claim_bytes = [0u8; 16];
    claim_bytes.copy_from_slice(&claim_hash[..16]);
    let claim128 = u128::from_be_bytes(claim_bytes);
    Ok((commitment_tag, point_tag, claim128))
}

fn keccak256_concat_domain(domain: &[u8], left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut input = Vec::new();
    input.extend_from_slice(domain);
    input.extend_from_slice(left);
    input.extend_from_slice(right);
    keccak256(&input)
}

fn keccak256_concat(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut input = Vec::with_capacity(64);
    input.extend_from_slice(left);
    input.extend_from_slice(right);
    keccak256(&input)
}

fn plonk_meta_hash(receipt: &PlonkReceipt) -> [u8; 32] {
    let mut input = Vec::with_capacity(64);
    input.extend_from_slice(b"GLYPH_PLONK_META");
    input.push(receipt.curve_id);
    input.push(receipt.backend_id);
    input.push(receipt.encoding_id);
    input.push(receipt.pcs_id);
    input.push(receipt.protocol_id);
    input.push(receipt.transcript_id);
    let params_hash = keccak256(&receipt.backend_params_bytes);
    input.extend_from_slice(&params_hash);
    keccak256(&input)
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
        return Err("bn254 public input not canonical".to_string());
    }
    Ok(fr)
}

fn decode_bn254_public_inputs(bytes: &[u8]) -> Result<Vec<Fr>, String> {
    if !bytes.len().is_multiple_of(32) {
        return Err("bn254 public inputs length must be multiple of 32".to_string());
    }
    let mut out = Vec::with_capacity(bytes.len() / 32);
    for chunk in bytes.chunks(32) {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(chunk);
        out.push(fr_from_be_bytes_strict(buf)?);
    }
    Ok(out)
}

fn bls_from_le_bytes_strict(bytes: [u8; 32]) -> Result<BlsScalar, String> {
    let candidate = BlsScalar::from_bytes(&bytes);
    let scalar = Option::<BlsScalar>::from(candidate)
        .ok_or_else(|| "bls public input not canonical".to_string())?;
    if scalar.to_bytes() != bytes {
        return Err("bls public input not canonical".to_string());
    }
    Ok(scalar)
}

fn decode_bls_public_inputs(bytes: &[u8]) -> Result<Vec<BlsScalar>, String> {
    if !bytes.len().is_multiple_of(32) {
        return Err("bls public inputs length must be multiple of 32".to_string());
    }
    let mut out = Vec::with_capacity(bytes.len() / 32);
    for chunk in bytes.chunks(32) {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(chunk);
        out.push(bls_from_le_bytes_strict(buf)?);
    }
    Ok(out)
}

fn read_u8(bytes: &[u8], off: &mut usize) -> Result<u8, String> {
    let b = *bytes.get(*off).ok_or_else(|| "plonk receipt EOF".to_string())?;
    *off += 1;
    Ok(b)
}

fn read_u32_be(bytes: &[u8], off: &mut usize) -> Result<u32, String> {
    let slice = bytes
        .get(*off..*off + 4)
        .ok_or_else(|| "plonk receipt EOF".to_string())?;
    *off += 4;
    Ok(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_vec(bytes: &[u8], off: &mut usize, len: usize) -> Result<Vec<u8>, String> {
    let slice = bytes
        .get(*off..*off + len)
        .ok_or_else(|| "plonk receipt EOF".to_string())?;
    *off += len;
    Ok(slice.to_vec())
}

fn verify_plonk_generic_backend(receipt: &PlonkReceipt) -> Result<(), String> {
    let generic_params = decode_plonk_generic_backend_params(&receipt.backend_params_bytes)?;
    match generic_params.backend_kind {
        PLONK_GENERIC_BACKEND_HALO2 => {
            if receipt.encoding_id != PLONK_ENCODING_HALO2_INSTANCES {
                return Err("plonk generic halo2 encoding mismatch".to_string());
            }
            if receipt.transcript_id != PLONK_TRANSCRIPT_BLAKE2B {
                return Err("plonk generic halo2 transcript mismatch".to_string());
            }
            let params = decode_plonk_halo2_backend_params(&generic_params.payload)?;
            verify_plonk_halo2_backend_with_params(receipt, &params)
        }
        PLONK_GENERIC_BACKEND_GNARK => {
            if receipt.curve_id != PLONK_CURVE_BN254 {
                return Err("plonk generic gnark curve mismatch".to_string());
            }
            if receipt.encoding_id != PLONK_ENCODING_BN254_BE {
                return Err("plonk generic gnark encoding mismatch".to_string());
            }
            if receipt.transcript_id != PLONK_TRANSCRIPT_NATIVE {
                return Err("plonk generic gnark transcript mismatch".to_string());
            }
            if !generic_params.payload.is_empty() {
                return Err("plonk generic gnark params must be empty".to_string());
            }
            verify_plonk_gnark_bn254(receipt)
        }
        PLONK_GENERIC_BACKEND_DUSK => {
            if receipt.curve_id != PLONK_CURVE_BLS12381 {
                return Err("plonk generic dusk curve mismatch".to_string());
            }
            if receipt.encoding_id != PLONK_ENCODING_BLS_LE {
                return Err("plonk generic dusk encoding mismatch".to_string());
            }
            if receipt.transcript_id != PLONK_TRANSCRIPT_NATIVE {
                return Err("plonk generic dusk transcript mismatch".to_string());
            }
            if !generic_params.payload.is_empty() {
                return Err("plonk generic dusk params must be empty".to_string());
            }
            verify_plonk_dusk_bls12381(receipt)
        }
        _ => Err("plonk generic backend unsupported".to_string()),
    }
}

fn verify_plonk_halo2_backend_with_params(
    receipt: &PlonkReceipt,
    params: &PlonkHalo2BackendParams,
) -> Result<(), String> {
    if params.params_bytes.is_empty() {
        return Err("plonk halo2 params bytes empty".to_string());
    }
    if params.circuit_id == halo2_receipt::HALO2_CIRCUIT_STANDARD_PLONK
        && !params.circuit_params_bytes.is_empty()
    {
        return Err("plonk halo2 standard circuit params unexpected".to_string());
    }
    if (params.circuit_id == halo2_receipt::HALO2_CIRCUIT_PARAMETRIC_PLONK
        || params.circuit_id == halo2_receipt::HALO2_CIRCUIT_CUSTOM_PLONK)
        && params.circuit_params_bytes.is_empty()
    {
        return Err("plonk halo2 circuit params missing".to_string());
    }

    let curve_id = match receipt.curve_id {
        PLONK_CURVE_BN254 => halo2_receipt::HALO2_CURVE_BN256,
        PLONK_CURVE_BLS12381 => halo2_receipt::HALO2_CURVE_BLS12381,
        _ => return Err("plonk halo2 curve id unsupported".to_string()),
    };
    let halo2_receipt = halo2_receipt::Halo2Receipt {
        curve_id,
        backend_id: params.halo2_backend_id,
        transcript_id: halo2_receipt::HALO2_TRANSCRIPT_BLAKE2B,
        circuit_id: params.circuit_id,
        compress_selectors: params.compress_selectors,
        circuit_params_bytes: params.circuit_params_bytes.clone(),
        params_bytes: params.params_bytes.clone(),
        vk_bytes: receipt.vk_bytes.clone(),
        instances_bytes: receipt.public_inputs_bytes.clone(),
        proof_bytes: receipt.proof_bytes.clone(),
    };
    halo2_receipt::verify_halo2_receipt_struct(&halo2_receipt)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolve_fixture_path(path: &str) -> String {
        if std::path::Path::new(path).exists() {
            return path.to_string();
        }
        if let Ok(root) = std::env::var("CARGO_MANIFEST_DIR") {
            return format!("{root}/{path}");
        }
        path.to_string()
    }

    fn parse_fixture_field<'a>(contents: &'a str, key: &str) -> Option<&'a str> {
        contents
            .lines()
            .map(|line| line.trim())
            .find(|line| line.starts_with(key))
            .and_then(|line| line.split_once('='))
            .map(|(_, value)| value.trim())
    }

    fn load_plonk_bn254_gnark_receipt() -> Result<Vec<u8>, String> {
        let candidate = "scripts/tools/fixtures/plonk_bn254_gnark_receipt.txt.candidate";
        let path = if std::path::Path::new(candidate).exists() {
            candidate
        } else {
            "scripts/tools/fixtures/plonk_bn254_gnark_receipt.txt"
        };
        let path = resolve_fixture_path(path);
        let contents = std::fs::read_to_string(path)
            .map_err(|err| format!("plonk bn254 fixture missing: {err}"))?;
        let vk_hex = parse_fixture_field(&contents, "vk_hex")
            .ok_or_else(|| "vk_hex missing".to_string())?;
        let proof_hex = parse_fixture_field(&contents, "proof_hex")
            .ok_or_else(|| "proof_hex missing".to_string())?;
        let pub_hex = parse_fixture_field(&contents, "pub_inputs_hex")
            .ok_or_else(|| "pub_inputs_hex missing".to_string())?;
        let vk_bytes = hex::decode(vk_hex).map_err(|_| "vk_hex decode failed".to_string())?;
        let proof_bytes = hex::decode(proof_hex).map_err(|_| "proof_hex decode failed".to_string())?;
        let public_inputs_bytes =
            hex::decode(pub_hex).map_err(|_| "pub_inputs_hex decode failed".to_string())?;
        let receipt = PlonkReceipt {
            backend_id: PLONK_BACKEND_GNARK,
            curve_id: PLONK_CURVE_BN254,
            encoding_id: PLONK_ENCODING_BN254_BE,
            pcs_id: PLONK_PCS_KZG,
            protocol_id: PLONK_PROTOCOL_PLONK,
            transcript_id: PLONK_TRANSCRIPT_NATIVE,
            backend_params_bytes: Vec::new(),
            vk_bytes,
            public_inputs_bytes,
            proof_bytes,
        };
        Ok(encode_plonk_receipt(&receipt))
    }

    fn load_plonk_bls_dusk_receipt() -> Result<Vec<u8>, String> {
        let candidate = "scripts/tools/fixtures/plonk_bls12381_receipt.txt.candidate";
        let path = if std::path::Path::new(candidate).exists() {
            candidate
        } else {
            "scripts/tools/fixtures/plonk_bls12381_receipt.txt"
        };
        let path = resolve_fixture_path(path);
        let contents = std::fs::read_to_string(path)
            .map_err(|err| format!("plonk bls fixture missing: {err}"))?;
        if let Some(receipt_hex) = parse_fixture_field(&contents, "receipt_hex") {
            return hex::decode(receipt_hex).map_err(|_| "receipt_hex decode failed".to_string());
        }
        let vk_hex = parse_fixture_field(&contents, "vk_hex")
            .ok_or_else(|| "vk_hex missing".to_string())?;
        let proof_hex = parse_fixture_field(&contents, "proof_hex")
            .ok_or_else(|| "proof_hex missing".to_string())?;
        let pub_hex = parse_fixture_field(&contents, "pub_inputs_hex")
            .ok_or_else(|| "pub_inputs_hex missing".to_string())?;
        let vk_bytes = hex::decode(vk_hex).map_err(|_| "vk_hex decode failed".to_string())?;
        let proof_bytes = hex::decode(proof_hex).map_err(|_| "proof_hex decode failed".to_string())?;
        let public_inputs_bytes =
            hex::decode(pub_hex).map_err(|_| "pub_inputs_hex decode failed".to_string())?;
        let receipt = PlonkReceipt {
            backend_id: PLONK_BACKEND_DUSK,
            curve_id: PLONK_CURVE_BLS12381,
            encoding_id: PLONK_ENCODING_BLS_LE,
            pcs_id: PLONK_PCS_KZG,
            protocol_id: PLONK_PROTOCOL_PLONK,
            transcript_id: PLONK_TRANSCRIPT_NATIVE,
            backend_params_bytes: Vec::new(),
            vk_bytes,
            public_inputs_bytes,
            proof_bytes,
        };
        Ok(encode_plonk_receipt(&receipt))
    }

    #[test]
    fn test_plonk_receipt_roundtrip_rejects_invalid() {
        let receipt = PlonkReceipt {
            backend_id: PLONK_BACKEND_GNARK,
            curve_id: PLONK_CURVE_BN254,
            encoding_id: PLONK_ENCODING_BN254_BE,
            pcs_id: PLONK_PCS_KZG,
            protocol_id: PLONK_PROTOCOL_PLONK,
            transcript_id: PLONK_TRANSCRIPT_NATIVE,
            backend_params_bytes: Vec::new(),
            vk_bytes: vec![1, 2],
            public_inputs_bytes: vec![0u8; 32],
            proof_bytes: vec![3, 4],
        };
        let bytes = encode_plonk_receipt(&receipt);
        let decoded = match decode_plonk_receipt(&bytes) {
            Ok(decoded) => decoded,
            Err(err) => {
                assert!(false, "decode: {err}");
                return;
            }
        };
        assert_eq!(decoded, receipt);
        assert!(verify_plonk_receipt(&bytes).is_err());
    }

    #[test]
    fn test_plonk_bn254_receipt_tamper_rejects() {
        let bytes = match load_plonk_bn254_gnark_receipt() {
            Ok(bytes) => bytes,
            Err(err) => {
                assert!(false, "fixture: {err}");
                return;
            }
        };
        if let Err(err) = verify_plonk_receipt(&bytes) {
            assert!(false, "plonk bn254 verify: {err}");
            return;
        }
        let receipt = match decode_plonk_receipt(&bytes) {
            Ok(receipt) => receipt,
            Err(err) => {
                assert!(false, "decode: {err}");
                return;
            }
        };

        let mut tampered_proof = receipt.clone();
        tampered_proof.proof_bytes[0] ^= 1;
        assert!(verify_plonk_receipt(&encode_plonk_receipt(&tampered_proof)).is_err());

        let mut tampered_pub = receipt.clone();
        tampered_pub.public_inputs_bytes[0] ^= 1;
        assert!(verify_plonk_receipt(&encode_plonk_receipt(&tampered_pub)).is_err());

        let mut tampered_vk = receipt;
        tampered_vk.vk_bytes[0] ^= 1;
        assert!(verify_plonk_receipt(&encode_plonk_receipt(&tampered_vk)).is_err());
    }

    #[test]
    fn test_plonk_generic_backend_gnark() {
        let bytes = match load_plonk_bn254_gnark_receipt() {
            Ok(bytes) => bytes,
            Err(err) => {
                assert!(false, "fixture: {err}");
                return;
            }
        };
        let receipt = match decode_plonk_receipt(&bytes) {
            Ok(receipt) => receipt,
            Err(err) => {
                assert!(false, "decode: {err}");
                return;
            }
        };
        let generic_params =
            encode_plonk_generic_backend_params(PLONK_GENERIC_BACKEND_GNARK, &[]);
        let generic_receipt = PlonkReceipt {
            backend_id: PLONK_BACKEND_GENERIC,
            backend_params_bytes: generic_params,
            ..receipt
        };
        let encoded = encode_plonk_receipt(&generic_receipt);
        if let Err(err) = verify_plonk_receipt(&encoded) {
            assert!(false, "plonk generic gnark verify: {err}");
            return;
        }
    }

    #[test]
    fn test_plonk_generic_backend_dusk() {
        let bytes = match load_plonk_bls_dusk_receipt() {
            Ok(bytes) => bytes,
            Err(err) => {
                assert!(false, "fixture: {err}");
                return;
            }
        };
        let receipt = match decode_plonk_receipt(&bytes) {
            Ok(receipt) => receipt,
            Err(err) => {
                assert!(false, "decode: {err}");
                return;
            }
        };
        let generic_params =
            encode_plonk_generic_backend_params(PLONK_GENERIC_BACKEND_DUSK, &[]);
        let generic_receipt = PlonkReceipt {
            backend_id: PLONK_BACKEND_GENERIC,
            backend_params_bytes: generic_params,
            ..receipt
        };
        let encoded = encode_plonk_receipt(&generic_receipt);
        if let Err(err) = verify_plonk_receipt(&encoded) {
            assert!(false, "plonk generic dusk verify: {err}");
            return;
        }
    }

    #[test]
    fn test_plonk_generic_backend_bn256() {
        use crate::halo2_receipt::{
            encode_halo2_instances, StandardPlonkCircuit, HALO2_BACKEND_KZG_GWC,
            HALO2_CIRCUIT_STANDARD_PLONK,
        };
        use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk_custom};
        use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
        use halo2_proofs::poly::kzg::multiopen::ProverGWC;
        use halo2_proofs::transcript::{Blake2bWrite, Challenge255, TranscriptWriterBuffer};
        use halo2_proofs::SerdeFormat;
        use halo2_proofs::halo2curves::bn256::{Bn256, Fr as Bn256Fr, G1Affine as Bn256G1Affine};
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        let k = 4u32;
        let mut rng = StdRng::seed_from_u64(0x22aa_45ff);
        let circuit = StandardPlonkCircuit::<Bn256Fr>(Bn256Fr::from(9u64));
        let params = ParamsKZG::<Bn256>::setup(k, &mut rng);
        let compress_selectors = true;
        let vk = match keygen_vk_custom(&params, &circuit, compress_selectors) {
            Ok(vk) => vk,
            Err(err) => {
                assert!(false, "vk: {err:?}");
                return;
            }
        };
        let pk = match keygen_pk(&params, vk.clone(), &circuit) {
            Ok(pk) => pk,
            Err(err) => {
                assert!(false, "pk: {err:?}");
                return;
            }
        };

        let instances: Vec<Vec<Vec<Bn256Fr>>> = vec![vec![vec![circuit.0]]];
        let mut transcript =
            Blake2bWrite::<_, _, Challenge255<Bn256G1Affine>>::init(vec![]);
        match create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverGWC<'_, Bn256>,
            Challenge255<Bn256G1Affine>,
            _,
            Blake2bWrite<Vec<u8>, Bn256G1Affine, Challenge255<Bn256G1Affine>>,
            _,
        >(
            &params,
            &pk,
            &[circuit],
            instances.as_slice(),
            &mut rng,
            &mut transcript,
        ) {
            Ok(()) => {}
            Err(err) => {
                assert!(false, "proof: {err:?}");
                return;
            }
        };
        let proof_bytes = transcript.finalize();

        let mut params_bytes = Vec::new();
        if let Err(err) = params
            .verifier_params()
            .write_custom(&mut params_bytes, SerdeFormat::RawBytes)
        {
            assert!(false, "params write: {err}");
            return;
        }
        let mut vk_bytes = Vec::new();
        if let Err(err) = vk.write(&mut vk_bytes, SerdeFormat::RawBytes) {
            assert!(false, "vk write: {err}");
            return;
        }
        let instances_bytes = match encode_halo2_instances(&instances[0]) {
            Ok(bytes) => bytes,
            Err(err) => {
                assert!(false, "instances: {err}");
                return;
            }
        };

        let halo2_params = PlonkHalo2BackendParams {
            halo2_backend_id: HALO2_BACKEND_KZG_GWC,
            circuit_id: HALO2_CIRCUIT_STANDARD_PLONK,
            compress_selectors,
            circuit_params_bytes: Vec::new(),
            params_bytes,
        };
        let generic_params = encode_plonk_generic_backend_params(
            PLONK_GENERIC_BACKEND_HALO2,
            &encode_plonk_halo2_backend_params(&halo2_params),
        );

        let receipt = PlonkReceipt {
            backend_id: PLONK_BACKEND_GENERIC,
            curve_id: PLONK_CURVE_BN254,
            encoding_id: PLONK_ENCODING_HALO2_INSTANCES,
            pcs_id: PLONK_PCS_KZG,
            protocol_id: PLONK_PROTOCOL_PLONK,
            transcript_id: PLONK_TRANSCRIPT_BLAKE2B,
            backend_params_bytes: generic_params,
            vk_bytes,
            public_inputs_bytes: instances_bytes,
            proof_bytes,
        };

        let encoded = encode_plonk_receipt(&receipt);
        if let Err(err) = verify_plonk_receipt(&encoded) {
            assert!(false, "plonk generic verify: {err}");
            return;
        }
    }
}
