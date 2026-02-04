//! Adapter SNARK IPA proofs (generic IPA receipts).
//!
//! Provides a canonical receipt format and verification that derives the GLYPH artifact
//! tags for GLYPH. Receipt verification is off-chain only.

use ark_bn254::{Fq as FqBn254, Fr as FrBn254, G1Affine as G1AffineBn254, G1Projective as G1ProjectiveBn254};
use ark_bls12_381::{Fq as FqBls12381, Fr as FrBls12381, G1Affine as G1AffineBls12381, G1Projective as G1ProjectiveBls12381};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField, One};
use crate::adapters::keccak256;
use crate::adapter_error::{wrap_stage};
use crate::ipa_bn254::{IPAParams as IPAParamsBn254, IPAVerifier as IPAVerifierBn254, IPAProofOptimized as IPAProofOptimizedBn254, CompressedG1 as CompressedG1Bn254};
use crate::ipa_bls12381::{IPAParams as IPAParamsBls12381, IPAVerifier as IPAVerifierBls12381, IPAProofOptimized as IPAProofOptimizedBls12381, CompressedG1 as CompressedG1Bls12381};

pub const SNARK_IPA_RECEIPT_TAG: &[u8] = b"GLYPH_SNARK_IPA_RECEIPT";
pub const SNARK_IPA_COMMITMENT_TAG_DOMAIN: &[u8] = b"GLYPH_SNARK_IPA_COMMITMENT_TAG";
pub const SNARK_IPA_POINT_TAG_DOMAIN: &[u8] = b"GLYPH_SNARK_IPA_POINT_TAG";
pub const SNARK_IPA_CLAIM_DOMAIN: &[u8] = b"GLYPH_SNARK_IPA_CLAIM";
pub const SNARK_IPA_STATEMENT_DOMAIN: &[u8] = b"GLYPH_SNARK_IPA_STATEMENT";

pub const IPA_CURVE_BN254: u8 = 0x01;
pub const IPA_CURVE_BLS12381: u8 = 0x02;
pub const IPA_BACKEND_HALO2: u8 = 0x01;
pub const IPA_BACKEND_GENERIC: u8 = 0x02;
pub const IPA_ENCODING_BN254_BE: u8 = 0x01;
pub const IPA_ENCODING_BLS12381_BE: u8 = 0x02;
pub const IPA_TRANSCRIPT_GLYPH: u8 = 0x01;

#[derive(Clone, Debug)]
pub struct IpaReceipt {
    pub curve_id: u8,
    pub backend_id: u8,
    pub encoding_id: u8,
    pub transcript_id: u8,
    pub n: usize,
    pub public_inputs_len: usize,
    pub public_inputs_bytes: Vec<u8>,
    pub commitment_bytes: Vec<u8>,
    pub proof_bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
pub struct IpaReceiptView<'a> {
    pub curve_id: u8,
    pub backend_id: u8,
    pub encoding_id: u8,
    pub transcript_id: u8,
    pub n: usize,
    pub public_inputs_len: usize,
    pub public_inputs_bytes: &'a [u8],
    pub commitment_bytes: &'a [u8],
    pub proof_bytes: &'a [u8],
}

impl<'a> IpaReceiptView<'a> {
    pub fn to_owned(&self) -> IpaReceipt {
        IpaReceipt {
            curve_id: self.curve_id,
            backend_id: self.backend_id,
            encoding_id: self.encoding_id,
            transcript_id: self.transcript_id,
            n: self.n,
            public_inputs_len: self.public_inputs_len,
            public_inputs_bytes: self.public_inputs_bytes.to_vec(),
            commitment_bytes: self.commitment_bytes.to_vec(),
            proof_bytes: self.proof_bytes.to_vec(),
        }
    }
}
const IPA_SCALAR_BYTES: usize = 32;
pub fn build_ipa_receipt_bn254(
    backend_id: u8,
    transcript_id: u8,
    n: usize,
    public_inputs: &[FrBn254],
    commitment: &G1AffineBn254,
    proof: &IPAProofOptimizedBn254,
) -> Vec<u8> {
    let public_inputs_bytes = encode_public_inputs_bytes(public_inputs, IPA_SCALAR_BYTES);
    let commitment_bytes = g1_to_bytes_uncompressed_bn254(commitment).to_vec();
    let proof_bytes = encode_ipa_proof_optimized_bn254(proof);
    let receipt = IpaReceipt {
        curve_id: IPA_CURVE_BN254,
        backend_id,
        encoding_id: IPA_ENCODING_BN254_BE,
        transcript_id,
        n,
        public_inputs_len: public_inputs.len(),
        public_inputs_bytes,
        commitment_bytes,
        proof_bytes,
    };
    encode_ipa_receipt(&receipt)
}

pub fn build_ipa_receipt_bls12381(
    backend_id: u8,
    transcript_id: u8,
    n: usize,
    public_inputs: &[FrBls12381],
    commitment: &G1AffineBls12381,
    proof: &IPAProofOptimizedBls12381,
) -> Vec<u8> {
    let public_inputs_bytes = encode_public_inputs_bytes(public_inputs, IPA_SCALAR_BYTES);
    let commitment_bytes = g1_to_bytes_uncompressed_bls12381(commitment).to_vec();
    let proof_bytes = encode_ipa_proof_optimized_bls12381(proof);
    let receipt = IpaReceipt {
        curve_id: IPA_CURVE_BLS12381,
        backend_id,
        encoding_id: IPA_ENCODING_BLS12381_BE,
        transcript_id,
        n,
        public_inputs_len: public_inputs.len(),
        public_inputs_bytes,
        commitment_bytes,
        proof_bytes,
    };
    encode_ipa_receipt(&receipt)
}

pub fn encode_ipa_receipt(receipt: &IpaReceipt) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(SNARK_IPA_RECEIPT_TAG);
    out.push(receipt.curve_id);
    out.push(receipt.backend_id);
    out.push(receipt.encoding_id);
    out.push(receipt.transcript_id);
    out.extend_from_slice(&(receipt.n as u16).to_be_bytes());
    out.extend_from_slice(&(receipt.public_inputs_len as u16).to_be_bytes());
    out.extend_from_slice(&receipt.public_inputs_bytes);
    out.extend_from_slice(&receipt.commitment_bytes);
    out.extend_from_slice(&(receipt.proof_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&receipt.proof_bytes);
    out
}

pub fn decode_ipa_receipt(bytes: &[u8]) -> Result<IpaReceipt, String> {
    let view = decode_ipa_receipt_view(bytes)?;
    Ok(view.to_owned())
}

pub fn decode_ipa_receipt_view(bytes: &[u8]) -> Result<IpaReceiptView<'_>, String> {
    if !bytes.starts_with(SNARK_IPA_RECEIPT_TAG) {
        return Err("snark ipa receipt missing tag".to_string());
    }
    let mut off = SNARK_IPA_RECEIPT_TAG.len();
    let curve_id = read_u8(bytes, &mut off)?;
    let backend_id = read_u8(bytes, &mut off)?;
    let encoding_id = read_u8(bytes, &mut off)?;
    let transcript_id = read_u8(bytes, &mut off)?;

    if backend_id != IPA_BACKEND_HALO2 && backend_id != IPA_BACKEND_GENERIC {
        return Err("snark ipa receipt unsupported backend id".to_string());
    }
    if transcript_id != IPA_TRANSCRIPT_GLYPH {
        return Err("snark ipa receipt unsupported transcript id".to_string());
    }

    let (scalar_bytes, commitment_bytes_len) = match (curve_id, encoding_id) {
        (IPA_CURVE_BN254, IPA_ENCODING_BN254_BE) => (IPA_SCALAR_BYTES, 64usize),
        (IPA_CURVE_BLS12381, IPA_ENCODING_BLS12381_BE) => (IPA_SCALAR_BYTES, 96usize),
        (IPA_CURVE_BN254, _) | (IPA_CURVE_BLS12381, _) => {
            return Err("snark ipa receipt unsupported encoding id".to_string());
        }
        _ => return Err("snark ipa receipt unsupported curve id".to_string()),
    };

    let n = read_u16_be(bytes, &mut off)? as usize;
    if n == 0 || !n.is_power_of_two() {
        return Err("snark ipa receipt n must be power of two".to_string());
    }
    let public_len = read_u16_be(bytes, &mut off)? as usize;
    let public_inputs_len_bytes = public_len
        .checked_mul(scalar_bytes)
        .ok_or_else(|| "snark ipa receipt public inputs length overflow".to_string())?;
    let public_inputs_bytes = read_fixed(bytes, &mut off, public_inputs_len_bytes)?;
    let commitment_bytes = read_fixed(bytes, &mut off, commitment_bytes_len)?;
    let proof_len = read_u32_be(bytes, &mut off)? as usize;
    let proof_bytes = read_fixed(bytes, &mut off, proof_len)?;
    if off != bytes.len() {
        return Err("snark ipa receipt has trailing bytes".to_string());
    }
    Ok(IpaReceiptView {
        curve_id,
        backend_id,
        encoding_id,
        transcript_id,
        n,
        public_inputs_len: public_len,
        public_inputs_bytes,
        commitment_bytes,
        proof_bytes,
    })
}

pub fn verify_ipa_receipt(receipt_bytes: &[u8]) -> Result<IpaReceipt, String> {
    let view = verify_ipa_receipt_view(receipt_bytes)
        .map_err(|e| wrap_stage("ipa", "verify", e))?;
    Ok(view.to_owned())
}

pub fn verify_ipa_receipt_view(receipt_bytes: &[u8]) -> Result<IpaReceiptView<'_>, String> {
    let receipt = decode_ipa_receipt_view(receipt_bytes)
        .map_err(|e| wrap_stage("ipa", "decode", e))?;
    let statement_hash = ipa_statement_hash_bytes(receipt.public_inputs_bytes);
    match receipt.curve_id {
        IPA_CURVE_BN254 => {
            let _public_inputs = decode_public_inputs_bn254(
                receipt.public_inputs_bytes,
                receipt.public_inputs_len,
            )?;
            let commitment = decode_commitment_bn254(receipt.commitment_bytes)?;
            let proof = decode_ipa_proof_optimized_bn254(receipt.proof_bytes)?;
            let params = IPAParamsBn254::new(receipt.n);
            let verifier = IPAVerifierBn254 { params: &params };
            let commitment_proj = G1ProjectiveBn254::from(commitment);
            let ok = verifier
                .verify_optimized_with_statement(
                    &commitment_proj,
                    FrBn254::one(),
                    &proof,
                    &statement_hash,
                )
                .map_err(|e| format!("snark ipa receipt verification failed: {e:?}"))?;
            if !ok {
                return Err("snark ipa receipt verification failed".to_string());
            }
        }
        IPA_CURVE_BLS12381 => {
            let _public_inputs = decode_public_inputs_bls12381(
                receipt.public_inputs_bytes,
                receipt.public_inputs_len,
            )?;
            let commitment = decode_commitment_bls12381(receipt.commitment_bytes)?;
            let proof = decode_ipa_proof_optimized_bls12381(receipt.proof_bytes)?;
            let params = IPAParamsBls12381::new(receipt.n);
            let verifier = IPAVerifierBls12381 { params: &params };
            let commitment_proj = G1ProjectiveBls12381::from(commitment);
            let ok = verifier
                .verify_optimized_with_statement(
                    &commitment_proj,
                    FrBls12381::one(),
                    &proof,
                    &statement_hash,
                )
                .map_err(|e| format!("snark ipa receipt verification failed: {e:?}"))?;
            if !ok {
                return Err("snark ipa receipt verification failed".to_string());
            }
        }
        _ => return Err("snark ipa receipt unsupported curve id".to_string()),
    }
    Ok(receipt)
}

pub fn derive_glyph_artifact_from_ipa_receipt(
    receipt_bytes: &[u8],
) -> Result<([u8; 32], [u8; 32], u128), String> {
    let receipt = verify_ipa_receipt_view(receipt_bytes)?;
    let pub_hash = keccak256(receipt.public_inputs_bytes);
    let proof_hash = keccak256(receipt.proof_bytes);

    let commitment_tag = keccak256_concat_domain(SNARK_IPA_COMMITMENT_TAG_DOMAIN, &proof_hash, &pub_hash);
    let point_tag = keccak256_concat_domain(SNARK_IPA_POINT_TAG_DOMAIN, &proof_hash, &pub_hash);
    let claim_hash = keccak256_concat_domain(SNARK_IPA_CLAIM_DOMAIN, &commitment_tag, &point_tag);
    let mut claim_bytes = [0u8; 16];
    claim_bytes.copy_from_slice(&claim_hash[..16]);
    let claim128 = u128::from_be_bytes(claim_bytes);
    Ok((commitment_tag, point_tag, claim128))
}

fn encode_public_inputs_bytes<F: PrimeField>(public_inputs: &[F], scalar_bytes: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(public_inputs.len() * scalar_bytes);
    for fr in public_inputs {
        let mut bytes = fr.into_bigint().to_bytes_be();
        if bytes.len() > scalar_bytes {
            bytes = bytes[bytes.len() - scalar_bytes..].to_vec();
        }
        if bytes.len() < scalar_bytes {
            let mut padded = vec![0u8; scalar_bytes - bytes.len()];
            padded.extend_from_slice(&bytes);
            bytes = padded;
        }
        out.extend_from_slice(&bytes);
    }
    out
}

pub fn ipa_statement_hash_bytes(public_inputs_bytes: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(SNARK_IPA_STATEMENT_DOMAIN.len() + public_inputs_bytes.len());
    input.extend_from_slice(SNARK_IPA_STATEMENT_DOMAIN);
    input.extend_from_slice(public_inputs_bytes);
    keccak256(&input)
}

pub fn ipa_statement_hash_bn254(public_inputs: &[FrBn254]) -> [u8; 32] {
    ipa_statement_hash_bytes(&encode_public_inputs_bytes(public_inputs, IPA_SCALAR_BYTES))
}

pub fn ipa_statement_hash_bls12381(public_inputs: &[FrBls12381]) -> [u8; 32] {
    ipa_statement_hash_bytes(&encode_public_inputs_bytes(public_inputs, IPA_SCALAR_BYTES))
}

fn fq_to_bytes_bn254(x: &FqBn254) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut bytes = x.into_bigint().to_bytes_be();
    if bytes.len() > 32 {
        bytes = bytes[bytes.len() - 32..].to_vec();
    }
    if bytes.len() < 32 {
        let mut padded = vec![0u8; 32 - bytes.len()];
        padded.extend_from_slice(&bytes);
        bytes = padded;
    }
    out.copy_from_slice(&bytes);
    out
}

fn fq_to_bytes_bls12381(x: &FqBls12381) -> [u8; 48] {
    let mut out = [0u8; 48];
    let mut bytes = x.into_bigint().to_bytes_be();
    if bytes.len() > 48 {
        bytes = bytes[bytes.len() - 48..].to_vec();
    }
    if bytes.len() < 48 {
        let mut padded = vec![0u8; 48 - bytes.len()];
        padded.extend_from_slice(&bytes);
        bytes = padded;
    }
    out.copy_from_slice(&bytes);
    out
}

fn g1_to_bytes_uncompressed_bn254(p: &G1AffineBn254) -> [u8; 64] {
    let mut out = [0u8; 64];
    let x_bytes = fq_to_bytes_bn254(&p.x);
    let y_bytes = fq_to_bytes_bn254(&p.y);
    out[..32].copy_from_slice(&x_bytes);
    out[32..].copy_from_slice(&y_bytes);
    out
}

fn g1_to_bytes_uncompressed_bls12381(p: &G1AffineBls12381) -> [u8; 96] {
    let mut out = [0u8; 96];
    let x_bytes = fq_to_bytes_bls12381(&p.x);
    let y_bytes = fq_to_bytes_bls12381(&p.y);
    out[..48].copy_from_slice(&x_bytes);
    out[48..].copy_from_slice(&y_bytes);
    out
}

fn encode_ipa_proof_optimized_bn254(proof: &IPAProofOptimizedBn254) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(proof.l_vec.len() as u32).to_be_bytes());
    for l in &proof.l_vec {
        out.extend_from_slice(&g1_to_bytes_uncompressed_bn254(&l.0));
    }
    for r in &proof.r_vec {
        out.extend_from_slice(&g1_to_bytes_uncompressed_bn254(&r.0));
    }
    out.extend_from_slice(&proof.a.into_bigint().to_bytes_be());
    out.extend_from_slice(&proof.b.into_bigint().to_bytes_be());
    out.extend_from_slice(&g1_to_bytes_uncompressed_bn254(&proof.g_final.0));
    out.extend_from_slice(&g1_to_bytes_uncompressed_bn254(&proof.h_final.0));
    out
}

fn encode_ipa_proof_optimized_bls12381(proof: &IPAProofOptimizedBls12381) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(proof.l_vec.len() as u32).to_be_bytes());
    for l in &proof.l_vec {
        out.extend_from_slice(&g1_to_bytes_uncompressed_bls12381(&l.0));
    }
    for r in &proof.r_vec {
        out.extend_from_slice(&g1_to_bytes_uncompressed_bls12381(&r.0));
    }
    out.extend_from_slice(&proof.a.into_bigint().to_bytes_be());
    out.extend_from_slice(&proof.b.into_bigint().to_bytes_be());
    out.extend_from_slice(&g1_to_bytes_uncompressed_bls12381(&proof.g_final.0));
    out.extend_from_slice(&g1_to_bytes_uncompressed_bls12381(&proof.h_final.0));
    out
}

fn decode_ipa_proof_optimized_bn254(bytes: &[u8]) -> Result<IPAProofOptimizedBn254, String> {
    let mut off = 0usize;
    let l_len = read_u32_be(bytes, &mut off)? as usize;
    let mut l_vec = Vec::with_capacity(l_len);
    let mut r_vec = Vec::with_capacity(l_len);
    for _ in 0..l_len {
        let b = read_fixed(bytes, &mut off, 64)?;
        let p = decode_uncompressed_g1_bn254(b)?;
        l_vec.push(CompressedG1Bn254(p));
    }
    for _ in 0..l_len {
        let b = read_fixed(bytes, &mut off, 64)?;
        let p = decode_uncompressed_g1_bn254(b)?;
        r_vec.push(CompressedG1Bn254(p));
    }
    let a_bytes = read_fixed(bytes, &mut off, 32)?;
    let b_bytes = read_fixed(bytes, &mut off, 32)?;
    let a = FrBn254::from_be_bytes_mod_order(a_bytes);
    let b = FrBn254::from_be_bytes_mod_order(b_bytes);
    let g_bytes = read_fixed(bytes, &mut off, 64)?;
    let h_bytes = read_fixed(bytes, &mut off, 64)?;
    let g_final = CompressedG1Bn254(decode_uncompressed_g1_bn254(g_bytes)?);
    let h_final = CompressedG1Bn254(decode_uncompressed_g1_bn254(h_bytes)?);
    if off != bytes.len() {
        return Err("ipa proof bytes trailing data".to_string());
    }
    Ok(IPAProofOptimizedBn254 {
        l_vec,
        r_vec,
        a,
        b,
        g_final,
        h_final,
    })
}

fn decode_ipa_proof_optimized_bls12381(bytes: &[u8]) -> Result<IPAProofOptimizedBls12381, String> {
    let mut off = 0usize;
    let l_len = read_u32_be(bytes, &mut off)? as usize;
    let mut l_vec = Vec::with_capacity(l_len);
    let mut r_vec = Vec::with_capacity(l_len);
    for _ in 0..l_len {
        let b = read_fixed(bytes, &mut off, 96)?;
        let p = decode_uncompressed_g1_bls12381(b)?;
        l_vec.push(CompressedG1Bls12381(p));
    }
    for _ in 0..l_len {
        let b = read_fixed(bytes, &mut off, 96)?;
        let p = decode_uncompressed_g1_bls12381(b)?;
        r_vec.push(CompressedG1Bls12381(p));
    }
    let a_bytes = read_fixed(bytes, &mut off, 32)?;
    let b_bytes = read_fixed(bytes, &mut off, 32)?;
    let a = FrBls12381::from_be_bytes_mod_order(a_bytes);
    let b = FrBls12381::from_be_bytes_mod_order(b_bytes);
    let g_bytes = read_fixed(bytes, &mut off, 96)?;
    let h_bytes = read_fixed(bytes, &mut off, 96)?;
    let g_final = CompressedG1Bls12381(decode_uncompressed_g1_bls12381(g_bytes)?);
    let h_final = CompressedG1Bls12381(decode_uncompressed_g1_bls12381(h_bytes)?);
    if off != bytes.len() {
        return Err("ipa proof bytes trailing data".to_string());
    }
    Ok(IPAProofOptimizedBls12381 {
        l_vec,
        r_vec,
        a,
        b,
        g_final,
        h_final,
    })
}

fn decode_public_inputs_bn254(bytes: &[u8], count: usize) -> Result<Vec<FrBn254>, String> {
    let expected = count * IPA_SCALAR_BYTES;
    if bytes.len() != expected {
        return Err("snark ipa receipt public inputs length mismatch".to_string());
    }
    let mut inputs = Vec::with_capacity(count);
    for i in 0..count {
        let start = i * IPA_SCALAR_BYTES;
        let end = start + IPA_SCALAR_BYTES;
        let fr = FrBn254::from_be_bytes_mod_order(&bytes[start..end]);
        inputs.push(fr);
    }
    Ok(inputs)
}

fn decode_public_inputs_bls12381(bytes: &[u8], count: usize) -> Result<Vec<FrBls12381>, String> {
    let expected = count * IPA_SCALAR_BYTES;
    if bytes.len() != expected {
        return Err("snark ipa receipt public inputs length mismatch".to_string());
    }
    let mut inputs = Vec::with_capacity(count);
    for i in 0..count {
        let start = i * IPA_SCALAR_BYTES;
        let end = start + IPA_SCALAR_BYTES;
        let fr = FrBls12381::from_be_bytes_mod_order(&bytes[start..end]);
        inputs.push(fr);
    }
    Ok(inputs)
}

fn decode_commitment_bn254(bytes: &[u8]) -> Result<G1AffineBn254, String> {
    if bytes.len() != 64 {
        return Err("snark ipa receipt commitment length mismatch".to_string());
    }
    let mut x_bytes = [0u8; 32];
    let mut y_bytes = [0u8; 32];
    x_bytes.copy_from_slice(&bytes[..32]);
    y_bytes.copy_from_slice(&bytes[32..64]);
    let x = FqBn254::from_be_bytes_mod_order(&x_bytes);
    let y = FqBn254::from_be_bytes_mod_order(&y_bytes);
    let p = G1AffineBn254::new(x, y);
    if !p.is_on_curve() || p.is_zero() {
        return Err("snark ipa receipt commitment invalid".to_string());
    }
    Ok(p)
}

fn decode_commitment_bls12381(bytes: &[u8]) -> Result<G1AffineBls12381, String> {
    if bytes.len() != 96 {
        return Err("snark ipa receipt commitment length mismatch".to_string());
    }
    let mut x_bytes = [0u8; 48];
    let mut y_bytes = [0u8; 48];
    x_bytes.copy_from_slice(&bytes[..48]);
    y_bytes.copy_from_slice(&bytes[48..96]);
    let x = FqBls12381::from_be_bytes_mod_order(&x_bytes);
    let y = FqBls12381::from_be_bytes_mod_order(&y_bytes);
    let p = G1AffineBls12381::new(x, y);
    if !p.is_on_curve() || p.is_zero() || !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err("snark ipa receipt commitment invalid".to_string());
    }
    Ok(p)
}

fn decode_uncompressed_g1_bn254(bytes: &[u8]) -> Result<G1AffineBn254, String> {
    if bytes.len() != 64 {
        return Err("uncompressed G1 length mismatch".to_string());
    }
    let mut x_bytes = [0u8; 32];
    let mut y_bytes = [0u8; 32];
    x_bytes.copy_from_slice(&bytes[..32]);
    y_bytes.copy_from_slice(&bytes[32..64]);
    let x = FqBn254::from_be_bytes_mod_order(&x_bytes);
    let y = FqBn254::from_be_bytes_mod_order(&y_bytes);
    let p = G1AffineBn254::new(x, y);
    if !p.is_on_curve() || p.is_zero() {
        return Err("uncompressed G1 invalid point".to_string());
    }
    Ok(p)
}

fn decode_uncompressed_g1_bls12381(bytes: &[u8]) -> Result<G1AffineBls12381, String> {
    if bytes.len() != 96 {
        return Err("uncompressed G1 length mismatch".to_string());
    }
    let mut x_bytes = [0u8; 48];
    let mut y_bytes = [0u8; 48];
    x_bytes.copy_from_slice(&bytes[..48]);
    y_bytes.copy_from_slice(&bytes[48..96]);
    let x = FqBls12381::from_be_bytes_mod_order(&x_bytes);
    let y = FqBls12381::from_be_bytes_mod_order(&y_bytes);
    let p = G1AffineBls12381::new(x, y);
    if !p.is_on_curve() || p.is_zero() || !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err("uncompressed G1 invalid point".to_string());
    }
    Ok(p)
}

fn keccak256_concat_domain(domain: &[u8], left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut input = Vec::new();
    input.extend_from_slice(domain);
    input.extend_from_slice(left);
    input.extend_from_slice(right);
    keccak256(&input)
}

fn read_u16_be(bytes: &[u8], off: &mut usize) -> Result<u16, String> {
    let slice = bytes
        .get(*off..*off + 2)
        .ok_or_else(|| "ipa receipt EOF".to_string())?;
    *off += 2;
    Ok(u16::from_be_bytes([slice[0], slice[1]]))
}

fn read_u8(bytes: &[u8], off: &mut usize) -> Result<u8, String> {
    let b = *bytes.get(*off).ok_or_else(|| "ipa receipt EOF".to_string())?;
    *off += 1;
    Ok(b)
}

fn read_u32_be(bytes: &[u8], off: &mut usize) -> Result<u32, String> {
    let slice = bytes
        .get(*off..*off + 4)
        .ok_or_else(|| "ipa receipt EOF".to_string())?;
    *off += 4;
    Ok(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_fixed<'a>(bytes: &'a [u8], off: &mut usize, len: usize) -> Result<&'a [u8], String> {
    let slice = bytes
        .get(*off..*off + len)
        .ok_or_else(|| "ipa receipt EOF".to_string())?;
    *off += len;
    Ok(slice)
}

#[allow(dead_code)]
fn read_vec(bytes: &[u8], off: &mut usize, len: usize) -> Result<Vec<u8>, String> {
    let slice = bytes
        .get(*off..*off + len)
        .ok_or_else(|| "ipa receipt EOF".to_string())?;
    *off += len;
    Ok(slice.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::CurveGroup;
    use ark_ff::UniformRand;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use crate::ipa_bn254::{IPAParams as IPAParamsBn254, IPAProver as IPAProverBn254, IPAVerifier as IPAVerifierBn254};
    use crate::ipa_bls12381::{IPAParams as IPAParamsBls12381, IPAProver as IPAProverBls12381, IPAVerifier as IPAVerifierBls12381};

    #[test]
    fn test_ipa_receipt_roundtrip_and_artifact_bn254() {
        let mut rng = StdRng::seed_from_u64(0xface_cafe);
        let n = 4usize;
        let params = IPAParamsBn254::new(n);
        let prover = IPAProverBn254 { params: &params };
        let a: Vec<FrBn254> = (0..n).map(|_| FrBn254::rand(&mut rng)).collect();
        let b: Vec<FrBn254> = (0..n).map(|_| FrBn254::rand(&mut rng)).collect();
        let public_inputs = a[..2].to_vec();
        let statement_hash = ipa_statement_hash_bn254(&public_inputs);
        let (commitment, _c, proof) = match prover.prove_optimized_with_statement(&a, &b, &statement_hash) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "prove");
                return;
            }
        };
        let verifier = IPAVerifierBn254 { params: &params };
        let verified = verifier
            .verify_optimized_with_statement(&commitment, FrBn254::one(), &proof, &statement_hash)
            .unwrap_or_else(|_| {
                assert!(false, "verify");
                false
            });
        assert!(verified, "raw ipa proof must verify");
        let bytes = build_ipa_receipt_bn254(
            IPA_BACKEND_GENERIC,
            IPA_TRANSCRIPT_GLYPH,
            n,
            &public_inputs,
            &commitment.into_affine(),
            &proof,
        );
        let decoded = match decode_ipa_receipt(&bytes) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "decode");
                return;
            }
        };
        assert_eq!(decoded.n, n);
        assert_eq!(decoded.public_inputs_len, public_inputs.len());
        assert!(verify_ipa_receipt(&bytes).is_ok());
        let (commitment_tag, point_tag, claim128) =
            derive_glyph_artifact_from_ipa_receipt(&bytes).unwrap_or_else(|_| {
                assert!(false, "artifact");
                ([0u8; 32], [0u8; 32], 0u128)
            });
        assert_ne!(commitment_tag, [0u8; 32]);
        assert_ne!(point_tag, [0u8; 32]);
        assert_ne!(claim128, 0u128);
    }

    #[test]
    fn test_ipa_receipt_roundtrip_and_artifact_bls12381() {
        let mut rng = StdRng::seed_from_u64(0xface_cafe);
        let n = 4usize;
        let params = IPAParamsBls12381::new(n);
        let prover = IPAProverBls12381 { params: &params };
        let a: Vec<FrBls12381> = (0..n).map(|_| FrBls12381::rand(&mut rng)).collect();
        let b: Vec<FrBls12381> = (0..n).map(|_| FrBls12381::rand(&mut rng)).collect();
        let public_inputs = a[..2].to_vec();
        let statement_hash = ipa_statement_hash_bls12381(&public_inputs);
        let (commitment, _c, proof) = match prover.prove_optimized_with_statement(&a, &b, &statement_hash) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "prove");
                return;
            }
        };
        let verifier = IPAVerifierBls12381 { params: &params };
        let verified = verifier
            .verify_optimized_with_statement(&commitment, FrBls12381::one(), &proof, &statement_hash)
            .unwrap_or_else(|_| {
                assert!(false, "verify");
                false
            });
        assert!(verified, "raw ipa proof must verify");
        let bytes = build_ipa_receipt_bls12381(
            IPA_BACKEND_GENERIC,
            IPA_TRANSCRIPT_GLYPH,
            n,
            &public_inputs,
            &commitment.into_affine(),
            &proof,
        );
        let decoded = match decode_ipa_receipt(&bytes) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "decode");
                return;
            }
        };
        assert_eq!(decoded.n, n);
        assert_eq!(decoded.public_inputs_len, public_inputs.len());
        assert!(verify_ipa_receipt(&bytes).is_ok());
        let (commitment_tag, point_tag, claim128) =
            derive_glyph_artifact_from_ipa_receipt(&bytes).unwrap_or_else(|_| {
                assert!(false, "artifact");
                ([0u8; 32], [0u8; 32], 0u128)
            });
        assert_ne!(commitment_tag, [0u8; 32]);
        assert_ne!(point_tag, [0u8; 32]);
        assert_ne!(claim128, 0u128);
    }
}
