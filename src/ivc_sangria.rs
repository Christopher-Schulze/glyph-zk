//! Sangria external proof verification for IVC.
//!
//! Implements a CompressedSNARK-backed verifier bound to the canonical R1CS receipt.

use crate::ivc_compressed::{generate_compressed_snark_bytes, verify_compressed_snark_bytes};
use crate::ivc_r1cs::R1csReceipt;

pub const IVC_SANGRIA_EXTERNAL_DOMAIN: &[u8] = b"GLYPH_IVC_SANGRIA_EXTERNAL";
pub const IVC_SANGRIA_EXTERNAL_VERSION: u16 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SangriaExternalProof {
    pub compressed_snark_bytes: Vec<u8>,
}

pub fn encode_sangria_external_proof_bytes(proof: &SangriaExternalProof) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        IVC_SANGRIA_EXTERNAL_DOMAIN.len() + 2 + 4 + proof.compressed_snark_bytes.len(),
    );
    out.extend_from_slice(IVC_SANGRIA_EXTERNAL_DOMAIN);
    out.extend_from_slice(&IVC_SANGRIA_EXTERNAL_VERSION.to_be_bytes());
    out.extend_from_slice(&(proof.compressed_snark_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&proof.compressed_snark_bytes);
    out
}

pub fn decode_sangria_external_proof_bytes(bytes: &[u8]) -> Result<SangriaExternalProof, String> {
    if !bytes.starts_with(IVC_SANGRIA_EXTERNAL_DOMAIN) {
        return Err("sangria external proof missing domain tag".to_string());
    }
    let mut off = IVC_SANGRIA_EXTERNAL_DOMAIN.len();
    let version = read_u16_be(bytes, &mut off)?;
    if version != IVC_SANGRIA_EXTERNAL_VERSION {
        return Err(format!("sangria external proof unsupported version={version}"));
    }
    let len = read_u32_be(bytes, &mut off)? as usize;
    let payload = read_vec(bytes, &mut off, len)?;
    if off != bytes.len() {
        return Err("sangria external proof trailing data".to_string());
    }
    Ok(SangriaExternalProof {
        compressed_snark_bytes: payload,
    })
}

pub fn generate_sangria_external_proof_bytes(receipt: &R1csReceipt) -> Result<Vec<u8>, String> {
    let compressed = generate_compressed_snark_bytes(receipt)?;
    let external = SangriaExternalProof {
        compressed_snark_bytes: compressed,
    };
    Ok(encode_sangria_external_proof_bytes(&external))
}

pub fn verify_sangria_external_proof_bytes(
    receipt: &R1csReceipt,
    bytes: &[u8],
) -> Result<(), String> {
    let external = decode_sangria_external_proof_bytes(bytes)?;
    verify_compressed_snark_bytes(receipt, &external.compressed_snark_bytes)
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

fn read_vec(bytes: &[u8], off: &mut usize, len: usize) -> Result<Vec<u8>, String> {
    let s = bytes
        .get(*off..*off + len)
        .ok_or_else(|| "unexpected EOF".to_string())?;
    *off += len;
    Ok(s.to_vec())
}
