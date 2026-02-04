//! Adapter SP1 Groth16/Plonk proofs (BN254 receipts).
//!
//! Provides a canonical receipt format and verification that derives the GLYPH artifact
//! tags for GLYPH. Receipt verification is off-chain only.

use crate::adapters::keccak256;
use crate::adapter_error::{wrap, wrap_stage};
use sp1_verifier::{Groth16Verifier, PlonkVerifier, GROTH16_VK_BYTES, PLONK_VK_BYTES};

pub const SP1_RECEIPT_TAG: &[u8] = b"GLYPH_SP1_RECEIPT";
pub const SP1_COMMITMENT_TAG_DOMAIN: &[u8] = b"GLYPH_SP1_COMMITMENT_TAG";
pub const SP1_POINT_TAG_DOMAIN: &[u8] = b"GLYPH_SP1_POINT_TAG";
pub const SP1_CLAIM_DOMAIN: &[u8] = b"GLYPH_SP1_CLAIM";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sp1ProofSystem {
    Groth16 = 0x01,
    Plonk = 0x02,
}

impl Sp1ProofSystem {
    pub fn from_u8(value: u8) -> Result<Self, String> {
        match value {
            0x01 => Ok(Self::Groth16),
            0x02 => Ok(Self::Plonk),
            _ => Err("sp1 proof system id invalid".to_string()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sp1Receipt {
    pub proof_system: Sp1ProofSystem,
    /// ASCII-encoded SP1 vkey hash string, e.g. "0x..."
    pub vkey_hash: Vec<u8>,
    pub public_inputs: Vec<u8>,
    pub proof_bytes: Vec<u8>,
}

pub fn encode_sp1_receipt(receipt: &Sp1Receipt) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        SP1_RECEIPT_TAG.len()
            + 1
            + 2
            + receipt.vkey_hash.len()
            + 4
            + receipt.public_inputs.len()
            + 4
            + receipt.proof_bytes.len(),
    );
    out.extend_from_slice(SP1_RECEIPT_TAG);
    out.push(receipt.proof_system as u8);
    out.extend_from_slice(&(receipt.vkey_hash.len() as u16).to_be_bytes());
    out.extend_from_slice(&receipt.vkey_hash);
    out.extend_from_slice(&(receipt.public_inputs.len() as u32).to_be_bytes());
    out.extend_from_slice(&receipt.public_inputs);
    out.extend_from_slice(&(receipt.proof_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&receipt.proof_bytes);
    out
}

pub fn decode_sp1_receipt(bytes: &[u8]) -> Result<Sp1Receipt, String> {
    if !bytes.starts_with(SP1_RECEIPT_TAG) {
        return Err("sp1 receipt missing tag".to_string());
    }
    let mut off = SP1_RECEIPT_TAG.len();
    let proof_system = Sp1ProofSystem::from_u8(read_u8(bytes, &mut off)?)?;
    let vkey_len = read_u16_be(bytes, &mut off)? as usize;
    let vkey_hash = read_vec(bytes, &mut off, vkey_len)?;
    let pub_len = read_u32_be(bytes, &mut off)? as usize;
    let public_inputs = read_vec(bytes, &mut off, pub_len)?;
    let proof_len = read_u32_be(bytes, &mut off)? as usize;
    let proof_bytes = read_vec(bytes, &mut off, proof_len)?;
    if off != bytes.len() {
        return Err("sp1 receipt has trailing bytes".to_string());
    }
    Ok(Sp1Receipt {
        proof_system,
        vkey_hash,
        public_inputs,
        proof_bytes,
    })
}

pub fn verify_sp1_receipt(bytes: &[u8]) -> Result<Sp1Receipt, String> {
    let receipt = decode_sp1_receipt(bytes).map_err(|e| wrap_stage("sp1", "decode", e))?;
    let vkey_hash = std::str::from_utf8(&receipt.vkey_hash)
        .map_err(|_| wrap("sp1", "vkey hash is not valid utf8"))?;
    match receipt.proof_system {
        Sp1ProofSystem::Groth16 => {
            Groth16Verifier::verify(
                &receipt.proof_bytes,
                &receipt.public_inputs,
                vkey_hash,
                &GROTH16_VK_BYTES,
            )
            .map_err(|e| wrap_stage("sp1", "groth16 verify failed", e))?;
        }
        Sp1ProofSystem::Plonk => {
            PlonkVerifier::verify(
                &receipt.proof_bytes,
                &receipt.public_inputs,
                vkey_hash,
                &PLONK_VK_BYTES,
            )
            .map_err(|e| wrap_stage("sp1", "plonk verify failed", e))?;
        }
    }
    Ok(receipt)
}

pub fn derive_glyph_artifact_from_sp1_receipt(
    receipt_bytes: &[u8],
) -> Result<([u8; 32], [u8; 32], u128), String> {
    let receipt = verify_sp1_receipt(receipt_bytes)?;
    let proof_hash = keccak256(&receipt.proof_bytes);
    let pub_hash = keccak256(&receipt.public_inputs);
    let vkey_hash = keccak256(&receipt.vkey_hash);

    let commitment_tag = keccak256_concat_domain(SP1_COMMITMENT_TAG_DOMAIN, &proof_hash, &vkey_hash);
    let point_tag = keccak256_concat_domain(SP1_POINT_TAG_DOMAIN, &pub_hash, &vkey_hash);
    let claim_hash = keccak256_concat_domain(SP1_CLAIM_DOMAIN, &commitment_tag, &point_tag);
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

fn read_u8(bytes: &[u8], off: &mut usize) -> Result<u8, String> {
    let b = *bytes.get(*off).ok_or_else(|| "sp1 receipt EOF".to_string())?;
    *off += 1;
    Ok(b)
}

fn read_u16_be(bytes: &[u8], off: &mut usize) -> Result<u16, String> {
    let slice = bytes
        .get(*off..*off + 2)
        .ok_or_else(|| "sp1 receipt EOF".to_string())?;
    *off += 2;
    Ok(u16::from_be_bytes([slice[0], slice[1]]))
}

fn read_u32_be(bytes: &[u8], off: &mut usize) -> Result<u32, String> {
    let slice = bytes
        .get(*off..*off + 4)
        .ok_or_else(|| "sp1 receipt EOF".to_string())?;
    *off += 4;
    Ok(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_vec(bytes: &[u8], off: &mut usize, len: usize) -> Result<Vec<u8>, String> {
    let slice = bytes
        .get(*off..*off + len)
        .ok_or_else(|| "sp1 receipt EOF".to_string())?;
    *off += len;
    Ok(slice.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sp1_receipt_roundtrip_rejects_invalid() {
        let receipt = Sp1Receipt {
            proof_system: Sp1ProofSystem::Groth16,
            vkey_hash: b"0x00".to_vec(),
            public_inputs: vec![1, 2, 3],
            proof_bytes: vec![4, 5, 6],
        };
        let bytes = encode_sp1_receipt(&receipt);
        let decoded = match decode_sp1_receipt(&bytes) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "decode");
                return;
            }
        };
        assert_eq!(decoded, receipt);
        assert!(verify_sp1_receipt(&bytes).is_err());
    }
}
