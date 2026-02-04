//! Miden STARK receipt verification for the generic STARK adapter.
//!
//! Canonical encoding ensures Miden program info and public inputs are strictly bound.

use miden_air::HashFunction;
use miden_verifier::{ExecutionProof, ProgramInfo, StackInputs, StackOutputs};
use winter_utils::Deserializable;

use crate::stark_receipt::{CanonicalStarkReceipt, CanonicalStarkVk};

pub const MIDEN_STARK_PROGRAM_TAG: &[u8] = b"MIDEN_STARK_PROGRAM";
pub const MIDEN_STARK_PROGRAM_VERSION: u16 = 1;
pub const MIDEN_PUBLIC_INPUTS_TAG: &[u8] = b"MIDEN_PUBLIC_INPUTS";
pub const MIDEN_PUBLIC_INPUTS_VERSION: u16 = 1;

pub const FIELD_MIDEN_GOLDILOCKS_ID: u8 = 0x08;
pub const VC_MERKLE_ID: u8 = 0x01;

pub const HASH_MIDEN_BLAKE3_192_ID: u8 = 0x10;
pub const HASH_MIDEN_BLAKE3_256_ID: u8 = 0x11;
pub const HASH_MIDEN_RPO_ID: u8 = 0x12;
pub const HASH_MIDEN_RPX_ID: u8 = 0x13;
pub const HASH_MIDEN_POSEIDON2_ID: u8 = 0x14;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MidenStarkProgram {
    pub version: u16,
    pub field_id: u8,
    pub hash_id: u8,
    pub commitment_scheme_id: u8,
    pub program_info_bytes: Vec<u8>,
}

impl MidenStarkProgram {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            MIDEN_STARK_PROGRAM_TAG.len() + 2 + 3 + 4 + self.program_info_bytes.len(),
        );
        out.extend_from_slice(MIDEN_STARK_PROGRAM_TAG);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.push(self.field_id);
        out.push(self.hash_id);
        out.push(self.commitment_scheme_id);
        out.extend_from_slice(&(self.program_info_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.program_info_bytes);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if !bytes.starts_with(MIDEN_STARK_PROGRAM_TAG) {
            return Err("miden program bytes missing MIDEN_STARK_PROGRAM_TAG prefix".to_string());
        }
        let mut off = MIDEN_STARK_PROGRAM_TAG.len();

        let version = read_u16_be(bytes, &mut off)?;
        if version != MIDEN_STARK_PROGRAM_VERSION {
            return Err(format!(
                "unsupported miden program version={version} (expected {MIDEN_STARK_PROGRAM_VERSION})"
            ));
        }
        let field_id = read_u8(bytes, &mut off)?;
        let hash_id = read_u8(bytes, &mut off)?;
        let commitment_scheme_id = read_u8(bytes, &mut off)?;
        let info_len = read_u32_be(bytes, &mut off)? as usize;
        let program_info_bytes = read_vec(bytes, &mut off, info_len)?;
        if off != bytes.len() {
            return Err("miden program bytes have trailing data".to_string());
        }
        Ok(Self {
            version,
            field_id,
            hash_id,
            commitment_scheme_id,
            program_info_bytes,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MidenPublicInputs {
    pub stack_inputs_bytes: Vec<u8>,
    pub stack_outputs_bytes: Vec<u8>,
}

impl MidenPublicInputs {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            MIDEN_PUBLIC_INPUTS_TAG.len()
                + 2
                + 4
                + self.stack_inputs_bytes.len()
                + 4
                + self.stack_outputs_bytes.len(),
        );
        out.extend_from_slice(MIDEN_PUBLIC_INPUTS_TAG);
        out.extend_from_slice(&MIDEN_PUBLIC_INPUTS_VERSION.to_be_bytes());
        out.extend_from_slice(&(self.stack_inputs_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.stack_inputs_bytes);
        out.extend_from_slice(&(self.stack_outputs_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.stack_outputs_bytes);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if !bytes.starts_with(MIDEN_PUBLIC_INPUTS_TAG) {
            return Err("miden public inputs missing MIDEN_PUBLIC_INPUTS_TAG prefix".to_string());
        }
        let mut off = MIDEN_PUBLIC_INPUTS_TAG.len();
        let version = read_u16_be(bytes, &mut off)?;
        if version != MIDEN_PUBLIC_INPUTS_VERSION {
            return Err(format!(
                "unsupported miden public inputs version={version} (expected {MIDEN_PUBLIC_INPUTS_VERSION})"
            ));
        }
        let inputs_len = read_u32_be(bytes, &mut off)? as usize;
        let stack_inputs_bytes = read_vec(bytes, &mut off, inputs_len)?;
        let outputs_len = read_u32_be(bytes, &mut off)? as usize;
        let stack_outputs_bytes = read_vec(bytes, &mut off, outputs_len)?;
        if off != bytes.len() {
            return Err("miden public inputs trailing data".to_string());
        }
        Ok(Self {
            stack_inputs_bytes,
            stack_outputs_bytes,
        })
    }
}

pub fn decode_miden_program(bytes: &[u8]) -> Result<MidenStarkProgram, String> {
    MidenStarkProgram::decode(bytes)
}

pub fn decode_miden_public_inputs(bytes: &[u8]) -> Result<MidenPublicInputs, String> {
    MidenPublicInputs::decode(bytes)
}

pub fn verify_miden_receipt(
    receipt: &CanonicalStarkReceipt,
    vk: &CanonicalStarkVk,
    program: &MidenStarkProgram,
) -> Result<(), String> {
    if vk.field_id != FIELD_MIDEN_GOLDILOCKS_ID {
        return Err(format!(
            "miden receipt field_id mismatch (expected 0x{FIELD_MIDEN_GOLDILOCKS_ID:02x})"
        ));
    }
    if vk.commitment_scheme_id != VC_MERKLE_ID {
        return Err("miden receipt commitment_scheme_id mismatch".to_string());
    }
    if vk.hash_id != program.hash_id {
        return Err("miden receipt hash_id mismatch with program".to_string());
    }
    if program.program_info_bytes.is_empty() {
        return Err("miden program_info_bytes is empty".to_string());
    }

    let program_info = ProgramInfo::read_from_bytes(&program.program_info_bytes)
        .map_err(|e| format!("miden program_info decode failed: {e}"))?;
    let pub_inputs = MidenPublicInputs::decode(&receipt.pub_inputs_bytes)?;
    let stack_inputs = StackInputs::read_from_bytes(&pub_inputs.stack_inputs_bytes)
        .map_err(|e| format!("miden stack inputs decode failed: {e}"))?;
    let stack_outputs = StackOutputs::read_from_bytes(&pub_inputs.stack_outputs_bytes)
        .map_err(|e| format!("miden stack outputs decode failed: {e}"))?;
    let proof = ExecutionProof::from_bytes(&receipt.proof_bytes)
        .map_err(|e| format!("miden proof decode failed: {e}"))?;
    let (hash_fn, _inner, requests) = proof.clone().into_parts();
    if !requests.is_empty() {
        return Err("miden proofs with precompile requests are not supported".to_string());
    }
    let expected_hash = miden_hash_id_to_hash_fn(vk.hash_id)?;
    if expected_hash != hash_fn {
        return Err("miden proof hash function mismatch with vk hash_id".to_string());
    }

    miden_verifier::verify(program_info, stack_inputs, stack_outputs, proof)
        .map_err(|e| format!("miden verify failed: {e}"))?;
    Ok(())
}

pub fn miden_hash_id_to_hash_fn(hash_id: u8) -> Result<HashFunction, String> {
    match hash_id {
        HASH_MIDEN_BLAKE3_192_ID => Ok(HashFunction::Blake3_192),
        HASH_MIDEN_BLAKE3_256_ID => Ok(HashFunction::Blake3_256),
        HASH_MIDEN_RPO_ID => Ok(HashFunction::Rpo256),
        HASH_MIDEN_RPX_ID => Ok(HashFunction::Rpx256),
        HASH_MIDEN_POSEIDON2_ID => Ok(HashFunction::Poseidon2),
        _ => Err("unsupported miden hash_id".to_string()),
    }
}

pub fn miden_hash_fn_to_id(hash_fn: HashFunction) -> u8 {
    match hash_fn {
        HashFunction::Blake3_192 => HASH_MIDEN_BLAKE3_192_ID,
        HashFunction::Blake3_256 => HASH_MIDEN_BLAKE3_256_ID,
        HashFunction::Rpo256 => HASH_MIDEN_RPO_ID,
        HashFunction::Rpx256 => HASH_MIDEN_RPX_ID,
        HashFunction::Poseidon2 => HASH_MIDEN_POSEIDON2_ID,
    }
}

fn read_u8(bytes: &[u8], off: &mut usize) -> Result<u8, String> {
    let v = bytes.get(*off).copied().ok_or_else(|| "unexpected EOF".to_string())?;
    *off += 1;
    Ok(v)
}

fn read_u16_be(bytes: &[u8], off: &mut usize) -> Result<u16, String> {
    let s = bytes.get(*off..*off + 2).ok_or_else(|| "unexpected EOF".to_string())?;
    *off += 2;
    Ok(u16::from_be_bytes([s[0], s[1]]))
}

fn read_u32_be(bytes: &[u8], off: &mut usize) -> Result<u32, String> {
    let s = bytes.get(*off..*off + 4).ok_or_else(|| "unexpected EOF".to_string())?;
    *off += 4;
    Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_vec(bytes: &[u8], off: &mut usize, len: usize) -> Result<Vec<u8>, String> {
    let s = bytes.get(*off..*off + len).ok_or_else(|| "unexpected EOF".to_string())?;
    *off += len;
    Ok(s.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stark_receipt::CanonicalStarkReceipt;

    #[test]
    fn test_miden_program_roundtrip_and_tamper() {
        let program = MidenStarkProgram {
            version: MIDEN_STARK_PROGRAM_VERSION,
            field_id: FIELD_MIDEN_GOLDILOCKS_ID,
            hash_id: HASH_MIDEN_RPO_ID,
            commitment_scheme_id: VC_MERKLE_ID,
            program_info_bytes: vec![1, 2, 3, 4],
        };
        let enc = program.encode();
        let dec = match MidenStarkProgram::decode(&enc) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "decode must succeed");
                return;
            }
        };
        assert_eq!(program, dec);

        let mut tampered = enc.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        let decoded = match MidenStarkProgram::decode(&tampered) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "tampered still decodes");
                return;
            }
        };
        assert_ne!(decoded, program);
    }

    #[test]
    fn test_miden_public_inputs_roundtrip() {
        let inputs = MidenPublicInputs {
            stack_inputs_bytes: vec![0xAA; 3],
            stack_outputs_bytes: vec![0xBB; 5],
        };
        let enc = inputs.encode();
        let dec = match MidenPublicInputs::decode(&enc) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "decode must succeed");
                return;
            }
        };
        assert_eq!(inputs, dec);
    }

    fn load_miden_fixture(path: &str) -> CanonicalStarkReceipt {
        let contents = match std::fs::read_to_string(path) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "miden fixture missing");
                return CanonicalStarkReceipt {
                    proof_bytes: Vec::new(),
                    pub_inputs_bytes: Vec::new(),
                    vk_bytes: Vec::new(),
                };
            }
        };
        let line = contents
            .lines()
            .map(|l| l.trim())
            .find(|l| l.starts_with("receipt_hex="));
        let line = match line {
            Some(value) => value,
            None => {
                assert!(false, "receipt_hex missing");
                return CanonicalStarkReceipt {
                    proof_bytes: Vec::new(),
                    pub_inputs_bytes: Vec::new(),
                    vk_bytes: Vec::new(),
                };
            }
        };
        let hex_str = line
            .split_once('=')
            .map(|(_, v)| v.trim())
            .unwrap_or("");
        if hex_str.is_empty() {
            assert!(false, "receipt_hex parse failed");
            return CanonicalStarkReceipt {
                proof_bytes: Vec::new(),
                pub_inputs_bytes: Vec::new(),
                vk_bytes: Vec::new(),
            };
        }
        let bytes = match hex::decode(hex_str) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "receipt_hex decode failed");
                return CanonicalStarkReceipt {
                    proof_bytes: Vec::new(),
                    pub_inputs_bytes: Vec::new(),
                    vk_bytes: Vec::new(),
                };
            }
        };
        match CanonicalStarkReceipt::decode(&bytes) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "receipt decode failed");
                CanonicalStarkReceipt {
                    proof_bytes: Vec::new(),
                    pub_inputs_bytes: Vec::new(),
                    vk_bytes: Vec::new(),
                }
            }
        }
    }

    fn assert_miden_tamper_rejects(path: &str) {
        let receipt = load_miden_fixture(path);
        let vk = match CanonicalStarkReceipt::decode_and_validate_vk(&receipt) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "vk decode");
                return;
            }
        };
        let program = match decode_miden_program(&vk.program_bytes) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "program decode");
                return;
            }
        };
        if let Err(_) = verify_miden_receipt(&receipt, &vk, &program) {
            assert!(false, "miden verify");
            return;
        }

        let mut tampered_proof = receipt.clone();
        tampered_proof.proof_bytes[0] ^= 1;
        assert!(verify_miden_receipt(&tampered_proof, &vk, &program).is_err());

        let mut tampered_inputs = receipt.clone();
        tampered_inputs.pub_inputs_bytes[0] ^= 1;
        assert!(verify_miden_receipt(&tampered_inputs, &vk, &program).is_err());

        let mut tampered_vk = receipt.clone();
        tampered_vk.vk_bytes[0] ^= 1;
        assert!(CanonicalStarkReceipt::decode_and_validate_vk(&tampered_vk).is_err());
    }

    #[test]
    fn test_miden_receipt_tamper_rejects() {
        assert_miden_tamper_rejects("scripts/tools/fixtures/miden_rpo_receipt.txt");
        assert_miden_tamper_rejects("scripts/tools/fixtures/miden_blake3_receipt.txt");
    }
}
