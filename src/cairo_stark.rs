//! Cairo, Stone, and SHARP receipt verification via swiftness.

use bincode::Options;
use serde_json;
use starknet_crypto::Felt;
use swiftness::parse as parse_cairo_proof_json;
use swiftness::transform::TransformTo;
use swiftness_proof_parser::StarkProof as ParserStarkProof;
use swiftness_stark::types::StarkProof;

use crate::stark_receipt::{CanonicalStarkReceipt, CanonicalStarkVk};

pub const CAIRO_STARK_PROGRAM_TAG: &[u8] = b"CAIRO_STARK_PROGRAM";
pub const CAIRO_STARK_PROGRAM_VERSION: u16 = 1;

pub const FIELD_CAIRO_PRIME_ID: u8 = 0x09;
pub const VC_MERKLE_ID: u8 = 0x01;

pub const LAYOUT_STARKNET_WITH_KECCAK_ID: u8 = 0x04;
pub const HASH_KECCAK_160_LSB_ID: u8 = 0x01;

pub const STONE6_ID: u8 = 0x06;

pub const VERIFIER_MONOLITH_ID: u8 = 0x01;
pub const VERIFIER_SPLIT_ID: u8 = 0x02;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CairoStarkProgram {
    pub version: u16,
    pub field_id: u8,
    pub hash_id: u8,
    pub commitment_scheme_id: u8,
    pub layout_id: u8,
    pub hasher_id: u8,
    pub stone_version: u8,
    pub verifier_type: u8,
    pub program_hash: [u8; 32],
}

impl CairoStarkProgram {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CAIRO_STARK_PROGRAM_TAG.len() + 2 + 8 + 32);
        out.extend_from_slice(CAIRO_STARK_PROGRAM_TAG);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.push(self.field_id);
        out.push(self.hash_id);
        out.push(self.commitment_scheme_id);
        out.push(self.layout_id);
        out.push(self.hasher_id);
        out.push(self.stone_version);
        out.push(self.verifier_type);
        out.extend_from_slice(&self.program_hash);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if !bytes.starts_with(CAIRO_STARK_PROGRAM_TAG) {
            return Err("cairo program bytes missing CAIRO_STARK_PROGRAM_TAG prefix".to_string());
        }
        let mut off = CAIRO_STARK_PROGRAM_TAG.len();
        let version = read_u16_be(bytes, &mut off)?;
        if version != CAIRO_STARK_PROGRAM_VERSION {
            return Err(format!(
                "unsupported cairo program version={version} (expected {CAIRO_STARK_PROGRAM_VERSION})"
            ));
        }
        let field_id = read_u8(bytes, &mut off)?;
        let hash_id = read_u8(bytes, &mut off)?;
        let commitment_scheme_id = read_u8(bytes, &mut off)?;
        let layout_id = read_u8(bytes, &mut off)?;
        let hasher_id = read_u8(bytes, &mut off)?;
        let stone_version = read_u8(bytes, &mut off)?;
        let verifier_type = read_u8(bytes, &mut off)?;
        let program_hash = read_bytes32(bytes, &mut off)?;
        if off != bytes.len() {
            return Err("cairo program bytes have trailing data".to_string());
        }
        Ok(Self {
            version,
            field_id,
            hash_id,
            commitment_scheme_id,
            layout_id,
            hasher_id,
            stone_version,
            verifier_type,
            program_hash,
        })
    }
}

pub fn decode_cairo_program(bytes: &[u8]) -> Result<CairoStarkProgram, String> {
    CairoStarkProgram::decode(bytes)
}

pub fn verify_cairo_receipt(
    receipt: &CanonicalStarkReceipt,
    vk: &CanonicalStarkVk,
    program: &CairoStarkProgram,
) -> Result<(), String> {
    if vk.field_id != FIELD_CAIRO_PRIME_ID {
        return Err(format!(
            "cairo receipt field_id mismatch (expected 0x{FIELD_CAIRO_PRIME_ID:02x})"
        ));
    }
    if vk.commitment_scheme_id != VC_MERKLE_ID {
        return Err("cairo receipt commitment_scheme_id mismatch".to_string());
    }
    if vk.hash_id != program.hash_id {
        return Err("cairo receipt hash_id mismatch with program".to_string());
    }
    if program.field_id != FIELD_CAIRO_PRIME_ID {
        return Err("cairo program field_id mismatch".to_string());
    }
    if program.hash_id != program.hasher_id {
        return Err("cairo program hash_id and hasher_id mismatch".to_string());
    }

    if program.hasher_id != HASH_KECCAK_160_LSB_ID {
        return Err("unsupported cairo hasher_id for current build".to_string());
    }
    if program.layout_id != LAYOUT_STARKNET_WITH_KECCAK_ID {
        return Err("unsupported cairo layout_id for current build".to_string());
    }
    if program.stone_version != STONE6_ID {
        return Err("unsupported cairo stone_version".to_string());
    }
    if program.verifier_type != VERIFIER_MONOLITH_ID {
        return Err("unsupported cairo verifier_type for current build".to_string());
    }

    let proof = decode_cairo_proof(&receipt.proof_bytes)?;
    let public_input = decode_cairo_public_input(&receipt.pub_inputs_bytes)?;
    if proof.public_input != public_input {
        return Err("cairo public input mismatch with proof".to_string());
    }

    let security_bits = proof.config.security_bits();
    let (program_hash, _program_output) =
        verify_cairo_by_layout(&proof, program.layout_id, security_bits)?;
    let expected_hash = Felt::from_bytes_be(&program.program_hash);
    if program_hash != expected_hash {
        return Err("cairo program hash mismatch".to_string());
    }
    Ok(())
}

pub fn parse_cairo_receipt_from_json(
    proof_json: &str,
    layout_id: u8,
    hasher_id: u8,
    stone_version: u8,
    verifier_type: u8,
) -> Result<(CanonicalStarkReceipt, CairoStarkProgram), String> {
    if hasher_id != HASH_KECCAK_160_LSB_ID {
        return Err("unsupported cairo hasher_id for current build".to_string());
    }
    if layout_id != LAYOUT_STARKNET_WITH_KECCAK_ID {
        return Err("unsupported cairo layout_id for current build".to_string());
    }
    if stone_version != STONE6_ID {
        return Err("unsupported cairo stone_version for current build".to_string());
    }
    if verifier_type != VERIFIER_MONOLITH_ID {
        return Err("unsupported cairo verifier_type for current build".to_string());
    }
    let parser_proof: ParserStarkProof = parse_cairo_proof_json(proof_json)
        .map_err(|e| format!("cairo json parse failed: {e}"))?;
    let proof: StarkProof = parser_proof.clone().transform_to();
    let public_inputs = proof.public_input.clone();
    let security_bits = proof.config.security_bits();
    let (program_hash, _program_output) = verify_cairo_by_layout(&proof, layout_id, security_bits)?;

    let proof_bytes = encode_cairo_proof(&proof)?;
    let pub_inputs_bytes = encode_cairo_public_input(&public_inputs)?;

    let mut program_hash_bytes = [0u8; 32];
    program_hash_bytes.copy_from_slice(&program_hash.to_bytes_be());

    let program = CairoStarkProgram {
        version: CAIRO_STARK_PROGRAM_VERSION,
        field_id: FIELD_CAIRO_PRIME_ID,
        hash_id: hasher_id,
        commitment_scheme_id: VC_MERKLE_ID,
        layout_id,
        hasher_id,
        stone_version,
        verifier_type,
        program_hash: program_hash_bytes,
    };

    let vk = CanonicalStarkVk {
        version: 1,
        field_id: program.field_id,
        hash_id: program.hash_id,
        commitment_scheme_id: program.commitment_scheme_id,
        consts_bytes: Vec::new(),
        program_bytes: program.encode(),
    };

    let receipt = CanonicalStarkReceipt {
        proof_bytes,
        pub_inputs_bytes,
        vk_bytes: vk.encode(),
    };

    Ok((receipt, program))
}

fn verify_cairo_by_layout(
    proof: &StarkProof,
    layout_id: u8,
    security_bits: Felt,
) -> Result<(Felt, Vec<Felt>), String> {
    match layout_id {
        LAYOUT_STARKNET_WITH_KECCAK_ID => {
            use swiftness_air::layout::starknet_with_keccak::Layout;
            proof.verify::<Layout>(security_bits).map_err(|e| e.to_string())
        }
        _ => Err("unsupported cairo layout_id".to_string()),
    }
}

fn bincode_options() -> impl bincode::Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
}

fn decode_cairo_proof(bytes: &[u8]) -> Result<StarkProof, String> {
    bincode_options()
        .deserialize(bytes)
        .or_else(|bincode_err| {
            serde_json::from_slice(bytes)
                .map_err(|json_err| format!("cairo proof decode failed: bincode={bincode_err}; json={json_err}"))
        })
}

fn decode_cairo_public_input(
    bytes: &[u8],
) -> Result<swiftness_air::public_memory::PublicInput, String> {
    bincode_options()
        .deserialize(bytes)
        .or_else(|bincode_err| {
            serde_json::from_slice(bytes).map_err(|json_err| {
                format!(
                    "cairo public input decode failed: bincode={bincode_err}; json={json_err}"
                )
            })
        })
}

fn encode_cairo_proof(proof: &StarkProof) -> Result<Vec<u8>, String> {
    serde_json::to_vec(proof).map_err(|e| format!("cairo proof encode failed: {e}"))
}

fn encode_cairo_public_input(
    public_input: &swiftness_air::public_memory::PublicInput,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(public_input)
        .map_err(|e| format!("cairo public input encode failed: {e}"))
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

fn read_bytes32(bytes: &[u8], off: &mut usize) -> Result<[u8; 32], String> {
    let s = bytes.get(*off..*off + 32).ok_or_else(|| "unexpected EOF".to_string())?;
    *off += 32;
    let mut out = [0u8; 32];
    out.copy_from_slice(s);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cairo_program_roundtrip() {
        let program = CairoStarkProgram {
            version: CAIRO_STARK_PROGRAM_VERSION,
            field_id: FIELD_CAIRO_PRIME_ID,
            hash_id: HASH_KECCAK_160_LSB_ID,
            commitment_scheme_id: VC_MERKLE_ID,
            layout_id: LAYOUT_STARKNET_WITH_KECCAK_ID,
            hasher_id: HASH_KECCAK_160_LSB_ID,
            stone_version: STONE6_ID,
            verifier_type: VERIFIER_MONOLITH_ID,
            program_hash: [0x11; 32],
        };
        let enc = program.encode();
        let dec = match CairoStarkProgram::decode(&enc) {
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
        let decoded = match CairoStarkProgram::decode(&tampered) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "tampered still decodes");
                return;
            }
        };
        assert_ne!(decoded, program);
    }

    #[test]
    fn test_cairo_receipt_tamper_rejects() {
        let proof_json = match std::fs::read_to_string(
            "scripts/tools/fixtures/cairo_stone6_keccak_160_lsb_example_proof.json",
        ) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "cairo fixture missing");
                return;
            }
        };
        let (receipt, program) = match parse_cairo_receipt_from_json(
            &proof_json,
            LAYOUT_STARKNET_WITH_KECCAK_ID,
            HASH_KECCAK_160_LSB_ID,
            STONE6_ID,
            VERIFIER_MONOLITH_ID,
        ) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "cairo receipt parse");
                return;
            }
        };
        let vk = match CanonicalStarkReceipt::decode_and_validate_vk(&receipt) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "vk decode");
                return;
            }
        };
        if let Err(_) = verify_cairo_receipt(&receipt, &vk, &program) {
            assert!(false, "cairo verify");
            return;
        }

        let mut tampered_proof = receipt.clone();
        tampered_proof.proof_bytes[0] ^= 1;
        assert!(verify_cairo_receipt(&tampered_proof, &vk, &program).is_err());

        let mut tampered_inputs = receipt.clone();
        tampered_inputs.pub_inputs_bytes[0] ^= 1;
        assert!(verify_cairo_receipt(&tampered_inputs, &vk, &program).is_err());

        let mut tampered_vk = receipt.clone();
        tampered_vk.vk_bytes[0] ^= 1;
        assert!(CanonicalStarkReceipt::decode_and_validate_vk(&tampered_vk).is_err());
    }
}
