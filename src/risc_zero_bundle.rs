use serde::{Deserialize, Serialize};

use crate::standard_stark::{
    decode_standard_stark_program,
    StandardStarkProfile,
    StandardStarkProgram,
};
use crate::stark_receipt::{CanonicalStarkReceipt, CanonicalStarkVk};

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RiscZeroReceiptBundle {
    pub version: u16,
    pub profile_hex: String,
    pub program_hex: String,
    pub proof_hex: String,
    pub pub_inputs_hex: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RiscZeroExternalReceipt {
    pub version: u16,
    pub profile_hex: String,
    pub program_hex: String,
    pub seal_hex: String,
    pub journal_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum RiscZeroReceiptInput {
    Bundle(RiscZeroReceiptBundle),
    External(RiscZeroExternalReceipt),
}

impl RiscZeroReceiptBundle {
    pub fn decode(json_bytes: &[u8]) -> Result<Self, String> {
        serde_json::from_slice::<Self>(json_bytes)
            .map_err(|e| format!("risc zero bundle json decode failed: {e}"))
    }

    pub fn into_receipt_and_program(self) -> Result<(CanonicalStarkReceipt, StandardStarkProgram), String> {
        if self.version != 1 {
            return Err(format!("unsupported risc zero bundle version={}", self.version));
        }
        let profile_bytes = decode_hex_string("profile_hex", &self.profile_hex)?;
        let program_bytes = decode_hex_string("program_hex", &self.program_hex)?;
        let proof_bytes = decode_hex_string("proof_hex", &self.proof_hex)?;
        let pub_inputs_bytes = decode_hex_string("pub_inputs_hex", &self.pub_inputs_hex)?;

        let _profile = StandardStarkProfile::decode(&profile_bytes)?;
        let program = decode_standard_stark_program(&program_bytes)?;
        let field_id = program.field_id;
        let hash_id = program.hash_id;
        let commitment_scheme_id = program.commitment_scheme_id;

        let vk = CanonicalStarkVk {
            version: 1,
            field_id,
            hash_id,
            commitment_scheme_id,
            consts_bytes: profile_bytes,
            program_bytes,
        };
        let receipt = CanonicalStarkReceipt {
            proof_bytes,
            pub_inputs_bytes,
            vk_bytes: vk.encode(),
        };
        Ok((receipt, program))
    }
}

impl RiscZeroExternalReceipt {
    pub fn into_receipt_and_program(self) -> Result<(CanonicalStarkReceipt, StandardStarkProgram), String> {
        if self.version != 1 {
            return Err(format!("unsupported risc zero receipt version={}", self.version));
        }
        let profile_bytes = decode_hex_string("profile_hex", &self.profile_hex)?;
        let program_bytes = decode_hex_string("program_hex", &self.program_hex)?;
        let proof_bytes = decode_hex_string("seal_hex", &self.seal_hex)?;
        let pub_inputs_bytes = decode_hex_string("journal_hex", &self.journal_hex)?;

        let _profile = StandardStarkProfile::decode(&profile_bytes)?;
        let program = decode_standard_stark_program(&program_bytes)?;
        let field_id = program.field_id;
        let hash_id = program.hash_id;
        let commitment_scheme_id = program.commitment_scheme_id;

        let vk = CanonicalStarkVk {
            version: 1,
            field_id,
            hash_id,
            commitment_scheme_id,
            consts_bytes: profile_bytes,
            program_bytes,
        };
        let receipt = CanonicalStarkReceipt {
            proof_bytes,
            pub_inputs_bytes,
            vk_bytes: vk.encode(),
        };
        Ok((receipt, program))
    }
}

pub fn decode_risc_zero_receipt_input(
    json_bytes: &[u8],
) -> Result<RiscZeroReceiptInput, String> {
    serde_json::from_slice::<RiscZeroReceiptInput>(json_bytes)
        .map_err(|e| format!("risc zero receipt json decode failed: {e}"))
}

fn decode_hex_string(label: &str, hex_str: &str) -> Result<Vec<u8>, String> {
    let trimmed = hex_str.trim();
    let stripped = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if stripped.is_empty() {
        return Err(format!("{label} is empty"));
    }
    hex::decode(stripped).map_err(|e| format!("{label} hex decode failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::standard_stark::{
        StandardConstraint, StandardStarkProgram, STANDARD_STARK_PROGRAM_VERSION,
        CONSTRAINT_CUBE_PLUS_CONST, FIELD_BABY_BEAR_STD_ID, HASH_SHA3_ID, VC_MERKLE_ID,
    };

    #[test]
    fn test_risc_zero_bundle_decode_roundtrip() {
        let profile = StandardStarkProfile {
            version: 1,
            log_domain_size: 3,
            num_queries: 2,
            blowup_factor: 1,
        };
        let profile_bytes = profile.encode();
        let program = StandardStarkProgram {
            version: STANDARD_STARK_PROGRAM_VERSION,
            field_id: FIELD_BABY_BEAR_STD_ID,
            hash_id: HASH_SHA3_ID,
            commitment_scheme_id: VC_MERKLE_ID,
            trace_width: 1,
            trace_length: 1u32 << profile.log_domain_size,
            constraints: vec![StandardConstraint {
                id: CONSTRAINT_CUBE_PLUS_CONST,
                col: 0,
                a: 0,
                b: 0,
                constant: 1,
            }],
            air_id: b"risc_zero_bundle_test".to_vec(),
        };
        let program_bytes = program.encode();

        let bundle = RiscZeroReceiptBundle {
            version: 1,
            profile_hex: hex::encode(&profile_bytes),
            program_hex: hex::encode(&program_bytes),
            proof_hex: hex::encode([1u8]),
            pub_inputs_hex: hex::encode([2u8]),
        };
        let json = match serde_json::to_vec(&bundle) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "bundle json");
                return;
            }
        };
        let decoded = match RiscZeroReceiptBundle::decode(&json) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "decode");
                return;
            }
        };
        let (receipt, decoded_program) = match decoded.into_receipt_and_program() {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "receipt");
                return;
            }
        };

        let decoded_vk = match CanonicalStarkVk::decode(&receipt.vk_bytes) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "vk");
                return;
            }
        };
        assert_eq!(decoded_vk.field_id, FIELD_BABY_BEAR_STD_ID);
        assert_eq!(decoded_vk.hash_id, program.hash_id);
        assert_eq!(decoded_vk.commitment_scheme_id, program.commitment_scheme_id);
        assert_eq!(decoded_vk.consts_bytes, profile_bytes);
        assert_eq!(decoded_vk.program_bytes, program_bytes);
        assert_eq!(decoded_program, program);
    }

    #[test]
    fn test_risc_zero_external_receipt_decode_roundtrip() {
        let profile = StandardStarkProfile {
            version: 1,
            log_domain_size: 3,
            num_queries: 2,
            blowup_factor: 1,
        };
        let profile_bytes = profile.encode();
        let program = StandardStarkProgram {
            version: STANDARD_STARK_PROGRAM_VERSION,
            field_id: FIELD_BABY_BEAR_STD_ID,
            hash_id: HASH_SHA3_ID,
            commitment_scheme_id: VC_MERKLE_ID,
            trace_width: 1,
            trace_length: 1u32 << profile.log_domain_size,
            constraints: vec![StandardConstraint {
                id: CONSTRAINT_CUBE_PLUS_CONST,
                col: 0,
                a: 0,
                b: 0,
                constant: 1,
            }],
            air_id: b"risc_zero_external_test".to_vec(),
        };
        let program_bytes = program.encode();

        let receipt = RiscZeroExternalReceipt {
            version: 1,
            profile_hex: hex::encode(&profile_bytes),
            program_hex: hex::encode(&program_bytes),
            seal_hex: hex::encode([9u8]),
            journal_hex: hex::encode([7u8]),
        };
        let json = match serde_json::to_vec(&receipt) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "receipt json");
                return;
            }
        };
        let decoded = match decode_risc_zero_receipt_input(&json) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "decode");
                return;
            }
        };
        let (receipt, decoded_program) = match decoded {
            RiscZeroReceiptInput::External(input) => match input.into_receipt_and_program() {
                Ok(value) => value,
                Err(_) => {
                    assert!(false, "receipt");
                    return;
                }
            },
            _ => {
                assert!(false, "expected external receipt");
                return;
            }
        };

        let decoded_vk = match CanonicalStarkVk::decode(&receipt.vk_bytes) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "vk");
                return;
            }
        };
        assert_eq!(decoded_vk.field_id, FIELD_BABY_BEAR_STD_ID);
        assert_eq!(decoded_vk.hash_id, program.hash_id);
        assert_eq!(decoded_vk.commitment_scheme_id, program.commitment_scheme_id);
        assert_eq!(decoded_vk.consts_bytes, profile_bytes);
        assert_eq!(decoded_vk.program_bytes, program_bytes);
        assert_eq!(decoded_program, program);
    }

    #[test]
    fn test_risc_zero_external_fixture_file_parses() {
        let raw = match std::fs::read("scripts/tools/fixtures/risc_zero_external_receipt.json") {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "fixture file must be readable");
                return;
            }
        };
        let input = match decode_risc_zero_receipt_input(&raw) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "decode");
                return;
            }
        };
        let (receipt, program) = match input {
            RiscZeroReceiptInput::External(receipt) => match receipt.into_receipt_and_program() {
                Ok(value) => value,
                Err(_) => {
                    assert!(false, "receipt");
                    return;
                }
            },
            RiscZeroReceiptInput::Bundle(bundle) => match bundle.into_receipt_and_program() {
                Ok(value) => value,
                Err(_) => {
                    assert!(false, "bundle");
                    return;
                }
            },
        };
        let decoded_vk = match CanonicalStarkVk::decode(&receipt.vk_bytes) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "vk");
                return;
            }
        };
        assert_eq!(decoded_vk.field_id, FIELD_BABY_BEAR_STD_ID);
        let decoded_program = match StandardStarkProgram::decode(&decoded_vk.program_bytes) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "program decode");
                return;
            }
        };
        assert_eq!(decoded_program, program);
    }
}
