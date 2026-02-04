use serde::{Deserialize, Serialize};

use crate::circle_stark::FIELD_M31_CIRCLE_ID;
use crate::stark_receipt::{CanonicalStarkReceipt, CanonicalStarkVk};
use crate::stwo_verifier::{StwoProfile, StwoProgram, HASH_BLAKE2S_ID, VC_MERKLE_ID};

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct StwoReceiptBundle {
    pub version: u16,
    pub profile_hex: String,
    pub program_hex: String,
    pub proof_hex: String,
    pub pub_inputs_hex: String,
}

impl StwoReceiptBundle {
    pub fn decode(json_bytes: &[u8]) -> Result<Self, String> {
        serde_json::from_slice::<Self>(json_bytes)
            .map_err(|e| format!("stwo bundle json decode failed: {e}"))
    }

    pub fn into_receipt_and_program(
        self,
    ) -> Result<(CanonicalStarkReceipt, StwoProgram), String> {
        if self.version != 1 {
            return Err(format!("unsupported stwo bundle version={}", self.version));
        }
        let profile_bytes = decode_hex_string("profile_hex", &self.profile_hex)?;
        let program_bytes = decode_hex_string("program_hex", &self.program_hex)?;
        let proof_bytes = decode_hex_string("proof_hex", &self.proof_hex)?;
        let pub_inputs_bytes = decode_hex_string("pub_inputs_hex", &self.pub_inputs_hex)?;

        let _profile = StwoProfile::decode(&profile_bytes)?;
        let program = StwoProgram::decode(&program_bytes)?;

        let vk = CanonicalStarkVk {
            version: 1,
            field_id: FIELD_M31_CIRCLE_ID,
            hash_id: HASH_BLAKE2S_ID,
            commitment_scheme_id: VC_MERKLE_ID,
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
    use crate::stark_receipt::CanonicalStarkVk;
    use crate::stwo_verifier::{StwoConstraint, StwoExpr, StwoProfile, STWO_TOOLCHAIN_ID};

    #[test]
    fn test_stwo_bundle_decode_roundtrip() {
        let profile = StwoProfile {
            log_domain_size: 8,
            num_queries: 12,
            blowup_factor: 2,
            log_last_layer_degree_bound: 1,
            pow_bits: 16,
        };
        let profile_bytes = profile.encode();
        let program = StwoProgram {
            toolchain_id: STWO_TOOLCHAIN_ID,
            trace_width: 2,
            log_trace_length: 4,
            constraints: vec![StwoConstraint {
                expr: StwoExpr::Add(
                    Box::new(StwoExpr::Col { col: 0, offset: 0 }),
                    Box::new(StwoExpr::Const(1)),
                ),
            }],
        };
        let program_bytes = program.encode();

        let bundle = StwoReceiptBundle {
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
        let decoded = match StwoReceiptBundle::decode(&json) {
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
        assert_eq!(decoded_program, program);

        let vk = match CanonicalStarkVk::decode(&receipt.vk_bytes) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "vk");
                return;
            }
        };
        assert_eq!(vk.consts_bytes, profile_bytes);
        assert_eq!(vk.program_bytes, program_bytes);
    }
}
