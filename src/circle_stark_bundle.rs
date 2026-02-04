use serde::Deserialize;

use crate::circle_stark::{
    decode_circle_stark_program,
    CircleStarkProfile,
    CircleStarkProgram,
};
use crate::stark_receipt::{CanonicalStarkReceipt, CanonicalStarkVk};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CircleReceiptBundle {
    pub version: u16,
    pub profile_hex: String,
    pub program_hex: String,
    pub proof_hex: String,
    pub pub_inputs_hex: String,
}

impl CircleReceiptBundle {
    pub fn decode(json_bytes: &[u8]) -> Result<Self, String> {
        serde_json::from_slice::<Self>(json_bytes)
            .map_err(|e| format!("bundle json decode failed: {e}"))
    }

    pub fn into_receipt_and_program(self) -> Result<(CanonicalStarkReceipt, CircleStarkProgram), String> {
        if self.version != 1 {
            return Err(format!("unsupported bundle version={}", self.version));
        }
        let profile_bytes = decode_hex_string("profile_hex", &self.profile_hex)?;
        let program_bytes = decode_hex_string("program_hex", &self.program_hex)?;
        let proof_bytes = decode_hex_string("proof_hex", &self.proof_hex)?;
        let pub_inputs_bytes = decode_hex_string("pub_inputs_hex", &self.pub_inputs_hex)?;

        let _profile = CircleStarkProfile::decode(&profile_bytes)?;
        let program = decode_circle_stark_program(&program_bytes)?;
        let field_id = program.field_id();
        let hash_id = program.hash_id();
        let commitment_scheme_id = program.commitment_scheme_id();

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

fn decode_hex_string(label: &str, hex_str: &str) -> Result<Vec<u8>, String> {
    let trimmed = hex_str.trim();
    let stripped = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if stripped.is_empty() {
        return Err(format!("{label} is empty"));
    }
    hex::decode(stripped).map_err(|e| format!("{label} hex decode failed: {e}"))
}
