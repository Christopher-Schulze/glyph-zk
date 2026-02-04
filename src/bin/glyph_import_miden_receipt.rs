use std::env;
use std::fs;

use glyph::adapters::AdapterFamily;
use glyph::cli_registry;
use glyph::miden_stark::{
    decode_miden_program,
    decode_miden_public_inputs,
    miden_hash_fn_to_id,
    miden_hash_id_to_hash_fn,
    verify_miden_receipt,
    MidenPublicInputs,
    MidenStarkProgram,
    FIELD_MIDEN_GOLDILOCKS_ID,
    VC_MERKLE_ID,
};
use glyph::stark_receipt::{CanonicalStarkReceipt, CanonicalStarkVk};
use miden_verifier::ExecutionProof;

fn strip_hex_prefix(s: &str) -> &str {
    s.strip_prefix("0x").unwrap_or(s)
}

fn decode_hex_string(label: &str, hex_str: &str) -> Result<Vec<u8>, String> {
    hex::decode(strip_hex_prefix(hex_str.trim()))
        .map_err(|e| format!("{label} hex decode failed: {e}"))
}

fn read_bytes(label: &str, hex_arg: Option<String>, file_arg: Option<String>) -> Result<Vec<u8>, String> {
    match (hex_arg, file_arg) {
        (Some(hex_str), None) => decode_hex_string(label, &hex_str),
        (None, Some(path)) => {
            let bytes = fs::read(&path).map_err(|e| format!("failed to read {label} file: {e}"))?;
            if bytes.is_empty() {
                return Err(format!("{label} file is empty"));
            }
            let text = String::from_utf8(bytes.clone());
            match text {
                Ok(s) => {
                    let trimmed = s.trim();
                    if trimmed.is_empty() {
                        return Err(format!("{label} file is empty"));
                    }
                    if trimmed.chars().all(|c| c.is_ascii_hexdigit() || c == 'x') {
                        return decode_hex_string(label, trimmed);
                    }
                    Ok(bytes)
                }
                Err(_) => Ok(bytes),
            }
        }
        (None, None) => Err(format!("missing {label} input")),
        _ => Err(format!("provide exactly one of {label}-hex or {label}-file")),
    }
}

fn parse_hash_override(arg: &str) -> Result<u8, String> {
    match arg {
        "blake3-192" | "blake3_192" | "blake3" => Ok(miden_hash_fn_to_id(
            miden_air::HashFunction::Blake3_192,
        )),
        "blake3-256" | "blake3_256" => Ok(miden_hash_fn_to_id(
            miden_air::HashFunction::Blake3_256,
        )),
        "rpo" | "rpo256" => Ok(miden_hash_fn_to_id(miden_air::HashFunction::Rpo256)),
        "rpx" | "rpx256" => Ok(miden_hash_fn_to_id(miden_air::HashFunction::Rpx256)),
        "poseidon2" => Ok(miden_hash_fn_to_id(
            miden_air::HashFunction::Poseidon2,
        )),
        _ => Err("unsupported --hash (use blake3-192, blake3-256, rpo, rpx, poseidon2)".to_string()),
    }
}

fn main() -> Result<(), String> {
    let mut program_hex: Option<String> = None;
    let mut program_file: Option<String> = None;
    let mut proof_hex: Option<String> = None;
    let mut proof_file: Option<String> = None;
    let mut inputs_hex: Option<String> = None;
    let mut inputs_file: Option<String> = None;
    let mut outputs_hex: Option<String> = None;
    let mut outputs_file: Option<String> = None;
    let mut out_path: Option<String> = None;
    let mut hash_override: Option<u8> = None;

    let mut args = env::args().skip(1).peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            "--program-hex" => program_hex = args.next(),
            "--program-file" => program_file = args.next(),
            "--proof-hex" => proof_hex = args.next(),
            "--proof-file" => proof_file = args.next(),
            "--stack-inputs-hex" => inputs_hex = args.next(),
            "--stack-inputs-file" => inputs_file = args.next(),
            "--stack-outputs-hex" => outputs_hex = args.next(),
            "--stack-outputs-file" => outputs_file = args.next(),
            "--hash" => {
                let val = args.next().ok_or_else(|| "missing --hash value".to_string())?;
                hash_override = Some(parse_hash_override(&val)?);
            }
            "--out" => out_path = args.next(),
            _ => return Err(format!("unknown arg: {arg}")),
        }
    }

    let program_info_bytes = read_bytes("program", program_hex, program_file)?;
    let proof_bytes = read_bytes("proof", proof_hex, proof_file)?;
    let stack_inputs_bytes = read_bytes("stack-inputs", inputs_hex, inputs_file)?;
    let stack_outputs_bytes = read_bytes("stack-outputs", outputs_hex, outputs_file)?;

    let proof = ExecutionProof::from_bytes(&proof_bytes)
        .map_err(|e| format!("proof decode failed: {e}"))?;
    let (hash_fn, _inner, requests) = proof.clone().into_parts();
    if !requests.is_empty() {
        return Err("miden proofs with precompile requests are not supported".to_string());
    }
    let inferred_hash_id = miden_hash_fn_to_id(hash_fn);
    if let Some(expected) = hash_override {
        if expected != inferred_hash_id {
            return Err("hash override does not match proof hash function".to_string());
        }
        miden_hash_id_to_hash_fn(expected)?;
    }

    let pub_inputs = MidenPublicInputs {
        stack_inputs_bytes,
        stack_outputs_bytes,
    };
    let program = MidenStarkProgram {
        version: glyph::miden_stark::MIDEN_STARK_PROGRAM_VERSION,
        field_id: FIELD_MIDEN_GOLDILOCKS_ID,
        hash_id: hash_override.unwrap_or(inferred_hash_id),
        commitment_scheme_id: VC_MERKLE_ID,
        program_info_bytes,
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
        pub_inputs_bytes: pub_inputs.encode(),
        vk_bytes: vk.encode(),
    };

    let decoded_vk = CanonicalStarkReceipt::decode_and_validate_vk(&receipt)?;
    let decoded_program = decode_miden_program(&decoded_vk.program_bytes)?;
    let decoded_pub_inputs = decode_miden_public_inputs(&receipt.pub_inputs_bytes)?;
    if decoded_pub_inputs.stack_inputs_bytes.is_empty()
        || decoded_pub_inputs.stack_outputs_bytes.is_empty()
    {
        return Err("stack inputs/outputs must be non-empty".to_string());
    }
    verify_miden_receipt(&receipt, &decoded_vk, &decoded_program)?;

    let receipt_hex = hex::encode(receipt.encode_for_hash());
    let payload = format!("receipt_hex={receipt_hex}\n");
    if let Some(path) = out_path {
        fs::write(&path, payload).map_err(|e| format!("write failed: {e}"))?;
    } else {
        print!("{payload}");
    }
    Ok(())
}

fn print_help() {
    eprintln!("glyph_import_miden_receipt \\");
    eprintln!("  --program-hex <0x..> | --program-file <path> \\");
    eprintln!("  --proof-hex <0x..> | --proof-file <path> \\");
    eprintln!("  --stack-inputs-hex <0x..> | --stack-inputs-file <path> \\");
    eprintln!("  --stack-outputs-hex <0x..> | --stack-outputs-file <path> \\");
    eprintln!("  [--hash <blake3-192|blake3-256|rpo|rpx|poseidon2>] [--out <path>]");
    let enabled = cli_registry::family_feature_enabled(AdapterFamily::StarkGoldilocks);
    let status = cli_registry::format_feature_status("stark-goldilocks", enabled);
    eprintln!("Requires feature: {status}");
    let fields = cli_registry::enabled_stark_fields();
    eprintln!("Enabled stark fields: {}", cli_registry::join_list(&fields));
}
