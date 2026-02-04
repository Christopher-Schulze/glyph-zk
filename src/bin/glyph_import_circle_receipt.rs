use std::env;
use std::fs;

use glyph::adapters::AdapterFamily;
use glyph::cli_registry;
use glyph::circle_stark::{
    decode_circle_stark_program,
    verify_circle_stark_receipt,
    CircleStarkProfile,
};
use glyph::circle_stark_bundle::CircleReceiptBundle;
use glyph::stark_receipt::{CanonicalStarkReceipt, CanonicalStarkVk};

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

fn main() -> Result<(), String> {
    let mut profile_hex: Option<String> = None;
    let mut profile_file: Option<String> = None;
    let mut program_hex: Option<String> = None;
    let mut program_file: Option<String> = None;
    let mut proof_hex: Option<String> = None;
    let mut proof_file: Option<String> = None;
    let mut pub_hex: Option<String> = None;
    let mut pub_file: Option<String> = None;
    let mut out_path: Option<String> = None;
    let mut bundle_json: Option<String> = None;

    let mut args = env::args().skip(1).peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            "--profile-hex" => profile_hex = args.next(),
            "--profile-file" => profile_file = args.next(),
            "--program-hex" => program_hex = args.next(),
            "--program-file" => program_file = args.next(),
            "--proof-hex" => proof_hex = args.next(),
            "--proof-file" => proof_file = args.next(),
            "--pub-hex" => pub_hex = args.next(),
            "--pub-file" => pub_file = args.next(),
            "--out" => out_path = args.next(),
            "--bundle-json" => bundle_json = args.next(),
            _ => return Err(format!("unknown arg: {arg}")),
        }
    }

    if let Some(bundle_path) = bundle_json {
        if profile_hex.is_some()
            || profile_file.is_some()
            || program_hex.is_some()
            || program_file.is_some()
            || proof_hex.is_some()
            || proof_file.is_some()
            || pub_hex.is_some()
            || pub_file.is_some()
        {
            return Err("bundle-json is mutually exclusive with manual inputs".to_string());
        }
        let bundle_bytes =
            fs::read(&bundle_path).map_err(|e| format!("failed to read bundle file: {e}"))?;
        let bundle = CircleReceiptBundle::decode(&bundle_bytes)?;
        let (receipt, program) = bundle.into_receipt_and_program()?;
        let decoded_vk = CanonicalStarkReceipt::decode_and_validate_vk(&receipt)?;
        verify_circle_stark_receipt(&receipt, &decoded_vk, &program)?;

        let receipt_hex = hex::encode(receipt.encode_for_hash());
        let payload = format!("receipt_hex={receipt_hex}\n");
        if let Some(path) = out_path {
            fs::write(&path, payload).map_err(|e| format!("write failed: {e}"))?;
        } else {
            print!("{payload}");
        }
        return Ok(());
    }

    let profile_bytes = read_bytes("profile", profile_hex, profile_file)?;
    let program_bytes = read_bytes("program", program_hex, program_file)?;
    let proof_bytes = read_bytes("proof", proof_hex, proof_file)?;
    let pub_inputs_bytes = read_bytes("pub", pub_hex, pub_file)?;

    let profile = CircleStarkProfile::decode(&profile_bytes)?;
    if profile.log_domain_size == 0 || profile.num_queries == 0 {
        return Err("circle profile invalid".to_string());
    }
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

    let decoded_vk = CanonicalStarkReceipt::decode_and_validate_vk(&receipt)?;
    verify_circle_stark_receipt(&receipt, &decoded_vk, &program)?;

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
    eprintln!("glyph_import_circle_receipt \\");
    eprintln!("  --profile-hex <0x..> | --profile-file <path> \\");
    eprintln!("  --program-hex <0x..> | --program-file <path> \\");
    eprintln!("  --proof-hex <0x..> | --proof-file <path> \\");
    eprintln!("  --pub-hex <0x..> | --pub-file <path> \\");
    eprintln!("  [--bundle-json <path>] [--out <path>]");
    let enabled = cli_registry::family_feature_enabled(AdapterFamily::StarkBabyBear);
    let status = cli_registry::format_feature_status("stark-babybear", enabled);
    eprintln!("Requires feature: {status}");
    let fields = cli_registry::enabled_stark_fields();
    eprintln!("Enabled stark fields: {}", cli_registry::join_list(&fields));
}
