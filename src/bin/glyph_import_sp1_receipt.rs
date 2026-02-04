use std::env;
use std::fs;

use glyph::cli_registry;
use glyph::sp1_adapter::{Sp1ProofSystem, Sp1Receipt, encode_sp1_receipt, verify_sp1_receipt};

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
    let mut proof_hex: Option<String> = None;
    let mut proof_file: Option<String> = None;
    let mut pub_hex: Option<String> = None;
    let mut pub_file: Option<String> = None;
    let mut vkey_hash: Option<String> = None;
    let mut proof_system: Option<Sp1ProofSystem> = None;
    let mut out_path: Option<String> = None;

    let mut args = env::args().skip(1).peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            "--proof-hex" => proof_hex = args.next(),
            "--proof-file" => proof_file = args.next(),
            "--pub-hex" => pub_hex = args.next(),
            "--pub-file" => pub_file = args.next(),
            "--vkey-hash" => vkey_hash = args.next(),
            "--proof-system" => {
                let val = args.next().ok_or_else(|| "missing --proof-system value".to_string())?;
                proof_system = match val.as_str() {
                    "groth16" => Some(Sp1ProofSystem::Groth16),
                    "plonk" => Some(Sp1ProofSystem::Plonk),
                    _ => return Err("unsupported --proof-system (use groth16 or plonk)".to_string()),
                };
            }
            "--out" => out_path = args.next(),
            _ => return Err(format!("unknown arg: {arg}")),
        }
    }

    let proof_bytes = read_bytes("proof", proof_hex, proof_file)?;
    let public_inputs = read_bytes("pub", pub_hex, pub_file)?;
    let vkey_hash = vkey_hash.ok_or_else(|| "missing --vkey-hash".to_string())?;
    let proof_system = proof_system.ok_or_else(|| "missing --proof-system".to_string())?;

    let receipt = Sp1Receipt {
        proof_system,
        vkey_hash: vkey_hash.as_bytes().to_vec(),
        public_inputs,
        proof_bytes,
    };
    let bytes = encode_sp1_receipt(&receipt);
    verify_sp1_receipt(&bytes)?;

    if let Some(path) = out_path {
        fs::write(&path, hex::encode(&bytes))
            .map_err(|e| format!("failed to write receipt: {e}"))?;
    } else {
        println!("{}", hex::encode(bytes));
    }
    Ok(())
}

fn print_help() {
    eprintln!("glyph_import_sp1_receipt \\");
    eprintln!("  --proof-hex <0x..> | --proof-file <path> \\");
    eprintln!("  --pub-hex <0x..> | --pub-file <path> \\");
    eprintln!("  --vkey-hash <0x..> --proof-system <groth16|plonk> [--out <path>]");
    let status = cli_registry::format_feature_status("snark", cli_registry::snark_feature_enabled());
    eprintln!("Requires feature: {status}");
    let kinds = cli_registry::enabled_snark_kinds();
    eprintln!("Enabled snark kinds: {}", cli_registry::join_list(&kinds));
}
