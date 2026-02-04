use std::env;
use std::fs;

use glyph::stwo_types::{decode_stwo_commitment_scheme_proof, StwoCommitmentSchemeProof};
use glyph::stwo_verifier::StwoProfile;

#[derive(serde::Serialize)]
struct BundleJson {
    version: u16,
    profile_hex: String,
    program_hex: String,
    proof_hex: String,
    pub_inputs_hex: String,
}

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
    let mut proof_json: Option<String> = None;
    let mut program_hex: Option<String> = None;
    let mut program_file: Option<String> = None;
    let mut pub_hex: Option<String> = None;
    let mut pub_file: Option<String> = None;
    let mut profile_hex: Option<String> = None;
    let mut profile_file: Option<String> = None;
    let mut log_domain_size: Option<u8> = None;
    let mut out_path: Option<String> = None;

    let mut args = env::args().skip(1).peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--proof-json" => proof_json = args.next(),
            "--program-hex" => program_hex = args.next(),
            "--program-file" => program_file = args.next(),
            "--pub-hex" => pub_hex = args.next(),
            "--pub-file" => pub_file = args.next(),
            "--profile-hex" => profile_hex = args.next(),
            "--profile-file" => profile_file = args.next(),
            "--log-domain-size" => {
                let v = args
                    .next()
                    .ok_or_else(|| "missing value for --log-domain-size".to_string())?;
                log_domain_size = Some(v.parse::<u8>().map_err(|_| "invalid log-domain-size".to_string())?);
            }
            "--out" => out_path = args.next(),
            _ => return Err(format!("unknown arg: {arg}")),
        }
    }

    let proof_path = proof_json.ok_or_else(|| "missing --proof-json".to_string())?;
    let proof_bytes = fs::read(&proof_path).map_err(|e| format!("failed to read proof json: {e}"))?;
    let proof: StwoCommitmentSchemeProof = decode_stwo_commitment_scheme_proof(&proof_bytes)?;
    let canonical_proof_bytes = serde_json::to_vec(&proof).map_err(|e| format!("proof json serialize failed: {e}"))?;

    let program_bytes = read_bytes("program", program_hex, program_file)?;
    let pub_inputs_bytes = read_bytes("pub", pub_hex, pub_file)?;

    let profile_bytes = if profile_hex.is_some() || profile_file.is_some() {
        read_bytes("profile", profile_hex, profile_file)?
    } else {
        let log_domain_size = log_domain_size.ok_or_else(|| "missing --log-domain-size (or provide profile bytes)".to_string())?;
        let profile = StwoProfile {
            log_domain_size,
            num_queries: proof.config.fri_config.n_queries as u8,
            blowup_factor: proof.config.fri_config.log_blowup_factor as u8,
            log_last_layer_degree_bound: proof.config.fri_config.log_last_layer_degree_bound as u8,
            pow_bits: proof.config.pow_bits as u8,
        };
        profile.encode()
    };

    let bundle = BundleJson {
        version: 1,
        profile_hex: hex::encode(profile_bytes),
        program_hex: hex::encode(program_bytes),
        proof_hex: hex::encode(canonical_proof_bytes),
        pub_inputs_hex: hex::encode(pub_inputs_bytes),
    };

    let bundle_json = serde_json::to_string_pretty(&bundle)
        .map_err(|e| format!("bundle json serialize failed: {e}"))?;
    if let Some(path) = out_path {
        fs::write(&path, bundle_json).map_err(|e| format!("write failed: {e}"))?;
    } else {
        print!("{bundle_json}");
    }
    Ok(())
}
