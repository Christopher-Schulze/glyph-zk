use std::env;
use std::fs;

use glyph::cli_registry;
use glyph::halo2_receipt::{
    decode_halo2_receipt, encode_halo2_receipt, verify_halo2_receipt, Halo2Receipt,
    HALO2_BACKEND_KZG_GWC, HALO2_BACKEND_KZG_SHPLONK, HALO2_CIRCUIT_STANDARD_PLONK,
    HALO2_CIRCUIT_PARAMETRIC_PLONK, HALO2_CIRCUIT_CUSTOM_PLONK, HALO2_CIRCUIT_CUSTOM_TAG,
    HALO2_CURVE_BLS12381, HALO2_CURVE_BN256, HALO2_TRANSCRIPT_BLAKE2B,
};

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

fn parse_curve_id(value: &str) -> Result<u8, String> {
    match value {
        "bn254" | "bn256" => Ok(HALO2_CURVE_BN256),
        "bls12-381" | "bls12381" | "bls" => Ok(HALO2_CURVE_BLS12381),
        _ => Err("unsupported --curve (use bn256 or bls12-381)".to_string()),
    }
}

fn parse_backend_id(value: &str) -> Result<u8, String> {
    match value {
        "gwc" => Ok(HALO2_BACKEND_KZG_GWC),
        "shplonk" => Ok(HALO2_BACKEND_KZG_SHPLONK),
        _ => Err("unsupported --backend (use gwc or shplonk)".to_string()),
    }
}

fn parse_transcript_id(value: &str) -> Result<u8, String> {
    match value {
        "blake2b" => Ok(HALO2_TRANSCRIPT_BLAKE2B),
        _ => Err("unsupported --transcript (use blake2b)".to_string()),
    }
}

fn parse_circuit_id(value: &str) -> Result<u8, String> {
    match value {
        "standard-plonk" | "standard" | "plonk" => Ok(HALO2_CIRCUIT_STANDARD_PLONK),
        "parametric-plonk" | "param-plonk" | "parametric" => {
            Ok(HALO2_CIRCUIT_PARAMETRIC_PLONK)
        }
        "custom-plonk" | "custom" => Ok(HALO2_CIRCUIT_CUSTOM_PLONK),
        _ => Err("unsupported --circuit (use standard-plonk, parametric-plonk, or custom-plonk)".to_string()),
    }
}

fn parse_bool(value: &str) -> Result<bool, String> {
    match value {
        "1" | "true" | "yes" => Ok(true),
        "0" | "false" | "no" => Ok(false),
        _ => Err("invalid boolean value (use true or false)".to_string()),
    }
}

fn main() -> Result<(), String> {
    let mut curve: Option<String> = None;
    let mut backend: Option<String> = None;
    let mut transcript: Option<String> = None;
    let mut circuit: Option<String> = None;
    let mut compress_selectors: Option<String> = None;

    let mut params_hex: Option<String> = None;
    let mut params_file: Option<String> = None;
    let mut vk_hex: Option<String> = None;
    let mut vk_file: Option<String> = None;
    let mut instances_hex: Option<String> = None;
    let mut instances_file: Option<String> = None;
    let mut proof_hex: Option<String> = None;
    let mut proof_file: Option<String> = None;
    let mut circuit_params_hex: Option<String> = None;
    let mut circuit_params_file: Option<String> = None;
    let mut out_path: Option<String> = None;

    let mut args = env::args().skip(1).peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            "--curve" => curve = args.next(),
            "--backend" => backend = args.next(),
            "--transcript" => transcript = args.next(),
            "--circuit" => circuit = args.next(),
            "--compress-selectors" => compress_selectors = args.next(),
            "--params-hex" => params_hex = args.next(),
            "--params-file" => params_file = args.next(),
            "--vk-hex" => vk_hex = args.next(),
            "--vk-file" => vk_file = args.next(),
            "--instances-hex" => instances_hex = args.next(),
            "--instances-file" => instances_file = args.next(),
            "--proof-hex" => proof_hex = args.next(),
            "--proof-file" => proof_file = args.next(),
            "--circuit-params-hex" => circuit_params_hex = args.next(),
            "--circuit-params-file" => circuit_params_file = args.next(),
            "--out" => out_path = args.next(),
            _ => return Err(format!("unknown arg: {arg}")),
        }
    }

    let curve_id = parse_curve_id(curve.as_deref().ok_or("missing --curve")?)?;
    let backend_id = parse_backend_id(backend.as_deref().ok_or("missing --backend")?)?;
    let transcript_id =
        parse_transcript_id(transcript.as_deref().ok_or("missing --transcript")?)?;
    let circuit_id = parse_circuit_id(circuit.as_deref().ok_or("missing --circuit")?)?;
    let compress_selectors = match compress_selectors.as_deref() {
        Some(value) => parse_bool(value)?,
        None => true,
    };

    let params_bytes = read_bytes("params", params_hex, params_file)?;
    let vk_bytes = read_bytes("vk", vk_hex, vk_file)?;
    let instances_bytes = read_bytes("instances", instances_hex, instances_file)?;
    let proof_bytes = read_bytes("proof", proof_hex, proof_file)?;
    let circuit_params_bytes = match (&circuit_params_hex, &circuit_params_file) {
        (None, None) => Vec::new(),
        _ => read_bytes("circuit-params", circuit_params_hex, circuit_params_file)?,
    };
    if circuit_id == HALO2_CIRCUIT_STANDARD_PLONK && !circuit_params_bytes.is_empty() {
        return Err("halo2 standard circuit does not accept params".to_string());
    }
    if (circuit_id == HALO2_CIRCUIT_PARAMETRIC_PLONK
        || circuit_id == HALO2_CIRCUIT_CUSTOM_PLONK)
        && circuit_params_bytes.is_empty()
    {
        return Err("halo2 circuit params missing".to_string());
    }
    if circuit_id == HALO2_CIRCUIT_CUSTOM_PLONK
        && !circuit_params_bytes.starts_with(HALO2_CIRCUIT_CUSTOM_TAG)
    {
        return Err("halo2 custom circuit params missing tag".to_string());
    }

    let receipt = Halo2Receipt {
        curve_id,
        backend_id,
        transcript_id,
        circuit_id,
        compress_selectors,
        circuit_params_bytes,
        params_bytes,
        vk_bytes,
        instances_bytes,
        proof_bytes,
    };

    let encoded = encode_halo2_receipt(&receipt);
    let decoded = decode_halo2_receipt(&encoded)?;
    verify_halo2_receipt(&encode_halo2_receipt(&decoded))?;

    let receipt_hex = hex::encode(encoded);
    let payload = format!("receipt_hex={receipt_hex}\n");
    if let Some(path) = out_path {
        fs::write(&path, payload).map_err(|e| format!("write failed: {e}"))?;
    } else {
        print!("{payload}");
    }
    Ok(())
}

fn print_help() {
    eprintln!("glyph_import_halo2_receipt \\");
    eprintln!("  --curve <bn256|bls12-381> --backend <gwc|shplonk> --transcript <blake2b> \\");
    eprintln!("  --circuit <standard-plonk|parametric-plonk|custom-plonk> \\");
    eprintln!("  [--compress-selectors <true|false>] \\");
    eprintln!("  --params-hex <0x..> | --params-file <path> \\");
    eprintln!("  --vk-hex <0x..> | --vk-file <path> \\");
    eprintln!("  --instances-hex <0x..> | --instances-file <path> \\");
    eprintln!("  --proof-hex <0x..> | --proof-file <path> \\");
    eprintln!("  [--circuit-params-hex <0x..> | --circuit-params-file <path>] [--out <path>]");
    let status = cli_registry::format_feature_status("snark", cli_registry::snark_feature_enabled());
    eprintln!("Requires feature: {status}");
    let kinds = cli_registry::enabled_snark_kinds();
    eprintln!("Enabled snark kinds: {}", cli_registry::join_list(&kinds));
}
