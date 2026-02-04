use std::env;
use std::fs;

use glyph::cli_registry;
use glyph::plonk_adapter::{
    decode_plonk_receipt,
    encode_plonk_receipt,
    encode_plonk_generic_backend_params,
    verify_plonk_receipt,
    PlonkReceipt,
    PLONK_BACKEND_DUSK,
    PLONK_BACKEND_GENERIC,
    PLONK_BACKEND_GNARK,
    PLONK_CURVE_BLS12381,
    PLONK_CURVE_BN254,
    PLONK_ENCODING_BLS_LE,
    PLONK_ENCODING_BN254_BE,
    PLONK_ENCODING_HALO2_INSTANCES,
    PLONK_GENERIC_BACKEND_HALO2,
    PLONK_GENERIC_BACKEND_GNARK,
    PLONK_GENERIC_BACKEND_DUSK,
    PLONK_PCS_KZG,
    PLONK_PROTOCOL_PLONK,
    PLONK_TRANSCRIPT_BLAKE2B,
    PLONK_TRANSCRIPT_NATIVE,
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

fn read_optional_bytes(
    label: &str,
    hex_arg: Option<String>,
    file_arg: Option<String>,
) -> Result<Vec<u8>, String> {
    if hex_arg.is_none() && file_arg.is_none() {
        return Ok(Vec::new());
    }
    read_bytes(label, hex_arg, file_arg)
}

fn parse_system_id(value: &str) -> Result<(u8, u8, u8, Option<u8>), String> {
    match value {
        "bn254" | "bn254-gnark" | "gnark" => Ok((
            PLONK_BACKEND_GNARK,
            PLONK_CURVE_BN254,
            PLONK_ENCODING_BN254_BE,
            None,
        )),
        "bls" | "bls12-381" | "bls12381" | "bls-dusk" | "dusk" => Ok((
            PLONK_BACKEND_DUSK,
            PLONK_CURVE_BLS12381,
            PLONK_ENCODING_BLS_LE,
            None,
        )),
        "halo2-bn254" | "halo2-bn256" => Ok((
            PLONK_BACKEND_GENERIC,
            PLONK_CURVE_BN254,
            PLONK_ENCODING_HALO2_INSTANCES,
            Some(PLONK_GENERIC_BACKEND_HALO2),
        )),
        "halo2-bls" | "halo2-bls12-381" | "halo2-bls12381" => Ok((
            PLONK_BACKEND_GENERIC,
            PLONK_CURVE_BLS12381,
            PLONK_ENCODING_HALO2_INSTANCES,
            Some(PLONK_GENERIC_BACKEND_HALO2),
        )),
        _ => Err("unsupported --system (use bn254-gnark, bls12-381-dusk, halo2-bn256, or halo2-bls12-381)".to_string()),
    }
}

fn parse_backend_id(value: &str) -> Result<u8, String> {
    match value {
        "gnark" => Ok(PLONK_BACKEND_GNARK),
        "dusk" => Ok(PLONK_BACKEND_DUSK),
        "generic" => Ok(PLONK_BACKEND_GENERIC),
        _ => Err("unsupported --backend (use gnark, dusk, or generic)".to_string()),
    }
}

fn parse_backend_kind(value: &str) -> Result<u8, String> {
    match value {
        "halo2" => Ok(PLONK_GENERIC_BACKEND_HALO2),
        "gnark" => Ok(PLONK_GENERIC_BACKEND_GNARK),
        "dusk" => Ok(PLONK_GENERIC_BACKEND_DUSK),
        _ => Err("unsupported --backend-kind (use halo2, gnark, or dusk)".to_string()),
    }
}

fn parse_curve_id(value: &str) -> Result<u8, String> {
    match value {
        "bn254" => Ok(PLONK_CURVE_BN254),
        "bls12-381" | "bls12381" | "bls" => Ok(PLONK_CURVE_BLS12381),
        _ => Err("unsupported --curve (use bn254 or bls12-381)".to_string()),
    }
}

fn parse_encoding_id(value: &str) -> Result<u8, String> {
    match value {
        "bn254-be" | "bn254" | "be" => Ok(PLONK_ENCODING_BN254_BE),
        "bls-le" | "bls" | "le" => Ok(PLONK_ENCODING_BLS_LE),
        "halo2" | "halo2-instances" => Ok(PLONK_ENCODING_HALO2_INSTANCES),
        _ => Err("unsupported --encoding (use bn254-be, bls-le, or halo2-instances)".to_string()),
    }
}

fn parse_pcs_id(value: &str) -> Result<u8, String> {
    match value {
        "kzg" => Ok(PLONK_PCS_KZG),
        _ => Err("unsupported --pcs (use kzg)".to_string()),
    }
}

fn parse_protocol_id(value: &str) -> Result<u8, String> {
    match value {
        "plonk" => Ok(PLONK_PROTOCOL_PLONK),
        _ => Err("unsupported --protocol (use plonk)".to_string()),
    }
}

fn parse_transcript_id(value: &str) -> Result<u8, String> {
    match value {
        "native" => Ok(PLONK_TRANSCRIPT_NATIVE),
        "blake2b" => Ok(PLONK_TRANSCRIPT_BLAKE2B),
        _ => Err("unsupported --transcript (use native or blake2b)".to_string()),
    }
}

fn main() -> Result<(), String> {
    let mut vk_hex: Option<String> = None;
    let mut vk_file: Option<String> = None;
    let mut proof_hex: Option<String> = None;
    let mut proof_file: Option<String> = None;
    let mut pub_hex: Option<String> = None;
    let mut pub_file: Option<String> = None;
    let mut system: Option<String> = None;
    let mut backend: Option<String> = None;
    let mut backend_kind: Option<String> = None;
    let mut curve: Option<String> = None;
    let mut encoding: Option<String> = None;
    let mut pcs: Option<String> = None;
    let mut protocol: Option<String> = None;
    let mut transcript: Option<String> = None;
    let mut backend_params_hex: Option<String> = None;
    let mut backend_params_file: Option<String> = None;
    let mut out_path: Option<String> = None;

    let mut args = env::args().skip(1).peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            "--vk-hex" => vk_hex = args.next(),
            "--vk-file" => vk_file = args.next(),
            "--proof-hex" => proof_hex = args.next(),
            "--proof-file" => proof_file = args.next(),
            "--pub-hex" => pub_hex = args.next(),
            "--pub-file" => pub_file = args.next(),
            "--system" => system = args.next(),
            "--backend" => backend = args.next(),
            "--backend-kind" => backend_kind = args.next(),
            "--curve" => curve = args.next(),
            "--encoding" => encoding = args.next(),
            "--pcs" => pcs = args.next(),
            "--protocol" => protocol = args.next(),
            "--transcript" => transcript = args.next(),
            "--backend-params-hex" => backend_params_hex = args.next(),
            "--backend-params-file" => backend_params_file = args.next(),
            "--out" => out_path = args.next(),
            _ => return Err(format!("unknown arg: {arg}")),
        }
    }

    let encoding_set = encoding.is_some();
    let _transcript_set = transcript.is_some();
    let (backend_id, curve_id, mut encoding_id, system_backend_kind) = if let Some(system) = system {
        if backend.is_some() || curve.is_some() || encoding.is_some() {
            return Err("do not combine --system with --backend/--curve/--encoding".to_string());
        }
        let (backend_id, curve_id, encoding_id, kind) = parse_system_id(&system)?;
        (backend_id, curve_id, encoding_id, kind)
    } else {
        let backend_id = parse_backend_id(backend.as_deref().ok_or("missing --backend")?)?;
        let curve_id = parse_curve_id(curve.as_deref().ok_or("missing --curve")?)?;
        let encoding_id = match encoding.as_deref() {
            Some(value) => parse_encoding_id(value)?,
            None => {
                if backend_id == PLONK_BACKEND_GENERIC {
                    PLONK_ENCODING_HALO2_INSTANCES
                } else {
                    match curve_id {
                        PLONK_CURVE_BN254 => PLONK_ENCODING_BN254_BE,
                        PLONK_CURVE_BLS12381 => PLONK_ENCODING_BLS_LE,
                        _ => return Err("unsupported --curve".to_string()),
                    }
                }
            }
        };
        (backend_id, curve_id, encoding_id, None)
    };
    let pcs_id = match pcs.as_deref() {
        Some(value) => parse_pcs_id(value)?,
        None => PLONK_PCS_KZG,
    };
    let protocol_id = match protocol.as_deref() {
        Some(value) => parse_protocol_id(value)?,
        None => PLONK_PROTOCOL_PLONK,
    };
    let mut backend_kind_id = None;
    if backend_id == PLONK_BACKEND_GENERIC {
        backend_kind_id = Some(match system_backend_kind {
            Some(kind) => kind,
            None => {
                let value = backend_kind
                    .as_deref()
                    .ok_or("missing --backend-kind for generic backend")?;
                parse_backend_kind(value)?
            }
        });
        let kind = match backend_kind_id {
            Some(kind) => kind,
            None => {
                return Err("missing --backend-kind for generic backend".to_string());
            }
        };
        if !encoding_set {
            match kind {
                PLONK_GENERIC_BACKEND_HALO2 => {
                    encoding_id = PLONK_ENCODING_HALO2_INSTANCES;
                }
                PLONK_GENERIC_BACKEND_GNARK => {
                    encoding_id = PLONK_ENCODING_BN254_BE;
                }
                PLONK_GENERIC_BACKEND_DUSK => {
                    encoding_id = PLONK_ENCODING_BLS_LE;
                }
                _ => {}
            }
        }
        match kind {
            PLONK_GENERIC_BACKEND_GNARK => {
                if curve_id != PLONK_CURVE_BN254 {
                    return Err("generic gnark requires --curve bn254".to_string());
                }
            }
            PLONK_GENERIC_BACKEND_DUSK => {
                if curve_id != PLONK_CURVE_BLS12381 {
                    return Err("generic dusk requires --curve bls12-381".to_string());
                }
            }
            _ => {}
        }
    }
    let transcript_id = match transcript.as_deref() {
        Some(value) => parse_transcript_id(value)?,
        None => {
            if backend_id == PLONK_BACKEND_GENERIC {
                match backend_kind_id {
                    Some(PLONK_GENERIC_BACKEND_HALO2) => PLONK_TRANSCRIPT_BLAKE2B,
                    Some(PLONK_GENERIC_BACKEND_GNARK)
                    | Some(PLONK_GENERIC_BACKEND_DUSK) => PLONK_TRANSCRIPT_NATIVE,
                    _ => PLONK_TRANSCRIPT_BLAKE2B,
                }
            } else {
                PLONK_TRANSCRIPT_NATIVE
            }
        }
    };
    let vk_bytes = read_bytes("vk", vk_hex, vk_file)?;
    let proof_bytes = read_bytes("proof", proof_hex, proof_file)?;
    let public_inputs_bytes = read_bytes("pub", pub_hex, pub_file)?;
    let mut backend_params_bytes =
        read_optional_bytes("backend-params", backend_params_hex, backend_params_file)?;
    if backend_id == PLONK_BACKEND_GENERIC {
        let backend_kind_id =
            backend_kind_id.ok_or("missing --backend-kind for generic backend")?;
        if backend_kind_id == PLONK_GENERIC_BACKEND_HALO2 && backend_params_bytes.is_empty() {
            return Err("missing --backend-params for generic halo2 backend".to_string());
        }
        backend_params_bytes =
            encode_plonk_generic_backend_params(backend_kind_id, &backend_params_bytes);
    }

    let receipt = PlonkReceipt {
        backend_id,
        curve_id,
        encoding_id,
        pcs_id,
        protocol_id,
        transcript_id,
        backend_params_bytes,
        vk_bytes,
        public_inputs_bytes,
        proof_bytes,
    };
    let encoded = encode_plonk_receipt(&receipt);
    let decoded = decode_plonk_receipt(&encoded)?;
    verify_plonk_receipt(&encode_plonk_receipt(&decoded))?;

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
    eprintln!("glyph_import_plonk_receipt \\");
    eprintln!("  --vk-hex <0x..> | --vk-file <path> \\");
    eprintln!("  --proof-hex <0x..> | --proof-file <path> \\");
    eprintln!("  --pub-hex <0x..> | --pub-file <path> \\");
    eprintln!("  [--system <bn254-gnark|bls12-381-dusk|halo2-bn256|halo2-bls12-381>] \\");
    eprintln!("  [--backend <gnark|dusk|generic>] [--backend-kind <halo2|gnark|dusk>] \\");
    eprintln!("  [--curve <bn254|bls12-381>] [--encoding <bn254-be|bls-le|halo2-instances>] \\");
    eprintln!("  [--pcs <kzg>] [--protocol <plonk>] [--transcript <native|blake2b>] \\");
    eprintln!("  [--backend-params-hex <0x..> | --backend-params-file <path>] [--out <path>]");
    let status = cli_registry::format_feature_status("snark", cli_registry::snark_feature_enabled());
    eprintln!("Requires feature: {status}");
    let kinds = cli_registry::enabled_snark_kinds();
    eprintln!("Enabled snark kinds: {}", cli_registry::join_list(&kinds));
}
