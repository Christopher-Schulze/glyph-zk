use std::env;
use std::fs;

use glyph::adapters::AdapterFamily;
use glyph::cli_registry;
use glyph::plonky3_stark::{
    decode_plonky3_program,
    encode_mul_air_params,
    encode_poseidon2_params,
    encode_poseidon_params,
    encode_rescue_params,
    verify_plonky3_receipt,
    MulAirParams,
    Plonky3StarkProfile,
    Plonky3StarkProgram,
    Poseidon2Params,
    PoseidonParams,
    RescueParams,
    FIELD_P3_BABY_BEAR_ID,
    FIELD_P3_GOLDILOCKS_ID,
    FIELD_P3_KOALA_BEAR_ID,
    FIELD_P3_M31_ID,
    HASH_P3_POSEIDON2_ID,
    HASH_P3_POSEIDON_ID,
    HASH_P3_RESCUE_ID,
    HASH_P3_KECCAK_ID,
    PLONKY3_AIR_FIBONACCI_ID,
    PLONKY3_AIR_MUL_ID,
    PLONKY3_PCS_FRI_ID,
    PLONKY3_STARK_PROFILE_VERSION,
    PLONKY3_STARK_PROGRAM_VERSION,
    VC_MERKLE_ID,
};
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

fn parse_field(value: &str) -> Result<u8, String> {
    match value {
        "m31" | "plonky3-m31" => Ok(FIELD_P3_M31_ID),
        "babybear" | "plonky3-babybear" => Ok(FIELD_P3_BABY_BEAR_ID),
        "koalabear" | "plonky3-koalabear" => Ok(FIELD_P3_KOALA_BEAR_ID),
        "goldilocks" | "plonky3-goldilocks" => Ok(FIELD_P3_GOLDILOCKS_ID),
        _ => Err("unsupported --field (use m31|babybear|koalabear|goldilocks)".to_string()),
    }
}

fn parse_hash(value: &str) -> Result<u8, String> {
    match value {
        "poseidon2" => Ok(HASH_P3_POSEIDON2_ID),
        "poseidon" => Ok(HASH_P3_POSEIDON_ID),
        "rescue" => Ok(HASH_P3_RESCUE_ID),
        "keccak" => Ok(glyph::plonky3_stark::HASH_P3_KECCAK_ID),
        _ => Err("unsupported --hash (use poseidon2|poseidon|rescue|keccak)".to_string()),
    }
}

fn parse_air(value: &str) -> Result<u8, String> {
    match value {
        "fib" | "fibonacci" => Ok(PLONKY3_AIR_FIBONACCI_ID),
        "mul" => Ok(PLONKY3_AIR_MUL_ID),
        _ => Err("unsupported --air (use fib|mul)".to_string()),
    }
}

fn parse_u8(label: &str, value: Option<String>, default: u8) -> Result<u8, String> {
    match value {
        Some(v) => v.parse().map_err(|_| format!("invalid {label}")),
        None => Ok(default),
    }
}

fn parse_u16(label: &str, value: Option<String>, default: u16) -> Result<u16, String> {
    match value {
        Some(v) => v.parse().map_err(|_| format!("invalid {label}")),
        None => Ok(default),
    }
}

fn parse_u64(label: &str, value: Option<String>, default: u64) -> Result<u64, String> {
    match value {
        Some(v) => v.parse().map_err(|_| format!("invalid {label}")),
        None => Ok(default),
    }
}

fn main() -> Result<(), String> {
    let mut proof_hex: Option<String> = None;
    let mut proof_file: Option<String> = None;
    let mut pub_hex: Option<String> = None;
    let mut pub_file: Option<String> = None;
    let mut field: Option<String> = None;
    let mut hash: Option<String> = None;
    let mut air: Option<String> = None;
    let mut out_path: Option<String> = None;

    let mut mul_degree: Option<String> = None;
    let mut mul_boundary: Option<String> = None;
    let mut mul_transition: Option<String> = None;

    let mut log_blowup: Option<String> = None;
    let mut log_final: Option<String> = None;
    let mut num_queries: Option<String> = None;
    let mut pow_commit: Option<String> = None;
    let mut pow_query: Option<String> = None;

    let mut poseidon2_seed: Option<String> = None;
    let mut poseidon2_width: Option<String> = None;
    let mut poseidon_width: Option<String> = None;
    let mut poseidon_alpha: Option<String> = None;
    let mut poseidon_half_full: Option<String> = None;
    let mut poseidon_partial: Option<String> = None;
    let mut poseidon_seed: Option<String> = None;
    let mut rescue_width: Option<String> = None;
    let mut rescue_alpha: Option<String> = None;
    let mut rescue_capacity: Option<String> = None;
    let mut rescue_sec: Option<String> = None;
    let mut rescue_seed: Option<String> = None;

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
            "--field" => field = args.next(),
            "--hash" => hash = args.next(),
            "--air" => air = args.next(),
            "--out" => out_path = args.next(),
            "--mul-degree" => mul_degree = args.next(),
            "--mul-boundary" => mul_boundary = args.next(),
            "--mul-transition" => mul_transition = args.next(),
            "--profile-log-blowup" => log_blowup = args.next(),
            "--profile-log-final" => log_final = args.next(),
            "--profile-num-queries" => num_queries = args.next(),
            "--profile-pow-commit" => pow_commit = args.next(),
            "--profile-pow-query" => pow_query = args.next(),
            "--poseidon2-width" => poseidon2_width = args.next(),
            "--poseidon2-seed" => poseidon2_seed = args.next(),
            "--poseidon-width" => poseidon_width = args.next(),
            "--poseidon-alpha" => poseidon_alpha = args.next(),
            "--poseidon-half-full" => poseidon_half_full = args.next(),
            "--poseidon-partial" => poseidon_partial = args.next(),
            "--poseidon-seed" => poseidon_seed = args.next(),
            "--rescue-width" => rescue_width = args.next(),
            "--rescue-alpha" => rescue_alpha = args.next(),
            "--rescue-capacity" => rescue_capacity = args.next(),
            "--rescue-sec" => rescue_sec = args.next(),
            "--rescue-seed" => rescue_seed = args.next(),
            _ => return Err(format!("unknown arg: {arg}")),
        }
    }

    let field_id = parse_field(field.as_deref().ok_or("missing --field")?)?;
    let hash_id = parse_hash(hash.as_deref().ok_or("missing --hash")?)?;
    let air_id = parse_air(air.as_deref().ok_or("missing --air")?)?;

    let proof_bytes = read_bytes("proof", proof_hex, proof_file)?;
    let pub_inputs_bytes = read_bytes("pub", pub_hex, pub_file)?;

    let air_params_bytes = if air_id == PLONKY3_AIR_MUL_ID {
        let degree = parse_u64("mul-degree", mul_degree, 3)?;
        let boundary = parse_u8("mul-boundary", mul_boundary, 1)? != 0;
        let transition = parse_u8("mul-transition", mul_transition, 1)? != 0;
        encode_mul_air_params(&MulAirParams {
            degree,
            uses_boundary_constraints: boundary,
            uses_transition_constraints: transition,
        })
    } else {
        Vec::new()
    };

    let hash_params_bytes = match hash_id {
        HASH_P3_POSEIDON2_ID => {
            let width = parse_u8("poseidon2-width", poseidon2_width, 16)?;
            let seed = parse_u64("poseidon2-seed", poseidon2_seed, 0)?;
            encode_poseidon2_params(&Poseidon2Params { width, seed })
        }
        HASH_P3_POSEIDON_ID => {
            let width = parse_u8("poseidon-width", poseidon_width, 16)?;
            let alpha = parse_u64("poseidon-alpha", poseidon_alpha, 7)?;
            let half_full = parse_u8("poseidon-half-full", poseidon_half_full, 4)?;
            let partial = parse_u16("poseidon-partial", poseidon_partial, 22)?;
            let seed = parse_u64("poseidon-seed", poseidon_seed, 1)?;
            encode_poseidon_params(&PoseidonParams {
                width,
                alpha,
                half_full_rounds: half_full,
                partial_rounds: partial,
                seed,
            })
        }
        HASH_P3_RESCUE_ID => {
            let width = parse_u8("rescue-width", rescue_width, 12)?;
            let alpha = parse_u64("rescue-alpha", rescue_alpha, 5)?;
            let capacity = parse_u8("rescue-capacity", rescue_capacity, 6)?;
            let sec = parse_u16("rescue-sec", rescue_sec, 128)?;
            let seed = parse_u64("rescue-seed", rescue_seed, 1)?;
            encode_rescue_params(&RescueParams {
                width,
                alpha,
                capacity,
                sec_level: sec,
                seed,
            })
        }
        HASH_P3_KECCAK_ID => Vec::new(),
        _ => return Err("unsupported hash id".to_string()),
    };

    let profile = Plonky3StarkProfile {
        version: PLONKY3_STARK_PROFILE_VERSION,
        pcs_type: PLONKY3_PCS_FRI_ID,
        log_blowup: parse_u8("profile-log-blowup", log_blowup, 2)?,
        log_final_poly_len: parse_u8("profile-log-final", log_final, 0)?,
        num_queries: parse_u16("profile-num-queries", num_queries, 2)?,
        commit_pow_bits: parse_u8("profile-pow-commit", pow_commit, 0)?,
        query_pow_bits: parse_u8("profile-pow-query", pow_query, 0)?,
        num_random_codewords: 0,
        hash_params_bytes,
    };

    let program = Plonky3StarkProgram {
        version: PLONKY3_STARK_PROGRAM_VERSION,
        field_id,
        hash_id,
        commitment_scheme_id: VC_MERKLE_ID,
        air_id,
        air_params_bytes,
    };

    let vk = CanonicalStarkVk {
        version: 1,
        field_id,
        hash_id,
        commitment_scheme_id: VC_MERKLE_ID,
        consts_bytes: profile.encode(),
        program_bytes: program.encode(),
    };
    let receipt = CanonicalStarkReceipt {
        proof_bytes,
        pub_inputs_bytes,
        vk_bytes: vk.encode(),
    };

    let decoded_vk = CanonicalStarkReceipt::decode_and_validate_vk(&receipt)?;
    let decoded_program = decode_plonky3_program(&decoded_vk.program_bytes)?;
    verify_plonky3_receipt(&receipt, &decoded_vk, &decoded_program)?;

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
    eprintln!("glyph_import_plonky3_receipt \\");
    eprintln!("  --proof-hex <0x..> | --proof-file <path> \\");
    eprintln!("  --pub-hex <0x..> | --pub-file <path> \\");
    eprintln!("  --field <m31|babybear|koalabear|goldilocks> --hash <poseidon2|poseidon|rescue|keccak> \\");
    eprintln!("  --air <fib|mul> [--out <path>] \\");
    eprintln!("  [--mul-degree <n>] [--mul-boundary <0|1>] [--mul-transition <0|1>] \\");
    eprintln!("  [--profile-log-blowup <n>] [--profile-log-final <n>] [--profile-num-queries <n>] \\");
    eprintln!("  [--profile-pow-commit <n>] [--profile-pow-query <n>] \\");
    eprintln!("  [--poseidon2-width <n>] [--poseidon2-seed <n>] \\");
    eprintln!("  [--poseidon-width <n>] [--poseidon-alpha <n>] [--poseidon-half-full <n>] \\");
    eprintln!("  [--poseidon-partial <n>] [--poseidon-seed <n>] \\");
    eprintln!("  [--rescue-width <n>] [--rescue-alpha <n>] [--rescue-capacity <n>] \\");
    eprintln!("  [--rescue-sec <n>] [--rescue-seed <n>]");
    let enabled = cli_registry::family_feature_enabled(AdapterFamily::StarkBabyBear);
    let status = cli_registry::format_feature_status("stark-babybear", enabled);
    eprintln!("Requires feature: {status}");
    let fields = cli_registry::enabled_stark_fields();
    eprintln!("Enabled stark fields: {}", cli_registry::join_list(&fields));
}
