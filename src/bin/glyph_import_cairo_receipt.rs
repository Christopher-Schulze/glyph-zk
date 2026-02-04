use std::env;
use std::fs;

use glyph::adapters::AdapterFamily;
use glyph::cli_registry;
use glyph::cairo_stark::{
    parse_cairo_receipt_from_json,
    decode_cairo_program,
    verify_cairo_receipt,
    CairoStarkProgram,
    HASH_KECCAK_160_LSB_ID,
    LAYOUT_STARKNET_WITH_KECCAK_ID,
    STONE6_ID,
    VERIFIER_MONOLITH_ID,
};
use glyph::stark_receipt::CanonicalStarkReceipt;

fn parse_layout_id(value: &str) -> Result<u8, String> {
    match value {
        "starknet_with_keccak" | "starknet-keccak" => Ok(LAYOUT_STARKNET_WITH_KECCAK_ID),
        _ => Err("unsupported --layout".to_string()),
    }
}

fn parse_hasher_id(value: &str) -> Result<u8, String> {
    match value {
        "keccak_160_lsb" | "keccak-160" | "keccak160" => Ok(HASH_KECCAK_160_LSB_ID),
        _ => Err("unsupported --hasher".to_string()),
    }
}

fn parse_stone_id(value: &str) -> Result<u8, String> {
    match value {
        "stone6" => Ok(STONE6_ID),
        _ => Err("unsupported --stone".to_string()),
    }
}

fn parse_verifier_id(value: &str) -> Result<u8, String> {
    match value {
        "monolith" => Ok(VERIFIER_MONOLITH_ID),
        _ => Err("unsupported --verifier (only monolith supported)".to_string()),
    }
}

fn main() -> Result<(), String> {
    let mut proof_json: Option<String> = None;
    let mut proof_file: Option<String> = None;
    let mut layout: Option<String> = None;
    let mut hasher: Option<String> = None;
    let mut stone: Option<String> = None;
    let mut verifier: Option<String> = None;
    let mut out_path: Option<String> = None;

    let mut args = env::args().skip(1).peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            "--proof-json" => proof_json = args.next(),
            "--proof-file" => proof_file = args.next(),
            "--layout" => layout = args.next(),
            "--hasher" => hasher = args.next(),
            "--stone" => stone = args.next(),
            "--verifier" => verifier = args.next(),
            "--out" => out_path = args.next(),
            _ => return Err(format!("unknown arg: {arg}")),
        }
    }

    let proof_contents = match (proof_json, proof_file) {
        (Some(json), None) => json,
        (None, Some(path)) => fs::read_to_string(&path)
            .map_err(|e| format!("failed to read proof file: {e}"))?,
        (None, None) => return Err("missing --proof-json or --proof-file".to_string()),
        _ => return Err("provide exactly one of --proof-json or --proof-file".to_string()),
    };

    let layout_id = parse_layout_id(layout.as_deref().ok_or("missing --layout")?)?;
    let hasher_id = parse_hasher_id(hasher.as_deref().ok_or("missing --hasher")?)?;
    let stone_version = parse_stone_id(stone.as_deref().ok_or("missing --stone")?)?;
    let verifier_type = parse_verifier_id(verifier.as_deref().ok_or("missing --verifier")?)?;

    let (receipt, _program) = parse_cairo_receipt_from_json(
        &proof_contents,
        layout_id,
        hasher_id,
        stone_version,
        verifier_type,
    )?;

    let decoded_vk = CanonicalStarkReceipt::decode_and_validate_vk(&receipt)?;
    let decoded_program: CairoStarkProgram = decode_cairo_program(&decoded_vk.program_bytes)?;
    verify_cairo_receipt(&receipt, &decoded_vk, &decoded_program)?;

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
    eprintln!("glyph_import_cairo_receipt \\");
    eprintln!("  --proof-json <json> | --proof-file <path> \\");
    eprintln!("  --layout <starknet_with_keccak> --hasher <keccak_160_lsb> \\");
    eprintln!("  --stone <stone6> --verifier <monolith> [--out <path>]");
    let enabled = cli_registry::family_feature_enabled(AdapterFamily::StarkM31);
    let status = cli_registry::format_feature_status("stark-m31", enabled);
    eprintln!("Requires feature: {status}");
    let fields = cli_registry::enabled_stark_fields();
    eprintln!("Enabled stark fields: {}", cli_registry::join_list(&fields));
}
