use std::env;
use std::fs;

use glyph::standard_stark::{
    StandardConstraint, StandardStarkProfile, StandardStarkProgram, STANDARD_STARK_PROGRAM_VERSION,
    CONSTRAINT_CUBE_PLUS_CONST, FIELD_BABY_BEAR_STD_ID, HASH_BLAKE3_ID, HASH_POSEIDON_ID,
    HASH_RESCUE_ID, HASH_SHA3_ID, VC_MERKLE_ID,
};
use glyph::risc_zero_bundle::RiscZeroReceiptBundle;

fn parse_args() -> Result<(String, u8), String> {
    let mut out_path: Option<String> = None;
    let mut hash_id = HASH_SHA3_ID;
    let mut args = env::args().skip(1).peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out" => out_path = args.next(),
            "--hash" => {
                let val = args.next().ok_or_else(|| "missing --hash value".to_string())?;
                match val.as_str() {
                    "sha3" => hash_id = HASH_SHA3_ID,
                    "blake3" => hash_id = HASH_BLAKE3_ID,
                    "poseidon" => hash_id = HASH_POSEIDON_ID,
                    "rescue" => hash_id = HASH_RESCUE_ID,
                    _ => return Err("unsupported --hash (use sha3, blake3, poseidon, or rescue)".to_string()),
                }
            }
            "--blake3" => hash_id = HASH_BLAKE3_ID,
            "--poseidon" => hash_id = HASH_POSEIDON_ID,
            "--rescue" => hash_id = HASH_RESCUE_ID,
            _ => return Err(format!("unknown arg: {arg}")),
        }
    }
    let out = out_path.ok_or_else(|| "missing --out <path>".to_string())?;
    Ok((out, hash_id))
}

fn main() -> Result<(), String> {
    let (out_path, hash_id) = parse_args()?;

    let profile = StandardStarkProfile {
        version: 1,
        log_domain_size: 3,
        num_queries: 2,
        blowup_factor: 1,
    };
    let program = StandardStarkProgram {
        version: STANDARD_STARK_PROGRAM_VERSION,
        field_id: FIELD_BABY_BEAR_STD_ID,
        hash_id,
        commitment_scheme_id: VC_MERKLE_ID,
        trace_width: 1,
        trace_length: 1u32 << profile.log_domain_size,
        constraints: vec![StandardConstraint {
            id: CONSTRAINT_CUBE_PLUS_CONST,
            col: 0,
            a: 0,
            b: 0,
            constant: 1,
        }],
        air_id: b"risc_zero_bundle".to_vec(),
    };

    let bundle = RiscZeroReceiptBundle {
        version: 1,
        profile_hex: hex::encode(profile.encode()),
        program_hex: hex::encode(program.encode()),
        proof_hex: hex::encode([0u8]),
        pub_inputs_hex: hex::encode([0u8]),
    };

    let json = serde_json::to_vec_pretty(&bundle)
        .map_err(|e| format!("bundle json encode failed: {e}"))?;
    fs::write(&out_path, json).map_err(|e| format!("failed to write bundle: {e}"))?;
    Ok(())
}
