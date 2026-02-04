use std::env;
use glyph::circle_stark::{
    build_circle_stark_receipt,
    build_circle_stark_expr_receipt,
    CircleConstraintTerm,
    CircleConstraint,
    CircleExprConstraint,
    CircleStarkProfile,
    CircleStarkSimpleProgram,
    CircleStarkExprProgram,
    CIRCLE_STARK_PROFILE_VERSION,
    CIRCLE_STARK_SIMPLE_PROGRAM_VERSION,
    CIRCLE_STARK_EXPR_PROGRAM_VERSION,
    CONSTRAINT_CUBE_PLUS_CONST,
    CONSTRAINT_LINEAR_MIX,
    CONSTRAINT_LINEAR_COMBO,
    CONSTRAINT_MUL_ADD,
    FIELD_BABY_BEAR_CIRCLE_ID,
    FIELD_KOALA_BEAR_CIRCLE_ID,
    FIELD_M31_CIRCLE_ID,
    HASH_BLAKE3_ID,
    HASH_POSEIDON_ID,
    HASH_RESCUE_ID,
    HASH_SHA3_ID,
    VC_MERKLE_ID,
};

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

fn write_fixture(out_path: &str, payload: &str) -> Result<(), String> {
    let path = std::path::Path::new(out_path);
    let target = if path.exists() {
        let candidate = format!("{}.candidate", out_path);
        std::path::PathBuf::from(candidate)
    } else {
        path.to_path_buf()
    };
    std::fs::write(&target, payload).map_err(|e| format!("fixture write failed: {e}"))?;
    println!("fixture_out={}", target.display());
    Ok(())
}

fn die(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let use_expr = args.iter().any(|a| a == "--expr");
    let large = args.iter().any(|a| a == "--large");
    let use_baby_bear = args.iter().any(|a| a == "--baby-bear");
    let use_koala_bear = args.iter().any(|a| a == "--koala-bear");
    let use_blake3 = args.iter().any(|a| a == "--blake3");
    let use_poseidon = args.iter().any(|a| a == "--poseidon");
    let use_rescue = args.iter().any(|a| a == "--rescue");
    let field_id = if use_koala_bear {
        FIELD_KOALA_BEAR_CIRCLE_ID
    } else if use_baby_bear {
        FIELD_BABY_BEAR_CIRCLE_ID
    } else {
        FIELD_M31_CIRCLE_ID
    };
    let hash_id = if use_rescue {
        HASH_RESCUE_ID
    } else if use_poseidon {
        HASH_POSEIDON_ID
    } else if use_blake3 {
        HASH_BLAKE3_ID
    } else {
        HASH_SHA3_ID
    };
    let out_path = env::var("GLYPH_FIXTURE_OUT").ok();

    let receipt = if use_expr {
        let profile = if large {
            CircleStarkProfile {
                version: CIRCLE_STARK_PROFILE_VERSION,
                log_domain_size: 10,
                num_queries: 8,
                blowup_factor: 2,
            }
        } else {
            CircleStarkProfile {
                version: CIRCLE_STARK_PROFILE_VERSION,
                log_domain_size: 6,
                num_queries: 4,
                blowup_factor: 2,
            }
        };
        let program = CircleStarkExprProgram {
            version: CIRCLE_STARK_EXPR_PROGRAM_VERSION,
            field_id,
            hash_id,
            commitment_scheme_id: VC_MERKLE_ID,
            trace_width: 4,
            trace_length: 1u32 << profile.log_domain_size,
            constraints: vec![
                CircleExprConstraint {
                    id: CONSTRAINT_LINEAR_COMBO,
                    out_col: 0,
                    out_is_next: 1,
                    a: 0,
                    a_is_next: 0,
                    b: 0,
                    b_is_next: 0,
                    constant: 7,
                    terms: vec![
                        CircleConstraintTerm {
                            col: 0,
                            coeff: 3,
                            is_next: 0,
                        },
                        CircleConstraintTerm {
                            col: 1,
                            coeff: 5,
                            is_next: 0,
                        },
                    ],
                },
                CircleExprConstraint {
                    id: CONSTRAINT_MUL_ADD,
                    out_col: 1,
                    out_is_next: 1,
                    a: 0,
                    a_is_next: 0,
                    b: 2,
                    b_is_next: 0,
                    constant: 9,
                    terms: vec![CircleConstraintTerm {
                        col: 1,
                        coeff: 11,
                        is_next: 0,
                    }],
                },
                CircleExprConstraint {
                    id: CONSTRAINT_LINEAR_COMBO,
                    out_col: 2,
                    out_is_next: 1,
                    a: 0,
                    a_is_next: 0,
                    b: 0,
                    b_is_next: 0,
                    constant: 3,
                    terms: vec![
                        CircleConstraintTerm {
                            col: 0,
                            coeff: 2,
                            is_next: 0,
                        },
                        CircleConstraintTerm {
                            col: 2,
                            coeff: 7,
                            is_next: 0,
                        },
                        CircleConstraintTerm {
                            col: 3,
                            coeff: 13,
                            is_next: 0,
                        },
                    ],
                },
                CircleExprConstraint {
                    id: CONSTRAINT_MUL_ADD,
                    out_col: 3,
                    out_is_next: 1,
                    a: 1,
                    a_is_next: 0,
                    b: 3,
                    b_is_next: 0,
                    constant: 5,
                    terms: vec![CircleConstraintTerm {
                        col: 0,
                        coeff: 17,
                        is_next: 0,
                    }],
                },
            ],
            air_id: b"circle_do_work:linear+mul".to_vec(),
        };
        let start_row = vec![7u32, 11u32, 5u32, 9u32];
        match build_circle_stark_expr_receipt(&profile, &program, start_row) {
            Ok(receipt) => receipt,
            Err(err) => die(&format!("circle receipt failed: {err}")),
        }
    } else {
        let profile = CircleStarkProfile {
            version: CIRCLE_STARK_PROFILE_VERSION,
            log_domain_size: 3,
            num_queries: 2,
            blowup_factor: 1,
        };
        let program = CircleStarkSimpleProgram {
            version: CIRCLE_STARK_SIMPLE_PROGRAM_VERSION,
            field_id,
            hash_id,
            commitment_scheme_id: VC_MERKLE_ID,
            trace_width: 2,
            trace_length: 1u32 << profile.log_domain_size,
            constraints: vec![
                CircleConstraint {
                    id: CONSTRAINT_CUBE_PLUS_CONST,
                    col: 0,
                    a: 0,
                    b: 0,
                    constant: 42,
                },
                CircleConstraint {
                    id: CONSTRAINT_LINEAR_MIX,
                    col: 1,
                    a: 1,
                    b: 0,
                    constant: 7,
                },
            ],
            air_id: b"circle_do_work_large:x^3+42,linear".to_vec(),
        };
        match build_circle_stark_receipt(&profile, &program, vec![7u32, 11u32]) {
            Ok(receipt) => receipt,
            Err(err) => die(&format!("circle receipt failed: {err}")),
        }
    };
    let receipt_hex = to_hex(&receipt.encode_for_hash());
    let payload = format!("receipt_hex={receipt_hex}\n");
    if let Some(path) = out_path.as_deref() {
        if let Err(err) = write_fixture(path, &payload) {
            die(&err);
        }
    } else {
        print!("{payload}");
    }
}
