#[cfg(feature = "stwo-prover")]
mod generator {
    use std::env;
    use std::fs;

    use glyph::stwo_bundle::StwoReceiptBundle;
    use glyph::stwo_verifier::{
        synthesize_stwo_proof_bytes, StwoConstraint, StwoExpr, StwoProfile, StwoProgram,
        STWO_TOOLCHAIN_ID,
    };
    fn parse_out_path() -> Result<String, String> {
        let mut out_path: Option<String> = None;
        let mut args = env::args().skip(1).peekable();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--out" => out_path = args.next(),
                _ => return Err(format!("unknown arg: {arg}")),
            }
        }
        out_path.ok_or_else(|| "missing --out <path>".to_string())
    }

    pub fn run() -> Result<(), String> {
        let out_path = parse_out_path()?;

        let profile = StwoProfile {
            log_domain_size: 3,
            num_queries: 2,
            blowup_factor: 1,
            log_last_layer_degree_bound: 1,
            pow_bits: 0,
        };
        let program = StwoProgram {
            toolchain_id: STWO_TOOLCHAIN_ID,
            trace_width: 1,
            log_trace_length: profile.log_domain_size as u32,
            constraints: vec![StwoConstraint {
                expr: StwoExpr::Add(
                    Box::new(StwoExpr::Col { col: 0, offset: 0 }),
                    Box::new(StwoExpr::Neg(Box::new(StwoExpr::Col { col: 0, offset: 0 }))),
                ),
            }],
        };

        let pub_inputs_bytes = vec![0u8];
        let proof_bytes = synthesize_stwo_proof_bytes(&program, &profile, &pub_inputs_bytes)?;
        let profile_bytes = profile.encode();
        let program_bytes = program.encode();

        let bundle = StwoReceiptBundle {
            version: 1,
            profile_hex: hex::encode(&profile_bytes),
            program_hex: hex::encode(&program_bytes),
            proof_hex: hex::encode(&proof_bytes),
            pub_inputs_hex: hex::encode(&pub_inputs_bytes),
        };
        let json = serde_json::to_vec_pretty(&bundle)
            .map_err(|e| format!("bundle json encode failed: {e}"))?;
        fs::write(&out_path, json).map_err(|e| format!("failed to write bundle: {e}"))?;

        Ok(())
    }
}

#[cfg(feature = "stwo-prover")]
fn main() {
    if let Err(err) = generator::run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

#[cfg(not(feature = "stwo-prover"))]
fn main() {
    eprintln!("gen_stwo_external_fixture requires --features stwo-prover");
    std::process::exit(1);
}
