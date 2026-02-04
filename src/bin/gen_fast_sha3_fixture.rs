use std::env;

use glyph::stark_winterfell::{DoWorkProverSha3, DoWorkPublicInputs, build_do_work_trace};
use glyph::stark_winterfell::StarkUpstreamReceipt;
use glyph::stark_winterfell_f64::{DoWorkProverSha3F64, DoWorkPublicInputsF64, build_do_work_trace as build_do_work_trace_f64};
use winterfell::{ProofOptions, FieldExtension, BatchingMethod, Prover};
use winterfell::math::fields::{f128::BaseElement as BaseElement128, f64::BaseElement as BaseElement64};

fn env_usize(name: &str, default: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(default)
}

fn proof_options_candidates(ext: FieldExtension) -> Vec<ProofOptions> {
    let mut out = Vec::new();
    let candidates = [
        (64, 16, 8, 31),
        (96, 16, 8, 31),
        (128, 16, 8, 31),
        (128, 32, 8, 31),
        (160, 32, 8, 31),
        (192, 32, 8, 31),
        (224, 64, 8, 31),
        (240, 64, 8, 31),
        (255, 64, 8, 31),
    ];
    for (num_queries, blowup_factor, fri_folding_factor, fri_remainder_len) in candidates {
        out.push(ProofOptions::new(
            num_queries,
            blowup_factor,
            0,
            ext,
            fri_folding_factor,
            fri_remainder_len,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        ));
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

fn main() -> Result<(), String> {
    let use_f64 = env::args().any(|arg| arg == "--f64");
    let out_path = env::var("GLYPH_FIXTURE_OUT").ok();
    let trace_length = env_usize("GLYPH_STARK_FIXTURE_TRACE_LEN", 64);
    let start_u128 = 7u128;
    let start_u64 = 7u64;

    if use_f64 {
        let mut last_err = None;
        for options in proof_options_candidates(FieldExtension::Quadratic) {
            let trace = build_do_work_trace_f64(BaseElement64::new(start_u64), trace_length);
            let result = trace.get(0, trace_length - 1);
            let pub_inputs = DoWorkPublicInputsF64 {
                start: BaseElement64::new(start_u64),
                result,
            };
            let prover = DoWorkProverSha3F64::new(options.clone());
            let proof = prover.prove(trace).map_err(|e| format!("prove failed: {e:?}"))?;
            let receipt = StarkUpstreamReceipt {
                proof_bytes: proof.to_bytes(),
                pub_inputs_bytes: glyph::stark_winterfell_f64::public_inputs_bytes(&pub_inputs),
                vk_params_bytes: glyph::stark_winterfell_f64::vk_params_bytes_sha3_canonical(
                    1,
                    trace_length,
                    &options,
                ),
            };
            match glyph::stark_winterfell_f64::verify_do_work_sha3(proof, pub_inputs) {
                Ok(_) => {
                    let payload = format!(
                        "proof_hex={}\npub_inputs_hex={}\nvk_params_hex={}\n",
                        hex::encode(&receipt.proof_bytes),
                        hex::encode(&receipt.pub_inputs_bytes),
                        hex::encode(&receipt.vk_params_bytes)
                    );
                    if let Some(path) = out_path.as_deref() {
                        write_fixture(path, &payload)?;
                    } else {
                        print!("{payload}");
                    }
                    return Ok(());
                }
                Err(e) => last_err = Some(format!("{e:?}")),
            }
        }
        return Err(format!(
            "no proof options met minimum security; last error: {}",
            last_err.unwrap_or_else(|| "unknown".to_string())
        ));
    }

    let mut last_err = None;
    for options in proof_options_candidates(FieldExtension::None) {
        let trace = build_do_work_trace(BaseElement128::new(start_u128), trace_length);
        let result = trace.get(0, trace_length - 1);
        let pub_inputs = DoWorkPublicInputs {
            start: BaseElement128::new(start_u128),
            result,
        };
        let prover = DoWorkProverSha3::new(options);
        let proof = prover.prove(trace).map_err(|e| format!("prove failed: {e:?}"))?;
        let receipt = StarkUpstreamReceipt::from_do_work_sha3_canonical(&proof, &pub_inputs, trace_length);
        match glyph::stark_winterfell::verify_do_work_sha3(proof, pub_inputs) {
            Ok(_) => {
                let payload = format!(
                    "proof_hex={}\npub_inputs_hex={}\nvk_params_hex={}\n",
                    hex::encode(&receipt.proof_bytes),
                    hex::encode(&receipt.pub_inputs_bytes),
                    hex::encode(&receipt.vk_params_bytes)
                );
                if let Some(path) = out_path.as_deref() {
                    write_fixture(path, &payload)?;
                } else {
                    print!("{payload}");
                }
                return Ok(());
            }
            Err(e) => last_err = Some(format!("{e:?}")),
        }
    }
    Err(format!(
        "no proof options met minimum security; last error: {}",
        last_err.unwrap_or_else(|| "unknown".to_string())
    ))
}
