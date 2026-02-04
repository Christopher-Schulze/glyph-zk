//! Benchmark BaseFold PCS commit/open/verify with configurable size.

use std::time::Instant;

use binius_field::BinaryField128b;
use rand::{RngCore, SeedableRng};
use rand::rngs::StdRng;

use glyph::glyph_field_simd::Goldilocks;
use glyph::glyph_pcs_basefold::{PcsProver, verify_opening};
use glyph::glyph_transcript::Transcript;
use glyph::pcs_binary_field::b128_from_goldilocks_le;

fn die(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1);
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(default)
}

fn env_opt_usize(name: &str) -> Option<usize> {
    std::env::var(name).ok().and_then(|v| v.parse::<usize>().ok())
}

fn build_evals(n_vars: usize, seed: u64) -> Result<Vec<Goldilocks>, String> {
    let len = 1usize
        .checked_shl(n_vars as u32)
        .ok_or_else(|| format!("n_vars too large for eval length: {n_vars}"))?;
    let mut rng = StdRng::seed_from_u64(seed);
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(Goldilocks::new(rng.next_u64()));
    }
    Ok(out)
}

fn build_eval_point(n_vars: usize, seed: u64) -> Vec<BinaryField128b> {
    let mut rng = StdRng::seed_from_u64(seed ^ 0x9e37_79b9);
    let mut out = Vec::with_capacity(n_vars);
    for _ in 0..n_vars {
        let v = Goldilocks::new(rng.next_u64());
        out.push(b128_from_goldilocks_le(v));
    }
    out
}

fn main() {
    let n_vars = env_usize("GLYPH_BASEFOLD_BENCH_N_VARS", 16).max(1);
    let seed = env_u64("GLYPH_BASEFOLD_BENCH_SEED", 0xA5A5_A5A5);

    let security_bits = env_opt_usize("GLYPH_PCS_BASEFOLD_SECURITY_BITS");
    let log_inv_rate = env_opt_usize("GLYPH_PCS_BASEFOLD_LOG_INV_RATE");
    let fold_arity = env_opt_usize("GLYPH_PCS_BASEFOLD_FOLD_ARITY");
    let host_mem = env_opt_usize("GLYPH_PCS_BASEFOLD_HOST_MEM");
    let dev_mem = env_opt_usize("GLYPH_PCS_BASEFOLD_DEV_MEM");

    let evals = match build_evals(n_vars, seed) {
        Ok(evals) => evals,
        Err(err) => die(&err),
    };
    let eval_point = build_eval_point(n_vars, seed);
    let evals_len = evals.len();

    let mut transcript = Transcript::new();
    let t0 = Instant::now();
    let prover = match PcsProver::commit_owned(evals, &mut transcript) {
        Ok(prover) => prover,
        Err(err) => die(&format!("pcs commit failed: {err}")),
    };
    let commit_ms = t0.elapsed().as_millis();

    let t1 = Instant::now();
    let opening = match prover.open(&eval_point) {
        Ok(opening) => opening,
        Err(err) => die(&format!("pcs open failed: {err}")),
    };
    let open_ms = t1.elapsed().as_millis();

    let t2 = Instant::now();
    let ok = verify_opening(&prover.commitment, &opening, prover.rho, None);
    let verify_ms = t2.elapsed().as_millis();

    if !ok {
        die("basefold verify failed");
    }

    let proof_bytes = opening.encoded_len();

    println!(
        "{{\"kpi\":\"BASEFOLD_PCS_BENCH\",\"n_vars\":{},\"evals_len\":{},\"seed\":{},\"security_bits\":{},\"log_inv_rate\":{},\"fold_arity\":{},\"host_mem\":{},\"dev_mem\":{},\"commit_ms\":{},\"open_ms\":{},\"verify_ms\":{},\"opening_bytes\":{}}}",
        n_vars,
        evals_len,
        seed,
        security_bits.map(|v| v.to_string()).unwrap_or_else(|| "null".to_string()),
        log_inv_rate.map(|v| v.to_string()).unwrap_or_else(|| "null".to_string()),
        fold_arity.map(|v| v.to_string()).unwrap_or_else(|| "null".to_string()),
        host_mem.map(|v| v.to_string()).unwrap_or_else(|| "null".to_string()),
        dev_mem.map(|v| v.to_string()).unwrap_or_else(|| "null".to_string()),
        commit_ms,
        open_ms,
        verify_ms,
        proof_bytes
    );
}
