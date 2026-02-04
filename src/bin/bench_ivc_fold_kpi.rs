use std::env;
use std::time::Instant;

use binius_field::{BinaryField128b, Field, underlier::WithUnderlier};
use glyph::adapters::keccak256;
use glyph::glyph_basefold::{derive_binius_eval_point, derive_basefold_weights, fold_instance_evals_with_weights};

fn env_usize(name: &str, default: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(default)
}

fn env_string(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_string())
}

fn b128_from_hash(hash: &[u8; 32]) -> BinaryField128b {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash[0..16]);
    BinaryField128b::from_underlier(u128::from_le_bytes(bytes))
}

fn derive_digest(seed: &[u8], idx: u32) -> [u8; 32] {
    let mut input = Vec::with_capacity(seed.len() + 4);
    input.extend_from_slice(seed);
    input.extend_from_slice(&idx.to_be_bytes());
    keccak256(&input)
}

fn make_evals(seed: &[u8], len: usize) -> Vec<BinaryField128b> {
    let mut out = Vec::with_capacity(len);
    for i in 0..len {
        let digest = derive_digest(seed, i as u32);
        out.push(b128_from_hash(&digest));
    }
    out
}

fn evaluate_multilinear(
    evals: &[BinaryField128b],
    point: &[BinaryField128b],
) -> Result<BinaryField128b, String> {
    let expected_len = 1usize << point.len();
    if evals.len() != expected_len {
        return Err("multilinear eval length mismatch".to_string());
    }
    let mut layer = evals.to_vec();
    for r in point {
        let mut next = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks_exact(2) {
            let a = pair[0];
            let b = pair[1];
            let val = a + (b - a) * *r;
            next.push(val);
        }
        layer = next;
    }
    Ok(layer[0])
}

fn main() {
    let n_vars = env_usize("GLYPH_IVC_KPI_NVARS", 16);
    let repeat = env_usize("GLYPH_IVC_KPI_REPEAT", 5).max(1);
    let fold_repeat = env_usize("GLYPH_IVC_KPI_FOLD_REPEAT", 5).max(1);
    let receipts = env_usize("GLYPH_IVC_KPI_RECEIPTS", 16).max(1);
    let seed = env_string("GLYPH_IVC_KPI_SEED", "glyph-ivc-kpi");
    let seed_bytes = seed.as_bytes();

    let table_len = 1usize
        .checked_shl(n_vars as u32)
        .unwrap_or_else(|| die("GLYPH_IVC_KPI_NVARS too large"));
    if table_len > (1 << 24) {
        die("GLYPH_IVC_KPI_NVARS too large for eval table");
    }

    let evals = make_evals(seed_bytes, table_len);
    let eval_point = derive_binius_eval_point(seed_bytes, 0, n_vars);

    let t0 = Instant::now();
    let mut eval_value = BinaryField128b::ZERO;
    for _ in 0..repeat {
        eval_value = match evaluate_multilinear(&evals, &eval_point) {
            Ok(value) => value,
            Err(err) => die(&format!("eval failed: {err}")),
        };
    }
    let eval_ms = t0.elapsed().as_millis() as u64;
    let eval_avg_ms = eval_ms / repeat as u64;

    let mut instance_digests = Vec::with_capacity(receipts);
    let mut per_instance_evals = Vec::with_capacity(receipts);
    for i in 0..receipts {
        let digest = derive_digest(seed_bytes, i as u32);
        instance_digests.push(digest);
        per_instance_evals.push(b128_from_hash(&digest));
    }

    let t1 = Instant::now();
    let weights = match derive_basefold_weights(&instance_digests) {
        Ok(weights) => weights,
        Err(err) => die(&format!("weights failed: {err}")),
    };
    let weights_ms = t1.elapsed().as_millis() as u64;

    let t2 = Instant::now();
    let mut folded_eval = BinaryField128b::ZERO;
    for _ in 0..fold_repeat {
        folded_eval = match fold_instance_evals_with_weights(&weights, &per_instance_evals) {
            Ok(value) => value,
            Err(err) => die(&format!("fold failed: {err}")),
        };
    }
    let fold_ms = t2.elapsed().as_millis() as u64;
    let fold_avg_ms = fold_ms / fold_repeat as u64;

    println!(
        "{{\"kpi\":\"GLYPH_IVC_FOLD_KPI\",\"n_vars\":{},\"evals_len\":{},\"eval_ms\":{},\"eval_avg_ms\":{},\"fold_receipts\":{},\"weights_ms\":{},\"fold_ms\":{},\"fold_avg_ms\":{},\"eval_u128\":{},\"fold_u128\":{}}}",
        n_vars,
        table_len,
        eval_ms,
        eval_avg_ms,
        receipts,
        weights_ms,
        fold_ms,
        fold_avg_ms,
        eval_value.to_underlier(),
        folded_eval.to_underlier(),
    );
}

fn die(msg: &str) -> ! {
    eprintln!("error: {}", msg);
    std::process::exit(1);
}
