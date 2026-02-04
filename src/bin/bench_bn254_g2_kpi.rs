use std::time::Instant;

use ark_bn254::{Fr, G2Affine as ArkG2Affine};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;

use glyph::bn254_ops::{validate_bn254_op_trace_batch_kpi, Bn254OpKind};
use glyph::bn254_pairing_trace::record_g2_scalar_mul_ops;

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
}

fn next_u64(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

fn next_fr(state: &mut u64) -> Fr {
    let mut bytes = [0u8; 32];
    for chunk in bytes.chunks_exact_mut(8) {
        let v = next_u64(state).to_be_bytes();
        chunk.copy_from_slice(&v);
    }
    Fr::from_be_bytes_mod_order(&bytes)
}

fn main() -> Result<(), String> {
    let iters = env_usize("BN254_G2_KPI_ITERS", 64);
    let seed = env_u64("BN254_G2_KPI_SEED", 0x4d78_2e55_b8a4_0c21);
    let window_min = env_usize("BN254_G2_KPI_WINDOW_MIN", 2).min(6);
    let window_max = env_usize("BN254_G2_KPI_WINDOW_MAX", 6).min(6);

    let base = ArkG2Affine::generator();
    let mut state = seed;

    for window in window_min..=window_max {
        let mut events = Vec::new();
        let trace_start = Instant::now();
        for _ in 0..iters {
            let scalar = next_fr(&mut state);
            let mut evs = record_g2_scalar_mul_ops(base, scalar, window)?;
            events.append(&mut evs);
        }
        let trace_ms = trace_start.elapsed().as_millis();

        let mut add_count = 0usize;
        let mut sub_count = 0usize;
        let mut mul_count = 0usize;
        for ev in &events {
            match ev.kind {
                Bn254OpKind::Add => add_count += 1,
                Bn254OpKind::Sub => sub_count += 1,
                Bn254OpKind::Mul => mul_count += 1,
            }
        }

        let validate_start = Instant::now();
        let kpi = validate_bn254_op_trace_batch_kpi(&events, None)?;
        let validate_ms = validate_start.elapsed().as_millis();

        println!(
            "{{\"kpi\":\"BN254_G2_TRACE_KPI\",\"iters\":{},\"window\":{},\"trace_ms\":{},\"validate_ms\":{},\"add_count\":{},\"sub_count\":{},\"mul_count\":{},\"add_cuda\":{},\"sub_cuda\":{},\"mul_cuda\":{}}}",
            iters,
            window,
            trace_ms,
            validate_ms,
            add_count,
            sub_count,
            mul_count,
            kpi.add_cuda,
            kpi.sub_cuda,
            kpi.mul_cuda
        );
    }

    Ok(())
}
