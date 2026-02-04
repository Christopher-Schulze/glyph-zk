use ark_bn254::Fq;
use ark_ff::PrimeField;
use std::time::Instant;

use glyph::bn254_field::{bn254_add_mod, bn254_mul_mod, bn254_sub_mod, limbs_from_fq};
use glyph::bn254_ops::{validate_bn254_op_trace_batch_kpi, Bn254OpKind, Bn254OpTraceEvent};

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

fn next_fq(state: &mut u64) -> Fq {
    let mut bytes = [0u8; 32];
    for chunk in bytes.chunks_exact_mut(8) {
        let v = next_u64(state).to_be_bytes();
        chunk.copy_from_slice(&v);
    }
    Fq::from_be_bytes_mod_order(&bytes)
}

fn main() -> Result<(), String> {
    let n = env_usize("BN254_TRACE_KPI_N", 1 << 16);
    let seed = env_u64("BN254_TRACE_KPI_SEED", 0x9b6f_8a12_5c3d_1174);

    let mut state = seed;
    let mut events = Vec::with_capacity(n);
    for idx in 0..n {
        let a = limbs_from_fq(next_fq(&mut state));
        let b = limbs_from_fq(next_fq(&mut state));
        let (kind, out) = match idx % 3 {
            0 => (Bn254OpKind::Add, bn254_add_mod(a, b)),
            1 => (Bn254OpKind::Sub, bn254_sub_mod(a, b)),
            _ => (Bn254OpKind::Mul, bn254_mul_mod(a, b)),
        };
        let out = out.ok_or_else(|| "bn254 trace kpi invalid limbs".to_string())?;
        events.push(Bn254OpTraceEvent { kind, a, b, out });
    }

    let start = Instant::now();
    let kpi = validate_bn254_op_trace_batch_kpi(&events, None)?;
    let ms = start.elapsed().as_millis();

    println!(
        "{{\"kpi\":\"BN254_TRACE_VALIDATE_KPI\",\"n\":{},\"add_count\":{},\"sub_count\":{},\"mul_count\":{},\"validate_ms\":{},\"add_cuda\":{},\"sub_cuda\":{},\"mul_cuda\":{}}}",
        n,
        kpi.add_count,
        kpi.sub_count,
        kpi.mul_count,
        ms,
        kpi.add_cuda,
        kpi.sub_cuda,
        kpi.mul_cuda
    );

    Ok(())
}
