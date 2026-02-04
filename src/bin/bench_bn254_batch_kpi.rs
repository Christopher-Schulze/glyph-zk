use ark_bn254::Fq;
use ark_ff::PrimeField;
use std::time::Instant;

use glyph::bn254_field::{bn254_add_mod_batch, bn254_mul_mod_batch, bn254_sub_mod_batch, limbs_from_fq};

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
    let n = env_usize("BN254_BATCH_KPI_N", 1 << 15);
    let seed = env_u64("BN254_BATCH_KPI_SEED", 0x6f23_a19b_2e3a_9c15);

    let mut state = seed;
    let mut a = Vec::with_capacity(n);
    let mut b = Vec::with_capacity(n);
    for _ in 0..n {
        let fa = next_fq(&mut state);
        let fb = next_fq(&mut state);
        a.push(limbs_from_fq(fa));
        b.push(limbs_from_fq(fb));
    }

    let mut out = vec!([0u64; 4]; n);

    let add_start = Instant::now();
    let add_cuda = bn254_add_mod_batch(&a, &b, &mut out)?;
    let add_ms = add_start.elapsed().as_millis();
    let add_acc = out.iter().fold(0u64, |acc, x| acc ^ x[0]);

    let sub_start = Instant::now();
    let sub_cuda = bn254_sub_mod_batch(&a, &b, &mut out)?;
    let sub_ms = sub_start.elapsed().as_millis();
    let sub_acc = out.iter().fold(0u64, |acc, x| acc ^ x[1]);

    let mul_start = Instant::now();
    let mul_cuda = bn254_mul_mod_batch(&a, &b, &mut out)?;
    let mul_ms = mul_start.elapsed().as_millis();
    let mul_acc = out.iter().fold(0u64, |acc, x| acc ^ x[2]);

    println!(
        "{{\"kpi\":\"BN254_BATCH_KPI\",\"n\":{},\"add_ms\":{},\"sub_ms\":{},\"mul_ms\":{},\"add_cuda\":{},\"sub_cuda\":{},\"mul_cuda\":{},\"add_acc\":{},\"sub_acc\":{},\"mul_acc\":{}}}",
        n,
        add_ms,
        sub_ms,
        mul_ms,
        add_cuda,
        sub_cuda,
        mul_cuda,
        add_acc,
        sub_acc,
        mul_acc
    );

    Ok(())
}
