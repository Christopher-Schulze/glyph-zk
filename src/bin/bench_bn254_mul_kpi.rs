use ark_bn254::Fq;
use ark_ff::PrimeField;
use glyph::bn254_field::{bn254_add_mod, bn254_mul_mod, bn254_sub_mod, limbs_from_fq};
use std::time::Instant;

fn die(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1);
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
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

fn next_limbs(state: &mut u64) -> [u64; 4] {
    let mut bytes = [0u8; 32];
    for chunk in bytes.chunks_exact_mut(8) {
        let v = next_u64(state).to_be_bytes();
        chunk.copy_from_slice(&v);
    }
    let fq = Fq::from_be_bytes_mod_order(&bytes);
    limbs_from_fq(fq)
}

fn main() {
    let add_n = env_usize("GLYPH_BN254_MUL_KPI_ADD", 100_000);
    let sub_n = env_usize("GLYPH_BN254_MUL_KPI_SUB", 100_000);
    let mul_n = env_usize("GLYPH_BN254_MUL_KPI_MUL", 50_000);
    let seed = env_u64("GLYPH_BN254_MUL_KPI_SEED", 0x5a17_3d2f_9a4c_e1b3);

    let mut state = seed;
    let mut add_inputs = Vec::with_capacity(add_n);
    let mut sub_inputs = Vec::with_capacity(sub_n);
    let mut mul_inputs = Vec::with_capacity(mul_n);

    for _ in 0..add_n {
        add_inputs.push((next_limbs(&mut state), next_limbs(&mut state)));
    }
    for _ in 0..sub_n {
        sub_inputs.push((next_limbs(&mut state), next_limbs(&mut state)));
    }
    for _ in 0..mul_n {
        mul_inputs.push((next_limbs(&mut state), next_limbs(&mut state)));
    }

    let mut acc = 0u64;
    let add_start = Instant::now();
    for (a, b) in add_inputs.iter().copied() {
        let out = match bn254_add_mod(a, b) {
            Some(out) => out,
            None => die("bn254 add failed"),
        };
        acc ^= out[0];
    }
    let add_elapsed = add_start.elapsed();

    let sub_start = Instant::now();
    for (a, b) in sub_inputs.iter().copied() {
        let out = match bn254_sub_mod(a, b) {
            Some(out) => out,
            None => die("bn254 sub failed"),
        };
        acc ^= out[1];
    }
    let sub_elapsed = sub_start.elapsed();

    let mul_start = Instant::now();
    for (a, b) in mul_inputs.iter().copied() {
        let out = match bn254_mul_mod(a, b) {
            Some(out) => out,
            None => die("bn254 mul failed"),
        };
        acc ^= out[2];
    }
    let mul_elapsed = mul_start.elapsed();

    let simd = std::env::var("GLYPH_BN254_SIMD").unwrap_or_else(|_| "auto".to_string());
    let mont = std::env::var("GLYPH_BN254_MUL_MONT").unwrap_or_else(|_| "auto".to_string());

    println!(
        "bn254 mul kpi: add={} sub={} mul={} add_t={:.2?} sub_t={:.2?} mul_t={:.2?} acc={} simd={} mont={}",
        add_n,
        sub_n,
        mul_n,
        add_elapsed,
        sub_elapsed,
        mul_elapsed,
        acc,
        simd,
        mont
    );
}
