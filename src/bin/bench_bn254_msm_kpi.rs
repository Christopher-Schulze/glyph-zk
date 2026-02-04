use std::fs::File;
use std::io::Read;
use std::time::Instant;

use ark_bn254::{Fr, G1Affine as ArkG1Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use glyph::bn254_groth16::{decode_groth16_public_inputs, decode_groth16_vk_bytes, Groth16VerifyingKey};
use glyph::bn254_ops::{validate_bn254_op_trace_batch_kpi, Bn254OpKind};
use glyph::bn254_pairing_trace::record_g1_msm_ops;

fn env_bool(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(default)
}

fn load_groth16_bn254_fixture() -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut file = File::open("scripts/tools/fixtures/groth16_bn254_fixture.txt")
        .map_err(|e| format!("fixture open: {e}"))?;
    let mut buf = String::new();
    file.read_to_string(&mut buf)
        .map_err(|e| format!("fixture read: {e}"))?;
    let mut vk_hex = None;
    let mut pub_hex = None;
    for line in buf.lines() {
        if let Some(rest) = line.strip_prefix("vk_hex=") {
            vk_hex = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("pub_inputs_hex=") {
            pub_hex = Some(rest.trim().to_string());
        }
    }
    let vk_hex = vk_hex.ok_or_else(|| "vk_hex missing".to_string())?;
    let pub_hex = pub_hex.ok_or_else(|| "pub_inputs_hex missing".to_string())?;
    let vk = hex::decode(vk_hex).map_err(|e| format!("vk hex decode: {e}"))?;
    let pub_inputs = hex::decode(pub_hex).map_err(|e| format!("pub hex decode: {e}"))?;
    Ok((vk, pub_inputs))
}

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

fn env_usize_opt(name: &str) -> Option<usize> {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
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

fn synthesize_vk_and_inputs(
    vk: &Groth16VerifyingKey,
    ic_len: usize,
    seed: u64,
) -> (Groth16VerifyingKey, Vec<Fr>) {
    let mut out_ic = Vec::with_capacity(ic_len.max(1));
    out_ic.push(vk.ic[0]);
    let base = ArkG1Affine::generator();
    for idx in 1..ic_len {
        let scalar = Fr::from((idx as u64) + 1);
        let point = base.mul_bigint(scalar.into_bigint()).into_affine();
        out_ic.push(point);
    }
    let mut state = seed;
    let mut inputs = Vec::with_capacity(out_ic.len().saturating_sub(1));
    for _ in 0..out_ic.len().saturating_sub(1) {
        inputs.push(next_fr(&mut state));
    }
    (
        Groth16VerifyingKey {
            alpha_g1: vk.alpha_g1,
            beta_g2: vk.beta_g2,
            gamma_g2: vk.gamma_g2,
            delta_g2: vk.delta_g2,
            ic: out_ic,
        },
        inputs,
    )
}

fn main() -> Result<(), String> {
    let use_precomp = env_bool("BN254_MSM_KPI_PRECOMP", false);
    let ic_len = env_usize("BN254_MSM_KPI_IC_LEN", 0);
    let seed = env_u64("BN254_MSM_KPI_SEED", 0x5b61_2a18_93d4_7e01);
    let window_min = env_usize("BN254_MSM_KPI_WINDOW_MIN", 2).min(12);
    let window_max = env_usize("BN254_MSM_KPI_WINDOW_MAX", 12).min(12);
    let (vk_bytes, pub_bytes) = load_groth16_bn254_fixture()?;
    let vk = decode_groth16_vk_bytes(&vk_bytes)?;
    let base_inputs = decode_groth16_public_inputs(&pub_bytes)?;
    let (vk, public_inputs) = if ic_len > 0 {
        synthesize_vk_and_inputs(&vk, ic_len, seed)
    } else {
        (vk, base_inputs)
    };

    let prev_window = std::env::var("GLYPH_BN254_MSM_WINDOW").ok();
    for window in window_min..=window_max {
        std::env::set_var("GLYPH_BN254_MSM_WINDOW", window.to_string());

        let trace_start = Instant::now();
        let events = record_g1_msm_ops(&vk, &public_inputs, use_precomp)?;
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
        let cuda_min = env_usize_opt("BN254_MSM_TRACE_CUDA_MIN_ELEMS");
        let kpi = validate_bn254_op_trace_batch_kpi(&events, cuda_min)?;
        let validate_ms = validate_start.elapsed().as_millis();

        println!(
            "{{\"kpi\":\"BN254_MSM_TRACE_KPI\",\"precomp\":{},\"ic_len\":{},\"window\":{},\"trace_ms\":{},\"validate_ms\":{},\"add_count\":{},\"sub_count\":{},\"mul_count\":{},\"add_cuda\":{},\"sub_cuda\":{},\"mul_cuda\":{}}}",
            use_precomp,
            vk.ic.len(),
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

    match prev_window {
        Some(v) => std::env::set_var("GLYPH_BN254_MSM_WINDOW", v),
        None => std::env::remove_var("GLYPH_BN254_MSM_WINDOW"),
    }

    Ok(())
}
