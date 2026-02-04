use rand::{RngCore, SeedableRng};
use rand::rngs::StdRng;
use glyph::adapters::keccak256;
use glyph::glyph_core::{prove_compiled, ProverConfig, ProverMode};
use glyph::glyph_ir_compiler::compile_hash_merge;
use glyph::glyph_ir_compiler::CompiledUcir;
use glyph::glyph_ir::{Ucir2, WitnessLayout, CustomGate, WRef, CUSTOM_GATE_KECCAK_MERGE, encode_three_wref_payload};

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

fn env_usize_list(name: &str, default: &[usize]) -> Vec<usize> {
    let raw = match std::env::var(name) {
        Ok(v) => v,
        Err(_) => {
            return default.to_vec();
        }
    };
    let mut out = Vec::new();
    for part in raw.split([',', ' ', ';', '|']) {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(v) = trimmed.parse::<usize>() {
            if v > 0 {
                out.push(v);
            }
        }
    }
    if out.is_empty() {
        default.to_vec()
    } else {
        out
    }
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(default)
}

fn env_hex_20(name: &str, default: [u8; 20]) -> [u8; 20] {
    let raw = match std::env::var(name) {
        Ok(v) => v,
        Err(_) => return default,
    };
    let s = raw.strip_prefix("0x").unwrap_or(&raw);
    if s.len() != 40 {
        return default;
    }
    let mut out = [0u8; 20];
    for i in 0..20 {
        let byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16);
        match byte {
            Ok(v) => out[i] = v,
            Err(_) => return default,
        }
    }
    out
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

fn compile_hash_repeat(seed: u64, repeat: usize) -> CompiledUcir {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut public_inputs = Vec::with_capacity(repeat * 12);
    let mut ucir = Ucir2::new();

    for i in 0..repeat {
        let mut left = [0u8; 32];
        let mut right = [0u8; 32];
        rng.fill_bytes(&mut left);
        rng.fill_bytes(&mut right);
        let mut input = [0u8; 64];
        input[..32].copy_from_slice(&left);
        input[32..].copy_from_slice(&right);
        let expected = keccak256(&input);

        let left_limbs = glyph::glyph_ir_compiler::embed_fq_limbs(&left);
        let right_limbs = glyph::glyph_ir_compiler::embed_fq_limbs(&right);
        let out_limbs = glyph::glyph_ir_compiler::embed_fq_limbs(&expected);
        public_inputs.extend_from_slice(&left_limbs);
        public_inputs.extend_from_slice(&right_limbs);
        public_inputs.extend_from_slice(&out_limbs);

        let base = (i * 12) as u32;
        let left_start = WRef(base);
        let right_start = WRef(base + 4);
        let out_start = WRef(base + 8);
        let payload = encode_three_wref_payload(left_start, right_start, out_start);
        ucir.add_custom_gate(CustomGate::new(CUSTOM_GATE_KECCAK_MERGE, payload));
    }

    ucir.witness_layout = WitnessLayout::fast_mode(public_inputs.len() as u32, 0, 0);
    CompiledUcir {
        ucir,
        public_inputs,
        wire_values: Vec::new(),
    }
}

fn main() {
    let seed = env_u64("GLYPH_LAYOUT_SEED", 0xA5A5_A5A5);
    let chainid = env_u64("GLYPH_LAYOUT_CHAINID", 31_337);
    let contract_addr = env_hex_20("GLYPH_LAYOUT_CONTRACT", [0x11u8; 20]);
    let repeat = env_usize("GLYPH_LAYOUT_REPEAT", 1).max(1);
    let arities = env_usize_list("GLYPH_LAYOUT_ARITIES", &[2, 4, 8, 16]);
    let pack_factors = env_usize_list("GLYPH_LAYOUT_PACK_FACTORS", &[1, 2, 4]);

    let compiled = if repeat == 1 {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut left = [0u8; 32];
        let mut right = [0u8; 32];
        rng.fill_bytes(&mut left);
        rng.fill_bytes(&mut right);
        let mut input = [0u8; 64];
        input[..32].copy_from_slice(&left);
        input[32..].copy_from_slice(&right);
        let expected = keccak256(&input);
        match compile_hash_merge(&left, &right, &expected) {
            Ok(compiled) => compiled,
            Err(err) => die(&format!("compile hash failed: {err:?}")),
        }
    } else {
        compile_hash_repeat(seed, repeat)
    };

    let cfg = ProverConfig {
        mode: ProverMode::FastMode,
        chainid: Some(chainid),
        contract_addr: Some(contract_addr),
        ..Default::default()
    };
    let proof = match prove_compiled(compiled, cfg) {
        Ok(proof) => proof,
        Err(err) => die(&format!("prove fast failed: {err:?}")),
    };

    let base_rounds = proof.packed_gkr_proof.rounds.len();
    let baseline_bytes = proof.packed_gkr_calldata.len();
    let header_words = 5usize;

    let mut entries = Vec::new();
    for arity in arities {
        if arity < 2 || !arity.is_power_of_two() {
            continue;
        }
        let arity_bits = arity.trailing_zeros() as usize;
        let rounds = base_rounds.div_ceil(arity_bits);
        for truncated in [false, true] {
            let coeffs_per_round = if truncated { arity.saturating_sub(1) } else { arity };
            for pack in &pack_factors {
                let pack_factor = (*pack).max(1);
                let total_coeffs = rounds.saturating_mul(coeffs_per_round);
                let packed_words = total_coeffs.div_ceil(pack_factor);
                let packed_calldata_bytes = 32usize.saturating_mul(header_words + packed_words);
                entries.push(format!(
                    "{{\"arity\":{},\"rounds\":{},\"truncated\":{},\"coeffs_per_round\":{},\"pack_factor\":{},\"packed_words\":{},\"packed_calldata_bytes\":{}}}",
                    arity,
                    rounds,
                    if truncated { "true" } else { "false" },
                    coeffs_per_round,
                    pack_factor,
                    packed_words,
                    packed_calldata_bytes
                ));
            }
        }
    }

    let json = format!(
        "{{\"kpi\":\"GLYPH_PACKED_GKR_LAYOUT\",\"seed\":{},\"repeat\":{},\"base_rounds\":{},\"header_words\":{},\"baseline_packed_calldata_bytes\":{},\"baseline_commitment_tag\":\"{}\",\"entries\":[{}]}}",
        seed,
        repeat,
        base_rounds,
        header_words,
        baseline_bytes,
        to_hex(&proof.artifact.commitment_tag),
        entries.join(",")
    );
    println!("{}", json);
}
