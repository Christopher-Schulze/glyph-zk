use rand::{RngCore, SeedableRng};
use rand::rngs::StdRng;

use glyph::adapters::keccak256;
use glyph::glyph_core::{prove_compiled, ProverConfig, ProverMode, UniversalProof};
use glyph::glyph_ir_compiler::compile_hash_merge;
use glyph::glyph_ir::{Ucir2, WitnessLayout, CustomGate, WRef, CUSTOM_GATE_KECCAK_MERGE, encode_three_wref_payload};
use glyph::glyph_logup::{LogUpProof, ProductTree};
use glyph::glyph_pcs_basefold::{PcsCommitment, PcsOpening};

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

fn compile_hash_repeat(seed: u64, repeat: usize) -> glyph::glyph_ir_compiler::CompiledUcir {
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
    glyph::glyph_ir_compiler::CompiledUcir {
        ucir,
        public_inputs,
        wire_values: Vec::new(),
    }
}

fn bytes_len_pcs_commitment(commitment: &PcsCommitment) -> usize {
    let mut len = 0usize;
    len += 32;
    len += 8;
    len += 8;
    len += 4;
    len += 4;
    if commitment.salt_commitment.is_some() {
        len += 32;
    }
    if commitment.mask_commitment.is_some() {
        len += 32;
    }
    len += 32;
    len
}

fn bytes_len_pcs_opening(opening: &PcsOpening) -> usize {
    opening.encoded_len()
}

fn bytes_len_product_tree(tree: &ProductTree) -> usize {
    let mut len = 0usize;
    len += tree.flat.len() * 8;
    len += tree.level_offsets.len() * 8;
    len += tree.level_sizes.len() * 8;
    len += 8;
    len
}

fn bytes_len_logup(logup: &LogUpProof) -> usize {
    let mut len = 0usize;
    for table in &logup.tables {
        len += 4;
        len += 8;
        len += bytes_len_product_tree(&table.a_tree);
        len += bytes_len_product_tree(&table.b_tree);
    }
    len
}

fn bytes_len_packed_gkr(rounds: usize) -> usize {
    32 + rounds * 128 + 32
}

fn proof_sizes(proof: &UniversalProof) -> String {
    let artifact_bytes = 32 + 32 + 16 + 32;
    let pcs_commitment_bytes = bytes_len_pcs_commitment(&proof.pcs_commitment);
    let pcs_rho_bytes = 8;
    let pcs_salt_bytes = proof.pcs_salt.as_ref().map(|_| 32usize).unwrap_or(0);
    let pcs_opening_bytes = proof
        .pcs_opening
        .as_ref()
        .map(bytes_len_pcs_opening)
        .unwrap_or(0);
    let logup_bytes = proof
        .logup_proof
        .as_ref()
        .map(bytes_len_logup)
        .unwrap_or(0);
    let sumcheck_rounds_bytes = proof.sumcheck_rounds.len() * 32;
    let sumcheck_challenges_bytes = proof.sumcheck_challenges.len() * 8;
    let final_eval_bytes = 16;
    let packed_gkr_bytes = bytes_len_packed_gkr(proof.packed_gkr_proof.rounds.len());
    let packed_calldata_bytes = proof.packed_gkr_calldata.len();

    let total_offchain_bytes = artifact_bytes
        + pcs_commitment_bytes
        + pcs_rho_bytes
        + pcs_salt_bytes
        + pcs_opening_bytes
        + logup_bytes
        + sumcheck_rounds_bytes
        + sumcheck_challenges_bytes
        + final_eval_bytes
        + packed_gkr_bytes;

    format!(
        "{{\"artifact_bytes\":{},\"pcs_commitment_bytes\":{},\"pcs_rho_bytes\":{},\"pcs_salt_bytes\":{},\"pcs_opening_bytes\":{},\"logup_bytes\":{},\"sumcheck_rounds_bytes\":{},\"sumcheck_challenges_bytes\":{},\"final_eval_bytes\":{},\"packed_gkr_bytes\":{},\"packed_calldata_bytes\":{},\"total_offchain_bytes\":{}}}",
        artifact_bytes,
        pcs_commitment_bytes,
        pcs_rho_bytes,
        pcs_salt_bytes,
        pcs_opening_bytes,
        logup_bytes,
        sumcheck_rounds_bytes,
        sumcheck_challenges_bytes,
        final_eval_bytes,
        packed_gkr_bytes,
        packed_calldata_bytes,
        total_offchain_bytes
    )
}

fn main() {
    let seed = env_u64("GLYPH_ZK_KPI_SEED", 0xA5A5_A5A5);
    let chainid = env_u64("GLYPH_ZK_KPI_CHAINID", 31_337);
    let contract_addr = env_hex_20("GLYPH_ZK_KPI_CONTRACT", [0x11u8; 20]);

    let repeat = env_usize("GLYPH_ZK_KPI_REPEAT", 1).max(1);

    let cfg_fast = ProverConfig {
        mode: ProverMode::FastMode,
        chainid: Some(chainid),
        contract_addr: Some(contract_addr),
        ..Default::default()
    };
    let (fast, input_digest) = if repeat == 1 {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut left = [0u8; 32];
        let mut right = [0u8; 32];
        rng.fill_bytes(&mut left);
        rng.fill_bytes(&mut right);
        let mut input = [0u8; 64];
        input[..32].copy_from_slice(&left);
        input[32..].copy_from_slice(&right);
        let expected = keccak256(&input);
        let compiled_fast = match compile_hash_merge(&left, &right, &expected) {
            Ok(compiled) => compiled,
            Err(err) => die(&format!("compile hash fast failed: {err:?}")),
        };
        let fast = match prove_compiled(compiled_fast, cfg_fast) {
            Ok(proof) => proof,
            Err(err) => die(&format!("prove fast failed: {err:?}")),
        };
        (fast, expected)
    } else {
        let compiled_fast = compile_hash_repeat(seed, repeat);
        let fast = match prove_compiled(compiled_fast, cfg_fast) {
            Ok(proof) => proof,
            Err(err) => die(&format!("prove fast failed: {err:?}")),
        };
        let mut tag = [0u8; 8];
        tag.copy_from_slice(&seed.to_le_bytes());
        let input_digest = keccak256(&tag);
        (fast, input_digest)
    };

    let mut seed_bytes = [0u8; 32];
    seed_bytes[..8].copy_from_slice(&seed.to_le_bytes());
    let cfg_zk = ProverConfig {
        mode: ProverMode::ZkMode,
        chainid: Some(chainid),
        contract_addr: Some(contract_addr),
        zk_seed: Some(seed_bytes),
        ..Default::default()
    };
    let compiled_zk = if repeat == 1 {
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
            Err(err) => die(&format!("compile hash zk failed: {err:?}")),
        }
    } else {
        compile_hash_repeat(seed, repeat)
    };
    let zk = match prove_compiled(compiled_zk, cfg_zk) {
        Ok(proof) => proof,
        Err(err) => die(&format!("prove zk failed: {err:?}")),
    };

    let json = format!(
        "{{\"kpi\":\"GLYPH_ZK_PROOF_SIZE\",\"seed\":{},\"repeat\":{},\"chainid\":{},\"contract\":\"{}\",\"input_digest\":\"{}\",\"fast\":{},\"zk\":{}}}",
        seed,
        repeat,
        chainid,
        to_hex(&contract_addr),
        to_hex(&input_digest),
        proof_sizes(&fast),
        proof_sizes(&zk)
    );
    println!("{}", json);
}
