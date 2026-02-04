use std::time::Instant;

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField};
use binius_field::underlier::WithUnderlier;
use glyph::adapters::{
    groth16_bn254_statement_bytes,
    groth16_bn254_vk_bytes_full_precomp,
    kzg_bn254_statement_bytes,
    kzg_bn254_vk_bytes_g2s_precomp,
    vk_hash_from_bytes,
    statement_hash_from_bytes,
    keccak256,
    AdapterFamily,
    SNARK_GROTH16_BN254_ID,
    SNARK_KZG_PLONK_ID,
    SNARK_SUB_GROTH16_BN254,
    SNARK_SUB_KZG_BN254,
};
use glyph::snark_groth16_bn254_adapter::load_groth16_bn254_fixture_bytes;
use glyph::snark_kzg_bn254_adapter::{
    encode_kzg_params_bytes,
    encode_kzg_proof_bytes,
    encode_kzg_public_inputs_bytes,
    encode_kzg_vk_bytes,
    KzgProof,
    KzgPublicInputs,
    KzgVk,
};
use glyph::ivc_adapter::{encode_ivc_basefold_proof_bytes, BaseFoldPcsOpeningProof};
use glyph::bn254_groth16::decode_groth16_vk_bytes;
use glyph::bn254_pairing_trace::{
    decode_g1_wnaf_precomp_pair,
    encode_g1_wnaf_precomp_bytes,
    encode_g1_wnaf_precomp_phi_bytes,
    encode_g2_precomp_bytes,
    G1WnafPrecomp,
};
use glyph::glyph_core::{encode_packed_gkr_calldata, prove_compiled, ProverConfig, ProverMode, UniversalProof};
use glyph::glyph_basefold::{derive_binius_eval_point, derive_basefold_weights};
use glyph::glyph_ir_compiler::{
    compile_groth16_bn254_with_bindings,
    compile_kzg_bn254_with_bindings,
    compile_ivc,
    compile_stark,
    compile_hash_merge_with_bindings,
    CompiledUcir,
};
use glyph::pcs_basefold::{BaseFoldConfig, BaseFoldProver, derive_basefold_commitment_tag, derive_basefold_point_tag};
use glyph::{stark_winterfell, stark_winterfell_f64};
use glyph::stark_winterfell::StarkUpstreamReceipt;

type Groth16Bn254Precomp = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<G1WnafPrecomp>);

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(default)
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
}

fn env_bool(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
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

fn load_hex_field(lines: &str, key: &str) -> Result<Vec<u8>, String> {
    for line in lines.lines() {
        if let Some(rest) = line.strip_prefix(key) {
            let hex = rest.trim();
            return hex::decode(hex).map_err(|e| format!("hex decode failed for {key}: {e}"));
        }
    }
    Err(format!("missing {key} in fixture"))
}

fn load_stark_receipt_fixture(path: &str, use_f64: bool) -> Result<Vec<u8>, String> {
    let raw = std::fs::read(path).map_err(|e| format!("fixture read failed: {e}"))?;
    let raw = decode_fixture_text(&raw)?;
    let proof = load_hex_field(&raw, "proof_hex=")?;
    let pub_inputs = load_hex_field(&raw, "pub_inputs_hex=")?;
    let vk_params = load_hex_field(&raw, "vk_params_hex=")?;
    let upstream = StarkUpstreamReceipt {
        proof_bytes: proof,
        pub_inputs_bytes: pub_inputs,
        vk_params_bytes: vk_params,
    };

    let canonical = if use_f64 {
        stark_winterfell_f64::canonical_stark_receipt_from_upstream_do_work(&upstream)
            .map_err(|e| format!("canonical receipt f64 failed: {e}"))?
    } else {
        stark_winterfell::canonical_stark_receipt_from_upstream_do_work(&upstream)
            .map_err(|e| format!("canonical receipt failed: {e}"))?
    };

    Ok(canonical.encode_for_hash())
}

fn decode_fixture_text(raw: &[u8]) -> Result<String, String> {
    if raw.starts_with(&[0xFF, 0xFE]) {
        let mut units = Vec::with_capacity((raw.len().saturating_sub(2)) / 2);
        for chunk in raw[2..].chunks(2) {
            if chunk.len() < 2 {
                break;
            }
            units.push(u16::from_le_bytes([chunk[0], chunk[1]]));
        }
        return String::from_utf16(&units).map_err(|e| format!("fixture utf16 decode failed: {e}"));
    }
    if raw.starts_with(&[0xFE, 0xFF]) {
        let mut units = Vec::with_capacity((raw.len().saturating_sub(2)) / 2);
        for chunk in raw[2..].chunks(2) {
            if chunk.len() < 2 {
                break;
            }
            units.push(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        return String::from_utf16(&units).map_err(|e| format!("fixture utf16 decode failed: {e}"));
    }
    Ok(String::from_utf8_lossy(raw).to_string())
}

fn load_canonical_receipt_fixture(path: &str) -> Result<Vec<u8>, String> {
    let raw = std::fs::read(path).map_err(|e| format!("fixture read failed: {e}"))?;
    let raw_str = decode_fixture_text(&raw)?;
    let key = "receipt_hex=";
    let idx = raw_str
        .find(key)
        .ok_or_else(|| "missing receipt_hex= in fixture".to_string())?;
    let rest = &raw_str[idx + key.len()..];
    let end = rest.find(['\n', '\r']).unwrap_or(rest.len());
    let hex = rest[..end].trim();
    hex::decode(hex).map_err(|e| format!("receipt_hex decode failed: {e}"))
}

fn build_groth16_bn254_precomp(
    window: usize,
    vk: &glyph::bn254_groth16::Groth16VerifyingKey,
) -> Result<Groth16Bn254Precomp, String> {
    let beta_precomp = encode_g2_precomp_bytes(vk.beta_g2);
    let gamma_precomp = encode_g2_precomp_bytes(vk.gamma_g2);
    let delta_precomp = encode_g2_precomp_bytes(vk.delta_g2);

    let mut ic_precomp_tables = Vec::with_capacity(vk.ic.len().saturating_sub(1));
    for ic in vk.ic.iter().skip(1) {
        let base_precomp = encode_g1_wnaf_precomp_bytes(*ic, window);
        let phi_precomp = encode_g1_wnaf_precomp_phi_bytes(*ic, window);
        let table = decode_g1_wnaf_precomp_pair(window, &base_precomp, &phi_precomp)?;
        ic_precomp_tables.push(table);
    }
    Ok((beta_precomp, gamma_precomp, delta_precomp, ic_precomp_tables))
}

fn build_groth16_bn254_adapter_vk_bytes(
    vk_hash: &[u8; 32],
    input_layout_hash: &[u8; 32],
    window: usize,
    vk: &glyph::bn254_groth16::Groth16VerifyingKey,
) -> Vec<u8> {
    let mut ic_precomp = Vec::with_capacity(vk.ic.len().saturating_sub(1));
    for ic in vk.ic.iter().skip(1) {
        let base_precomp = encode_g1_wnaf_precomp_bytes(*ic, window);
        let phi_precomp = encode_g1_wnaf_precomp_phi_bytes(*ic, window);
        ic_precomp.push(glyph::adapters::Groth16Bn254IcPrecomp {
            base_precomp,
            phi_precomp,
        });
    }
    groth16_bn254_vk_bytes_full_precomp(
        SNARK_GROTH16_BN254_ID,
        vk_hash,
        input_layout_hash,
        &encode_g2_precomp_bytes(vk.beta_g2),
        &encode_g2_precomp_bytes(vk.gamma_g2),
        &encode_g2_precomp_bytes(vk.delta_g2),
        window as u8,
        &ic_precomp,
    )
}

fn clone_compiled(src: &CompiledUcir) -> CompiledUcir {
    CompiledUcir {
        ucir: src.ucir.clone(),
        public_inputs: src.public_inputs.clone(),
        wire_values: src.wire_values.clone(),
    }
}

struct ProofSizes {
    artifact_bytes: usize,
    pcs_commitment_bytes: usize,
    pcs_rho_bytes: usize,
    pcs_salt_bytes: usize,
    pcs_opening_bytes: usize,
    logup_bytes: usize,
    sumcheck_rounds_bytes: usize,
    sumcheck_challenges_bytes: usize,
    final_eval_bytes: usize,
    packed_gkr_bytes: usize,
    packed_calldata_bytes: usize,
    total_offchain_bytes: usize,
}

fn bytes_len_pcs_commitment(commitment: &glyph::glyph_pcs_basefold::PcsCommitment) -> usize {
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

fn bytes_len_pcs_opening(opening: &glyph::glyph_pcs_basefold::PcsOpening) -> usize {
    opening.encoded_len()
}

fn bytes_len_product_tree(tree: &glyph::glyph_logup::ProductTree) -> usize {
    let mut len = 0usize;
    len += tree.flat.len() * 8;
    len += tree.level_offsets.len() * 8;
    len += tree.level_sizes.len() * 8;
    len += 8;
    len
}

fn bytes_len_logup(logup: &glyph::glyph_logup::LogUpProof) -> usize {
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

fn proof_sizes(proof: &UniversalProof) -> ProofSizes {
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

    ProofSizes {
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
        total_offchain_bytes,
    }
}

fn sizes_json(s: &ProofSizes) -> String {
    format!(
        "{{\"artifact_bytes\":{},\"pcs_commitment_bytes\":{},\"pcs_rho_bytes\":{},\"pcs_salt_bytes\":{},\"pcs_opening_bytes\":{},\"logup_bytes\":{},\"sumcheck_rounds_bytes\":{},\"sumcheck_challenges_bytes\":{},\"final_eval_bytes\":{},\"packed_gkr_bytes\":{},\"packed_calldata_bytes\":{},\"total_offchain_bytes\":{}}}",
        s.artifact_bytes,
        s.pcs_commitment_bytes,
        s.pcs_rho_bytes,
        s.pcs_salt_bytes,
        s.pcs_opening_bytes,
        s.logup_bytes,
        s.sumcheck_rounds_bytes,
        s.sumcheck_challenges_bytes,
        s.final_eval_bytes,
        s.packed_gkr_bytes,
        s.packed_calldata_bytes,
        s.total_offchain_bytes
    )
}

fn prove_with_mode(
    compiled: CompiledUcir,
    mode: ProverMode,
    chainid: u64,
    contract_addr: [u8; 20],
    zk_seed: Option<[u8; 32]>,
) -> Result<(UniversalProof, u128), String> {
    let cfg = ProverConfig {
        mode,
        chainid: Some(chainid),
        contract_addr: Some(contract_addr),
        zk_seed,
        ..Default::default()
    };

    let start = Instant::now();
    let mut proof = prove_compiled(compiled, cfg).map_err(|e| format!("prove failed: {e:?}"))?;
    if proof.packed_gkr_calldata.is_empty() {
        proof.packed_gkr_calldata = encode_packed_gkr_calldata(&proof);
    }
    Ok((proof, start.elapsed().as_millis()))
}

fn main() -> Result<(), String> {
    let adapters = std::env::var("GLYPH_ADAPTER_ZK_KPI")
        .unwrap_or_else(|_| "all".to_string())
        .to_lowercase();
    let run_all = adapters == "all";
    let do_groth16 = run_all || adapters.contains("groth16");
    let do_kzg = run_all || adapters.contains("kzg");
    let do_ivc = run_all || adapters.contains("ivc");
    let do_stark = run_all || adapters.contains("stark");
    let do_hash = run_all || adapters.contains("hash");

    let ic_window = env_usize("GLYPH_ADAPTER_ZK_KPI_GROTH16_BN254_IC_WINDOW", 4);
    let use_groth16_precomp = env_bool("GLYPH_ADAPTER_ZK_KPI_GROTH16_BN254_PRECOMP", true);
    let use_kzg_precomp = env_bool("GLYPH_ADAPTER_ZK_KPI_KZG_BN254_PRECOMP", true);
    let use_stark_f64 = env_bool("GLYPH_ADAPTER_ZK_KPI_STARK_F64", false);
    let use_stark_circle = env_bool("GLYPH_ADAPTER_ZK_KPI_STARK_CIRCLE", false);
    let use_stark_circle_large = env_bool("GLYPH_ADAPTER_ZK_KPI_STARK_CIRCLE_LARGE", false);
    let use_stark_baby_bear = env_bool("GLYPH_ADAPTER_ZK_KPI_STARK_BABY_BEAR", false);

    let chainid = env_u64("GLYPH_ZK_KPI_CHAINID", 31_337);
    let contract_addr = env_hex_20("GLYPH_ZK_KPI_CONTRACT", [0x11u8; 20]);
    let seed = env_u64("GLYPH_ZK_KPI_SEED", 0xA5A5_A5A5);
    let mut seed_bytes = [0u8; 32];
    seed_bytes[..8].copy_from_slice(&seed.to_le_bytes());
    let zk_seed = Some(seed_bytes);

    if do_groth16 {
        let (raw_vk_bytes, raw_proof_bytes, raw_pub_bytes) =
            load_groth16_bn254_fixture_bytes().map_err(|e| format!("groth16 fixture: {e}"))?;
        let input_layout_hash = keccak256(b"glyph-groth16-bn254-zk-kpi-layout");
        let vk_hash = keccak256(&raw_vk_bytes);
        let pub_hash = keccak256(&raw_pub_bytes);
        let vk = decode_groth16_vk_bytes(&raw_vk_bytes).map_err(|e| format!("vk decode: {e}"))?;
        let adapter_vk_bytes =
            build_groth16_bn254_adapter_vk_bytes(&vk_hash, &input_layout_hash, ic_window, &vk);
        let adapter_statement_bytes = groth16_bn254_statement_bytes(&input_layout_hash, &pub_hash);

        let bindings = [
            vk_hash_from_bytes(
                AdapterFamily::Snark,
                SNARK_SUB_GROTH16_BN254,
                &adapter_vk_bytes,
            ),
            statement_hash_from_bytes(
                AdapterFamily::Snark,
                SNARK_SUB_GROTH16_BN254,
                &adapter_statement_bytes,
            ),
            keccak256(&raw_proof_bytes),
            keccak256(&raw_pub_bytes),
        ];
        let (beta_pre, gamma_pre, delta_pre, ic_tables) = build_groth16_bn254_precomp(ic_window, &vk)?;

        let compile_start = Instant::now();
        let compiled = compile_groth16_bn254_with_bindings(
            &raw_vk_bytes,
            &raw_proof_bytes,
            &raw_pub_bytes,
            &bindings,
            if use_groth16_precomp { Some(beta_pre.as_slice()) } else { None },
            if use_groth16_precomp { Some(gamma_pre.as_slice()) } else { None },
            if use_groth16_precomp { Some(delta_pre.as_slice()) } else { None },
            if use_groth16_precomp { Some(ic_tables.as_slice()) } else { None },
        )
        .map_err(|e| format!("groth16-bn254 compile failed: {e:?}"))?;
        let compile_ms = compile_start.elapsed().as_millis();

        let (fast_proof, fast_ms) = prove_with_mode(
            clone_compiled(&compiled),
            ProverMode::FastMode,
            chainid,
            contract_addr,
            None,
        )?;
        let (zk_proof, zk_ms) = prove_with_mode(
            compiled,
            ProverMode::ZkMode,
            chainid,
            contract_addr,
            zk_seed,
        )?;

        println!(
            "{{\"kpi\":\"GLYPH_ADAPTER_ZK_KPI\",\"adapter\":\"SNARK_GROTH16_BN254\",\"compile_ms\":{},\"fast_ms\":{},\"zk_ms\":{},\"fast\":{},\"zk\":{}}}",
            compile_ms,
            fast_ms,
            zk_ms,
            sizes_json(&proof_sizes(&fast_proof)),
            sizes_json(&proof_sizes(&zk_proof))
        );
    }

    if do_kzg {
        let s = ark_bn254::Fr::from(5u64);
        let z = ark_bn254::Fr::from(13u64);
        let coeffs = [
            ark_bn254::Fr::from(3u64),
            ark_bn254::Fr::from(11u64),
            ark_bn254::Fr::from(7u64),
            ark_bn254::Fr::from(2u64),
        ];
        let eval_poly = |x: ark_bn254::Fr| -> ark_bn254::Fr {
            let mut pow = ark_bn254::Fr::ONE;
            let mut acc = ark_bn254::Fr::ZERO;
            for c in coeffs.iter() {
                acc += *c * pow;
                pow *= x;
            }
            acc
        };
        let y = eval_poly(z);
        let f_s = eval_poly(s);
        let denom = (s - z).inverse().ok_or_else(|| "s == z".to_string())?;
        let q_s = (f_s - y) * denom;

        let g1 = ark_bn254::G1Affine::generator();
        let g2 = ark_bn254::G2Affine::generator();
        let g2_s = g2.mul_bigint(s.into_bigint()).into_affine();
        let commitment = g1.mul_bigint(f_s.into_bigint()).into_affine();
        let proof = g1.mul_bigint(q_s.into_bigint()).into_affine();

        let vk = KzgVk { g1, g2, g2_s };
        let kzg_proof = KzgProof { commitment, proof };
        let inputs = KzgPublicInputs { z, y };
        let raw_vk_bytes = encode_kzg_vk_bytes(&vk);
        let raw_proof_bytes = encode_kzg_proof_bytes(&kzg_proof);
        let raw_inputs_bytes = encode_kzg_public_inputs_bytes(&inputs);

        let input_layout_hash = keccak256(b"glyph-kzg-bn254-zk-kpi-layout");
        let vk_hash = keccak256(&raw_vk_bytes);
        let pub_hash = keccak256(&raw_inputs_bytes);
        let params_hash = keccak256(&encode_kzg_params_bytes(&vk));
        let g2s_precomp = encode_g2_precomp_bytes(g2_s);
        let adapter_vk_bytes = kzg_bn254_vk_bytes_g2s_precomp(
            SNARK_KZG_PLONK_ID,
            &params_hash,
            &vk_hash,
            &input_layout_hash,
            &g2s_precomp,
        );
        let adapter_statement_bytes = kzg_bn254_statement_bytes(&input_layout_hash, &pub_hash);

        let bindings = [
            vk_hash_from_bytes(
                AdapterFamily::Snark,
                SNARK_SUB_KZG_BN254,
                &adapter_vk_bytes,
            ),
            statement_hash_from_bytes(
                AdapterFamily::Snark,
                SNARK_SUB_KZG_BN254,
                &adapter_statement_bytes,
            ),
            keccak256(&raw_proof_bytes),
            keccak256(&raw_inputs_bytes),
        ];

        let compile_start = Instant::now();
        let compiled = compile_kzg_bn254_with_bindings(
            &raw_vk_bytes,
            &raw_proof_bytes,
            &raw_inputs_bytes,
            &bindings,
            if use_kzg_precomp { Some(g2s_precomp.as_slice()) } else { None },
        )
        .map_err(|e| format!("kzg-bn254 compile failed: {e:?}"))?;
        let compile_ms = compile_start.elapsed().as_millis();

        let (fast_proof, fast_ms) = prove_with_mode(
            clone_compiled(&compiled),
            ProverMode::FastMode,
            chainid,
            contract_addr,
            None,
        )?;
        let (zk_proof, zk_ms) = prove_with_mode(
            compiled,
            ProverMode::ZkMode,
            chainid,
            contract_addr,
            zk_seed,
        )?;

        println!(
            "{{\"kpi\":\"GLYPH_ADAPTER_ZK_KPI\",\"adapter\":\"SNARK_KZG_BN254\",\"compile_ms\":{},\"fast_ms\":{},\"zk_ms\":{},\"fast\":{},\"zk\":{}}}",
            compile_ms,
            fast_ms,
            zk_ms,
            sizes_json(&proof_sizes(&fast_proof)),
            sizes_json(&proof_sizes(&zk_proof))
        );
    }

    if do_ivc {
        let seed = b"glyph-ivc-zk-kpi";
        let inst = keccak256(seed);
        let instance_digests = vec![inst];
        let weights = derive_basefold_weights(&instance_digests)
            .map_err(|e| format!("ivc weights: {e}"))?;
        let n_vars = 4usize;
        let eval_point = derive_binius_eval_point(seed, 0, n_vars);
        let evals: Vec<binius_field::BinaryField128b> = (0..(1usize << n_vars))
            .map(|i| binius_field::BinaryField128b::from_underlier((i as u128) + 1))
            .collect();
        let prover = BaseFoldProver::commit(&evals, n_vars, BaseFoldConfig::default())
            .map_err(|e| format!("ivc basefold commit: {e}"))?;
        let commitment = prover.commitment();
        let opening = prover.open(&eval_point).map_err(|e| format!("ivc basefold open: {e}"))?;
        let opening = BaseFoldPcsOpeningProof {
            instance_digests,
            weights,
            commitment,
            eval_point,
            claimed_eval: opening.eval,
            proofs: opening.proofs,
        };
        let proof_bytes =
            encode_ivc_basefold_proof_bytes(&opening).map_err(|e| format!("ivc encode: {e}"))?;
        let commitment_tag = derive_basefold_commitment_tag(&opening.commitment);
        let point_tag = derive_basefold_point_tag(&commitment_tag, &opening.eval_point);
        let claim128 = opening.claimed_eval.to_underlier();
        let vk_bytes = glyph::adapters::ivc_vk_bytes(
            4,
            glyph::adapters::IvcProofType::BaseFoldTransparent,
        );
        let stmt_bytes = glyph::adapters::ivc_statement_bytes(
            &commitment_tag,
            &point_tag,
            claim128,
            glyph::adapters::IvcProofType::BaseFoldTransparent,
        );
        let ir = glyph::adapter_ir::AdapterIr {
            version: glyph::adapter_ir::ADAPTER_IR_VERSION,
            ops: vec![glyph::adapter_ir::AdapterIrOp {
                kernel_id: glyph::adapter_ir::kernel_id::IVC_VERIFY,
                args: vec![],
            }],
        };
        let ir_bytes = ir.encode();

        let compile_start = Instant::now();
        let compiled = compile_ivc(&ir_bytes, &vk_bytes, &stmt_bytes, &proof_bytes)
            .map_err(|e| format!("ivc compile failed: {e:?}"))?;
        let compile_ms = compile_start.elapsed().as_millis();

        let (fast_proof, fast_ms) = prove_with_mode(
            clone_compiled(&compiled),
            ProverMode::FastMode,
            chainid,
            contract_addr,
            None,
        )?;
        let (zk_proof, zk_ms) = prove_with_mode(
            compiled,
            ProverMode::ZkMode,
            chainid,
            contract_addr,
            zk_seed,
        )?;

        println!(
            "{{\"kpi\":\"GLYPH_ADAPTER_ZK_KPI\",\"adapter\":\"IVC\",\"compile_ms\":{},\"fast_ms\":{},\"zk_ms\":{},\"fast\":{},\"zk\":{}}}",
            compile_ms,
            fast_ms,
            zk_ms,
            sizes_json(&proof_sizes(&fast_proof)),
            sizes_json(&proof_sizes(&zk_proof))
        );
    }

    if do_stark {
        let seed = b"glyph-stark-zk-kpi-seed";
        let receipt_bytes = if use_stark_baby_bear {
            if use_stark_f64 {
                return Err("stark baby bear fixture does not support f64 receipt".to_string());
            }
            load_canonical_receipt_fixture("scripts/tools/fixtures/fast_circle_stark_baby_bear_receipt.txt")?
        } else if use_stark_circle || use_stark_circle_large {
            if use_stark_f64 {
                return Err("stark circle fixture does not support f64 receipt".to_string());
            }
            let path = if use_stark_circle_large {
                "scripts/tools/fixtures/fast_circle_stark_receipt_large.txt"
            } else {
                "scripts/tools/fixtures/fast_circle_stark_receipt.txt"
            };
            load_canonical_receipt_fixture(path)?
        } else {
            let path = if use_stark_f64 {
                "scripts/tools/fixtures/fast_sha3_receipt_f64.txt"
            } else {
                "scripts/tools/fixtures/fast_sha3_receipt.txt"
            };
            load_stark_receipt_fixture(path, use_stark_f64)?
        };
        let compile_start = Instant::now();
        let compiled = compile_stark(&receipt_bytes, seed)
            .map_err(|e| format!("stark compile failed: {e:?}"))?;
        let compile_ms = compile_start.elapsed().as_millis();

        let (fast_proof, fast_ms) = prove_with_mode(
            clone_compiled(&compiled),
            ProverMode::FastMode,
            chainid,
            contract_addr,
            None,
        )?;
        let (zk_proof, zk_ms) = prove_with_mode(
            compiled,
            ProverMode::ZkMode,
            chainid,
            contract_addr,
            zk_seed,
        )?;

        println!(
            "{{\"kpi\":\"GLYPH_ADAPTER_ZK_KPI\",\"adapter\":\"STARK\",\"compile_ms\":{},\"fast_ms\":{},\"zk_ms\":{},\"fast\":{},\"zk\":{}}}",
            compile_ms,
            fast_ms,
            zk_ms,
            sizes_json(&proof_sizes(&fast_proof)),
            sizes_json(&proof_sizes(&zk_proof))
        );
    }

    if do_hash {
        let left = keccak256(b"glyph-hash-left");
        let right = keccak256(b"glyph-hash-right");
        let mut input = [0u8; 64];
        input[..32].copy_from_slice(&left);
        input[32..].copy_from_slice(&right);
        let expected = keccak256(&input);
        let bindings = [
            keccak256(b"hash-zk-bind-1"),
            keccak256(b"hash-zk-bind-2"),
        ];
        let compile_start = Instant::now();
        let compiled = compile_hash_merge_with_bindings(&left, &right, &expected, &bindings)
            .map_err(|e| format!("hash compile failed: {e:?}"))?;
        let compile_ms = compile_start.elapsed().as_millis();

        let (fast_proof, fast_ms) = prove_with_mode(
            clone_compiled(&compiled),
            ProverMode::FastMode,
            chainid,
            contract_addr,
            None,
        )?;
        let (zk_proof, zk_ms) = prove_with_mode(
            compiled,
            ProverMode::ZkMode,
            chainid,
            contract_addr,
            zk_seed,
        )?;

        println!(
            "{{\"kpi\":\"GLYPH_ADAPTER_ZK_KPI\",\"adapter\":\"HASH\",\"compile_ms\":{},\"fast_ms\":{},\"zk_ms\":{},\"fast\":{},\"zk\":{}}}",
            compile_ms,
            fast_ms,
            zk_ms,
            sizes_json(&proof_sizes(&fast_proof)),
            sizes_json(&proof_sizes(&zk_proof))
        );
    }

    Ok(())
}
