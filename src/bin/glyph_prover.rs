use std::env;
use std::fs;

use glyph::adapter_ir::{kernel_id, AdapterIrOp, AdapterIr, ADAPTER_IR_VERSION};
use glyph::adapter_gate;
use glyph::adapter_registry;
use glyph::adapters::{
    apply_groth16_bn254_profile_defaults, apply_kzg_bn254_profile_defaults,
    apply_ivc_profile_defaults, apply_ipa_profile_defaults, apply_hash_profile_defaults,
    apply_sp1_profile_defaults, apply_binius_profile_defaults, AdapterFamily, IpaSystem, CurveFamily,
    SnarkKind,
};
use glyph::ipa_adapter::{decode_ipa_receipt, IPA_BACKEND_GENERIC, IPA_BACKEND_HALO2};
use glyph::glyph_core::{encode_packed_gkr_calldata, prove_compiled, ProverConfig, ProverMode};
use glyph::adapter_facade::{
    compile_binius_checked, compile_groth16_bls12381_checked, compile_groth16_bn254_checked,
    compile_hash_merge_checked, compile_ivc_checked, compile_kzg_bls12381_checked,
    compile_kzg_bn254_checked, compile_ipa_checked, compile_plonk_checked, compile_sp1_checked,
    compile_stark_checked,
};
use glyph::glyph_ir_compiler::CompiledUcir;

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut family: Option<AdapterFamily> = None;
    let mut snark_kind: Option<SnarkKind> = None;
    let mut mode = ProverMode::ZkMode;
    let mut json = false;
    let mut calldata_only = false;
    let mut gkr_truncated = false;
    let mut profile: Option<String> = None;
    let mut auto_config = false;

    let mut vk_path: Option<String> = None;
    let mut vk_hex: Option<Vec<u8>> = None;
    let mut proof_path: Option<String> = None;
    let mut proof_hex: Option<Vec<u8>> = None;
    let mut pub_path: Option<String> = None;
    let mut pub_hex: Option<Vec<u8>> = None;

    let mut adapter_vk_path: Option<String> = None;
    let mut adapter_vk_hex: Option<Vec<u8>> = None;
    let mut adapter_statement_path: Option<String> = None;
    let mut adapter_statement_hex: Option<Vec<u8>> = None;
    let mut ir_path: Option<String> = None;
    let mut ir_hex: Option<Vec<u8>> = None;

    let mut receipt_path: Option<String> = None;
    let mut receipt_hex: Option<Vec<u8>> = None;
    let mut seed_string: Option<String> = None;
    let mut seed_hex: Option<Vec<u8>> = None;
    let mut stark_field_raw: Option<String> = None;
    let mut ipa_system: Option<IpaSystem> = None;
    let mut curve_family: Option<CurveFamily> = None;

    let mut left_hex: Option<[u8; 32]> = None;
    let mut right_hex: Option<[u8; 32]> = None;
    let mut digest_hex: Option<[u8; 32]> = None;

    let mut chain_id: Option<u64> = None;
    let mut verifier_addr: Option<[u8; 20]> = None;
    let mut memory_limit: Option<usize> = None;
    let mut sumcheck_rounds: Option<usize> = None;
    let mut sumcheck_chunk_size: Option<usize> = None;
    let mut zk_seed_hex: Option<[u8; 32]> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--auto" => {
                auto_config = true;
            }
            "--family" => {
                i += 1;
                family = AdapterFamily::parse(args.get(i).map(|s| s.as_str()).unwrap_or(""));
            }
            "--mode" => {
                i += 1;
                let m = args.get(i).map(|s| s.as_str()).unwrap_or("zk");
                mode = match m {
                    "fast" => ProverMode::FastMode,
                    "zk" => ProverMode::ZkMode,
                    _ => die("invalid --mode (use fast or zk)"),
                };
            }
            "--snark-kind" => {
                i += 1;
                let value = args.get(i).map(|s| s.as_str()).unwrap_or("");
                snark_kind = SnarkKind::parse(value);
                if snark_kind.is_none() {
                    die("invalid --snark-kind (use groth16-bn254|kzg-bn254|plonk|halo2-kzg|ipa-bn254|ipa-bls12381|sp1)");
                }
            }
            "--vk" => {
                i += 1;
                vk_path = args.get(i).cloned();
            }
            "--vk-hex" => {
                i += 1;
                vk_hex = args.get(i).and_then(|s| parse_hex_vec(s));
            }
            "--proof" => {
                i += 1;
                proof_path = args.get(i).cloned();
            }
            "--proof-hex" => {
                i += 1;
                proof_hex = args.get(i).and_then(|s| parse_hex_vec(s));
            }
            "--pub" => {
                i += 1;
                pub_path = args.get(i).cloned();
            }
            "--pub-hex" => {
                i += 1;
                pub_hex = args.get(i).and_then(|s| parse_hex_vec(s));
            }
            "--adapter-vk" => {
                i += 1;
                adapter_vk_path = args.get(i).cloned();
            }
            "--adapter-vk-hex" => {
                i += 1;
                adapter_vk_hex = args.get(i).and_then(|s| parse_hex_vec(s));
            }
            "--adapter-statement" => {
                i += 1;
                adapter_statement_path = args.get(i).cloned();
            }
            "--adapter-statement-hex" => {
                i += 1;
                adapter_statement_hex = args.get(i).and_then(|s| parse_hex_vec(s));
            }
            "--ir" => {
                i += 1;
                ir_path = args.get(i).cloned();
            }
            "--ir-hex" => {
                i += 1;
                ir_hex = args.get(i).and_then(|s| parse_hex_vec(s));
            }
            "--receipt" => {
                i += 1;
                receipt_path = args.get(i).cloned();
            }
            "--receipt-hex" => {
                i += 1;
                receipt_hex = args.get(i).and_then(|s| parse_hex_vec(s));
            }
            "--seed" => {
                i += 1;
                seed_string = args.get(i).cloned();
            }
            "--seed-hex" => {
                i += 1;
                seed_hex = args.get(i).and_then(|s| parse_hex_vec(s));
            }
            "--stark-field" => {
                i += 1;
                stark_field_raw = args.get(i).cloned();
            }
            "--ipa-system" => {
                i += 1;
                let value = args.get(i).map(|s| s.as_str()).unwrap_or("");
                ipa_system = IpaSystem::parse(value);
                if ipa_system.is_none() {
                    die("invalid --ipa-system (use halo2-ipa|generic-ipa)");
                }
            }
            "--curve" => {
                i += 1;
                let value = args.get(i).map(|s| s.as_str()).unwrap_or("");
                curve_family = CurveFamily::parse(value);
                if curve_family.is_none() {
                    die("invalid --curve (use bn254|bls12-381)");
                }
            }
            "--left" => {
                i += 1;
                left_hex = args.get(i).and_then(|s| parse_hex_32(s));
            }
            "--right" => {
                i += 1;
                right_hex = args.get(i).and_then(|s| parse_hex_32(s));
            }
            "--digest" => {
                i += 1;
                digest_hex = args.get(i).and_then(|s| parse_hex_32(s));
            }
            "--chain-id" => {
                i += 1;
                chain_id = args.get(i).and_then(|s| s.parse::<u64>().ok());
            }
            "--verifier" => {
                i += 1;
                verifier_addr = args.get(i).and_then(|s| parse_hex_20(s));
            }
            "--memory-limit" => {
                i += 1;
                memory_limit = args.get(i).and_then(|s| s.parse::<usize>().ok());
            }
            "--sumcheck-rounds" => {
                i += 1;
                sumcheck_rounds = args.get(i).and_then(|s| s.parse::<usize>().ok());
            }
            "--sumcheck-chunk-size" => {
                i += 1;
                sumcheck_chunk_size = args.get(i).and_then(|s| s.parse::<usize>().ok());
            }
            "--zk-seed-hex" => {
                i += 1;
                zk_seed_hex = args.get(i).and_then(|s| parse_hex_32(s));
            }
            "--gkr-truncated" => {
                gkr_truncated = true;
            }
            "--profile" => {
                i += 1;
                profile = args.get(i).cloned();
            }
            "--json" => {
                json = true;
            }
            "--calldata-only" => {
                calldata_only = true;
            }
            "--help" | "-h" => {
                print_help();
                return;
            }
            _ => {}
        }
        i += 1;
    }

    if auto_config && profile.is_none() {
        profile = Some("auto".to_string());
    }

    if auto_config {
        eprintln!("auto config enabled");
    }

    if let Some(family) = family {
        adapter_gate::ensure_family_enabled(family).unwrap_or_else(|e| die(&e));
    }

    let family = family.unwrap_or_else(|| die("missing --family"));
    if family == AdapterFamily::Snark && snark_kind.is_none() {
        die("--snark-kind is required with --family snark");
    }
    if family != AdapterFamily::Snark && snark_kind.is_some() {
        die("--snark-kind is only valid with --family snark");
    }
    if let Some(kind) = snark_kind {
        adapter_gate::ensure_snark_kind_enabled(kind).unwrap_or_else(|e| die(&e));
    }

    if let Some(profile) = profile.as_ref() {
        match family {
            AdapterFamily::Snark => {
                let snark_kind = match snark_kind {
                    Some(kind) => kind,
                    None => die("snark kind required"),
                };
                match snark_kind {
                    SnarkKind::Groth16Bn254 => {
                        env::set_var("GLYPH_GROTH16_BN254_PROFILE", profile)
                    }
                    SnarkKind::KzgBn254 => env::set_var("GLYPH_KZG_BN254_PROFILE", profile),
                    SnarkKind::Plonk | SnarkKind::Halo2Kzg => {
                        env::set_var("GLYPH_PLONK_PROFILE", profile)
                    }
                    SnarkKind::IpaBn254 | SnarkKind::IpaBls12381 => {
                        env::set_var("GLYPH_IPA_PROFILE", profile)
                    }
                    SnarkKind::Sp1 => env::set_var("GLYPH_SP1_PROFILE", profile),
                }
            }
            AdapterFamily::Ivc => env::set_var("GLYPH_IVC_PROFILE", profile),
            AdapterFamily::StarkGoldilocks
            | AdapterFamily::StarkBabyBear
            | AdapterFamily::StarkM31 => env::set_var("GLYPH_STARK_PROFILE", profile),
            AdapterFamily::Hash => env::set_var("GLYPH_HASH_PROFILE", profile),
            AdapterFamily::Binius => env::set_var("GLYPH_BINIUS_PROFILE", profile),
        }
    }

    if stark_field_raw.is_some()
        && !matches!(
            family,
            AdapterFamily::StarkGoldilocks
                | AdapterFamily::StarkBabyBear
                | AdapterFamily::StarkM31
        )
    {
        die("--stark-field is only valid with --family stark-*");
    }
    if ipa_system.is_some()
        && !(family == AdapterFamily::Snark
            && matches!(snark_kind, Some(SnarkKind::IpaBn254 | SnarkKind::IpaBls12381)))
    {
        die("--ipa-system is only valid with --family snark --snark-kind ipa-bn254 or ipa-bls12381");
    }
    if curve_family.is_some()
        && !(family == AdapterFamily::Snark
            && matches!(snark_kind, Some(SnarkKind::Groth16Bn254 | SnarkKind::KzgBn254)))
    {
        die("--curve is only valid with --family snark --snark-kind groth16-bn254|kzg-bn254");
    }

    let stark_field = if let Some(raw) = stark_field_raw.as_deref() {
        let field = adapter_gate::parse_stark_field(raw).unwrap_or_else(|e| die(&e));
        adapter_gate::ensure_stark_field_enabled(field).unwrap_or_else(|e| die(&e));
        adapter_gate::ensure_stark_field_allowed(family, field).unwrap_or_else(|e| die(&e));
        Some(field)
    } else {
        None
    };

    let compiled = match family {
        AdapterFamily::Snark => {
            let snark_kind = match snark_kind {
                Some(kind) => kind,
                None => die("snark kind required"),
            };
            match snark_kind {
            SnarkKind::Groth16Bn254 => {
            apply_groth16_bn254_profile_defaults();
            let vk_bytes = read_bytes_arg(&vk_path, &vk_hex, "--vk/--vk-hex");
            let proof_bytes = read_bytes_arg(&proof_path, &proof_hex, "--proof/--proof-hex");
            let pub_bytes = read_bytes_arg(&pub_path, &pub_hex, "--pub/--pub-hex");
            if curve_family == Some(CurveFamily::Bls12381) {
                let receipt = glyph::groth16_bls12381::Groth16Bls12381Receipt {
                    vk_bytes,
                    proof_bytes,
                    pub_inputs_bytes: pub_bytes,
                };
                let receipt_bytes =
                    glyph::groth16_bls12381::encode_groth16_bls12381_receipt(&receipt);
                compile_groth16_bls12381_checked(&receipt_bytes)
                    .unwrap_or_else(|e| die(&format!("groth16 bls12381 compile failed: {e:?}")))
            } else {
                compile_groth16_bn254_checked(&vk_bytes, &proof_bytes, &pub_bytes)
                    .unwrap_or_else(|e| die(&format!("groth16 bn254 compile failed: {e:?}")))
            }
            }
            SnarkKind::KzgBn254 => {
            apply_kzg_bn254_profile_defaults();
            let vk_bytes = read_bytes_arg(&vk_path, &vk_hex, "--vk/--vk-hex");
            let proof_bytes = read_bytes_arg(&proof_path, &proof_hex, "--proof/--proof-hex");
            let pub_bytes = read_bytes_arg(&pub_path, &pub_hex, "--pub/--pub-hex");
            if curve_family == Some(CurveFamily::Bls12381) {
                let receipt = glyph::kzg_bls12381::KzgBls12381Receipt {
                    vk_bytes,
                    proof_bytes,
                    pub_inputs_bytes: pub_bytes,
                };
                let receipt_bytes =
                    glyph::kzg_bls12381::encode_kzg_bls12381_receipt(&receipt);
                compile_kzg_bls12381_checked(&receipt_bytes)
                    .unwrap_or_else(|e| die(&format!("kzg bls12381 compile failed: {e:?}")))
            } else {
                compile_kzg_bn254_checked(&vk_bytes, &proof_bytes, &pub_bytes)
                    .unwrap_or_else(|e| die(&format!("kzg bn254 compile failed: {e:?}")))
            }
            }
        SnarkKind::IpaBn254 | SnarkKind::IpaBls12381 => {
            apply_ipa_profile_defaults();
            let receipt_bytes =
                read_bytes_arg(&receipt_path, &receipt_hex, "--receipt/--receipt-hex");
            if let Some(system) = ipa_system {
                let receipt = decode_ipa_receipt(&receipt_bytes)
                    .unwrap_or_else(|e| die(&format!("ipa receipt decode failed: {e}")));
                let expected = match system {
                    IpaSystem::Halo2Ipa => IPA_BACKEND_HALO2,
                    IpaSystem::GenericIpa => IPA_BACKEND_GENERIC,
                };
                if receipt.backend_id != expected {
                    die("ipa receipt backend_id does not match --ipa-system");
                }
            }
            compile_ipa_checked(&receipt_bytes)
                .unwrap_or_else(|e| die(&format!("ipa compile failed: {e:?}")))
        }
            SnarkKind::Sp1 => {
                apply_sp1_profile_defaults();
                let receipt_bytes =
                    read_bytes_arg(&receipt_path, &receipt_hex, "--receipt/--receipt-hex");
                compile_sp1_checked(&receipt_bytes)
                    .unwrap_or_else(|e| die(&format!("sp1 compile failed: {e:?}")))
            }
            SnarkKind::Plonk | SnarkKind::Halo2Kzg => {
                let receipt_bytes =
                    read_bytes_arg(&receipt_path, &receipt_hex, "--receipt/--receipt-hex");
                compile_plonk_checked(&receipt_bytes)
                    .unwrap_or_else(|e| die(&format!("plonk compile failed: {e:?}")))
            }
            }
        }
        AdapterFamily::Ivc => {
            apply_ivc_profile_defaults();
            let adapter_vk_bytes =
                read_bytes_arg(&adapter_vk_path, &adapter_vk_hex, "--adapter-vk/--adapter-vk-hex");
            let adapter_statement_bytes = read_bytes_arg(
                &adapter_statement_path,
                &adapter_statement_hex,
                "--adapter-statement/--adapter-statement-hex",
            );
            let proof_bytes = read_bytes_arg(&proof_path, &proof_hex, "--proof/--proof-hex");
            let ir_bytes = match (&ir_path, &ir_hex) {
                (Some(path), None) => fs::read(path).unwrap_or_else(|_| die("failed to read --ir")),
                (None, Some(bytes)) => bytes.clone(),
                (None, None) => {
                    let ir = AdapterIr {
                        version: ADAPTER_IR_VERSION,
                        ops: vec![AdapterIrOp {
                            kernel_id: kernel_id::IVC_VERIFY,
                            args: Vec::new(),
                        }],
                    };
                    ir.encode()
                }
                _ => die("provide exactly one of --ir or --ir-hex"),
            };
            compile_ivc_checked(
                &ir_bytes,
                &adapter_vk_bytes,
                &adapter_statement_bytes,
                &proof_bytes,
            )
            .unwrap_or_else(|e| die(&format!("ivc compile failed: {e:?}")))
        }
        AdapterFamily::Binius => {
            apply_binius_profile_defaults();
            let adapter_vk_bytes =
                read_bytes_arg(&adapter_vk_path, &adapter_vk_hex, "--adapter-vk/--adapter-vk-hex");
            let adapter_statement_bytes = read_bytes_arg(
                &adapter_statement_path,
                &adapter_statement_hex,
                "--adapter-statement/--adapter-statement-hex",
            );
            let proof_bytes = read_bytes_arg(&proof_path, &proof_hex, "--proof/--proof-hex");
            compile_binius_checked(&adapter_vk_bytes, &adapter_statement_bytes, &proof_bytes)
                .unwrap_or_else(|e| die(&format!("binius compile failed: {e:?}")))
        }
        AdapterFamily::StarkGoldilocks | AdapterFamily::StarkBabyBear | AdapterFamily::StarkM31 => {
            let receipt_bytes = read_bytes_arg(&receipt_path, &receipt_hex, "--receipt/--receipt-hex");
            let seed_bytes = resolve_seed_bytes(seed_string.as_deref(), seed_hex.as_ref());
            compile_stark_checked(family, &receipt_bytes, &seed_bytes, stark_field)
                .unwrap_or_else(|e| die(&format!("stark compile failed: {e:?}")))
        }
        AdapterFamily::Hash => {
            apply_hash_profile_defaults();
            let left = left_hex.unwrap_or_else(|| die("missing --left"));
            let right = right_hex.unwrap_or_else(|| die("missing --right"));
            let digest = digest_hex.unwrap_or_else(|| die("missing --digest"));
            compile_hash_merge_checked(&left, &right, &digest)
                .unwrap_or_else(|e| die(&format!("hash compile failed: {e:?}")))
        }
    };

    let proof = run_prover(compiled, mode, gkr_truncated, chain_id, verifier_addr, memory_limit, sumcheck_rounds, sumcheck_chunk_size, zk_seed_hex);

    let calldata = if let (Some(_chain_id), Some(_verifier_addr)) = (chain_id, verifier_addr) {
        if proof.packed_gkr_calldata.is_empty() {
            encode_packed_gkr_calldata(&proof)
        } else {
            proof.packed_gkr_calldata.clone()
        }
    } else {
        Vec::new()
    };

    if calldata_only {
        if calldata.is_empty() {
            die("calldata requested but --chain-id and --verifier are missing");
        }
        if json {
            println!(
                "{{\"calldata_len\":{},\"calldata\":\"0x{}\"}}",
                calldata.len(),
                hex::encode(&calldata)
            );
        } else {
            println!("0x{}", hex::encode(&calldata));
        }
        return;
    }

    let artifact = &proof.artifact;
    if json {
        println!("{{");
        println!("  \"family\": \"{}\",", adapter_registry::family_name(family));
        if let Some(kind) = snark_kind {
            println!("  \"snark_kind\": \"{}\",", adapter_registry::snark_kind_name(kind));
        } else {
            println!("  \"snark_kind\": null,");
        }
        println!("  \"mode\": \"{}\",", mode_name(mode));
        println!("  \"commitment_tag\": \"0x{}\",", hex::encode(artifact.commitment_tag));
        println!("  \"point_tag\": \"0x{}\",", hex::encode(artifact.point_tag));
        println!("  \"claim128\": \"0x{:032x}\",", artifact.claim128);
        println!("  \"initial_claim\": \"0x{}\",", hex::encode(artifact.initial_claim));
        println!("  \"gkr_truncated\": {},", gkr_truncated);
        println!("  \"calldata_len\": {},", calldata.len());
        println!("  \"calldata\": \"0x{}\"", hex::encode(&calldata));
        println!("}}");
    } else {
        println!("family={}", adapter_registry::family_name(family));
        if let Some(kind) = snark_kind {
            println!("snark_kind={}", adapter_registry::snark_kind_name(kind));
        }
        println!("mode={}", mode_name(mode));
        println!("commitment_tag=0x{}", hex::encode(artifact.commitment_tag));
        println!("point_tag=0x{}", hex::encode(artifact.point_tag));
        println!("claim128=0x{:032x}", artifact.claim128);
        println!("initial_claim=0x{}", hex::encode(artifact.initial_claim));
        println!("gkr_truncated={}", gkr_truncated);
        println!("calldata_len={}", calldata.len());
        if !calldata.is_empty() {
            println!("calldata=0x{}", hex::encode(&calldata));
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_prover(
    compiled: CompiledUcir,
    mode: ProverMode,
    gkr_truncated: bool,
    chain_id: Option<u64>,
    verifier_addr: Option<[u8; 20]>,
    memory_limit: Option<usize>,
    sumcheck_rounds: Option<usize>,
    sumcheck_chunk_size: Option<usize>,
    zk_seed_hex: Option<[u8; 32]>,
) -> glyph::glyph_core::UniversalProof {
    let mut config = ProverConfig {
        mode,
        gkr_truncated,
        chainid: chain_id,
        contract_addr: verifier_addr,
        zk_seed: zk_seed_hex,
        ..Default::default()
    };
    if let Some(limit) = memory_limit {
        config.memory_limit = limit;
    }
    if let Some(rounds) = sumcheck_rounds {
        config.sumcheck_rounds = rounds;
    }
    if let Some(chunk) = sumcheck_chunk_size {
        config.sumcheck_chunk_size = chunk;
    }

    prove_compiled(compiled, config).unwrap_or_else(|e| die(&format!("glyph-prover failed: {e:?}")))
}

fn resolve_seed_bytes(seed_string: Option<&str>, seed_hex: Option<&Vec<u8>>) -> Vec<u8> {
    if let Some(bytes) = seed_hex {
        return bytes.clone();
    }
    let seed_string = seed_string.unwrap_or_else(|| die("missing --seed or --seed-hex"));
    if let Some(hex) = seed_string.strip_prefix("0x") {
        return hex::decode(hex).unwrap_or_else(|_| die("invalid --seed hex value"));
    }
    seed_string.as_bytes().to_vec()
}

fn read_bytes_arg(path: &Option<String>, hex: &Option<Vec<u8>>, name: &str) -> Vec<u8> {
    match (path, hex) {
        (Some(p), None) => fs::read(p).unwrap_or_else(|_| die(&format!("failed to read {name}"))),
        (None, Some(bytes)) => bytes.clone(),
        (Some(_), Some(_)) => die(&format!("provide exactly one of {name}")),
        (None, None) => die(&format!("missing {name}")),
    }
}

fn strip_0x(s: &str) -> &str {
    s.strip_prefix("0x").unwrap_or(s)
}

fn parse_hex_vec(s: &str) -> Option<Vec<u8>> {
    hex::decode(strip_0x(s)).ok()
}

fn parse_hex_20(s: &str) -> Option<[u8; 20]> {
    let bytes = hex::decode(strip_0x(s)).ok()?;
    if bytes.len() != 20 {
        return None;
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn parse_hex_32(s: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(strip_0x(s)).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn mode_name(mode: ProverMode) -> &'static str {
    match mode {
        ProverMode::FastMode => "fast",
        ProverMode::ZkMode => "zk",
    }
}

fn join_list(items: &[&str], sep: &str) -> String {
    if items.is_empty() {
        "none".to_string()
    } else {
        items.join(sep)
    }
}

fn print_help() {
    eprintln!("glyph-prover \\");
    eprintln!("  --family <hash|snark|stark-goldilocks|stark-babybear|stark-m31|ivc|binius> \\");
    eprintln!("  [--snark-kind <groth16-bn254|kzg-bn254|plonk|halo2-kzg|ipa-bn254|ipa-bls12381|sp1>] \\");
    eprintln!("  [--mode <fast|zk>] [--profile <name>] [--auto] [--json] [--calldata-only] \\");
    eprintln!("  [--chain-id <u64>] [--verifier <0x20bytes>] [--gkr-truncated] \\");
    eprintln!("  [--memory-limit <bytes>] [--sumcheck-rounds <n>] [--sumcheck-chunk-size <n>] \\");
    eprintln!("  [--zk-seed-hex <0x32bytes>]");
    eprintln!();
    eprintln!("SNARK Groth16 or KZG inputs:");
    eprintln!("  --vk <path> | --vk-hex <0x...>");
    eprintln!("  --proof <path> | --proof-hex <0x...>");
    eprintln!("  --pub <path> | --pub-hex <0x...>");
    eprintln!("  [--curve <bn254|bls12-381>]");
    eprintln!();
    eprintln!("IVC inputs:");
    eprintln!("  --adapter-vk <path> | --adapter-vk-hex <0x...>");
    eprintln!("  --adapter-statement <path> | --adapter-statement-hex <0x...>");
    eprintln!("  --proof <path> | --proof-hex <0x...>");
    eprintln!("  [--ir <path> | --ir-hex <0x...>] (default: canonical IVC IR)");
    eprintln!();
    eprintln!("Binius inputs:");
    eprintln!("  --adapter-vk <path> | --adapter-vk-hex <0x...>");
    eprintln!("  --adapter-statement <path> | --adapter-statement-hex <0x...>");
    eprintln!("  --proof <path> | --proof-hex <0x...>");
    eprintln!();
    eprintln!("SNARK IPA inputs:");
    eprintln!("  --receipt <path> | --receipt-hex <0x...>");
    eprintln!("  [--ipa-system <halo2-ipa|generic-ipa>]");
    eprintln!();
    let stark_fields = adapter_registry::available_stark_fields();
    let stark_field_names: Vec<&str> = stark_fields.iter().map(|info| info.name).collect();
    let stark_field_list = if stark_field_names.is_empty() {
        "disabled (enable with --features stark-babybear,stark-goldilocks,stark-m31)".to_string()
    } else {
        join_list(&stark_field_names, "|")
    };
    eprintln!("STARK inputs:");
    eprintln!("  --receipt <path> | --receipt-hex <0x...>");
    eprintln!("  --seed <string|0x..> | --seed-hex <0x...>");
    eprintln!("  [--stark-field <{}>]", stark_field_list);
    eprintln!();
    eprintln!("Hash inputs:");
    eprintln!("  --left <0x32bytes> --right <0x32bytes> --digest <0x32bytes>");
    eprintln!();
    eprintln!("SNARK SP1 inputs:");
    eprintln!("  --receipt <path> | --receipt-hex <0x...>");
    eprintln!();
    eprintln!("SNARK PLONK or Halo2-KZG inputs:");
    eprintln!("  --receipt <path> | --receipt-hex <0x...>");
    eprintln!();
    let enabled_families: Vec<&str> = adapter_registry::available_families()
        .iter()
        .map(|info| info.name)
        .collect();
    eprintln!("Enabled families: {}", join_list(&enabled_families, ", "));
    let disabled_families: Vec<String> = adapter_registry::registry()
        .iter()
        .filter(|info| !info.enabled)
        .map(|info| format!("{} (feature {})", info.name, info.feature))
        .collect();
    if !disabled_families.is_empty() {
        eprintln!("Disabled families: {}", disabled_families.join(", "));
    }
    let enabled_snark_kinds: Vec<&str> = adapter_registry::available_snark_kinds()
        .iter()
        .map(|info| info.name)
        .collect();
    eprintln!("Enabled snark kinds: {}", join_list(&enabled_snark_kinds, ", "));
    let disabled_snark_kinds: Vec<String> = adapter_registry::snark_kind_registry()
        .iter()
        .filter(|info| !info.enabled)
        .map(|info| format!("{} (feature {})", info.name, info.feature))
        .collect();
    if !disabled_snark_kinds.is_empty() {
        eprintln!("Disabled snark kinds: {}", disabled_snark_kinds.join(", "));
    }
    if !stark_field_names.is_empty() {
        eprintln!("Enabled stark fields: {}", join_list(&stark_field_names, ", "));
    }
}

fn die(msg: &str) -> ! {
    eprintln!("error: {}", msg);
    std::process::exit(1);
}
