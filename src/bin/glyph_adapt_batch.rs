use std::env;
use std::fs;

use glyph::adapter_ir::{
    execute_groth16_bn254_ir_batch,
    execute_kzg_bn254_ir_batch,
    Groth16Bn254BatchItem,
    KzgBn254BatchItem,
};
use glyph::adapter_gate;
use glyph::adapters::SnarkKind;
use glyph::cli_registry;
use glyph::glyph_basefold::derive_glyph_artifact_from_instance_digests;

fn main() {
    {
        let args: Vec<String> = env::args().collect();
        let mut family = None;
        let mut ir_file: Option<String> = None;
        let mut adapter_vk_file: Option<String> = None;
        let mut raw_vk_file: Option<String> = None;
        let mut items_file: Option<String> = None;
        let mut profile: Option<String> = None;
        let mut json = false;
        let mut artifact = false;

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--family" => {
                    i += 1;
                    family = args.get(i).map(|s| s.as_str().to_string());
                }
                "--ir-file" => {
                    i += 1;
                    ir_file = args.get(i).cloned();
                }
                "--adapter-vk-file" => {
                    i += 1;
                    adapter_vk_file = args.get(i).cloned();
                }
                "--raw-vk-file" => {
                    i += 1;
                    raw_vk_file = args.get(i).cloned();
                }
                "--items-file" => {
                    i += 1;
                    items_file = args.get(i).cloned();
                }
                "--profile" => {
                    i += 1;
                    profile = args.get(i).cloned();
                }
                "--json" => {
                    json = true;
                }
                "--artifact" => {
                    artifact = true;
                }
                "--help" | "-h" => {
                    print_help();
                    return;
                }
                _ => {}
            }
            i += 1;
        }

        let family = family.unwrap_or_else(|| die("missing --family (groth16-bn254|kzg-bn254)"));
        let ir_file = ir_file.unwrap_or_else(|| die("missing --ir-file"));
        let adapter_vk_file = adapter_vk_file.unwrap_or_else(|| die("missing --adapter-vk-file"));
        let raw_vk_file = raw_vk_file.unwrap_or_else(|| die("missing --raw-vk-file"));
        let items_file = items_file.unwrap_or_else(|| die("missing --items-file"));

        let ir_bytes = read_file(&ir_file, "--ir-file");
        let adapter_vk_bytes = read_file(&adapter_vk_file, "--adapter-vk-file");
        let raw_vk_bytes = read_file(&raw_vk_file, "--raw-vk-file");
        let items = read_items(&items_file);

        if items.is_empty() {
            die("items-file is empty");
        }

        let snark_kind = match family.as_str() {
            "groth16-bn254" => Some(SnarkKind::Groth16Bn254),
            "kzg-bn254" => Some(SnarkKind::KzgBn254),
            _ => None,
        };
        let snark_kind = snark_kind.unwrap_or_else(|| {
            die("invalid --family (expected groth16-bn254 or kzg-bn254)")
        });
        adapter_gate::ensure_snark_kind_enabled(snark_kind).unwrap_or_else(|e| die(&e));

        match family.as_str() {
            "groth16-bn254" => {
                if let Some(profile) = profile.as_ref() {
                    env::set_var("GLYPH_GROTH16_BN254_PROFILE", profile);
                }
                let batch_items: Vec<Groth16Bn254BatchItem<'_>> = items
                    .iter()
                    .map(|item| Groth16Bn254BatchItem {
                        adapter_statement_bytes: &item.statement,
                        raw_proof_bytes: &item.proof,
                        raw_public_inputs_bytes: &item.public_inputs,
                    })
                    .collect();
                let results = execute_groth16_bn254_ir_batch(
                    &ir_bytes,
                    &adapter_vk_bytes,
                    &raw_vk_bytes,
                    &batch_items,
                )
                .unwrap_or_else(|e| die(&format!("groth16-bn254 batch failed: {e}")));
                let digests: Vec<[u8; 32]> = results
                    .iter()
                    .map(|r| r.proof.artifact.initial_claim)
                    .collect();
                emit_results(digests, &results, json, artifact);
            }
            "kzg-bn254" => {
                if let Some(profile) = profile.as_ref() {
                    env::set_var("GLYPH_KZG_BN254_PROFILE", profile);
                }
                let batch_items: Vec<KzgBn254BatchItem<'_>> = items
                    .iter()
                    .map(|item| KzgBn254BatchItem {
                        adapter_statement_bytes: &item.statement,
                        raw_proof_bytes: &item.proof,
                        raw_public_inputs_bytes: &item.public_inputs,
                    })
                    .collect();
                let results = execute_kzg_bn254_ir_batch(
                    &ir_bytes,
                    &adapter_vk_bytes,
                    &raw_vk_bytes,
                    &batch_items,
                )
                .unwrap_or_else(|e| die(&format!("kzg-bn254 batch failed: {e}")));
                let digests: Vec<[u8; 32]> = results
                    .iter()
                    .map(|r| r.proof.artifact.initial_claim)
                    .collect();
                emit_results(digests, &results, json, artifact);
            }
            _ => die("invalid --family (expected groth16-bn254 or kzg-bn254)"),
        }
    }
}

struct ItemBytes {
    statement: Vec<u8>,
    proof: Vec<u8>,
    public_inputs: Vec<u8>,
}

fn read_items(path: &str) -> Vec<ItemBytes> {
    let content = fs::read_to_string(path).unwrap_or_else(|_| die("failed to read --items-file"));
    let mut out = Vec::new();
    for (line_idx, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = if line.contains(',') {
            line.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect()
        } else {
            line.split_whitespace().collect()
        };
        if parts.len() != 3 {
            die(&format!("items-file line {} must have 3 fields", line_idx + 1));
        }
        let statement = read_file(parts[0], "statement");
        let proof = read_file(parts[1], "proof");
        let public_inputs = read_file(parts[2], "public inputs");
        out.push(ItemBytes {
            statement,
            proof,
            public_inputs,
        });
    }
    out
}

fn read_file(path: &str, label: &str) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|_| die(&format!("failed to read {label}: {path}")))
}

fn emit_results(digests: Vec<[u8; 32]>, results: &[impl HasTranscript], json: bool, artifact: bool) {
    if json {
        println!("{{");
        println!("  \"items\": [");
        for (idx, (digest, result)) in digests.iter().zip(results.iter()).enumerate() {
            println!(
                "    {{ \"index\": {}, \"instance_digest\": \"0x{}\", \"transcript_len\": {} }}{}",
                idx,
                hex(digest),
                result.transcript_len(),
                if idx + 1 == results.len() { "" } else { "," }
            );
        }
        println!("  ]");
        if artifact {
            let instance_vec: Vec<[u8; 32]> = digests.clone();
            let (commitment, point, claim) = derive_glyph_artifact_from_instance_digests(&instance_vec)
                .unwrap_or_else(|e| die(&format!("artifact derivation failed: {e}")));
            println!(
                "  ,\"artifact\": {{ \"commitment\": \"0x{}\", \"point\": \"0x{}\", \"claim_u128\": {} }}",
                hex(&commitment),
                hex(&point),
                claim
            );
        }
        println!("}}");
        return;
    }

    for (idx, (digest, result)) in digests.iter().zip(results.iter()).enumerate() {
        println!(
            "item {}: instance_digest=0x{} transcript_len={}",
            idx,
            hex(digest),
            result.transcript_len()
        );
    }
    if artifact {
        let instance_vec: Vec<[u8; 32]> = digests;
            let (commitment, point, claim) = derive_glyph_artifact_from_instance_digests(&instance_vec)
            .unwrap_or_else(|e| die(&format!("artifact derivation failed: {e}")));
        println!("artifact.commitment=0x{}", hex(&commitment));
        println!("artifact.point=0x{}", hex(&point));
        println!("artifact.claim_u128={claim}");
    }
}

trait HasTranscript {
    fn transcript_len(&self) -> usize;
}

impl HasTranscript for glyph::adapter_ir::Groth16Bn254Result {
    fn transcript_len(&self) -> usize {
        self.proof.packed_gkr_proof.rounds.len()
    }
}

impl HasTranscript for glyph::adapter_ir::KzgBn254Result {
    fn transcript_len(&self) -> usize {
        self.proof.packed_gkr_proof.rounds.len()
    }
}

fn hex(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

fn print_help() {
    println!("glyph_adapt_batch --family groth16-bn254|kzg-bn254 --ir-file <path> --adapter-vk-file <path> --raw-vk-file <path> --items-file <path> [--profile <name>] [--artifact] [--json]");
    let snark_status = cli_registry::format_feature_status("snark", cli_registry::snark_feature_enabled());
    println!("Requires feature: {snark_status}");
    let enabled_kinds = cli_registry::enabled_snark_kinds();
    println!("Enabled snark kinds: {}", cli_registry::join_list(&enabled_kinds));
}

fn die(msg: &str) -> ! {
    eprintln!("{msg}");
    std::process::exit(1)
}
