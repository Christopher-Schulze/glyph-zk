use std::fs;

use glyph::adapters::keccak256_concat;
use glyph::glyph_core::{encode_packed_gkr_calldata, prove_compiled, ProverConfig, ProverMode};
use glyph::state_transition_vm::{
    StateTransitionBatch, StateUpdate, MerkleProof,
    compile_state_transition_batch, state_transition_schema_id, key_matches_path_bits, validate_batch,
    VmOpKind,
};
use glyph::state_transition_vm::diff_bytes_from_updates;
use serde::Deserialize;

#[derive(Deserialize)]
struct JsonProof {
    siblings: Vec<String>,
    path_bits: Vec<u8>,
}

#[derive(Deserialize)]
struct JsonUpdate {
    key: String,
    old_value: String,
    new_value: String,
    proof: JsonProof,
    op: Option<String>,
    operand: Option<String>,
}

#[derive(Deserialize)]
struct JsonBatch {
    old_root: String,
    updates: Vec<JsonUpdate>,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 1 || args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return;
    }

    let mut input_path: Option<String> = None;
    let mut chainid: Option<u64> = None;
    let mut verifier: Option<[u8; 20]> = None;
    let mut mode = ProverMode::ZkMode;
    let mut gkr_truncated = false;
    let mut out_path: Option<String> = None;
    let mut emit_diff_bytes: Option<String> = None;
    let mut json = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--in" => {
                i += 1;
                input_path = args.get(i).cloned();
            }
            "--chainid" => {
                i += 1;
                chainid = args.get(i).and_then(|v| v.parse::<u64>().ok());
            }
            "--verifier" => {
                i += 1;
                verifier = args.get(i).and_then(|v| parse_hex_20(v));
            }
            "--mode" => {
                i += 1;
                let v = args.get(i).map(|s| s.as_str()).unwrap_or("");
                mode = match v {
                    "fast" => ProverMode::FastMode,
                    "zk" => ProverMode::ZkMode,
                    _ => die("invalid --mode (use fast|zk)"),
                };
            }
            "--truncated" => gkr_truncated = true,
            "--out" => {
                i += 1;
                out_path = args.get(i).cloned();
            }
            "--emit-diff-bytes" => {
                i += 1;
                emit_diff_bytes = args.get(i).cloned();
            }
            "--json" => json = true,
            _ => {}
        }
        i += 1;
    }

    let input_path = input_path.unwrap_or_else(|| die("missing --in <file>"));
    let raw = fs::read_to_string(&input_path).unwrap_or_else(|_| die("failed to read input"));
    let batch_json: JsonBatch =
        serde_json::from_str(&raw).unwrap_or_else(|_| die("invalid JSON input"));

    let batch = parse_batch(&batch_json).unwrap_or_else(|e| die(&e));
    let summary = validate_batch(&batch).unwrap_or_else(|e| die(&e));
    let diff_bytes = diff_bytes_from_updates(&batch.updates);
    let schema_id = state_transition_schema_id();

    let compiled = compile_state_transition_batch(&batch).unwrap_or_else(|e| die(&e));

    let config = ProverConfig {
        mode,
        gkr_truncated,
        chainid,
        contract_addr: verifier,
        ..Default::default()
    };
    let proof = prove_compiled(compiled, config).unwrap_or_else(|e| die(&format!("prove failed: {e:?}")));

    let commitment_tag = proof.artifact.commitment_tag;
    let point_tag = proof.artifact.point_tag;
    let artifact_tag = keccak256_concat(&[&commitment_tag, &point_tag]);
    let claim_bytes = proof.artifact.claim_word_bytes32();

    let calldata = if !proof.packed_gkr_calldata.is_empty() {
        hex_0x(&proof.packed_gkr_calldata)
    } else {
        hex_0x(&encode_packed_gkr_calldata(&proof))
    };

    let output = format!(
        "{{\n  \"schema_id\": \"{}\",\n  \"old_root\": \"{}\",\n  \"new_root\": \"{}\",\n  \"state_diff_root\": \"{}\",\n  \"diff_bytes_len\": {},\n  \"commitment_tag\": \"{}\",\n  \"point_tag\": \"{}\",\n  \"artifact_tag\": \"{}\",\n  \"claim\": \"{}\",\n  \"calldata\": \"{}\"\n}}",
        hex_0x(&schema_id),
        hex_0x(&summary.old_root),
        hex_0x(&summary.new_root),
        hex_0x(&summary.diff_root),
        diff_bytes.len(),
        hex_0x(&commitment_tag),
        hex_0x(&point_tag),
        hex_0x(&artifact_tag),
        hex_0x(&claim_bytes),
        calldata,
    );

    if let Some(path) = out_path {
        fs::write(&path, output.as_bytes()).unwrap_or_else(|_| die("failed to write output"));
    } else if json {
        println!("{output}");
    } else {
        println!("schema_id={}", hex_0x(&schema_id));
        println!("old_root={}", hex_0x(&summary.old_root));
        println!("new_root={}", hex_0x(&summary.new_root));
        println!("state_diff_root={}", hex_0x(&summary.diff_root));
        println!("diff_bytes_len={}", diff_bytes.len());
        println!("commitment_tag={}", hex_0x(&commitment_tag));
        println!("point_tag={}", hex_0x(&point_tag));
        println!("artifact_tag={}", hex_0x(&artifact_tag));
        println!("claim={}", hex_0x(&claim_bytes));
        println!("calldata={calldata}");
    }

    if let Some(path) = emit_diff_bytes {
        fs::write(&path, &diff_bytes).unwrap_or_else(|_| die("failed to write diff bytes"));
    }
}

fn parse_batch(batch: &JsonBatch) -> Result<StateTransitionBatch, String> {
    let old_root = parse_hex_32(&batch.old_root)?;
    let mut updates = Vec::with_capacity(batch.updates.len());
    for upd in &batch.updates {
        let key = parse_hex_32(&upd.key)?;
        let old_value = parse_hex_32(&upd.old_value)?;
        let new_value = parse_hex_32(&upd.new_value)?;
        let mut siblings = Vec::with_capacity(upd.proof.siblings.len());
        for s in &upd.proof.siblings {
            siblings.push(parse_hex_32(s)?);
        }
        if upd.proof.path_bits.len() != siblings.len() {
            return Err("path_bits length mismatch".to_string());
        }
        let proof = MerkleProof {
            siblings,
            path_bits: upd.proof.path_bits.clone(),
        };
        key_matches_path_bits(&key, &proof.path_bits)?;
        let (op, operand) = parse_op(&upd.op, &upd.operand, &new_value)?;
        updates.push(StateUpdate {
            key,
            old_value,
            new_value,
            proof,
            op,
            operand,
        });
    }
    Ok(StateTransitionBatch { old_root, updates })
}

fn print_help() {
    eprintln!("glyph_state_transition_prove \\");
    eprintln!("  --in <batch.json> \\");
    eprintln!("  [--chainid <u64> --verifier <0xaddr20>] \\");
    eprintln!("  [--mode fast|zk] [--truncated] [--out <file>] [--emit-diff-bytes <file>] [--json]");
    eprintln!();
    eprintln!("JSON schema notes:");
    eprintln!("  - key must be a 32-byte index value (little-endian u32 in bytes 0..4).");
    eprintln!("  - proof.path_bits must match the index bits (LSB first).");
    eprintln!("  - op: \"store\" or \"add\" (default: store).");
    eprintln!("  - operand: for store, must equal new_value. for add, delta (required).");
}

fn die(msg: &str) -> ! {
    eprintln!("error: {}", msg);
    std::process::exit(1);
}

fn parse_hex_32(raw: &str) -> Result<[u8; 32], String> {
    let raw = raw.strip_prefix("0x").unwrap_or(raw);
    let bytes = hex::decode(raw).map_err(|_| "invalid hex".to_string())?;
    if bytes.len() != 32 {
        return Err("expected 32-byte hex string".to_string());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_hex_20(raw: &str) -> Option<[u8; 20]> {
    let raw = raw.strip_prefix("0x").unwrap_or(raw);
    let bytes = hex::decode(raw).ok()?;
    if bytes.len() != 20 {
        return None;
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn hex_0x(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2 + 2);
    s.push_str("0x");
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn parse_op(
    op: &Option<String>,
    operand: &Option<String>,
    new_value: &[u8; 32],
) -> Result<(VmOpKind, [u8; 32]), String> {
    match op.as_deref().unwrap_or("store") {
        "store" => {
            if let Some(raw) = operand {
                let val = parse_hex_32(raw)?;
                if &val != new_value {
                    return Err("store operand must equal new_value".to_string());
                }
                Ok((VmOpKind::Store, val))
            } else {
                Ok((VmOpKind::Store, *new_value))
            }
        }
        "add" => {
            let delta = operand.as_ref().ok_or("add op requires operand")?;
            let val = parse_hex_32(delta)?;
            Ok((VmOpKind::Add, val))
        }
        _ => Err("invalid op (use store|add)".to_string()),
    }
}
