use std::fs;

use glyph::adapters::keccak256_concat;
use glyph::glyph_core::{encode_packed_gkr_calldata, prove_compiled, ProverConfig, ProverMode};
use glyph::state_diff_merkle::{compile_state_diff_merkle, state_diff_merkle_root, state_diff_schema_id};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 1 || args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return;
    }

    let mut bytes_path: Option<String> = None;
    let mut chainid: Option<u64> = None;
    let mut verifier: Option<[u8; 20]> = None;
    let mut mode = ProverMode::ZkMode;
    let mut gkr_truncated = false;
    let mut out_path: Option<String> = None;
    let mut json = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--bytes" => {
                i += 1;
                bytes_path = args.get(i).cloned();
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
            "--json" => json = true,
            _ => {}
        }
        i += 1;
    }

    let bytes_path = bytes_path.unwrap_or_else(|| die("missing --bytes"));
    let bytes = fs::read(&bytes_path).unwrap_or_else(|_| die("failed to read bytes"));

    let (root, leaves) = state_diff_merkle_root(&bytes);
    let schema_id = state_diff_schema_id();
    let compiled = compile_state_diff_merkle(&bytes);

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
        "{{\n  \"schema_id\": \"{}\",\n  \"state_diff_root\": \"{}\",\n  \"leaf_count\": {},\n  \"commitment_tag\": \"{}\",\n  \"point_tag\": \"{}\",\n  \"artifact_tag\": \"{}\",\n  \"claim\": \"{}\",\n  \"calldata\": \"{}\"\n}}",
        hex_0x(&schema_id),
        hex_0x(&root),
        leaves.len(),
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
        println!("state_diff_root={}", hex_0x(&root));
        println!("leaf_count={}", leaves.len());
        println!("commitment_tag={}", hex_0x(&commitment_tag));
        println!("point_tag={}", hex_0x(&point_tag));
        println!("artifact_tag={}", hex_0x(&artifact_tag));
        println!("claim={}", hex_0x(&claim_bytes));
        println!("calldata={calldata}");
    }
}

fn print_help() {
    eprintln!("glyph_state_diff_prove \\");
    eprintln!("  --bytes <file> \\");
    eprintln!("  [--chainid <u64> --verifier <0xaddr20>] \\");
    eprintln!("  [--mode fast|zk] [--truncated] [--out <file>] [--json]");
}

fn die(msg: &str) -> ! {
    eprintln!("error: {}", msg);
    std::process::exit(1);
}

fn hex_0x(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2 + 2);
    s.push_str("0x");
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
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
