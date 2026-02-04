use std::fs;

use glyph::state_transition_vm::{GlyphVm, VmOp};
use serde::Deserialize;

#[derive(Deserialize)]
struct JsonOp {
    op: String,
    key: String,
    value: Option<String>,
    delta: Option<String>,
}

#[derive(Deserialize)]
struct JsonExec {
    depth: usize,
    ops: Vec<JsonOp>,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 1 || args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return;
    }

    let mut input_path: Option<String> = None;
    let mut out_path: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--in" => {
                i += 1;
                input_path = args.get(i).cloned();
            }
            "--out" => {
                i += 1;
                out_path = args.get(i).cloned();
            }
            _ => {}
        }
        i += 1;
    }

    let input_path = input_path.unwrap_or_else(|| die("missing --in <file>"));
    let raw = fs::read_to_string(&input_path).unwrap_or_else(|_| die("failed to read input"));
    let exec: JsonExec = serde_json::from_str(&raw).unwrap_or_else(|_| die("invalid JSON input"));

    let mut vm = GlyphVm::new(exec.depth).unwrap_or_else(|e| die(&e));
    let mut ops = Vec::with_capacity(exec.ops.len());
    for op in exec.ops {
        let key = parse_hex_32(&op.key).unwrap_or_else(|e| die(&e));
        match op.op.as_str() {
            "store" => {
                let value_raw = op.value.as_ref().unwrap_or_else(|| die("store op requires value"));
                let value = parse_hex_32(value_raw).unwrap_or_else(|e| die(&e));
                ops.push(VmOp::Store { key, value });
            }
            "add" => {
                let delta_raw = op.delta.as_ref().unwrap_or_else(|| die("add op requires delta"));
                let delta = parse_hex_32(delta_raw).unwrap_or_else(|e| die(&e));
                ops.push(VmOp::Add { key, delta });
            }
            _ => die("invalid op (use store|add)"),
        }
    }

    let (_batch, trace) = vm.execute_with_trace(&ops).unwrap_or_else(|e| die(&e));

    let mut out = String::new();
    out.push_str("{\n");
    out.push_str(&format!("  \"depth\": {},\n", exec.depth));
    out.push_str(&format!("  \"old_root\": \"{}\",\n", hex_0x(&trace.old_root)));
    out.push_str(&format!("  \"new_root\": \"{}\",\n", hex_0x(&trace.new_root)));
    out.push_str("  \"updates\": [\n");

    for (idx, step) in trace.steps.iter().enumerate() {
        let op_str = match step.op {
            VmOp::Store { .. } => "store",
            VmOp::Add { .. } => "add",
        };
        let update = &step.update;
        out.push_str("    {\n");
        out.push_str(&format!("      \"op\": \"{}\",\n", op_str));
        out.push_str(&format!("      \"operand\": \"{}\",\n", hex_0x(&update.operand)));
        out.push_str(&format!("      \"key\": \"{}\",\n", hex_0x(&update.key)));
        out.push_str(&format!("      \"old_value\": \"{}\",\n", hex_0x(&update.old_value)));
        out.push_str(&format!("      \"new_value\": \"{}\",\n", hex_0x(&update.new_value)));
        out.push_str("      \"proof\": {\n");
        out.push_str("        \"siblings\": [");
        for (i, sib) in update.proof.siblings.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            out.push_str(&format!("\"{}\"", hex_0x(sib)));
        }
        out.push_str("],\n");
        out.push_str("        \"path_bits\": [");
        for (i, bit) in update.proof.path_bits.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            out.push_str(&format!("{}", bit));
        }
        out.push_str("]\n");
        out.push_str("      }\n");
        out.push_str("    }");
        if idx + 1 != trace.steps.len() {
            out.push(',');
        }
        out.push('\n');
    }

    out.push_str("  ]\n");
    out.push_str("}\n");

    if let Some(path) = out_path {
        fs::write(&path, out.as_bytes()).unwrap_or_else(|_| die("failed to write output"));
    } else {
        println!("{out}");
    }
}

fn print_help() {
    eprintln!("glyph_state_transition_execute \\");
    eprintln!("  --in <ops.json> \\");
    eprintln!("  [--out <file>]");
    eprintln!();
    eprintln!("JSON schema:");
    eprintln!("  {{ depth: <1..=32>, ops: [ {{ op: store|add, key, value?, delta? }} ] }}");
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

fn hex_0x(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2 + 2);
    s.push_str("0x");
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
