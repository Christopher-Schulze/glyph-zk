use std::time::Instant;

use glyph::glyph_ir_compiler::embed_fq_limbs;
use glyph::state_transition_vm::{
    compile_state_transition_batch, validate_batch, GlyphVm, StateTransitionBatch, VmOp,
};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 1 || args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return;
    }

    let mut ops: usize = 1024;
    let mut depth: usize = 16;
    let mut iters: usize = 5;
    let mut warmup: usize = 1;
    let mut add_percent: u8 = 50;
    let mut seed: u64 = 1;
    let mut compile = true;
    let mut json = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--ops" => {
                i += 1;
                ops = args
                    .get(i)
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or_else(|| die("invalid --ops"));
            }
            "--depth" => {
                i += 1;
                depth = args
                    .get(i)
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or_else(|| die("invalid --depth"));
            }
            "--iters" => {
                i += 1;
                iters = args
                    .get(i)
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or_else(|| die("invalid --iters"));
            }
            "--warmup" => {
                i += 1;
                warmup = args
                    .get(i)
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or_else(|| die("invalid --warmup"));
            }
            "--add-percent" => {
                i += 1;
                add_percent = args
                    .get(i)
                    .and_then(|v| v.parse::<u8>().ok())
                    .unwrap_or_else(|| die("invalid --add-percent"));
            }
            "--seed" => {
                i += 1;
                seed = args
                    .get(i)
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or_else(|| die("invalid --seed"));
            }
            "--no-compile" => compile = false,
            "--json" => json = true,
            _ => {}
        }
        i += 1;
    }

    if ops == 0 {
        die("ops must be > 0");
    }
    if depth == 0 || depth > 32 {
        die("depth must be in 1..=32");
    }
    if add_percent > 100 {
        die("add-percent must be 0..=100");
    }

    let op_list = build_ops(ops, depth, add_percent, seed);
    let mask = if depth == 32 { u32::MAX } else { (1u32 << depth) - 1 };
    let case = format!(
        "ops={},depth={},mask=0x{:08x},add_pct={},compile={}",
        ops, depth, mask, add_percent, compile
    );

    for _ in 0..warmup {
        let mut vm = GlyphVm::new(depth).unwrap_or_else(|e| die(&e));
        let batch = vm.execute(&op_list).unwrap_or_else(|e| die(&e));
        let _ = validate_batch(&batch).unwrap_or_else(|e| die(&e));
        if compile {
            let _ = compile_state_transition_batch(&batch).unwrap_or_else(|e| die(&e));
        }
    }

    let mut exec_total_ms = 0.0;
    let mut compile_total_ms = 0.0;
    let mut last_batch: Option<StateTransitionBatch> = None;
    for _ in 0..iters {
        let mut vm = GlyphVm::new(depth).unwrap_or_else(|e| die(&e));
        let start_exec = Instant::now();
        let batch = vm.execute(&op_list).unwrap_or_else(|e| die(&e));
        exec_total_ms += start_exec.elapsed().as_secs_f64() * 1000.0;

        if compile {
            let start_compile = Instant::now();
            let _ = compile_state_transition_batch(&batch).unwrap_or_else(|e| die(&e));
            compile_total_ms += start_compile.elapsed().as_secs_f64() * 1000.0;
        }
        last_batch = Some(batch);
    }

    let last_batch = last_batch.unwrap_or_else(|| die("missing batch"));
    let summary = validate_batch(&last_batch).unwrap_or_else(|e| die(&e));
    let expected_inputs = {
        let mut v = Vec::with_capacity(12);
        v.extend_from_slice(&embed_fq_limbs(&summary.old_root));
        v.extend_from_slice(&embed_fq_limbs(&summary.new_root));
        v.extend_from_slice(&embed_fq_limbs(&summary.diff_root));
        v.len()
    };

    let exec_avg_ms = if iters == 0 { 0.0 } else { exec_total_ms / iters as f64 };
    let compile_avg_ms = if iters == 0 { 0.0 } else { compile_total_ms / iters as f64 };
    let total_avg_ms = exec_avg_ms + compile_avg_ms;

    if json {
        println!("{{");
        println!("  \"case\": \"{}\",", case);
        println!("  \"ops\": {},", ops);
        println!("  \"depth\": {},", depth);
        println!("  \"add_percent\": {},", add_percent);
        println!("  \"iters\": {},", iters);
        println!("  \"warmup\": {},", warmup);
        println!("  \"compile\": {},", compile);
        println!("  \"exec_avg_ms\": {:.6},", exec_avg_ms);
        println!("  \"compile_avg_ms\": {:.6},", compile_avg_ms);
        println!("  \"total_avg_ms\": {:.6},", total_avg_ms);
        println!("  \"public_inputs_len\": {},", expected_inputs);
        println!("  \"old_root\": \"{}\",", hex_0x(&summary.old_root));
        println!("  \"new_root\": \"{}\",", hex_0x(&summary.new_root));
        println!("  \"diff_root\": \"{}\"", hex_0x(&summary.diff_root));
        println!("}}");
        return;
    }

    println!("case={}", case);
    println!("ops={}", ops);
    println!("depth={}", depth);
    println!("add_percent={}", add_percent);
    println!("iters={}", iters);
    println!("warmup={}", warmup);
    println!("compile={}", compile);
    println!("exec_avg_ms={:.6}", exec_avg_ms);
    println!("compile_avg_ms={:.6}", compile_avg_ms);
    println!("total_avg_ms={:.6}", total_avg_ms);
    println!("public_inputs_len={}", expected_inputs);
    println!("old_root={}", hex_0x(&summary.old_root));
    println!("new_root={}", hex_0x(&summary.new_root));
    println!("diff_root={}", hex_0x(&summary.diff_root));
}

fn build_ops(ops: usize, depth: usize, add_percent: u8, seed: u64) -> Vec<VmOp> {
    let mask = if depth == 32 { u32::MAX } else { (1u32 << depth) - 1 };
    let mut rng = XorShift64::new(seed);
    let mut out = Vec::with_capacity(ops);
    for _ in 0..ops {
        let idx = (rng.next_u64() as u32) & mask;
        let key = index_bytes(idx);
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        if add_percent > 0 && (rng.next_u64() % 100) < add_percent as u64 {
            if bytes == [0u8; 32] {
                bytes[31] = 1;
            }
            out.push(VmOp::Add { key, delta: bytes });
        } else {
            out.push(VmOp::Store { key, value: bytes });
        }
    }
    out
}

fn print_help() {
    eprintln!("bench_state_transition_vm \\");
    eprintln!("  --ops <n> --depth <n> [--iters <n>] [--warmup <n>] \\");
    eprintln!("  [--add-percent <n>] [--seed <n>] [--no-compile] [--json]");
}

fn die(msg: &str) -> ! {
    eprintln!("error: {}", msg);
    std::process::exit(1);
}

fn index_bytes(index: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0..4].copy_from_slice(&index.to_le_bytes());
    out
}

fn hex_0x(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(66);
    s.push_str("0x");
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        let state = if seed == 0 { 0x9e3779b97f4a7c15 } else { seed };
        Self { state }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn fill_bytes(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            let len = chunk.len();
            chunk.copy_from_slice(&v[..len]);
        }
    }
}
