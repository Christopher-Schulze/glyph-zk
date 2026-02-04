use std::fs;
use std::time::Instant;

use glyph::glyph_core::{prove_compiled, ProverConfig, ProverMode};
use glyph::state_diff_merkle::compile_state_diff_merkle;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 1 || args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return;
    }

    let mut bytes_path: Option<String> = None;
    let mut mode = ProverMode::FastMode;
    let mut warmup: usize = 1;
    let mut json = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--bytes" => {
                i += 1;
                bytes_path = args.get(i).cloned();
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
            "--warmup" => {
                i += 1;
                warmup = args
                    .get(i)
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or_else(|| die("invalid --warmup"));
            }
            "--json" => json = true,
            _ => {}
        }
        i += 1;
    }

    let bytes_path = bytes_path.unwrap_or_else(|| die("missing --bytes"));
    let bytes = fs::read(&bytes_path).unwrap_or_else(|_| die("failed to read bytes"));

    for _ in 0..warmup {
        let compiled = compile_state_diff_merkle(&bytes);
        let config = ProverConfig {
            mode,
            ..Default::default()
        };
        let _ = prove_compiled(compiled, config)
            .unwrap_or_else(|e| die(&format!("prove failed: {e:?}")));
    }

    let compile_start = Instant::now();
    let compiled = compile_state_diff_merkle(&bytes);
    let compile_ms = compile_start.elapsed().as_secs_f64() * 1000.0;

    let config = ProverConfig {
        mode,
        ..Default::default()
    };
    let prove_start = Instant::now();
    let proof = prove_compiled(compiled, config).unwrap_or_else(|e| die(&format!("prove failed: {e:?}")));
    let prove_ms = prove_start.elapsed().as_secs_f64() * 1000.0;

    if json {
        println!("{{");
        println!("  \"bytes\": {},", bytes.len());
        println!("  \"mode\": \"{}\",", if matches!(mode, ProverMode::FastMode) { "fast" } else { "zk" });
        println!("  \"warmup\": {},", warmup);
        println!("  \"compile_ms\": {:.6},", compile_ms);
        println!("  \"prove_ms\": {:.6},", prove_ms);
        println!("  \"total_ms\": {:.6},", compile_ms + prove_ms);
        println!("  \"proof_bytes\": {}", proof.packed_gkr_calldata.len());
        println!("}}");
        return;
    }

    println!("bytes={}", bytes.len());
    println!("mode={}", if matches!(mode, ProverMode::FastMode) { "fast" } else { "zk" });
    println!("warmup={}", warmup);
    println!("compile_ms={:.6}", compile_ms);
    println!("prove_ms={:.6}", prove_ms);
    println!("total_ms={:.6}", compile_ms + prove_ms);
    println!("proof_bytes={}", proof.packed_gkr_calldata.len());
}

fn print_help() {
    eprintln!("bench_state_diff_compile_prove \\");
    eprintln!("  --bytes <file> \\");
    eprintln!("  [--mode fast|zk] [--warmup <n>] [--json]");
}

fn die(msg: &str) -> ! {
    eprintln!("error: {}", msg);
    std::process::exit(1);
}
