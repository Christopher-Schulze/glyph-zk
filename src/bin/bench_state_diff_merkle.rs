use std::fs;
use std::time::Instant;

use glyph::state_diff_merkle::state_diff_merkle_root;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 1 || args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return;
    }

    let mut bytes_path: Option<String> = None;
    let mut iters: usize = 10;
    let mut warmup: usize = 2;
    let mut json = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--bytes" => {
                i += 1;
                bytes_path = args.get(i).cloned();
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
            "--json" => json = true,
            _ => {}
        }
        i += 1;
    }

    let bytes_path = bytes_path.unwrap_or_else(|| die("missing --bytes"));
    let bytes = fs::read(&bytes_path).unwrap_or_else(|_| die("failed to read bytes"));

    for _ in 0..warmup {
        let _ = state_diff_merkle_root(&bytes);
    }

    let start = Instant::now();
    let mut last_root = [0u8; 32];
    let mut last_leaf_count = 0usize;
    for _ in 0..iters {
        let (root, leaves) = state_diff_merkle_root(&bytes);
        last_root = root;
        last_leaf_count = leaves.len();
    }
    let elapsed = start.elapsed();
    let total_ms = elapsed.as_secs_f64() * 1000.0;
    let per_iter_ms = if iters == 0 {
        0.0
    } else {
        total_ms / iters as f64
    };

    if json {
        println!("{{");
        println!("  \"bytes\": {},", bytes.len());
        println!("  \"leaf_count\": {},", last_leaf_count);
        println!("  \"iters\": {},", iters);
        println!("  \"warmup\": {},", warmup);
        println!("  \"total_ms\": {:.6},", total_ms);
        println!("  \"per_iter_ms\": {:.6},", per_iter_ms);
        println!("  \"root\": \"{}\"", hex_0x(&last_root));
        println!("}}");
        return;
    }

    println!("bytes={}", bytes.len());
    println!("leaf_count={}", last_leaf_count);
    println!("iters={}", iters);
    println!("warmup={}", warmup);
    println!("total_ms={:.6}", total_ms);
    println!("per_iter_ms={:.6}", per_iter_ms);
    println!("root={}", hex_0x(&last_root));
}

fn print_help() {
    eprintln!("bench_state_diff_merkle \\");
    eprintln!("  --bytes <file> \\");
    eprintln!("  [--iters <n>] [--warmup <n>] [--json]");
}

fn die(msg: &str) -> ! {
    eprintln!("error: {}", msg);
    std::process::exit(1);
}

fn hex_0x(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(66);
    s.push_str("0x");
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
