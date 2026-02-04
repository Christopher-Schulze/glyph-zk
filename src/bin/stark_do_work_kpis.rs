use std::env;
use std::time::Instant;

use glyph::adapters::{
    keccak256,
    statement_hash_from_bytes,
    vk_hash_from_bytes,
    AdapterFamily,
    SUB_ID_NONE,
};
use glyph::stark_adapter::verified_canonical_stark_receipts_to_glyph_artifact;
use glyph::stark_winterfell::{
    canonical_stark_receipt_from_upstream_do_work as canonical_receipt_f128,
    do_work_public_inputs_from_bytes as do_work_pub_inputs_f128,
    prove_do_work as prove_do_work_f128,
    prove_do_work_sha3 as prove_do_work_sha3_f128,
    seeded_do_work_receipts as seeded_do_work_receipts_f128,
    seeded_do_work_receipts_sha3 as seeded_do_work_receipts_sha3_f128,
    stark_receipt_digest,
    StarkUpstreamReceipt,
};
use glyph::stark_winterfell_f64::{
    canonical_stark_receipt_from_upstream_do_work as canonical_receipt_f64,
    do_work_public_inputs_from_bytes as do_work_pub_inputs_f64,
    prove_do_work_blake3 as prove_do_work_blake3_f64,
    prove_do_work_sha3 as prove_do_work_sha3_f64,
    public_inputs_bytes as public_inputs_bytes_f64,
    seeded_do_work_receipts_blake3 as seeded_do_work_receipts_blake3_f64,
    seeded_do_work_receipts_sha3 as seeded_do_work_receipts_sha3_f64,
    vk_params_bytes_canonical as vk_params_bytes_f64,
    vk_params_bytes_sha3_canonical as vk_params_bytes_sha3_f64,
};
use winterfell::math::StarkField;

#[cfg(unix)]
fn max_rss_bytes() -> u64 {
    use std::mem::MaybeUninit;
    let mut usage = MaybeUninit::<libc::rusage>::uninit();
    let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    if rc != 0 {
        return 0;
    }
    let usage = unsafe { usage.assume_init() };
    let rss = usage.ru_maxrss as u64;

    #[cfg(target_os = "linux")]
    {
        rss.saturating_mul(1024)
    }

    #[cfg(not(target_os = "linux"))]
    {
        rss
    }
}

#[cfg(not(unix))]
fn max_rss_bytes() -> u64 {
    0
}

fn parse_u128(s: &str) -> Option<u128> {
    if let Some(hex) = s.strip_prefix("0x") {
        u128::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u128>().ok()
    }
}

fn parse_usize(s: &str) -> Option<usize> {
    s.parse::<usize>().ok()
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut start: u128 = 3;
    let mut trace_length: usize = 1024;
    let mut statement: Option<Vec<u8>> = None;
    let mut json = false;
    let mut sha3 = false;
    let mut use_f64 = false;
    let mut seed: Option<Vec<u8>> = None;
    let mut receipts: usize = 1;
    let mut glyph_artifact = false;
    let mut report_id: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--start" => {
                i += 1;
                start = args
                    .get(i)
                    .and_then(|s| parse_u128(s))
                    .unwrap_or_else(|| die("invalid --start"));
            }
            "--trace-length" => {
                i += 1;
                trace_length = args
                    .get(i)
                    .and_then(|s| parse_usize(s))
                    .unwrap_or_else(|| die("invalid --trace-length"));
            }
            "--statement" => {
                i += 1;
                statement = args.get(i).map(|s| s.as_bytes().to_vec());
            }
            "--seed" => {
                i += 1;
                seed = args.get(i).map(|s| s.as_bytes().to_vec());
            }
            "--receipts" => {
                i += 1;
                receipts = args
                    .get(i)
                    .and_then(|s| parse_usize(s))
                    .unwrap_or_else(|| die("invalid --receipts"));
            }
            "--sha3" => {
                sha3 = true;
            }
            "--f64" => {
                use_f64 = true;
            }
            "--glyph-artifact" => {
                glyph_artifact = true;
            }
            "--json" => {
                json = true;
            }
            "--report-id" => {
                i += 1;
                report_id = args.get(i).map(|s| s.to_string());
            }
            "--help" | "-h" => {
                print_help();
                return;
            }
            _ => {}
        }
        i += 1;
    }

    if receipts == 0 {
        die("--receipts must be >= 1");
    }
    if receipts > 1 && seed.is_none() {
        die("--receipts > 1 requires --seed");
    }
    if glyph_artifact && seed.is_none() {
        die("--glyph-artifact requires --seed");
    }

    let start_u64 = if use_f64 {
        u64::try_from(start).unwrap_or_else(|_| die("--start must fit in u64 for --f64"))
    } else {
        0
    };

    let statement = statement.unwrap_or_else(|| {
        let tag = if use_f64 { "do_work_f64" } else { "do_work" };
        let hash_tag = if sha3 { "sha3" } else { "blake3" };
        if let Some(ref seed_bytes) = seed {
            format!(
                "{tag}_{hash_tag}_seeded({}, {}, {})",
                String::from_utf8_lossy(seed_bytes),
                trace_length,
                receipts
            )
            .into_bytes()
        } else if use_f64 {
            format!("{tag}_{hash_tag}({}, {})", start_u64, trace_length).into_bytes()
        } else {
            format!("{tag}_{hash_tag}({}, {})", start, trace_length).into_bytes()
        }
    });

    let t0 = Instant::now();
    let receipts_vec = if use_f64 {
        if sha3 {
            if let Some(ref seed_bytes) = seed {
                seeded_do_work_receipts_sha3_f64(seed_bytes, trace_length, receipts)
                    .unwrap_or_else(|e| die(&format!("sha3 receipts failed: {e}")))
            } else {
                let (proof, pub_inputs) = prove_do_work_sha3_f64(start_u64, trace_length)
                    .unwrap_or_else(|e| die(&format!("prove sha3 failed: {e}")));
                let trace_width = 1;
                vec![StarkUpstreamReceipt {
                    proof_bytes: proof.to_bytes(),
                    pub_inputs_bytes: public_inputs_bytes_f64(&pub_inputs),
                    vk_params_bytes: vk_params_bytes_sha3_f64(trace_width, trace_length, proof.options()),
                }]
            }
        } else if let Some(ref seed_bytes) = seed {
            seeded_do_work_receipts_blake3_f64(seed_bytes, trace_length, receipts)
                .unwrap_or_else(|e| die(&format!("blake3 receipts failed: {e}")))
        } else {
            let (proof, pub_inputs) = prove_do_work_blake3_f64(start_u64, trace_length)
                .unwrap_or_else(|e| die(&format!("prove blake3 failed: {e}")));
            let trace_width = 1;
            vec![StarkUpstreamReceipt {
                proof_bytes: proof.to_bytes(),
                pub_inputs_bytes: public_inputs_bytes_f64(&pub_inputs),
                vk_params_bytes: vk_params_bytes_f64(trace_width, trace_length, proof.options()),
            }]
        }
    } else if sha3 {
        if let Some(ref seed_bytes) = seed {
            seeded_do_work_receipts_sha3_f128(seed_bytes, trace_length, receipts)
                .unwrap_or_else(|e| die(&format!("sha3 receipts failed: {e}")))
        } else {
            let (proof, pub_inputs) = prove_do_work_sha3_f128(start, trace_length)
                .unwrap_or_else(|e| die(&format!("prove sha3 failed: {e}")));
            vec![StarkUpstreamReceipt::from_do_work_sha3_canonical(
                &proof,
                &pub_inputs,
                trace_length,
            )]
        }
    } else if let Some(ref seed_bytes) = seed {
        seeded_do_work_receipts_f128(seed_bytes, trace_length, receipts)
            .unwrap_or_else(|e| die(&format!("blake3 receipts failed: {e}")))
    } else {
        let (proof, pub_inputs) = prove_do_work_f128(start, trace_length)
            .unwrap_or_else(|e| die(&format!("prove blake3 failed: {e}")));
        vec![StarkUpstreamReceipt::from_do_work_canonical(
            &proof,
            &pub_inputs,
            trace_length,
        )]
    };
    let prove_ms = t0.elapsed().as_millis() as u64;

    let proof_bytes_total: u64 = receipts_vec.iter().map(|r| r.proof_bytes.len() as u64).sum();
    let pub_bytes_total: u64 = receipts_vec.iter().map(|r| r.pub_inputs_bytes.len() as u64).sum();
    let vk_params_bytes_total: u64 = receipts_vec.iter().map(|r| r.vk_params_bytes.len() as u64).sum();

    let receipt_digests: Vec<[u8; 32]> = receipts_vec.iter().map(stark_receipt_digest).collect();
    let mut canonical_receipt_digests: Vec<[u8; 32]> = Vec::new();
    let mut canonical_receipts = Vec::new();
    if sha3 || glyph_artifact {
        for (idx, receipt) in receipts_vec.iter().enumerate() {
            let canonical = if use_f64 {
                canonical_receipt_f64(receipt)
            } else {
                canonical_receipt_f128(receipt)
            }
            .unwrap_or_else(|e| die(&format!("canonical receipt failed for receipt[{idx}]: {e}")));
            canonical_receipt_digests.push(canonical.digest());
            canonical_receipts.push(canonical);
        }
    }

    let family = AdapterFamily::StarkGoldilocks;
    let vk_hash = vk_hash_from_bytes(family, SUB_ID_NONE, &receipts_vec[0].vk_params_bytes);
    let statement_hash = statement_hash_from_bytes(family, SUB_ID_NONE, &statement);
    let statement_bytes_hash = keccak256(&statement);

    let proof_hash = keccak256(&receipts_vec[0].proof_bytes);
    let pub_hash = keccak256(&receipts_vec[0].pub_inputs_bytes);

    let max_rss_bytes = max_rss_bytes();
    let receipt_digest = receipt_digests[0];
    let mut starts: Vec<u128> = Vec::new();
    if seed.is_some() {
        for (idx, receipt) in receipts_vec.iter().enumerate() {
            let start = if use_f64 {
                do_work_pub_inputs_f64(&receipt.pub_inputs_bytes)
                    .unwrap_or_else(|| die(&format!("receipt[{idx}] invalid pub_inputs bytes")))
                    .start
                    .as_int() as u128
            } else {
                do_work_pub_inputs_f128(&receipt.pub_inputs_bytes)
                    .unwrap_or_else(|| die(&format!("receipt[{idx}] invalid pub_inputs bytes")))
                    .start
                    .as_int() as u128
            };
            starts.push(start);
        }
    }

    let glyph_artifact_out = if glyph_artifact {
        let seed_bytes = match seed.as_ref() {
            Some(bytes) => bytes,
            None => die("--glyph-artifact requires --seed"),
        };
        Some(
            verified_canonical_stark_receipts_to_glyph_artifact(seed_bytes, &canonical_receipts)
                .unwrap_or_else(|e| die(&format!("glyph artifact derivation failed: {e}"))),
        )
    } else {
        None
    };

    if !json {
        if let Some(ref rid) = report_id {
            println!("report_id={}", rid);
        }
        println!("start={}", start);
        println!("trace_length={}", trace_length);
        println!("f64={}", use_f64);
        println!("sha3={}", sha3);
        println!("receipts={}", receipts);
        if let Some(ref seed_bytes) = seed {
            println!("seed={}", String::from_utf8_lossy(seed_bytes));
        }
        println!("prove_ms={}", prove_ms);
        println!("max_rss_bytes={}", max_rss_bytes);
        println!("proof_bytes_total={}", proof_bytes_total);
        println!("pub_bytes_total={}", pub_bytes_total);
        println!("vk_params_bytes_total={}", vk_params_bytes_total);
        for (idx, digest) in receipt_digests.iter().enumerate() {
            println!("receipt_digest[{}]=0x{}", idx, hex::encode(digest));
        }
        if !canonical_receipt_digests.is_empty() {
            for (idx, digest) in canonical_receipt_digests.iter().enumerate() {
                println!("canonical_receipt_digest[{}]=0x{}", idx, hex::encode(digest));
            }
        }
        println!("vk_hash=0x{}", hex::encode(vk_hash));
        println!("statement_hash=0x{}", hex::encode(statement_hash));
        println!("statement_bytes_hash=0x{}", hex::encode(statement_bytes_hash));
        println!("proof_hash=0x{}", hex::encode(proof_hash));
        println!("pub_hash=0x{}", hex::encode(pub_hash));
        if let Some((commitment_tag, point_tag, claim_u128)) = glyph_artifact_out {
            println!("commitment_tag=0x{}", hex::encode(commitment_tag));
            println!("point_tag=0x{}", hex::encode(point_tag));
            println!("claim128=0x{}", hex::encode(claim_u128.to_be_bytes()));
        }
        return;
    }

    let statement_utf8 = String::from_utf8_lossy(&statement);

    println!("{{");
    if let Some(ref rid) = report_id {
        println!("  \"workload_id\": \"{}\",", json_escape(rid));
    } else {
        println!("  \"workload_id\": null,");
    }
    println!("  \"family\": \"stark-goldilocks\",");
    println!("  \"start\": {},", start);
    println!("  \"trace_length\": {},", trace_length);
    println!("  \"f64\": {},", if use_f64 { "true" } else { "false" });
    println!("  \"sha3\": {},", if sha3 { "true" } else { "false" });
    println!("  \"hash\": \"{}\",", if sha3 { "sha3" } else { "blake3" });
    println!("  \"receipts\": {},", receipts);
    if let Some(ref seed_bytes) = seed {
        println!("  \"seed\": \"{}\",", json_escape(&String::from_utf8_lossy(seed_bytes)));
    } else {
        println!("  \"seed\": null,");
    }
    println!("  \"statement\": \"{}\",", json_escape(&statement_utf8));
    println!("  \"prove_ms\": {},", prove_ms);
    println!("  \"max_rss_bytes\": {},", max_rss_bytes);
    println!("  \"proof_bytes_total\": {},", proof_bytes_total);
    println!("  \"pub_bytes_total\": {},", pub_bytes_total);
    println!("  \"vk_params_bytes_total\": {},", vk_params_bytes_total);
    print!("  \"receipt_digests\": [");
    for (i, digest) in receipt_digests.iter().enumerate() {
        if i > 0 {
            print!(", ");
        }
        print!("\"0x{}\"", hex::encode(digest));
    }
    println!("],");
    if !canonical_receipt_digests.is_empty() {
        print!("  \"canonical_receipt_digests\": [");
        for (i, digest) in canonical_receipt_digests.iter().enumerate() {
            if i > 0 {
                print!(", ");
            }
            print!("\"0x{}\"", hex::encode(digest));
        }
        println!("],");
    }
    if !starts.is_empty() {
        print!("  \"starts\": [");
        for (i, s) in starts.iter().enumerate() {
            if i > 0 {
                print!(", ");
            }
            print!("{}", s);
        }
        println!("],");
    }
    println!("  \"receipt_digest\": \"0x{}\",", hex::encode(receipt_digest));
    println!("  \"vk_hash\": \"0x{}\",", hex::encode(vk_hash));
    println!("  \"statement_hash\": \"0x{}\",", hex::encode(statement_hash));
    println!("  \"statement_bytes_hash\": \"0x{}\",", hex::encode(statement_bytes_hash));
    println!("  \"proof_hash\": \"0x{}\",", hex::encode(proof_hash));
    println!("  \"pub_hash\": \"0x{}\",", hex::encode(pub_hash));
    if let Some((commitment_tag, point_tag, claim_u128)) = glyph_artifact_out {
        println!("  \"commitment_tag\": \"0x{}\",", hex::encode(commitment_tag));
        println!("  \"point_tag\": \"0x{}\",", hex::encode(point_tag));
        println!("  \"claim128\": \"0x{}\"", hex::encode(claim_u128.to_be_bytes()));
        println!("}}");
    } else {
        println!("  \"commitment_tag\": null,");
        println!("  \"point_tag\": null,");
        println!("  \"claim128\": null");
        println!("}}");
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(ch),
        }
    }
    out
}

fn die(msg: &str) -> ! {
    eprintln!("error: {}", msg);
    std::process::exit(1);
}

fn print_help() {
    eprintln!("stark_do_work_kpis \\");
    eprintln!("  [--start <u128|0x..>] \\");
    eprintln!("  [--trace-length <usize>] \\");
    eprintln!("  [--statement <string>] \\");
    eprintln!("  [--sha3] (default is blake3) \\");
    eprintln!("  [--f64] (use Winterfell F64 receipts) \\");
    eprintln!("  [--seed <string>] \\");
    eprintln!("  [--receipts <usize>] \\");
    eprintln!("  [--glyph-artifact] (requires --sha3 and --seed) \\");
    eprintln!("  [--report-id <string>] \\");
    eprintln!("  [--json]");
}
