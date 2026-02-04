use std::env;


use glyph::adapters::keccak256;
use glyph::glyph_gkr::{
    encode_artifact_poly_bound_packed_calldata_be, encode_artifact_poly_bound_packed_calldata_be_with_tag,
    encode_packed_calldata_be, encode_packed_calldata_be_truncated, encode_statement_bound_packed_calldata_be,
    encode_stmt_poly_bound_packed_calldata_be, prove_packed, prove_packed_artifact_poly_sumcheck,
    prove_packed_artifact_poly_sumcheck_with_tag, prove_packed_statement, prove_packed_stmt_poly_sumcheck,
    prove_packed_toy_sumcheck, prove_packed_toy_sumcheck_folded, prove_packed_toy_sumcheck_folded_statement,
    prove_packed_toy_sumcheck_statement,
    gkr_bytes32_to_u128, gkr_canonicalize_u128, gkr_from_bytes32_mod_order,
};
use glyph::stark_winterfell::{build_do_work_trace, default_proof_options, vk_params_bytes_canonical, DoWorkPublicInputs};
use winterfell::math::fields::f128::BaseElement;

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut seed: Vec<u8> = b"glyph-default-seed".to_vec();
    let mut rounds: usize = 5;
    let mut json = false;
    let mut words = false;
    let mut truncated = false;
    let mut truncated_override: Option<bool> = None;
    let mut bind = false;
    let mut stmt_poly = false;
    let mut artifact_poly = false;
    let mut hash_merge = false;
    let mut toy_sumcheck = false;
    let mut toy_fold_instances: usize = 1;
    let mut do_work_statement = false;
    let mut do_work_start: u128 = 3;
    let mut do_work_steps: usize = 1024;
    let mut chainid: Option<u64> = None;
    let mut verifier_addr: Option<[u8; 20]> = None;
    let mut statement: Option<[u8; 32]> = None;
    let mut commitment_tag: Option<[u8; 32]> = None;
    let mut point_tag: Option<[u8; 32]> = None;
    let mut artifact_tag: Option<[u8; 32]> = None;
    let mut claim_u128: Option<[u8; 32]> = None;
    let mut hash_left: Option<[u8; 32]> = None;
    let mut hash_right: Option<[u8; 32]> = None;
    let mut hash_digest: Option<[u8; 32]> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--seed" => {
                i += 1;
                seed = args
                    .get(i)
                    .map(|s| s.as_bytes().to_vec())
                    .unwrap_or_else(|| die("missing --seed value"));
            }
            "--rounds" => {
                i += 1;
                rounds = args
                    .get(i)
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap_or_else(|| die("invalid --rounds value"));
            }
            "--json" => json = true,
            "--words" => words = true,
            "--truncated" => {
                truncated = true;
                truncated_override = Some(true);
            }
            "--full" => {
                truncated = false;
                truncated_override = Some(false);
            }
            "--bind" => bind = true,
            "--stmt-poly" => stmt_poly = true,
            "--artifact-poly" => artifact_poly = true,
            "--hash-merge" => {
                hash_merge = true;
            }
            "--toy-sumcheck" => toy_sumcheck = true,
            "--toy-fold" => {
                i += 1;
                toy_fold_instances = args
                    .get(i)
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap_or_else(|| die("invalid --toy-fold value"));
            }
            "--do-work-statement" => do_work_statement = true,
            "--do-work-start" => {
                i += 1;
                do_work_start = args
                    .get(i)
                    .and_then(|s| s.parse::<u128>().ok())
                    .unwrap_or_else(|| die("invalid --do-work-start value"));
            }
            "--do-work-steps" => {
                i += 1;
                do_work_steps = args
                    .get(i)
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap_or_else(|| die("invalid --do-work-steps value"));
            }
            "--chainid" => {
                i += 1;
                chainid = Some(
                    args.get(i)
                        .and_then(|s| s.parse::<u64>().ok())
                        .unwrap_or_else(|| die("invalid --chainid value")),
                );
            }
            "--verifier" => {
                i += 1;
                verifier_addr = Some(parse_addr20(
                    args.get(i).map(|s| s.as_str()).unwrap_or(""),
                ));
            }
            "--statement" => {
                i += 1;
                statement = Some(parse_bytes32(
                    args.get(i).map(|s| s.as_str()).unwrap_or(""),
                ));
            }
            "--commitment" => {
                i += 1;
                commitment_tag = Some(parse_bytes32(
                    args.get(i).map(|s| s.as_str()).unwrap_or(""),
                ));
            }
            "--point" => {
                i += 1;
                point_tag = Some(parse_bytes32(
                    args.get(i).map(|s| s.as_str()).unwrap_or(""),
                ));
            }
            "--artifact-tag" => {
                i += 1;
                artifact_tag = Some(parse_bytes32(
                    args.get(i).map(|s| s.as_str()).unwrap_or(""),
                ));
            }
            "--claim" => {
                i += 1;
                claim_u128 = Some(parse_bytes32(
                    args.get(i).map(|s| s.as_str()).unwrap_or(""),
                ));
            }
            "--help" | "-h" => {
                print_help();
                return;
            }
            _ => {}
        }
        i += 1;
    }

    if hash_merge {
        use glyph::adapter_ir::{kernel_id, AdapterIrOp, AdapterIr, ADAPTER_IR_VERSION};

        if commitment_tag.is_some() || point_tag.is_some() || claim_u128.is_some() {
            die("--hash-merge derives --commitment/--point/--claim automatically (do not pass them manually)");
        }

        let mut seed_input = Vec::with_capacity(seed.len() + 1);
        seed_input.extend_from_slice(&seed);
        seed_input.push(0);
        let left = keccak256(&seed_input);
        let last = seed_input.len() - 1;
        seed_input[last] = 1;
        let right = keccak256(&seed_input);
        let mut digest_input = [0u8; 64];
        digest_input[..32].copy_from_slice(&left);
        digest_input[32..].copy_from_slice(&right);
        let digest = keccak256(&digest_input);

        let ir = AdapterIr {
            version: ADAPTER_IR_VERSION,
            ops: vec![AdapterIrOp {
                kernel_id: kernel_id::HASH_SHA3_MERGE,
                args: vec![],
            }],
        };
        let ir_bytes = ir.encode();
        let (commitment, point, claim_u128_value) =
            glyph::adapter_ir::derive_glyph_artifact_from_hash_ir(&ir_bytes, &left, &right)
                .unwrap_or_else(|e| die(&format!("hash merge failed: {e}")));

        commitment_tag = Some(commitment);
        point_tag = Some(point);
        let mut claim_bytes = [0u8; 32];
        claim_bytes[16..32].copy_from_slice(&claim_u128_value.to_be_bytes());
        claim_u128 = Some(claim_bytes);
        artifact_poly = true;

        hash_left = Some(left);
        hash_right = Some(right);
        hash_digest = Some(digest);
    }

    if toy_sumcheck && rounds > 7 {
        die("--toy-sumcheck only supports --rounds <= 7 (8-ary enumeration)");
    }
    if toy_fold_instances == 0 {
        die("--toy-fold must be >= 1");
    }
    if toy_fold_instances > 1 && !toy_sumcheck {
        die("--toy-fold requires --toy-sumcheck");
    }
    if artifact_poly && (stmt_poly || toy_sumcheck || do_work_statement || bind || statement.is_some()) {
        die("--artifact-poly cannot be combined with --stmt-poly, --bind, --toy-sumcheck, --do-work-statement, or --statement");
    }
    if stmt_poly && (toy_sumcheck || do_work_statement) {
        die("--stmt-poly cannot be combined with --toy-sumcheck or --do-work-statement");
    }
    if do_work_statement && statement.is_some() {
        die("cannot combine --do-work-statement with --statement");
    }
    if artifact_tag.is_some() && (commitment_tag.is_some() || point_tag.is_some()) {
        die("--artifact-tag cannot be combined with --commitment or --point");
    }
    if artifact_poly && artifact_tag.is_none() && (commitment_tag.is_none() || point_tag.is_none()) {
        die("--artifact-poly requires --commitment and --point, or --artifact-tag");
    }
    if artifact_poly && claim_u128.is_none() {
        die("--artifact-poly requires --claim");
    }
    if stmt_poly && statement.is_none() {
        die("missing --statement for --stmt-poly");
    }
    if !stmt_poly && (do_work_statement || statement.is_some()) && !bind {
        die("--do-work-statement/--statement requires --bind (statement is encoded only in the statement-bound layout)");
    }
    if do_work_statement && do_work_steps == 0 {
        die("--do-work-steps must be > 0");
    }
    if truncated_override.is_none() && artifact_poly {
        truncated = true;
    }

    let derived_statement = if do_work_statement {
        let start = BaseElement::new(do_work_start);
        let trace = build_do_work_trace(start, do_work_steps);
        let result = trace.get(0, do_work_steps - 1);
        let pub_inputs = DoWorkPublicInputs { start, result };

        let options = default_proof_options();
        let vk_bytes = vk_params_bytes_canonical(1, do_work_steps, &options);
        let pub_bytes = glyph::stark_winterfell::public_inputs_bytes(&pub_inputs);

        let mut buf = Vec::with_capacity(32 + vk_bytes.len() + pub_bytes.len());
        buf.extend_from_slice(b"GLYPH_DO_WORK_STMT");
        buf.extend_from_slice(&vk_bytes);
        buf.extend_from_slice(&pub_bytes);
        let digest = keccak256(&buf);
        Some(gkr_from_bytes32_mod_order(&digest))
    } else {
        None
    };

    let calldata = if artifact_poly {
        let chainid = chainid.unwrap_or_else(|| die("missing --chainid for --artifact-poly"));
        let verifier = verifier_addr.unwrap_or_else(|| die("missing --verifier for --artifact-poly"));
        let claim_bytes = claim_u128.unwrap_or_else(|| die("missing --claim for --artifact-poly"));
        let claim_raw = gkr_bytes32_to_u128(&claim_bytes)
            .unwrap_or_else(|| die("--claim must fit in 128 bits (upper 16 bytes must be zero)"));
        let claim = gkr_canonicalize_u128(claim_raw);
        if let Some(tag) = artifact_tag.as_ref() {
            let proof = prove_packed_artifact_poly_sumcheck_with_tag(tag, &claim, chainid, verifier, rounds);
            encode_artifact_poly_bound_packed_calldata_be_with_tag(&proof, tag, &claim, truncated)
        } else {
            let commitment = commitment_tag.unwrap_or_else(|| die("missing --commitment for --artifact-poly"));
            let point = point_tag.unwrap_or_else(|| die("missing --point for --artifact-poly"));
            let proof = prove_packed_artifact_poly_sumcheck(&commitment, &point, &claim, chainid, verifier, rounds);
            encode_artifact_poly_bound_packed_calldata_be(
                &proof,
                chainid,
                verifier,
                &commitment,
                &point,
                &claim,
                truncated,
            )
        }
    } else if stmt_poly {
        let chainid = chainid.unwrap_or_else(|| die("missing --chainid for --stmt-poly"));
        let verifier = verifier_addr.unwrap_or_else(|| die("missing --verifier for --stmt-poly"));
        let st = statement.unwrap_or_else(|| die("missing --statement for --stmt-poly"));
        let st_raw = gkr_bytes32_to_u128(&st)
            .unwrap_or_else(|| die("--statement must fit in 128 bits (upper 16 bytes must be zero)"));
        let st_val = gkr_canonicalize_u128(st_raw);
        let proof = prove_packed_stmt_poly_sumcheck(&st_val, rounds);
        encode_stmt_poly_bound_packed_calldata_be(&proof, chainid, verifier, &st_val, truncated)
    } else if bind {
        let chainid = chainid.unwrap_or_else(|| die("missing --chainid for --bind"));
        let verifier = verifier_addr.unwrap_or_else(|| die("missing --verifier for --bind"));
        let st_val_opt: Option<u128> = if let Some(st) = statement {
            let st_raw = gkr_bytes32_to_u128(&st)
                .unwrap_or_else(|| die("--statement must fit in 128 bits (upper 16 bytes must be zero)"));
            Some(gkr_canonicalize_u128(st_raw))
        } else {
            derived_statement
        };
        if let Some(st_val) = st_val_opt {
            let proof = if toy_sumcheck && toy_fold_instances > 1 {
                prove_packed_toy_sumcheck_folded_statement(&seed, rounds, toy_fold_instances, &st_val)
            } else if toy_sumcheck {
                prove_packed_toy_sumcheck_statement(&seed, rounds, &st_val)
            } else {
                prove_packed_statement(&seed, rounds, &st_val)
            };
            encode_statement_bound_packed_calldata_be(&proof, chainid, verifier, &st_val, truncated)
        } else {
            die("--bind now requires --statement (legacy bound layout removed)")
        }
    } else {
        let proof = if toy_sumcheck && toy_fold_instances > 1 {
            prove_packed_toy_sumcheck_folded(&seed, rounds, toy_fold_instances)
        } else if toy_sumcheck {
            prove_packed_toy_sumcheck(&seed, rounds)
        } else {
            prove_packed(&seed, rounds)
        };
        if truncated {
            encode_packed_calldata_be_truncated(&proof)
        } else {
            encode_packed_calldata_be(&proof)
        }
    };

    let is_bound = bind || stmt_poly || artifact_poly;

    if json {
        println!("{{");
        println!("  \"rounds\": {},", rounds);
        println!("  \"truncated\": {},", if truncated { "true" } else { "false" });
        println!("  \"bound\": {},", if is_bound { "true" } else { "false" });
        println!(
            "  \"binding_version\": {},",
            if artifact_poly {
                4
            } else if stmt_poly {
                3
            } else if bind && (statement.is_some() || do_work_statement) {
                2
            } else if bind {
                1
            } else {
                0
            }
        );
        if artifact_poly {
            let claim = match claim_u128 {
                Some(claim) => claim,
                None => die("claim must be set for --artifact-poly"),
            };
            println!("  \"claim\": \"0x{}\",", hex::encode(claim));
            if let Some(tag) = artifact_tag.as_ref() {
                println!("  \"artifact_tag\": \"0x{}\",", hex::encode(tag));
            } else {
                let commitment = match commitment_tag {
                    Some(commitment) => commitment,
                    None => die("commitment_tag must be set for --artifact-poly"),
                };
                let point = match point_tag {
                    Some(point) => point,
                    None => die("point_tag must be set for --artifact-poly"),
                };
                println!("  \"commitment_tag\": \"0x{}\",", hex::encode(commitment));
                println!("  \"point_tag\": \"0x{}\",", hex::encode(point));
            }
        }
        if let (Some(left), Some(right), Some(digest)) = (hash_left, hash_right, hash_digest) {
            println!("  \"hash_left\": \"0x{}\",", hex::encode(left));
            println!("  \"hash_right\": \"0x{}\",", hex::encode(right));
            println!("  \"hash_digest\": \"0x{}\",", hex::encode(digest));
        }
        println!("  \"calldata_len\": {},", calldata.len());
        println!("  \"calldata\": \"0x{}\"", hex::encode(&calldata));
        println!("}}");
        return;
    }

    println!("rounds={}", rounds);
    println!("truncated={}", truncated);
    println!("bound={}", is_bound);
    println!("calldata_len={}", calldata.len());
    println!("calldata=0x{}", hex::encode(&calldata));

    if words {
        println!();
        println!("words_u256_dec:");
        for (idx, chunk) in calldata.chunks_exact(32).enumerate() {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(chunk);
            let n = num_bigint::BigUint::from_bytes_be(&bytes);
            println!("{}: {}", idx, n);
        }
    }
}

fn print_help() {
    eprintln!("gen-gkr-proof \\");
    eprintln!("  [--seed <string>] \\");
    eprintln!("  [--rounds <usize>] \\");
    eprintln!("  [--hash-merge] (implies --artifact-poly) \\");
    eprintln!("  [--toy-sumcheck] \\");
    eprintln!("  [--toy-fold <usize>] (requires --toy-sumcheck) \\");
    eprintln!("  [--truncated] [--full] \\");
    eprintln!("    - artifact-poly defaults to truncated unless --full is set");
    eprintln!("  [--stmt-poly --statement <0xbytes32>] (requires --chainid and --verifier) \\");
    eprintln!("  [--artifact-poly --claim <0xbytes32> (--commitment <0xbytes32> --point <0xbytes32> | --artifact-tag <0xbytes32>)] (requires --chainid and --verifier) \\");
    eprintln!("  [--statement <0xbytes32>] (requires --bind) \\");
    eprintln!("  [--do-work-statement [--do-work-start <u128>] [--do-work-steps <usize>]] (requires --bind) \\");
    eprintln!("  [--bind --chainid <u64> --verifier <0xaddr20>] \\");
    eprintln!("  [--json] [--words]");
}

fn die(msg: &str) -> ! {
    eprintln!("error: {}", msg);
    std::process::exit(1);
}

fn parse_addr20(s: &str) -> [u8; 20] {
    let raw = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(raw).unwrap_or_else(|_| die("invalid --verifier hex"));
    if bytes.len() != 20 {
        die("invalid --verifier length (expected 20 bytes)");
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    out
}

fn parse_bytes32(s: &str) -> [u8; 32] {
    let raw = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(raw).unwrap_or_else(|_| die("invalid bytes32 hex"));
    if bytes.len() != 32 {
        die("invalid bytes32 length (expected 32 bytes)");
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}
