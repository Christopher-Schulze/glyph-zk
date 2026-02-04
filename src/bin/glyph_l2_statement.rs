use glyph::l2_statement::{
    claim_from_statement_hash, statement_hash_extended, statement_hash_minimal, tags_for_statement,
};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 1 || args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print_help();
        return;
    }

    let mut chainid: Option<u64> = None;
    let mut contract_addr: Option<[u8; 20]> = None;
    let mut old_root: Option<[u8; 32]> = None;
    let mut new_root: Option<[u8; 32]> = None;
    let mut da_commitment: Option<[u8; 32]> = None;
    let mut batch_id: Option<u64> = None;
    let mut extra_commitment: Option<[u8; 32]> = None;
    let mut extra_schema_id: Option<[u8; 32]> = None;
    let mut json = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--chainid" => {
                i += 1;
                chainid = Some(parse_u64(args.get(i)));
            }
            "--contract" => {
                i += 1;
                contract_addr = Some(parse_addr20(args.get(i)));
            }
            "--old-root" => {
                i += 1;
                old_root = Some(parse_bytes32(args.get(i)));
            }
            "--new-root" => {
                i += 1;
                new_root = Some(parse_bytes32(args.get(i)));
            }
            "--da" => {
                i += 1;
                da_commitment = Some(parse_bytes32(args.get(i)));
            }
            "--batch-id" => {
                i += 1;
                batch_id = Some(parse_u64(args.get(i)));
            }
            "--extra-commitment" => {
                i += 1;
                extra_commitment = Some(parse_bytes32(args.get(i)));
            }
            "--extra-schema-id" => {
                i += 1;
                extra_schema_id = Some(parse_bytes32(args.get(i)));
            }
            "--json" => json = true,
            _ => {}
        }
        i += 1;
    }

    let chainid = chainid.unwrap_or_else(|| die("missing --chainid"));
    let contract_addr = contract_addr.unwrap_or_else(|| die("missing --contract"));
    let old_root = old_root.unwrap_or_else(|| die("missing --old-root"));
    let new_root = new_root.unwrap_or_else(|| die("missing --new-root"));
    let da_commitment = da_commitment.unwrap_or_else(|| die("missing --da"));
    let batch_id = batch_id.unwrap_or_else(|| die("missing --batch-id"));

    let statement_hash = if extra_commitment.is_some() || extra_schema_id.is_some() {
        let extra_commitment =
            extra_commitment.unwrap_or_else(|| die("missing --extra-commitment"));
        let extra_schema_id =
            extra_schema_id.unwrap_or_else(|| die("missing --extra-schema-id"));
        statement_hash_extended(
            chainid,
            contract_addr,
            old_root,
            new_root,
            da_commitment,
            batch_id,
            extra_commitment,
            extra_schema_id,
        )
    } else {
        statement_hash_minimal(
            chainid,
            contract_addr,
            old_root,
            new_root,
            da_commitment,
            batch_id,
        )
    };

    let tags = tags_for_statement(statement_hash);
    let claim = claim_from_statement_hash(statement_hash);

    if json {
        println!("{{");
        println!("  \"statement_hash\": \"0x{}\",", hex::encode(tags.statement_hash));
        println!("  \"commitment_tag\": \"0x{}\",", hex::encode(tags.commitment_tag));
        println!("  \"point_tag\": \"0x{}\",", hex::encode(tags.point_tag));
        println!("  \"artifact_tag\": \"0x{}\",", hex::encode(tags.artifact_tag));
        println!("  \"claim\": \"0x{}\"", hex::encode(claim));
        println!("}}");
        return;
    }

    println!("statement_hash=0x{}", hex::encode(tags.statement_hash));
    println!("commitment_tag=0x{}", hex::encode(tags.commitment_tag));
    println!("point_tag=0x{}", hex::encode(tags.point_tag));
    println!("artifact_tag=0x{}", hex::encode(tags.artifact_tag));
    println!("claim=0x{}", hex::encode(claim));
}

fn print_help() {
    eprintln!("glyph_l2_statement \\");
    eprintln!("  --chainid <u64> \\");
    eprintln!("  --contract <0xaddr20> \\");
    eprintln!("  --old-root <0xbytes32> \\");
    eprintln!("  --new-root <0xbytes32> \\");
    eprintln!("  --da <0xbytes32> \\");
    eprintln!("  --batch-id <u64> \\");
    eprintln!("  [--extra-commitment <0xbytes32>] \\");
    eprintln!("  [--extra-schema-id <0xbytes32>] \\");
    eprintln!("  [--json]");
}

fn die(msg: &str) -> ! {
    eprintln!("error: {}", msg);
    std::process::exit(1);
}

fn parse_u64(value: Option<&String>) -> u64 {
    value
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or_else(|| die("invalid numeric value"))
}

fn parse_addr20(value: Option<&String>) -> [u8; 20] {
    let raw = value.unwrap_or_else(|| die("missing address")).as_str();
    let raw = raw.strip_prefix("0x").unwrap_or(raw);
    let bytes = hex::decode(raw).unwrap_or_else(|_| die("invalid address hex"));
    if bytes.len() != 20 {
        die("invalid address length (expected 20 bytes)");
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    out
}

fn parse_bytes32(value: Option<&String>) -> [u8; 32] {
    let raw = value.unwrap_or_else(|| die("missing bytes32")).as_str();
    let raw = raw.strip_prefix("0x").unwrap_or(raw);
    let bytes = hex::decode(raw).unwrap_or_else(|_| die("invalid bytes32 hex"));
    if bytes.len() != 32 {
        die("invalid bytes32 length (expected 32 bytes)");
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}
