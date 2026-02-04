use sp1_sdk::{HashableKey, Prover, ProverClient, SP1Stdin};

const SP1_RECEIPT_TAG: &[u8] = b"GLYPH_SP1_RECEIPT";
const SP1_PROOF_GROTH16: u8 = 0x01;
const SP1_PROOF_PLONK: u8 = 0x02;

#[derive(Clone, Copy)]
enum ProofMode {
    Groth16,
    Plonk,
}

struct Config {
    elf_path: String,
    out_path: String,
    mode: ProofMode,
    stdin_hex: Option<String>,
    stdin_file: Option<String>,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let cfg = parse_args()?;
    let elf = std::fs::read(&cfg.elf_path)
        .map_err(|e| format!("failed to read elf '{}': {e}", cfg.elf_path))?;
    let stdin_bytes = match (&cfg.stdin_hex, &cfg.stdin_file) {
        (Some(_), Some(_)) => {
            return Err("use only one of --stdin-hex or --stdin-file".to_string());
        }
        (Some(hex), None) => Some(decode_hex_arg(hex)?),
        (None, Some(path)) => Some(
            std::fs::read(path).map_err(|e| format!("failed to read stdin file '{path}': {e}"))?,
        ),
        (None, None) => None,
    };
    let stdin = match stdin_bytes {
        Some(bytes) => SP1Stdin::from(bytes.as_slice()),
        None => SP1Stdin::new(),
    };

    let client = ProverClient::builder().cpu().build();
    let (pk, vk) = client.setup(&elf);
    let proof = match cfg.mode {
        ProofMode::Groth16 => client
            .prove(&pk, &stdin)
            .groth16()
            .run()
            .map_err(|e| format!("groth16 prove failed: {e}"))?,
        ProofMode::Plonk => client
            .prove(&pk, &stdin)
            .plonk()
            .run()
            .map_err(|e| format!("plonk prove failed: {e}"))?,
    };
    client
        .verify(&proof, &vk)
        .map_err(|e| format!("proof verify failed: {e}"))?;

    let vkey_hash = vk.bytes32();
    let public_inputs = proof.public_values.to_vec();
    let proof_bytes = proof.bytes();
    let receipt_bytes = encode_sp1_receipt(cfg.mode, vkey_hash.as_bytes(), &public_inputs, &proof_bytes);
    let payload = format!("receipt_hex={}\n", hex::encode(receipt_bytes));
    std::fs::write(&cfg.out_path, payload)
        .map_err(|e| format!("failed to write output '{}': {e}", cfg.out_path))?;
    Ok(())
}

fn encode_sp1_receipt(mode: ProofMode, vkey_hash: &[u8], public_inputs: &[u8], proof_bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        SP1_RECEIPT_TAG.len()
            + 1
            + 2
            + vkey_hash.len()
            + 4
            + public_inputs.len()
            + 4
            + proof_bytes.len(),
    );
    out.extend_from_slice(SP1_RECEIPT_TAG);
    out.push(match mode {
        ProofMode::Groth16 => SP1_PROOF_GROTH16,
        ProofMode::Plonk => SP1_PROOF_PLONK,
    });
    out.extend_from_slice(&(vkey_hash.len() as u16).to_be_bytes());
    out.extend_from_slice(vkey_hash);
    out.extend_from_slice(&(public_inputs.len() as u32).to_be_bytes());
    out.extend_from_slice(public_inputs);
    out.extend_from_slice(&(proof_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(proof_bytes);
    out
}

fn decode_hex_arg(value: &str) -> Result<Vec<u8>, String> {
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    hex::decode(trimmed).map_err(|e| format!("stdin hex decode failed: {e}"))
}

fn parse_args() -> Result<Config, String> {
    let mut elf_path = None;
    let mut out_path = None;
    let mut mode = None;
    let mut stdin_hex = None;
    let mut stdin_file = None;

    let mut args = std::env::args();
    let _ = args.next();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--elf" => {
                elf_path = Some(next_arg(&mut args, "--elf")?);
            }
            "--out" => {
                out_path = Some(next_arg(&mut args, "--out")?);
            }
            "--mode" => {
                let value = next_arg(&mut args, "--mode")?;
                mode = Some(parse_mode(&value)?);
            }
            "--stdin-hex" => {
                stdin_hex = Some(next_arg(&mut args, "--stdin-hex")?);
            }
            "--stdin-file" => {
                stdin_file = Some(next_arg(&mut args, "--stdin-file")?);
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => {
                return Err(format!("unknown argument: {other}"));
            }
        }
    }

    Ok(Config {
        elf_path: elf_path.ok_or_else(|| "missing --elf".to_string())?,
        out_path: out_path.ok_or_else(|| "missing --out".to_string())?,
        mode: mode.ok_or_else(|| "missing --mode".to_string())?,
        stdin_hex,
        stdin_file,
    })
}

fn parse_mode(value: &str) -> Result<ProofMode, String> {
    match value {
        "groth16" => Ok(ProofMode::Groth16),
        "plonk" => Ok(ProofMode::Plonk),
        other => Err(format!("unsupported mode: {other}")),
    }
}

fn next_arg(args: &mut std::env::Args, flag: &str) -> Result<String, String> {
    args.next().ok_or_else(|| format!("missing value for {flag}"))
}

fn print_usage() {
    eprintln!(
        "Usage: sp1_fixture_gen --elf <path> --mode <groth16|plonk> --out <path> [--stdin-hex <hex> | --stdin-file <path>]"
    );
}
