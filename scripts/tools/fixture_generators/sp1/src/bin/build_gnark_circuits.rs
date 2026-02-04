use sp1_core_executor::SP1Context;
use sp1_core_machine::io::SP1Stdin;
use sp1_prover::build::{
    build_groth16_bn254_artifacts, build_plonk_bn254_artifacts,
    groth16_bn254_artifacts_dev_dir,
};
use sp1_prover::components::CpuProverComponents;
use sp1_prover::SP1Prover;
use sp1_stark::SP1ProverOpts;
use std::path::PathBuf;

#[derive(Clone, Copy)]
enum BuildMode {
    Groth16,
    Plonk,
    Both,
}

struct Config {
    elf_path: String,
    build_dir: Option<String>,
    mode: BuildMode,
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

    let prover: SP1Prover<CpuProverComponents> = SP1Prover::new();
    let opts = SP1ProverOpts::auto();
    let context = SP1Context::default();

    let (_pk, pk_d, program, vk) = prover.setup(&elf);
    let core_proof = prover
        .prove_core(&pk_d, program, &stdin, opts, context)
        .map_err(|e| format!("prove core failed: {e}"))?;
    let compressed = prover
        .compress(&vk, core_proof, vec![], opts)
        .map_err(|e| format!("compress failed: {e}"))?;
    let shrink = prover
        .shrink(compressed, opts)
        .map_err(|e| format!("shrink failed: {e}"))?;
    let wrapped = prover
        .wrap_bn254(shrink, opts)
        .map_err(|e| format!("wrap bn254 failed: {e}"))?;

    let build_dir = cfg
        .build_dir
        .map(PathBuf::from)
        .unwrap_or_else(groth16_bn254_artifacts_dev_dir);

    match cfg.mode {
        BuildMode::Groth16 => {
            build_groth16_bn254_artifacts(&wrapped.vk, &wrapped.proof, &build_dir);
        }
        BuildMode::Plonk => {
            build_plonk_bn254_artifacts(&wrapped.vk, &wrapped.proof, &build_dir);
        }
        BuildMode::Both => {
            build_groth16_bn254_artifacts(&wrapped.vk, &wrapped.proof, &build_dir);
            build_plonk_bn254_artifacts(&wrapped.vk, &wrapped.proof, &build_dir);
        }
    }

    Ok(())
}

fn decode_hex_arg(value: &str) -> Result<Vec<u8>, String> {
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    hex::decode(trimmed).map_err(|e| format!("stdin hex decode failed: {e}"))
}

fn parse_args() -> Result<Config, String> {
    let mut elf_path = None;
    let mut build_dir = None;
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
            "--build-dir" => {
                build_dir = Some(next_arg(&mut args, "--build-dir")?);
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
        build_dir,
        mode: mode.unwrap_or(BuildMode::Both),
        stdin_hex,
        stdin_file,
    })
}

fn parse_mode(value: &str) -> Result<BuildMode, String> {
    match value {
        "groth16" => Ok(BuildMode::Groth16),
        "plonk" => Ok(BuildMode::Plonk),
        "both" => Ok(BuildMode::Both),
        other => Err(format!("unsupported mode: {other}")),
    }
}

fn next_arg(args: &mut std::env::Args, flag: &str) -> Result<String, String> {
    args.next().ok_or_else(|| format!("missing value for {flag}"))
}

fn print_usage() {
    eprintln!(
        "Usage: sp1_build_gnark_circuits --elf <path> [--build-dir <path>] [--mode <groth16|plonk|both>] [--stdin-hex <hex> | --stdin-file <path>]"
    );
}
