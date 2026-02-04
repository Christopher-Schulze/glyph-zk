use sp1_build::{execute_build_program, BuildArgs};
use std::path::PathBuf;

fn main() -> Result<(), String> {
    let program_dir = PathBuf::from("guest");
    let out_dir = program_dir.join("elf");
    if let Err(err) = std::fs::create_dir_all(&out_dir) {
        return Err(format!("failed to create guest elf dir: {err}"));
    }

    let mut args = BuildArgs::default();
    args.docker = true;
    args.packages = vec!["sp1-fixture-guest".to_string()];
    args.binaries = vec!["sp1-fixture-guest".to_string()];
    args.output_directory = Some(out_dir.to_string_lossy().to_string());
    args.elf_name = Some("sp1_fixture_guest".to_string());

    execute_build_program(&args, Some(program_dir))
        .map_err(|e| format!("sp1 guest build failed: {e}"))?;

    println!("guest_elf=guest/elf/sp1_fixture_guest");
    Ok(())
}
