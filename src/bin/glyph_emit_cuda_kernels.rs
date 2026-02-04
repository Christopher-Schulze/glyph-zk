#[cfg(not(feature = "cuda"))]
fn main() {
    eprintln!("glyph_emit_cuda_kernels requires the 'cuda' feature");
    std::process::exit(1);
}

#[cfg(feature = "cuda")]
fn main() {
    use std::env;
    use std::fs;
    use std::path::PathBuf;

    fn die(msg: &str) -> ! {
        eprintln!("error: {msg}");
        std::process::exit(1);
    }

    let out = env::args()
        .nth(1)
        .unwrap_or_else(|| "target/glyph_cuda_kernels.cu".to_string());
    let path = PathBuf::from(&out);
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Err(err) = fs::write(&path, glyph::glyph_field_simd::glyph_cuda_kernels_src()) {
        die(&format!("write glyph cuda kernels failed: {err}"));
    }
    println!("wrote {}", path.display());
}
