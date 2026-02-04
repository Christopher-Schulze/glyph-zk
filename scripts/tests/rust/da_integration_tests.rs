use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn live_enabled() -> bool {
    env::var("GLYPH_DA_LIVE").map(|v| v == "1").unwrap_or(false)
}

fn require_env(name: &str) -> Option<String> {
    match env::var(name) {
        Ok(val) if !val.trim().is_empty() => Some(val),
        _ => None,
    }
}

fn has_blob_fetch_env() -> bool {
    require_env("BLOB_RETRIEVER_URL_TEMPLATE").is_some()
        || require_env("BLOB_BEACON_API_URL").is_some()
}

fn has_arweave_submit_env() -> bool {
    require_env("ARWEAVE_CMD").is_some() || require_env("ARWEAVE_JWK_PATH").is_some()
}

fn has_eigenda_submit_env() -> bool {
    require_env("EIGENDA_CMD").is_some() || require_env("EIGENDA_PROXY_URL").is_some()
}

fn has_eigenda_fetch_env() -> bool {
    require_env("EIGENDA_RETRIEVER_URL_TEMPLATE").is_some()
        || require_env("EIGENDA_PROXY_URL").is_some()
}

fn skip(msg: &str) {
    eprintln!("skip: {}", msg);
}

fn temp_dir(label: &str) -> PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let dir = env::temp_dir().join(format!("glyph-da-{}-{}", label, now));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn write_artifact(path: &Path) {
    let mut bytes = Vec::with_capacity(96);
    for i in 0..96u8 {
        bytes.push(i.wrapping_mul(3).wrapping_add(1));
    }
    fs::write(path, &bytes).expect("write artifact");
}

fn glyph_da_bin() -> PathBuf {
    if let Ok(val) = env::var("GLYPH_DA_BIN") {
        if !val.trim().is_empty() {
            let path = PathBuf::from(val);
            if path.is_relative() {
                let root = env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
                return PathBuf::from(root).join(path);
            }
            return path;
        }
    }

    if let Ok(val) = env::var("CARGO_BIN_EXE_glyph_da") {
        if !val.trim().is_empty() {
            return PathBuf::from(val);
        }
    }

    let root = env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let fallback = PathBuf::from(root).join("target").join("debug").join("glyph_da");
    if fallback.exists() {
        return fallback;
    }
    panic!("glyph_da binary not found; set GLYPH_DA_BIN or build target/debug/glyph_da");
}

fn run_cmd(mut cmd: Command) -> String {
    let output = cmd.output().expect("run command");
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!("command failed: {}", stderr.trim());
    }
    String::from_utf8(output.stdout).expect("stdout utf8").trim().to_string()
}

fn run_profile(profile: &str, providers: &[&str]) {
    let bin = glyph_da_bin();
    let dir = temp_dir(profile);
    let artifact_path = dir.join("artifact.bin");
    write_artifact(&artifact_path);

    let out_dir = dir.join("out");
    let mut submit_cmd = Command::new(&bin);
    submit_cmd
        .arg("submit")
        .arg("--profile")
        .arg(profile)
        .arg("--mode")
        .arg("minimal")
        .arg("--artifact")
        .arg(&artifact_path)
        .arg("--out-dir")
        .arg(&out_dir);
    let envelope_path = run_cmd(submit_cmd);

    assert!(!envelope_path.is_empty(), "envelope path empty");
    let envelope_path = PathBuf::from(envelope_path);

    for provider in providers {
        let fetched = out_dir.join(format!("payload.{}.bin", provider));
        let mut fetch_cmd = Command::new(&bin);
        fetch_cmd
            .arg("fetch")
            .arg("--provider")
            .arg(provider)
            .arg("--envelope")
            .arg(&envelope_path)
            .arg("--out")
            .arg(&fetched);
        let payload_path = run_cmd(fetch_cmd);
        let payload_path = PathBuf::from(payload_path);

        let mut verify_cmd = Command::new(&bin);
        verify_cmd
            .arg("verify")
            .arg("--envelope")
            .arg(&envelope_path)
            .arg("--payload")
            .arg(&payload_path);
        let verify_out = run_cmd(verify_cmd);
        assert_eq!(verify_out, "ok");
    }
}

#[test]
fn test_da_blob_only_live() {
    if !live_enabled() {
        skip("GLYPH_DA_LIVE not set");
        return;
    }
    if require_env("BLOB_RPC_URL").is_none()
        || require_env("BLOB_PRIVATE_KEY").is_none()
        || !has_blob_fetch_env()
    {
        skip("missing blob envs");
        return;
    }
    run_profile("blob-only", &["blob"]);
}

#[test]
fn test_da_blob_arweave_live() {
    if !live_enabled() {
        skip("GLYPH_DA_LIVE not set");
        return;
    }
    if require_env("BLOB_RPC_URL").is_none()
        || require_env("BLOB_PRIVATE_KEY").is_none()
        || !has_blob_fetch_env()
        || !has_arweave_submit_env()
        || require_env("ARWEAVE_GATEWAY_URL").is_none()
    {
        skip("missing blob or arweave envs");
        return;
    }
    run_profile("blob-arweave", &["blob", "arweave"]);
}

#[test]
fn test_da_blob_eigenda_arweave_live() {
    if !live_enabled() {
        skip("GLYPH_DA_LIVE not set");
        return;
    }
    if require_env("BLOB_RPC_URL").is_none()
        || require_env("BLOB_PRIVATE_KEY").is_none()
        || !has_blob_fetch_env()
        || !has_arweave_submit_env()
        || require_env("ARWEAVE_GATEWAY_URL").is_none()
        || !has_eigenda_submit_env()
        || !has_eigenda_fetch_env()
    {
        skip("missing blob, eigenda, or arweave envs");
        return;
    }
    run_profile("blob-eigenda-arweave", &["blob", "eigenda", "arweave"]);
}
