use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use glyph::da::{
    extract_artifact_tag, hex_0x, keccak256, DaCommitment, DaEnvelope, DaPayload, DaPayloadParts,
    DaProfile, DaProvider, PayloadMode,
};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

fn die(msg: &str) -> ! {
    eprintln!("ERROR: {}", msg);
    std::process::exit(1)
}

fn read_file(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|err| die(&format!("read failed for {}: {}", path.display(), err)))
}

fn write_file(path: &Path, data: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap_or_else(|err| {
            die(&format!("create dir failed for {}: {}", parent.display(), err))
        });
    }
    fs::write(path, data)
        .unwrap_or_else(|err| die(&format!("write failed for {}: {}", path.display(), err)));
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn default_out_dir(profile: &DaProfile) -> PathBuf {
    let ts = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
        .replace([':', '-'], "");
    project_root()
        .join("scripts")
        .join("out")
        .join("da")
        .join(profile.as_str())
        .join(ts)
}

fn parse_meta(values: &[String]) -> BTreeMap<String, serde_json::Value> {
    let mut map = BTreeMap::new();
    for item in values {
        if let Some((k, v)) = item.split_once('=') {
            map.insert(k.to_string(), serde_json::Value::String(v.to_string()));
        }
    }
    map
}

fn build_payload(
    artifact_path: &Path,
    proof_path: Option<&Path>,
    vk_path: Option<&Path>,
    mode: PayloadMode,
) -> (DaPayload, String, String, Option<String>, Option<String>) {
    let artifact_bytes = read_file(artifact_path);
    let artifact_tag = extract_artifact_tag(&artifact_bytes)
        .unwrap_or_else(|err| die(&format!("artifact tag parse failed: {}", err)));
    let artifact_hash = hex_0x(&keccak256(&artifact_bytes));

    let proof_bytes = proof_path.map(read_file);
    let vk_bytes = vk_path.map(read_file);

    if mode == PayloadMode::Full && (proof_bytes.is_none() || vk_bytes.is_none()) {
        die("full mode requires --proof and --vk");
    }

    let proof_hash = proof_bytes.as_ref().map(|b| hex_0x(&keccak256(b)));
    let vk_hash = vk_bytes.as_ref().map(|b| hex_0x(&keccak256(b)));

    let payload = DaPayload {
        version: 1,
        parts: DaPayloadParts {
            artifact_bytes,
            upstream_proof_bytes: proof_bytes,
            vk_bytes,
        },
    };

    (
        payload,
        hex_0x(&artifact_tag),
        artifact_hash,
        proof_hash,
        vk_hash,
    )
}

fn run_script(script: &Path, envs: &[(&str, &str)]) -> serde_json::Value {
    let mut cmd = Command::new("bash");
    cmd.arg(script);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.env("DA_PROJECT_ROOT", project_root());
    let output = cmd.output().unwrap_or_else(|err| {
        die(&format!("failed to run {}: {}", script.display(), err))
    });
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        die(&format!(
            "script failed: {}",
            stderr.trim()
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&stdout).unwrap_or_else(|err| {
        die(&format!(
            "failed to parse script output as json: {}",
            err
        ))
    })
}

fn submit_provider(provider: DaProvider, payload_path: &Path) -> DaCommitment {
    let root = project_root();
    let script = match provider {
        DaProvider::Blob => root.join("scripts/da/submit_blob.sh"),
        DaProvider::Arweave => root.join("scripts/da/submit_arweave.sh"),
        DaProvider::EigenDa => root.join("scripts/da/submit_eigenda.sh"),
    };
    if !script.exists() {
        die(&format!("missing script: {}", script.display()));
    }

    let payload_path_str = payload_path.to_string_lossy();
    let envs = [
        ("DA_PAYLOAD_PATH", payload_path_str.as_ref()),
        ("DA_PROVIDER", provider.as_str()),
    ];
    let value = run_script(&script, &envs);

    match provider {
        DaProvider::Blob => {
            let tx_hash = value
                .get("tx_hash")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let versioned = value
                .get("versioned_hashes")
                .and_then(|v| v.as_array())
                .unwrap_or(&Vec::new())
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>();
            let chain_id = value.get("chain_id").and_then(|v| v.as_u64());
            if tx_hash.is_empty() || versioned.is_empty() {
                die("blob provider output missing tx_hash or versioned_hashes");
            }
            DaCommitment::Blob {
                tx_hash,
                versioned_hashes: versioned,
                chain_id,
            }
        }
        DaProvider::Arweave => {
            let tx_id = value
                .get("tx_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let gateway_url = value.get("gateway_url").and_then(|v| v.as_str()).map(|s| s.to_string());
            if tx_id.is_empty() {
                die("arweave provider output missing tx_id");
            }
            DaCommitment::Arweave { tx_id, gateway_url }
        }
        DaProvider::EigenDa => {
            let blob_key = value
                .get("blob_key")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let certificate_hash = value
                .get("certificate_hash")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let request_id = value
                .get("request_id")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let status = value
                .get("status")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let disperser_url = value.get("disperser_url").and_then(|v| v.as_str()).map(|s| s.to_string());
            let has_blob_key = blob_key.as_ref().map(|s| !s.is_empty()).unwrap_or(false);
            let has_ready = has_blob_key
                && certificate_hash.as_ref().map(|s| !s.is_empty()).unwrap_or(false);
            let has_pending = request_id.as_ref().map(|s| !s.is_empty()).unwrap_or(false);
            if !has_ready && !has_pending && !has_blob_key {
                die("eigenda provider output missing blob_key, certificate_hash, or request_id");
            }
            DaCommitment::EigenDa {
                blob_key,
                certificate_hash,
                request_id,
                status,
                disperser_url,
            }
        }
    }
}

fn fetch_provider(provider: DaProvider, envelope_path: &Path, out_path: &Path) -> PathBuf {
    let root = project_root();
    let script = match provider {
        DaProvider::Blob => root.join("scripts/da/fetch_blob.sh"),
        DaProvider::Arweave => root.join("scripts/da/fetch_arweave.sh"),
        DaProvider::EigenDa => root.join("scripts/da/fetch_eigenda.sh"),
    };
    if !script.exists() {
        die(&format!("missing script: {}", script.display()));
    }
    let envelope_path_str = envelope_path.to_string_lossy();
    let out_path_str = out_path.to_string_lossy();
    let envs = [
        ("DA_ENVELOPE_PATH", envelope_path_str.as_ref()),
        ("DA_OUTPUT_PATH", out_path_str.as_ref()),
        ("DA_PROVIDER", provider.as_str()),
    ];
    let value = run_script(&script, &envs);
    let payload_path = value
        .get("payload_path")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if payload_path.is_empty() {
        die("fetch script did not return payload_path");
    }
    PathBuf::from(payload_path)
}

fn write_json(path: &Path, value: &serde_json::Value) {
    let json = serde_json::to_string_pretty(value).unwrap_or_else(|err| {
        die(&format!("json serialize failed: {}", err))
    });
    write_file(path, json.as_bytes());
}

fn write_meta(path: &Path, json_path: &Path) {
    let git = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let meta = serde_json::json!({
        "timestamp": now_rfc3339(),
        "git_commit": git,
        "json_out": json_path.file_name().and_then(|s| s.to_str()).unwrap_or(""),
    });
    write_json(path, &meta);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        die("usage: glyph_da <envelope|submit|fetch|verify> [args]");
    }

    match args[1].as_str() {
        "envelope" => {
            let mut profile = None;
            let mut mode = PayloadMode::Minimal;
            let mut artifact = None;
            let mut proof = None;
            let mut vk = None;
            let mut chain_id = None;
            let mut verifier = None;
            let mut meta_items = Vec::new();
            let mut out_dir = None;

            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--profile" => {
                        i += 1;
                        profile = args.get(i).and_then(|s| DaProfile::parse(s));
                    }
                    "--mode" => {
                        i += 1;
                        mode = PayloadMode::parse(args.get(i).map(|s| s.as_str()).unwrap_or(""))
                            .unwrap_or_else(|| die("invalid --mode"));
                    }
                    "--artifact" => {
                        i += 1;
                        artifact = args.get(i).map(PathBuf::from);
                    }
                    "--proof" => {
                        i += 1;
                        proof = args.get(i).map(PathBuf::from);
                    }
                    "--vk" => {
                        i += 1;
                        vk = args.get(i).map(PathBuf::from);
                    }
                    "--chain-id" => {
                        i += 1;
                        chain_id = args.get(i).and_then(|s| s.parse::<u64>().ok());
                    }
                    "--verifier" => {
                        i += 1;
                        verifier = args.get(i).cloned();
                    }
                    "--meta" => {
                        i += 1;
                        if let Some(val) = args.get(i) {
                            meta_items.push(val.clone());
                        }
                    }
                    "--out-dir" => {
                        i += 1;
                        out_dir = args.get(i).map(PathBuf::from);
                    }
                    _ => die("unknown argument"),
                }
                i += 1;
            }

            let profile = profile.unwrap_or(DaProfile::VerifierOnly);
            let artifact = artifact.unwrap_or_else(|| die("--artifact required"));

            let (payload, artifact_tag, artifact_hash, proof_hash, vk_hash) =
                build_payload(&artifact, proof.as_deref(), vk.as_deref(), mode);

            let payload_bytes = payload.encode();
            let payload_hash = hex_0x(&keccak256(&payload_bytes));

            let envelope = DaEnvelope {
                version: 1,
                profile_id: profile.as_str().to_string(),
                payload_mode: mode.as_str().to_string(),
                created_at_utc: now_rfc3339(),
                artifact_tag,
                artifact_bytes_hash: artifact_hash,
                payload_hash,
                upstream_proof_hash: proof_hash,
                vk_hash,
                chain_id,
                verifier_address: verifier,
                commitments: Vec::new(),
                meta: parse_meta(&meta_items),
                envelope_hash: None,
            };

            let mut envelope = envelope;
            let envelope_hash = envelope
                .compute_envelope_hash()
                .unwrap_or_else(|err| die(&format!("hash failed: {}", err)));
            envelope.envelope_hash = Some(envelope_hash.clone());

            let out_dir = out_dir.unwrap_or_else(|| default_out_dir(&profile));
            let envelope_path = out_dir.join("envelope.json");
            let payload_path = out_dir.join("payload.bin");
            let meta_path = out_dir.join("envelope.meta.json");

            write_file(&payload_path, &payload_bytes);
            let envelope_json = serde_json::to_value(&envelope).unwrap_or_else(|err| {
                die(&format!("serialize failed: {}", err))
            });
            write_json(&envelope_path, &envelope_json);
            write_meta(&meta_path, &envelope_path);

            println!("{}", envelope_path.display());
        }
        "submit" => {
            let mut profile = None;
            let mut mode = PayloadMode::Minimal;
            let mut artifact = None;
            let mut proof = None;
            let mut vk = None;
            let mut chain_id = None;
            let mut verifier = None;
            let mut meta_items = Vec::new();
            let mut out_dir = None;

            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--profile" => {
                        i += 1;
                        profile = args.get(i).and_then(|s| DaProfile::parse(s));
                    }
                    "--mode" => {
                        i += 1;
                        mode = PayloadMode::parse(args.get(i).map(|s| s.as_str()).unwrap_or(""))
                            .unwrap_or_else(|| die("invalid --mode"));
                    }
                    "--artifact" => {
                        i += 1;
                        artifact = args.get(i).map(PathBuf::from);
                    }
                    "--proof" => {
                        i += 1;
                        proof = args.get(i).map(PathBuf::from);
                    }
                    "--vk" => {
                        i += 1;
                        vk = args.get(i).map(PathBuf::from);
                    }
                    "--chain-id" => {
                        i += 1;
                        chain_id = args.get(i).and_then(|s| s.parse::<u64>().ok());
                    }
                    "--verifier" => {
                        i += 1;
                        verifier = args.get(i).cloned();
                    }
                    "--meta" => {
                        i += 1;
                        if let Some(val) = args.get(i) {
                            meta_items.push(val.clone());
                        }
                    }
                    "--out-dir" => {
                        i += 1;
                        out_dir = args.get(i).map(PathBuf::from);
                    }
                    _ => die("unknown argument"),
                }
                i += 1;
            }

            let profile = profile.unwrap_or(DaProfile::VerifierOnly);
            let artifact = artifact.unwrap_or_else(|| die("--artifact required"));

            let (payload, artifact_tag, artifact_hash, proof_hash, vk_hash) =
                build_payload(&artifact, proof.as_deref(), vk.as_deref(), mode);

            let payload_bytes = payload.encode();
            let payload_hash = hex_0x(&keccak256(&payload_bytes));

            let mut envelope = DaEnvelope {
                version: 1,
                profile_id: profile.as_str().to_string(),
                payload_mode: mode.as_str().to_string(),
                created_at_utc: now_rfc3339(),
                artifact_tag,
                artifact_bytes_hash: artifact_hash,
                payload_hash,
                upstream_proof_hash: proof_hash,
                vk_hash,
                chain_id,
                verifier_address: verifier,
                commitments: Vec::new(),
                meta: parse_meta(&meta_items),
                envelope_hash: None,
            };

            let out_dir = out_dir.unwrap_or_else(|| default_out_dir(&profile));
            let envelope_path = out_dir.join("envelope.json");
            let payload_path = out_dir.join("payload.bin");
            let meta_path = out_dir.join("envelope.meta.json");

            write_file(&payload_path, &payload_bytes);

            let mut commitments = Vec::new();
            for provider in profile.providers() {
                commitments.push(submit_provider(*provider, &payload_path));
            }

            envelope.commitments = commitments;
            let envelope_hash = envelope
                .compute_envelope_hash()
                .unwrap_or_else(|err| die(&format!("hash failed: {}", err)));
            envelope.envelope_hash = Some(envelope_hash);

            let envelope_json = serde_json::to_value(&envelope).unwrap_or_else(|err| {
                die(&format!("serialize failed: {}", err))
            });
            write_json(&envelope_path, &envelope_json);
            write_meta(&meta_path, &envelope_path);

            println!("{}", envelope_path.display());
        }
        "fetch" => {
            let mut envelope_path = None;
            let mut provider = None;
            let mut out_path = None;

            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--envelope" => {
                        i += 1;
                        envelope_path = args.get(i).map(PathBuf::from);
                    }
                    "--provider" => {
                        i += 1;
                        provider = args.get(i).and_then(|s| match s.as_str() {
                            "blob" => Some(DaProvider::Blob),
                            "arweave" => Some(DaProvider::Arweave),
                            "eigenda" => Some(DaProvider::EigenDa),
                            _ => None,
                        });
                    }
                    "--out" => {
                        i += 1;
                        out_path = args.get(i).map(PathBuf::from);
                    }
                    _ => die("unknown argument"),
                }
                i += 1;
            }

            let envelope_path = envelope_path.unwrap_or_else(|| die("--envelope required"));
            let provider = provider.unwrap_or_else(|| die("--provider required"));
            let out_path = out_path.unwrap_or_else(|| {
                envelope_path
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .join("payload.fetched.bin")
            });

            let payload_path = fetch_provider(provider, &envelope_path, &out_path);
            println!("{}", payload_path.display());
        }
        "verify" => {
            let mut envelope_path = None;
            let mut payload_path = None;
            let mut fetch_provider_flag = None;

            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--envelope" => {
                        i += 1;
                        envelope_path = args.get(i).map(PathBuf::from);
                    }
                    "--payload" => {
                        i += 1;
                        payload_path = args.get(i).map(PathBuf::from);
                    }
                    "--fetch" => {
                        i += 1;
                        fetch_provider_flag = args.get(i).and_then(|s| match s.as_str() {
                            "blob" => Some(DaProvider::Blob),
                            "arweave" => Some(DaProvider::Arweave),
                            "eigenda" => Some(DaProvider::EigenDa),
                            _ => None,
                        });
                    }
                    _ => die("unknown argument"),
                }
                i += 1;
            }

            let envelope_path = envelope_path.unwrap_or_else(|| die("--envelope required"));
            let envelope_bytes = read_file(&envelope_path);
            let envelope: DaEnvelope = serde_json::from_slice(&envelope_bytes)
                .unwrap_or_else(|err| die(&format!("invalid envelope: {}", err)));

            let payload_path = if let Some(provider) = fetch_provider_flag {
                let out = envelope_path
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .join("payload.fetched.bin");
                fetch_provider(provider, &envelope_path, &out)
            } else {
                payload_path.unwrap_or_else(|| die("--payload required"))
            };

            let payload_bytes = read_file(&payload_path);
            let payload_hash = hex_0x(&keccak256(&payload_bytes));
            if payload_hash != envelope.payload_hash {
                die("payload hash mismatch");
            }

            let payload = DaPayload::decode(&payload_bytes)
                .unwrap_or_else(|err| die(&format!("payload decode failed: {}", err)));
            let artifact_tag = extract_artifact_tag(&payload.parts.artifact_bytes)
                .unwrap_or_else(|err| die(&format!("artifact tag parse failed: {}", err)));
            let artifact_hash = hex_0x(&keccak256(&payload.parts.artifact_bytes));

            if envelope.artifact_tag != hex_0x(&artifact_tag) {
                die("artifact_tag mismatch");
            }
            if envelope.artifact_bytes_hash != artifact_hash {
                die("artifact_bytes_hash mismatch");
            }

            if let Some(expected) = envelope.upstream_proof_hash.as_ref() {
                let proof = payload
                    .parts
                    .upstream_proof_bytes
                    .as_ref()
                    .unwrap_or_else(|| die("payload missing upstream proof"));
                let got = hex_0x(&keccak256(proof));
                if &got != expected {
                    die("upstream_proof_hash mismatch");
                }
            }

            if let Some(expected) = envelope.vk_hash.as_ref() {
                let vk = payload
                    .parts
                    .vk_bytes
                    .as_ref()
                    .unwrap_or_else(|| die("payload missing vk"));
                let got = hex_0x(&keccak256(vk));
                if &got != expected {
                    die("vk_hash mismatch");
                }
            }

            let hash_check = envelope.compute_envelope_hash()
                .unwrap_or_else(|err| die(&format!("envelope hash failed: {}", err)));
            if let Some(existing) = envelope.envelope_hash.as_ref() {
                if &hash_check != existing {
                    die("envelope_hash mismatch");
                }
            }

            println!("ok");
        }
        _ => die("unknown subcommand"),
    }
}
