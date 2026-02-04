use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerfParamType {
    Bool,
    U64,
    I64,
    String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerfValue {
    Bool(bool),
    U64(u64),
    I64(i64),
    String(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PerfParam {
    pub name: &'static str,
    pub kind: PerfParamType,
    pub min: Option<i64>,
    pub max: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PerfConfigEntry {
    pub name: &'static str,
    pub kind: PerfParamType,
    pub present: bool,
    pub raw: Option<String>,
    pub value: Option<PerfValue>,
    pub min: Option<i64>,
    pub max: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GlyphPerfConfig {
    pub source: &'static str,
    pub timestamp: String,
    pub entries: Vec<PerfConfigEntry>,
}

const PERF_PARAMS: &[PerfParam] = &[
    PerfParam { name: "GLYPH_PCS_MASK_ROWS", kind: PerfParamType::U64, min: Some(1), max: None },
    PerfParam { name: "GLYPH_SUMCHECK_PAGED", kind: PerfParamType::Bool, min: None, max: None },
    PerfParam { name: "GLYPH_PCS_RING_SWITCH_PAR_MIN", kind: PerfParamType::U64, min: Some(1), max: None },
    PerfParam { name: "GLYPH_PCS_BASEFOLD_SECURITY_BITS", kind: PerfParamType::U64, min: Some(1), max: None },
    PerfParam { name: "GLYPH_PCS_BASEFOLD_LOG_INV_RATE", kind: PerfParamType::U64, min: Some(1), max: None },
    PerfParam { name: "GLYPH_PCS_BASEFOLD_HOST_MEM", kind: PerfParamType::U64, min: Some(1), max: None },
    PerfParam { name: "GLYPH_PCS_BASEFOLD_DEV_MEM", kind: PerfParamType::U64, min: Some(1), max: None },
    PerfParam { name: "GLYPH_PCS_BASEFOLD_FOLD_ARITY", kind: PerfParamType::U64, min: Some(1), max: None },
    PerfParam { name: "GLYPH_PCS_BASEFOLD_TRACE", kind: PerfParamType::Bool, min: None, max: None },
    PerfParam { name: "GLYPH_PCS_BASEFOLD_CPU_ONLY", kind: PerfParamType::Bool, min: None, max: None },
    PerfParam { name: "GLYPH_PCS_BASEFOLD_PAR_MIN", kind: PerfParamType::U64, min: Some(1), max: None },
    PerfParam { name: "GLYPH_CUDA", kind: PerfParamType::Bool, min: None, max: None },
    PerfParam { name: "GLYPH_CUDA_DEBUG", kind: PerfParamType::Bool, min: None, max: None },
    PerfParam { name: "GLYPH_CUDA_PTX", kind: PerfParamType::String, min: None, max: None },
    PerfParam { name: "GLYPH_CUDA_MIN_ELEMS", kind: PerfParamType::U64, min: Some(1), max: None },
    PerfParam { name: "GLYPH_CUDA_BN254_MIN_ELEMS", kind: PerfParamType::U64, min: Some(1), max: None },
    PerfParam { name: "GLYPH_CUDA_PINNED_HOST", kind: PerfParamType::Bool, min: None, max: None },
    PerfParam { name: "GLYPH_STARK_MIN_SECURITY", kind: PerfParamType::U64, min: Some(1), max: None },
    PerfParam { name: "GLYPH_CIRCLE_STARK_PAR_MIN", kind: PerfParamType::U64, min: Some(1), max: None },
    PerfParam { name: "GLYPH_STANDARD_STARK_PAR_MIN", kind: PerfParamType::U64, min: Some(1), max: None },
    PerfParam { name: "GLYPH_STWO_PAR_MIN", kind: PerfParamType::U64, min: Some(1), max: None },
    PerfParam { name: "GLYPH_BN254_SIMD", kind: PerfParamType::Bool, min: None, max: None },
    PerfParam { name: "GLYPH_BN254_MUL_MONT", kind: PerfParamType::Bool, min: None, max: None },
    PerfParam { name: "GLYPH_BN254_PAR_MIN", kind: PerfParamType::U64, min: Some(1), max: None },
    PerfParam { name: "GLYPH_BN254_WITNESS_BATCH", kind: PerfParamType::U64, min: Some(1), max: None },
    PerfParam { name: "GLYPH_BN254_WITNESS_BATCH_MIN", kind: PerfParamType::U64, min: Some(1), max: None },
    PerfParam { name: "GLYPH_WITNESS_WATCHERS_MAX_EDGES", kind: PerfParamType::U64, min: Some(1), max: None },
    PerfParam { name: "GLYPH_WITNESS_WATCHER_FANOUT", kind: PerfParamType::U64, min: Some(1), max: None },
    PerfParam { name: "GLYPH_KECCAK_X4", kind: PerfParamType::Bool, min: None, max: None },
    PerfParam { name: "GLYPH_KZG_BN254_TRACE_G2S_PRECOMP", kind: PerfParamType::Bool, min: None, max: None },
    PerfParam { name: "GLYPH_KZG_BN254_TRACE_STATS", kind: PerfParamType::Bool, min: None, max: None },
    PerfParam { name: "GLYPH_GROTH16_BN254_TRACE_STATS", kind: PerfParamType::Bool, min: None, max: None },
    PerfParam { name: "GLYPH_GROTH16_BN254_TRACE_IC_PRECOMP", kind: PerfParamType::Bool, min: None, max: None },
    PerfParam { name: "GLYPH_BN254_FIXED_BASE_PRECOMP", kind: PerfParamType::Bool, min: None, max: None },
    PerfParam { name: "GLYPH_BN254_KZG_JOINT_MSM", kind: PerfParamType::Bool, min: None, max: None },
    PerfParam { name: "GLYPH_BN254_IC_PRECOMP_AUTO", kind: PerfParamType::Bool, min: None, max: None },
    PerfParam { name: "GLYPH_BN254_G2_PRECOMP_AUTO", kind: PerfParamType::Bool, min: None, max: None },
    PerfParam { name: "GLYPH_BN254_TRACE_VALIDATE_BATCH", kind: PerfParamType::Bool, min: None, max: None },
    PerfParam { name: "GLYPH_BN254_SCALAR_WINDOW", kind: PerfParamType::U64, min: Some(1), max: None },
    PerfParam { name: "GLYPH_BN254_SCALAR_MUL", kind: PerfParamType::String, min: None, max: None },
    PerfParam { name: "GLYPH_BN254_WNAF_SLOW", kind: PerfParamType::Bool, min: None, max: None },
    PerfParam { name: "GLYPH_BN254_MSM_GLV", kind: PerfParamType::Bool, min: None, max: None },
    PerfParam { name: "GLYPH_BN254_MSM_WINDOW", kind: PerfParamType::U64, min: Some(1), max: None },
    PerfParam { name: "GLYPH_BN254_MSM_SMALL_THRESHOLD", kind: PerfParamType::U64, min: Some(1), max: None },
    PerfParam { name: "GLYPH_BN254_MSM_PRECOMP_THRESHOLD", kind: PerfParamType::U64, min: Some(1), max: None },
    PerfParam { name: "GLYPH_BN254_MSM_SHAMIR", kind: PerfParamType::Bool, min: None, max: None },
    PerfParam { name: "GLYPH_PROFILE_VERSION", kind: PerfParamType::String, min: None, max: None },
    PerfParam { name: "GLYPH_ACCEL_PROFILE", kind: PerfParamType::String, min: None, max: None },
    PerfParam { name: "GLYPH_BN254_PROVER_CORE", kind: PerfParamType::String, min: None, max: None },
    PerfParam { name: "GLYPH_GROTH16_BN254_PROFILE", kind: PerfParamType::String, min: None, max: None },
    PerfParam { name: "GLYPH_KZG_BN254_PROFILE", kind: PerfParamType::String, min: None, max: None },
    PerfParam { name: "GLYPH_IVC_PROFILE", kind: PerfParamType::String, min: None, max: None },
    PerfParam { name: "GLYPH_STARK_PROFILE", kind: PerfParamType::String, min: None, max: None },
    PerfParam { name: "GLYPH_HASH_PROFILE", kind: PerfParamType::String, min: None, max: None },
    PerfParam { name: "GLYPH_SP1_PROFILE", kind: PerfParamType::String, min: None, max: None },
    PerfParam { name: "GLYPH_PLONK_PROFILE", kind: PerfParamType::String, min: None, max: None },
    PerfParam { name: "GLYPH_ZK_KPI_SEED", kind: PerfParamType::U64, min: Some(0), max: None },
    PerfParam { name: "GLYPH_ZK_KPI_REPEAT", kind: PerfParamType::U64, min: Some(1), max: None },
    PerfParam { name: "GLYPH_ZK_KPI_CHAINID", kind: PerfParamType::U64, min: Some(1), max: None },
    PerfParam { name: "GLYPH_ZK_KPI_CONTRACT", kind: PerfParamType::String, min: None, max: None },
    PerfParam { name: "GLYPH_CUDA_KPI_N", kind: PerfParamType::U64, min: Some(1), max: None },
    PerfParam { name: "GLYPH_CUDA_KPI_ROWS", kind: PerfParamType::U64, min: Some(1), max: None },
    PerfParam { name: "GLYPH_CUDA_KPI_COLS", kind: PerfParamType::U64, min: Some(1), max: None },
    PerfParam { name: "GLYPH_CUDA_KPI_HASHES", kind: PerfParamType::U64, min: Some(1), max: None },
    PerfParam { name: "GLYPH_CUDA_KPI_SEED", kind: PerfParamType::U64, min: Some(0), max: None },
    PerfParam { name: "GLYPH_ADAPTER_KPI", kind: PerfParamType::String, min: None, max: None },
    PerfParam { name: "GLYPH_ADAPTER_KPI_GROTH16_BN254_IC_WINDOW", kind: PerfParamType::U64, min: Some(1), max: None },
    PerfParam { name: "GLYPH_ADAPTER_KPI_GROTH16_BN254_PRECOMP", kind: PerfParamType::Bool, min: None, max: None },
    PerfParam { name: "GLYPH_ADAPTER_KPI_KZG_BN254_PRECOMP", kind: PerfParamType::Bool, min: None, max: None },
    PerfParam { name: "GLYPH_ADAPTER_KPI_STARK_F64", kind: PerfParamType::Bool, min: None, max: None },
    PerfParam { name: "GLYPH_TEST_PROFILE", kind: PerfParamType::String, min: None, max: None },
    PerfParam { name: "GLYPH_TEST_FEATURES", kind: PerfParamType::String, min: None, max: None },
    PerfParam { name: "GLYPH_SKIP_FUZZ", kind: PerfParamType::Bool, min: None, max: None },
    PerfParam { name: "GLYPH_FULL_TESTS", kind: PerfParamType::Bool, min: None, max: None },
    PerfParam { name: "GLYPH_FUZZ_STARK", kind: PerfParamType::Bool, min: None, max: None },
    PerfParam { name: "GLYPH_FUZZ_CAIRO", kind: PerfParamType::Bool, min: None, max: None },
    PerfParam { name: "GLYPH_E2E_INCLUDE_F64", kind: PerfParamType::Bool, min: None, max: None },
    PerfParam { name: "GLYPH_E2E_INCLUDE_CIRCLE_LARGE", kind: PerfParamType::Bool, min: None, max: None },
    PerfParam { name: "GLYPH_E2E_INCLUDE_PLONKY2", kind: PerfParamType::Bool, min: None, max: None },
    PerfParam { name: "GLYPH_E2E_INCLUDE_PLONKY3", kind: PerfParamType::Bool, min: None, max: None },
    PerfParam { name: "GLYPH_E2E_INCLUDE_MIDEN", kind: PerfParamType::Bool, min: None, max: None },
    PerfParam { name: "GLYPH_E2E_INCLUDE_CAIRO", kind: PerfParamType::Bool, min: None, max: None },
    PerfParam { name: "GLYPH_E2E_INCLUDE_SP1", kind: PerfParamType::Bool, min: None, max: None },
    PerfParam { name: "GLYPH_PERF_CONFIG_OUT", kind: PerfParamType::String, min: None, max: None },
    PerfParam { name: "GLYPH_PERF_CONFIG_DISABLE", kind: PerfParamType::Bool, min: None, max: None },
];

fn parse_bool(raw: &str) -> Result<bool, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(format!("invalid bool: {raw}")),
    }
}

fn parse_param(param: &PerfParam, raw: &str) -> Result<PerfValue, String> {
    match param.kind {
        PerfParamType::Bool => Ok(PerfValue::Bool(parse_bool(raw)?)),
        PerfParamType::U64 => {
            let value = raw.trim().parse::<u64>().map_err(|_| format!("invalid u64: {raw}"))?;
            if let Some(min) = param.min {
                if value < min as u64 {
                    return Err(format!("value below min {min}: {raw}"));
                }
            }
            if let Some(max) = param.max {
                if value > max as u64 {
                    return Err(format!("value above max {max}: {raw}"));
                }
            }
            Ok(PerfValue::U64(value))
        }
        PerfParamType::I64 => {
            let value = raw.trim().parse::<i64>().map_err(|_| format!("invalid i64: {raw}"))?;
            if let Some(min) = param.min {
                if value < min {
                    return Err(format!("value below min {min}: {raw}"));
                }
            }
            if let Some(max) = param.max {
                if value > max {
                    return Err(format!("value above max {max}: {raw}"));
                }
            }
            Ok(PerfValue::I64(value))
        }
        PerfParamType::String => Ok(PerfValue::String(raw.to_string())),
    }
}

fn build_entries() -> Result<Vec<PerfConfigEntry>, String> {
    let mut entries = Vec::with_capacity(PERF_PARAMS.len());
    for param in PERF_PARAMS {
        match std::env::var(param.name) {
            Ok(raw) => {
                let parsed = parse_param(param, &raw)
                    .map_err(|e| format!("{}: {e}", param.name))?;
                entries.push(PerfConfigEntry {
                    name: param.name,
                    kind: param.kind,
                    present: true,
                    raw: Some(raw),
                    value: Some(parsed),
                    min: param.min,
                    max: param.max,
                });
            }
            Err(std::env::VarError::NotPresent) => {
                entries.push(PerfConfigEntry {
                    name: param.name,
                    kind: param.kind,
                    present: false,
                    raw: None,
                    value: None,
                    min: param.min,
                    max: param.max,
                });
            }
            Err(err) => {
                return Err(format!("{}: env error: {err}", param.name));
            }
        }
    }
    Ok(entries)
}

impl GlyphPerfConfig {
    pub fn from_env() -> Result<Self, String> {
        let timestamp = format!("{:?}", std::time::SystemTime::now());
        let entries = build_entries()?;
        Ok(Self { source: "env", timestamp, entries })
    }
}

fn should_write_snapshot() -> bool {
    match std::env::var("GLYPH_PERF_CONFIG_DISABLE") {
        Ok(raw) => !parse_bool(&raw).unwrap_or(false),
        Err(_) => true,
    }
}

fn snapshot_path() -> String {
    std::env::var("GLYPH_PERF_CONFIG_OUT")
        .unwrap_or_else(|_| "scripts/out/perf/perf_config.json".to_string())
}

fn write_snapshot(config: &GlyphPerfConfig) -> Result<(), String> {
    if !should_write_snapshot() {
        return Ok(());
    }
    let path = snapshot_path();
    if let Some(parent) = std::path::Path::new(&path).parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("perf config mkdir failed: {e}"))?;
    }
    let payload = serde_json::to_vec_pretty(config)
        .map_err(|e| format!("perf config serialize failed: {e}"))?;
    std::fs::write(&path, payload).map_err(|e| format!("perf config write failed: {e}"))?;
    let run_report_path = "scripts/out/perf/perf_run.json";
    let run_report = serde_json::json!({
        "timestamp": config.timestamp,
        "perf_config_path": path,
        "pid": std::process::id(),
        "cwd": std::env::current_dir().ok().and_then(|p| p.to_str().map(|s| s.to_string())),
        "exe": std::env::current_exe().ok().and_then(|p| p.to_str().map(|s| s.to_string())),
    });
    if let Some(parent) = std::path::Path::new(run_report_path).parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("perf run mkdir failed: {e}"))?;
    }
    let run_payload = serde_json::to_vec_pretty(&run_report)
        .map_err(|e| format!("perf run serialize failed: {e}"))?;
    std::fs::write(run_report_path, run_payload)
        .map_err(|e| format!("perf run write failed: {e}"))?;
    Ok(())
}

static PERF_CONFIG: OnceLock<Result<GlyphPerfConfig, String>> = OnceLock::new();

pub fn init_once() -> Result<&'static GlyphPerfConfig, String> {
    let result = PERF_CONFIG.get_or_init(|| {
        let config = GlyphPerfConfig::from_env()?;
        write_snapshot(&config)?;
        Ok(config)
    });
    match result {
        Ok(cfg) => Ok(cfg),
        Err(err) => Err(err.clone()),
    }
}
