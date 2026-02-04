use std::sync::OnceLock;
use tiny_keccak::{Hasher as KeccakHasher, Keccak};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdapterFamily {
    Hash,
    Snark,
    StarkGoldilocks,
    StarkBabyBear,
    StarkM31,
    Ivc,
    Binius,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnarkKind {
    Groth16Bn254,
    KzgBn254,
    Plonk,
    Halo2Kzg,
    IpaBn254,
    IpaBls12381,
    Sp1,
}

pub const SUB_ID_NONE: u8 = 0x00;
pub const SNARK_SUB_GROTH16_BN254: u8 = 0x01;
pub const SNARK_SUB_KZG_BN254: u8 = 0x02;
pub const SNARK_SUB_PLONK: u8 = 0x03;
pub const SNARK_SUB_HALO2_KZG: u8 = 0x04;
pub const SNARK_SUB_IPA_BN254: u8 = 0x05;
pub const SNARK_SUB_SP1: u8 = 0x06;
pub const SNARK_SUB_IPA_BLS12381: u8 = 0x07;

impl SnarkKind {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "groth16" | "groth16-bn254" => Some(SnarkKind::Groth16Bn254),
            "kzg" | "kzg-bn254" => Some(SnarkKind::KzgBn254),
            "plonk" => Some(SnarkKind::Plonk),
            "halo2-kzg" => Some(SnarkKind::Halo2Kzg),
            "ipa" | "ipa-bn254" => Some(SnarkKind::IpaBn254),
            "ipa-bls12381" | "ipa-bls" | "ipa-bls12-381" => Some(SnarkKind::IpaBls12381),
            "sp1" => Some(SnarkKind::Sp1),
            _ => None,
        }
    }

    pub fn sub_id(self) -> u8 {
        match self {
            SnarkKind::Groth16Bn254 => SNARK_SUB_GROTH16_BN254,
            SnarkKind::KzgBn254 => SNARK_SUB_KZG_BN254,
            SnarkKind::Plonk => SNARK_SUB_PLONK,
            SnarkKind::Halo2Kzg => SNARK_SUB_HALO2_KZG,
            SnarkKind::IpaBn254 => SNARK_SUB_IPA_BN254,
            SnarkKind::IpaBls12381 => SNARK_SUB_IPA_BLS12381,
            SnarkKind::Sp1 => SNARK_SUB_SP1,
        }
    }
}

pub const IVC_VK_BYTES_LABEL: &[u8] = b"GLYPH_IVC_VK_BYTES";
pub const IVC_STATEMENT_BYTES_LABEL: &[u8] = b"GLYPH_IVC_STATEMENT_BYTES";
pub const SNARK_GROTH16_BN254_VK_BYTES_LABEL: &[u8] = b"GLYPH_GROTH16_BN254_VK_BYTES";
pub const SNARK_GROTH16_BN254_VK_BYTES_G2_PRECOMP_LABEL: &[u8] =
    b"GLYPH_GROTH16_BN254_VK_BYTES_G2_PRECOMP";
pub const SNARK_GROTH16_BN254_VK_BYTES_FULL_PRECOMP_LABEL: &[u8] =
    b"GLYPH_GROTH16_BN254_VK_BYTES_FULL_PRECOMP";
pub const SNARK_GROTH16_BN254_STATEMENT_BYTES_LABEL: &[u8] =
    b"GLYPH_GROTH16_BN254_STATEMENT_BYTES";
pub const SNARK_KZG_BN254_VK_BYTES_LABEL: &[u8] = b"GLYPH_KZG_BN254_VK_BYTES";
pub const SNARK_KZG_BN254_VK_BYTES_G2S_PRECOMP_LABEL: &[u8] =
    b"GLYPH_KZG_BN254_VK_BYTES_G2S_PRECOMP";
pub const SNARK_KZG_BN254_STATEMENT_BYTES_LABEL: &[u8] =
    b"GLYPH_KZG_BN254_STATEMENT_BYTES";
pub const HASH_VK_BYTES_LABEL: &[u8] = b"GLYPH_HASH_VK_BYTES";
pub const HASH_STATEMENT_BYTES_LABEL: &[u8] = b"GLYPH_HASH_STATEMENT_BYTES";
pub const BINIUS_VK_BYTES_LABEL: &[u8] = b"GLYPH_BINIUS_VK_BYTES";
pub const BINIUS_STATEMENT_BYTES_LABEL: &[u8] = b"GLYPH_BINIUS_STATEMENT_BYTES";
pub const HASH_SHA3_256_ID: u8 = 0x02;
pub const SNARK_GROTH16_BN254_CURVE_ID: u8 = 0x01;
pub const SNARK_GROTH16_BN254_ID: u8 = 0x01;
pub const SNARK_KZG_BN254_CURVE_ID: u8 = 0x01;
pub const SNARK_KZG_PLONK_ID: u8 = 0x01;

#[derive(Clone, Copy, Debug)]
pub struct Bn254TraceProfile {
    pub scalar_mul: &'static str,
    pub scalar_window: usize,
    pub msm_window: Option<usize>,
    pub msm_glv: bool,
    pub fixed_base_precomp: bool,
    pub ic_precomp_auto: bool,
    pub g2_precomp_auto: bool,
    pub kzg_joint_msm: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct IvcFoldingProfile {
    pub chunk_size: usize,
    pub recursion_limit: usize,
    pub parallel_threshold: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpaSystem {
    Halo2Ipa,
    GenericIpa,
}

impl IpaSystem {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "halo2" | "halo2-ipa" | "ipa" => Some(IpaSystem::Halo2Ipa),
            "generic" | "generic-ipa" => Some(IpaSystem::GenericIpa),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CurveFamily {
    Bn254,
    Bls12381,
}

impl CurveFamily {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "bn254" => Some(CurveFamily::Bn254),
            "bls12-381" | "bls12381" | "bls381" => Some(CurveFamily::Bls12381),
            _ => None,
        }
    }
}

pub fn ipa_domain_tag(system: IpaSystem) -> [u8; 32] {
    let label = match system {
        IpaSystem::Halo2Ipa => b"GLYPH_ADAPTER_HALO2_IPA".as_slice(),
        IpaSystem::GenericIpa => b"GLYPH_ADAPTER_GENERIC_IPA".as_slice(),
    };
    keccak256(label)
}

#[cfg(any(
    feature = "stark-babybear",
    feature = "stark-goldilocks",
    feature = "stark-m31"
))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StarkField {
    F128,
    F64,
    Goldilocks,
    Plonky3Goldilocks,
    MidenGoldilocks,
    CairoPrime,
    M31,
    Plonky3M31,
    BabyBear,
    Plonky3BabyBear,
    BabyBearStd,
    KoalaBear,
    Plonky3KoalaBear,
}

#[cfg(not(any(
    feature = "stark-babybear",
    feature = "stark-goldilocks",
    feature = "stark-m31"
)))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StarkField {
    Disabled,
}

#[derive(Clone, Copy, Debug)]
pub struct StarkFieldProfile {
    pub field: StarkField,
    pub fri_fold_factor: usize,
    pub query_count: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct AdapterProfile {
    pub name: &'static str,
    pub bn254: Option<Bn254TraceProfile>,
    pub ivc_folding: Option<IvcFoldingProfile>,
    pub stark_field: Option<StarkFieldProfile>,
}

impl StarkField {
    #[cfg(any(
        feature = "stark-babybear",
        feature = "stark-goldilocks",
        feature = "stark-m31"
    ))]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "f128" | "winterfell-f128" => Some(StarkField::F128),
            "f64" | "winterfell-f64" => Some(StarkField::F64),
            "goldilocks" | "plonky2" => Some(StarkField::Goldilocks),
            "plonky3-goldilocks" => Some(StarkField::Plonky3Goldilocks),        
            "miden" | "miden-goldilocks" => Some(StarkField::MidenGoldilocks),  
            "cairo" | "cairo-prime" | "starknet-prime" => Some(StarkField::CairoPrime),
            "m31" | "m31-circle" | "circle-m31" | "stwo" => Some(StarkField::M31),
            "plonky3-m31" => Some(StarkField::Plonky3M31),
            "babybear" | "baby-bear" | "bb" | "circle-babybear" => {
                Some(StarkField::BabyBear)
            }
            "plonky3-babybear" | "plonky3-baby-bear" => Some(StarkField::Plonky3BabyBear),
            "babybear-std" | "babybear-standard" | "risc0" | "risc-zero" => {
                Some(StarkField::BabyBearStd)
            }
            "koalabear" | "koala-bear" | "kb" => {
                Some(StarkField::KoalaBear)
            }
            "plonky3-koalabear" | "plonky3-koala-bear" => Some(StarkField::Plonky3KoalaBear),
            _ => None,
        }
    }

    #[cfg(not(any(
        feature = "stark-babybear",
        feature = "stark-goldilocks",
        feature = "stark-m31"
    )))]
    pub fn parse(_s: &str) -> Option<Self> {
        None
    }

    #[cfg(any(
        feature = "stark-babybear",
        feature = "stark-goldilocks",
        feature = "stark-m31"
    ))]
    pub fn field_id(self) -> Option<u8> {
        match self {
            StarkField::F128 => Some(crate::stark_winterfell::FIELD_F128_ID),   
            StarkField::F64 => Some(crate::stark_winterfell_f64::FIELD_F64_ID), 
            StarkField::M31 => Some(crate::circle_stark::FIELD_M31_CIRCLE_ID),  
            StarkField::BabyBear => Some(crate::circle_stark::FIELD_BABY_BEAR_CIRCLE_ID),
            StarkField::BabyBearStd => Some(crate::standard_stark::FIELD_BABY_BEAR_STD_ID),
            StarkField::Goldilocks => Some(crate::plonky2_receipt::FIELD_GOLDILOCKS_ID),
            StarkField::Plonky3Goldilocks => Some(crate::plonky3_stark::FIELD_P3_GOLDILOCKS_ID),
            StarkField::MidenGoldilocks => Some(crate::miden_stark::FIELD_MIDEN_GOLDILOCKS_ID),
            StarkField::CairoPrime => Some(crate::cairo_stark::FIELD_CAIRO_PRIME_ID),
            StarkField::KoalaBear => Some(crate::circle_stark::FIELD_KOALA_BEAR_CIRCLE_ID),
            StarkField::Plonky3M31 => Some(crate::plonky3_stark::FIELD_P3_M31_ID),
            StarkField::Plonky3BabyBear => Some(crate::plonky3_stark::FIELD_P3_BABY_BEAR_ID),
            StarkField::Plonky3KoalaBear => Some(crate::plonky3_stark::FIELD_P3_KOALA_BEAR_ID),
        }
    }

    #[cfg(not(any(
        feature = "stark-babybear",
        feature = "stark-goldilocks",
        feature = "stark-m31"
    )))]
    pub fn field_id(self) -> Option<u8> {
        let _ = self;
        None
    }
}

#[cfg(any(
    feature = "stark-babybear",
    feature = "stark-goldilocks",
    feature = "stark-m31"
))]
pub fn stark_domain_tag(field: StarkField) -> [u8; 32] {
    let label = match field {
        StarkField::F128 => b"GLYPH_ADAPTER_STARK_F128".as_slice(),
        StarkField::F64 => b"GLYPH_ADAPTER_STARK_F64".as_slice(),
        StarkField::Goldilocks => b"GLYPH_ADAPTER_STARK_GOLDILOCKS".as_slice(), 
        StarkField::Plonky3Goldilocks => b"GLYPH_ADAPTER_STARK_P3_GOLDILOCKS".as_slice(),
        StarkField::MidenGoldilocks => b"GLYPH_ADAPTER_STARK_MIDEN_GOLDILOCKS".as_slice(),
        StarkField::CairoPrime => b"GLYPH_ADAPTER_STARK_CAIRO_PRIME".as_slice(),
        StarkField::M31 => b"GLYPH_ADAPTER_STARK_M31".as_slice(),
        StarkField::Plonky3M31 => b"GLYPH_ADAPTER_STARK_P3_M31".as_slice(),     
        StarkField::BabyBear => b"GLYPH_ADAPTER_STARK_BABYBEAR".as_slice(),     
        StarkField::Plonky3BabyBear => b"GLYPH_ADAPTER_STARK_P3_BABYBEAR".as_slice(),
        StarkField::BabyBearStd => b"GLYPH_ADAPTER_STARK_BABYBEAR_STD".as_slice(),
        StarkField::KoalaBear => b"GLYPH_ADAPTER_STARK_KOALABEAR".as_slice(),   
        StarkField::Plonky3KoalaBear => b"GLYPH_ADAPTER_STARK_P3_KOALABEAR".as_slice(),
    };
    keccak256(label)
}

#[cfg(not(any(
    feature = "stark-babybear",
    feature = "stark-goldilocks",
    feature = "stark-m31"
)))]
pub fn stark_domain_tag(_field: StarkField) -> [u8; 32] {
    keccak256(b"GLYPH_ADAPTER_STARK_DISABLED")
}

fn profile_version_cpu_aware() -> bool {
    matches!(
        std::env::var("GLYPH_PROFILE_VERSION").ok().as_deref(),
        Some("cpu-aware")
    )
}

fn set_env_if_missing(key: &str, value: &str) {
    if std::env::var_os(key).is_none() {
        std::env::set_var(key, value);
    }
}

fn apply_accel_profile() {
    // CPU-only is the standard profile. CUDA remains opt-in via GLYPH_ACCEL_PROFILE.
    let accel = std::env::var("GLYPH_ACCEL_PROFILE")
        .ok()
        .unwrap_or_else(|| "cpu".to_string());
    match accel.as_str() {
        "cpu" | "cpu-only" | "cpu_only" => {
            set_env_if_missing("GLYPH_CUDA", "0");
        }
        "cuda" | "cpu-cuda" | "cpu_cuda" | "cpu+cuda" => {
            set_env_if_missing("GLYPH_CUDA", "1");
            set_env_if_missing("GLYPH_CUDA_MIN_ELEMS", "1");
            set_env_if_missing("GLYPH_CUDA_PINNED_HOST", "1");
            set_env_if_missing("GLYPH_CUDA_BN254_MIN_ELEMS", "32768");
            set_env_if_missing("BN254_TRACE_CUDA_MIN_ELEMS", "32768");
            set_env_if_missing("BN254_MSM_TRACE_CUDA_MIN_ELEMS", "16384");
            set_env_if_missing("BN254_TRACE_CUDA_WINDOW", "65536");
        }
        other => {
            eprintln!("unknown GLYPH_ACCEL_PROFILE={other}, falling back to cpu");
            set_env_if_missing("GLYPH_CUDA", "0");
        }
    }
}

fn deny_legacy_env() {
    for (key, value) in std::env::vars() {
        if key.starts_with("GLYPH_M3") || key.starts_with("GLYPH_BN254_R7X") {
            eprintln!(
                "legacy env var {key}={value} is not supported in GLYPH-PROVER, ignoring"
            );
            std::env::remove_var(&key);
        }
    }
    if let Ok(value) = std::env::var("GLYPH_BN254_PROVER_CORE") {
        eprintln!(
            "legacy env var GLYPH_BN254_PROVER_CORE={value} is not supported in GLYPH-PROVER, ignoring"
        );
        std::env::remove_var("GLYPH_BN254_PROVER_CORE");
    }
}

fn apply_bn254_profile(profile: Bn254TraceProfile) {
    set_env_if_missing("GLYPH_BN254_SCALAR_MUL", profile.scalar_mul);
    set_env_if_missing("GLYPH_BN254_SCALAR_WINDOW", &profile.scalar_window.to_string());
    if let Some(window) = profile.msm_window {
        set_env_if_missing("GLYPH_BN254_MSM_WINDOW", &window.to_string());
    }
    set_env_if_missing("GLYPH_BN254_WITNESS_BATCH", "1");
    set_env_if_missing("GLYPH_BN254_WITNESS_BATCH_MIN", "256");
    set_env_if_missing("BN254_TRACE_VALIDATE_CHUNK", "16384");
    set_env_if_missing("BN254_TRACE_CUDA_WINDOW", "65536");
    set_env_if_missing(
        "GLYPH_BN254_MSM_GLV",
        if profile.msm_glv { "1" } else { "0" },
    );
    set_env_if_missing(
        "GLYPH_BN254_FIXED_BASE_PRECOMP",
        if profile.fixed_base_precomp { "1" } else { "0" },
    );
    set_env_if_missing(
        "GLYPH_BN254_IC_PRECOMP_AUTO",
        if profile.ic_precomp_auto { "1" } else { "0" },
    );
    set_env_if_missing(
        "GLYPH_BN254_G2_PRECOMP_AUTO",
        if profile.g2_precomp_auto { "1" } else { "0" },
    );
    set_env_if_missing(
        "GLYPH_BN254_KZG_JOINT_MSM",
        if profile.kzg_joint_msm { "1" } else { "0" },
    );
}

fn apply_adapter_profile(profile: AdapterProfile) {
    apply_accel_profile();
    if let Some(bn254) = profile.bn254 {
        apply_bn254_profile(bn254);
    }
}

fn parse_constraints_env(key: &str) -> Option<usize> {
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
}

pub fn select_groth16_bn254_profile_by_constraints(num_constraints: usize) -> AdapterProfile {
    let cpu_aware = profile_version_cpu_aware();
    if num_constraints < 1_000 {
        if cpu_aware {
            groth16_bn254_profile_single_cpu_aware()
        } else {
            groth16_bn254_profile_single()
        }
    } else if num_constraints <= 10_000 {
        if cpu_aware {
            groth16_bn254_profile_prod_cpu_aware()
        } else {
            groth16_bn254_profile_prod()
        }
    } else if cpu_aware {
        groth16_bn254_profile_bench_cpu_aware()
    } else {
        groth16_bn254_profile_bench()
    }
}

fn select_kzg_bn254_profile_by_constraints(num_constraints: usize) -> AdapterProfile {
    let cpu_aware = profile_version_cpu_aware();
    if num_constraints < 1_000 {
        if cpu_aware {
            kzg_bn254_profile_single_cpu_aware()
        } else {
            kzg_bn254_profile_single()
        }
    } else if num_constraints <= 10_000 {
        if cpu_aware {
            kzg_bn254_profile_prod_cpu_aware()
        } else {
            kzg_bn254_profile_prod()
        }
    } else if cpu_aware {
        kzg_bn254_profile_bench_cpu_aware()
    } else {
        kzg_bn254_profile_bench()
    }
}

fn groth16_bn254_profile_prod() -> AdapterProfile {
    AdapterProfile {
        name: "prod",
        bn254: Some(Bn254TraceProfile {
            scalar_mul: "glv",
            scalar_window: 4,
            msm_window: Some(4),
            msm_glv: true,
            fixed_base_precomp: true,
            ic_precomp_auto: true,
            g2_precomp_auto: true,
            kzg_joint_msm: true,
        }),
        ivc_folding: None,
        stark_field: None,
    }
}

fn groth16_bn254_profile_single() -> AdapterProfile {
    AdapterProfile {
        name: "single",
        bn254: Some(Bn254TraceProfile {
            scalar_mul: "glv",
            scalar_window: 4,
            msm_window: Some(4),
            msm_glv: true,
            fixed_base_precomp: true,
            ic_precomp_auto: true,
            g2_precomp_auto: true,
            kzg_joint_msm: true,
        }),
        ivc_folding: None,
        stark_field: None,
    }
}

fn groth16_bn254_profile_prod_cpu_aware() -> AdapterProfile {
    AdapterProfile {
        name: "prod-cpu-aware",
        bn254: Some(Bn254TraceProfile {
            scalar_mul: "glv",
            scalar_window: 4,
            msm_window: Some(4),
            msm_glv: true,
            fixed_base_precomp: true,
            ic_precomp_auto: true,
            g2_precomp_auto: true,
            kzg_joint_msm: false,
        }),
        ivc_folding: None,
        stark_field: None,
    }
}

fn groth16_bn254_profile_single_cpu_aware() -> AdapterProfile {
    AdapterProfile {
        name: "single-cpu-aware",
        bn254: Some(Bn254TraceProfile {
            scalar_mul: "glv",
            scalar_window: 4,
            msm_window: Some(4),
            msm_glv: true,
            fixed_base_precomp: true,
            ic_precomp_auto: true,
            g2_precomp_auto: true,
            kzg_joint_msm: true,
        }),
        ivc_folding: None,
        stark_field: None,
    }
}

fn groth16_bn254_profile_fast() -> AdapterProfile {
    AdapterProfile {
        name: "fast",
        bn254: Some(Bn254TraceProfile {
            scalar_mul: "glv",
            scalar_window: 4,
            msm_window: Some(4),
            msm_glv: true,
            fixed_base_precomp: true,
            ic_precomp_auto: true,
            g2_precomp_auto: true,
            kzg_joint_msm: false,
        }),
        ivc_folding: None,
        stark_field: None,
    }
}

fn groth16_bn254_profile_fast_cpu_aware() -> AdapterProfile {
    AdapterProfile {
        name: "fast-cpu-aware",
        bn254: Some(Bn254TraceProfile {
            scalar_mul: "glv",
            scalar_window: 4,
            msm_window: Some(4),
            msm_glv: true,
            fixed_base_precomp: true,
            ic_precomp_auto: true,
            g2_precomp_auto: true,
            kzg_joint_msm: false,
        }),
        ivc_folding: None,
        stark_field: None,
    }
}

fn groth16_bn254_profile_bench() -> AdapterProfile {
    AdapterProfile {
        name: "bench",
        bn254: Some(Bn254TraceProfile {
            scalar_mul: "glv",
            scalar_window: 4,
            msm_window: Some(4),
            msm_glv: true,
            fixed_base_precomp: true,
            ic_precomp_auto: true,
            g2_precomp_auto: true,
            kzg_joint_msm: false,
        }),
        ivc_folding: None,
        stark_field: None,
    }
}

fn groth16_bn254_profile_bench_cpu_aware() -> AdapterProfile {
    AdapterProfile {
        name: "bench-cpu-aware",
        bn254: Some(Bn254TraceProfile {
            scalar_mul: "glv",
            scalar_window: 4,
            msm_window: Some(4),
            msm_glv: true,
            fixed_base_precomp: true,
            ic_precomp_auto: true,
            g2_precomp_auto: true,
            kzg_joint_msm: false,
        }),
        ivc_folding: None,
        stark_field: None,
    }
}

fn kzg_bn254_profile_prod() -> AdapterProfile {
    AdapterProfile {
        name: "prod",
        bn254: Some(Bn254TraceProfile {
            scalar_mul: "glv",
            scalar_window: 6,
            msm_window: Some(6),
            msm_glv: true,
            fixed_base_precomp: true,
            ic_precomp_auto: true,
            g2_precomp_auto: true,
            kzg_joint_msm: true,
        }),
        ivc_folding: None,
        stark_field: None,
    }
}

fn kzg_bn254_profile_single() -> AdapterProfile {
    AdapterProfile {
        name: "single",
        bn254: Some(Bn254TraceProfile {
            scalar_mul: "glv",
            scalar_window: 6,
            msm_window: Some(6),
            msm_glv: true,
            fixed_base_precomp: true,
            ic_precomp_auto: true,
            g2_precomp_auto: true,
            kzg_joint_msm: true,
        }),
        ivc_folding: None,
        stark_field: None,
    }
}

fn kzg_bn254_profile_prod_cpu_aware() -> AdapterProfile {
    AdapterProfile {
        name: "prod-cpu-aware",
        bn254: Some(Bn254TraceProfile {
            scalar_mul: "glv",
            scalar_window: 6,
            msm_window: Some(6),
            msm_glv: true,
            fixed_base_precomp: true,
            ic_precomp_auto: true,
            g2_precomp_auto: true,
            kzg_joint_msm: true,
        }),
        ivc_folding: None,
        stark_field: None,
    }
}

fn kzg_bn254_profile_single_cpu_aware() -> AdapterProfile {
    AdapterProfile {
        name: "single-cpu-aware",
        bn254: Some(Bn254TraceProfile {
            scalar_mul: "glv",
            scalar_window: 6,
            msm_window: Some(6),
            msm_glv: true,
            fixed_base_precomp: true,
            ic_precomp_auto: true,
            g2_precomp_auto: true,
            kzg_joint_msm: true,
        }),
        ivc_folding: None,
        stark_field: None,
    }
}

fn kzg_bn254_profile_fast() -> AdapterProfile {
    AdapterProfile {
        name: "fast",
        bn254: Some(Bn254TraceProfile {
            scalar_mul: "glv",
            scalar_window: 6,
            msm_window: Some(6),
            msm_glv: true,
            fixed_base_precomp: true,
            ic_precomp_auto: true,
            g2_precomp_auto: true,
            kzg_joint_msm: true,
        }),
        ivc_folding: None,
        stark_field: None,
    }
}

fn kzg_bn254_profile_fast_cpu_aware() -> AdapterProfile {
    AdapterProfile {
        name: "fast-cpu-aware",
        bn254: Some(Bn254TraceProfile {
            scalar_mul: "glv",
            scalar_window: 6,
            msm_window: Some(6),
            msm_glv: true,
            fixed_base_precomp: true,
            ic_precomp_auto: true,
            g2_precomp_auto: true,
            kzg_joint_msm: true,
        }),
        ivc_folding: None,
        stark_field: None,
    }
}

fn kzg_bn254_profile_bench() -> AdapterProfile {
    AdapterProfile {
        name: "bench",
        bn254: Some(Bn254TraceProfile {
            scalar_mul: "glv",
            scalar_window: 6,
            msm_window: Some(6),
            msm_glv: true,
            fixed_base_precomp: true,
            ic_precomp_auto: true,
            g2_precomp_auto: true,
            kzg_joint_msm: true,
        }),
        ivc_folding: None,
        stark_field: None,
    }
}

fn ivc_profile_prod() -> AdapterProfile {
    AdapterProfile {
        name: "prod",
        bn254: None,
        ivc_folding: Some(IvcFoldingProfile {
            chunk_size: 256,
            recursion_limit: 32,
            parallel_threshold: 2048,
        }),
        stark_field: None,
    }
}

fn ivc_profile_fast() -> AdapterProfile {
    AdapterProfile {
        name: "fast",
        bn254: None,
        ivc_folding: None,
        stark_field: None,
    }
}

fn ivc_profile_bench() -> AdapterProfile {
    AdapterProfile {
        name: "bench",
        bn254: None,
        ivc_folding: None,
        stark_field: None,
    }
}

#[cfg(any(
    feature = "stark-babybear",
    feature = "stark-goldilocks",
    feature = "stark-m31"
))]
fn stark_profile_prod() -> AdapterProfile {
    AdapterProfile {
        name: "prod",
        bn254: None,
        ivc_folding: None,
        stark_field: None,
    }
}

#[cfg(any(
    feature = "stark-babybear",
    feature = "stark-goldilocks",
    feature = "stark-m31"
))]
fn stark_profile_fast() -> AdapterProfile {
    AdapterProfile {
        name: "fast",
        bn254: None,
        ivc_folding: None,
        stark_field: None,
    }
}

#[cfg(any(
    feature = "stark-babybear",
    feature = "stark-goldilocks",
    feature = "stark-m31"
))]
fn stark_profile_bench() -> AdapterProfile {
    AdapterProfile {
        name: "bench",
        bn254: None,
        ivc_folding: None,
        stark_field: None,
    }
}

#[cfg(any(
    feature = "stark-babybear",
    feature = "stark-goldilocks",
    feature = "stark-m31"
))]
pub fn stark_field_profile_m31_circle() -> StarkFieldProfile {
    StarkFieldProfile {
        field: StarkField::M31,
        fri_fold_factor: 2,
        query_count: 30,
    }
}

#[cfg(any(
    feature = "stark-babybear",
    feature = "stark-goldilocks",
    feature = "stark-m31"
))]
pub fn stark_field_profile_baby_bear_circle() -> StarkFieldProfile {
    StarkFieldProfile {
        field: StarkField::BabyBear,
        fri_fold_factor: 2,
        query_count: 30,
    }
}

#[cfg(any(
    feature = "stark-babybear",
    feature = "stark-goldilocks",
    feature = "stark-m31"
))]
pub fn stark_field_profile_baby_bear_standard() -> StarkFieldProfile {
    StarkFieldProfile {
        field: StarkField::BabyBearStd,
        fri_fold_factor: 2,
        query_count: 30,
    }
}

#[cfg(any(
    feature = "stark-babybear",
    feature = "stark-goldilocks",
    feature = "stark-m31"
))]
pub fn stark_field_profile_goldilocks_winterfell() -> StarkFieldProfile {
    StarkFieldProfile {
        field: StarkField::Goldilocks,
        fri_fold_factor: 8,
        query_count: 128,
    }
}

fn hash_profile_prod() -> AdapterProfile {
    AdapterProfile {
        name: "prod",
        bn254: None,
        ivc_folding: None,
        stark_field: None,
    }
}

fn hash_profile_fast() -> AdapterProfile {
    AdapterProfile {
        name: "fast",
        bn254: None,
        ivc_folding: None,
        stark_field: None,
    }
}

fn hash_profile_bench() -> AdapterProfile {
    AdapterProfile {
        name: "bench",
        bn254: None,
        ivc_folding: None,
        stark_field: None,
    }
}

fn kzg_bn254_profile_bench_cpu_aware() -> AdapterProfile {
    AdapterProfile {
        name: "bench-cpu-aware",
        bn254: Some(Bn254TraceProfile {
            scalar_mul: "glv",
            scalar_window: 6,
            msm_window: Some(6),
            msm_glv: true,
            fixed_base_precomp: true,
            ic_precomp_auto: true,
            g2_precomp_auto: true,
            kzg_joint_msm: false,
        }),
        ivc_folding: None,
        stark_field: None,
    }
}

pub fn apply_groth16_bn254_profile_defaults() {
    deny_legacy_env();
    let cpu_aware = profile_version_cpu_aware();
    let profile = match std::env::var("GLYPH_GROTH16_BN254_PROFILE")
        .ok()
        .as_deref()
    {
        Some("auto") | Some("adaptive") => {
            if let Some(num_constraints) =
                parse_constraints_env("GLYPH_GROTH16_BN254_CONSTRAINTS")
            {
                select_groth16_bn254_profile_by_constraints(num_constraints)
            } else {
                eprintln!(
                    "GLYPH_GROTH16_BN254_PROFILE=auto requires GLYPH_GROTH16_BN254_CONSTRAINTS, falling back to prod"
                );
                if cpu_aware {
                    groth16_bn254_profile_prod_cpu_aware()
                } else {
                    groth16_bn254_profile_prod()
                }
            }
        }
        Some("fast") => {
            if cpu_aware {
                groth16_bn254_profile_fast_cpu_aware()
            } else {
                groth16_bn254_profile_fast()
            }
        }
        Some("bench") => {
            if cpu_aware {
                groth16_bn254_profile_bench_cpu_aware()
            } else {
                groth16_bn254_profile_bench()
            }
        }
        Some("single") => {
            if cpu_aware {
                groth16_bn254_profile_single_cpu_aware()
            } else {
                groth16_bn254_profile_single()
            }
        }
        Some("prod") => {
            if cpu_aware {
                groth16_bn254_profile_prod_cpu_aware()
            } else {
                groth16_bn254_profile_prod()
            }
        }
        None => {
            if cpu_aware {
                groth16_bn254_profile_prod_cpu_aware()
            } else {
                groth16_bn254_profile_prod()
            }
        }
        Some(other) => {
            eprintln!(
                "unknown GLYPH_GROTH16_BN254_PROFILE={other}, falling back to prod"
            );
            if cpu_aware {
                groth16_bn254_profile_prod_cpu_aware()
            } else {
                groth16_bn254_profile_prod()
            }
        }
    };
    apply_adapter_profile(profile);
}

pub fn apply_kzg_bn254_profile_defaults() {
    deny_legacy_env();
    let cpu_aware = profile_version_cpu_aware();
    let profile = match std::env::var("GLYPH_KZG_BN254_PROFILE")
        .ok()
        .as_deref()
    {
        Some("auto") | Some("adaptive") => {
            if let Some(num_constraints) =
                parse_constraints_env("GLYPH_KZG_BN254_CONSTRAINTS")
            {
                select_kzg_bn254_profile_by_constraints(num_constraints)
            } else {
                eprintln!(
                    "GLYPH_KZG_BN254_PROFILE=auto requires GLYPH_KZG_BN254_CONSTRAINTS, falling back to prod"
                );
                if cpu_aware {
                    kzg_bn254_profile_prod_cpu_aware()
                } else {
                    kzg_bn254_profile_prod()
                }
            }
        }
        Some("fast") => {
            if cpu_aware {
                kzg_bn254_profile_fast_cpu_aware()
            } else {
                kzg_bn254_profile_fast()
            }
        }
        Some("bench") => {
            if cpu_aware {
                kzg_bn254_profile_bench_cpu_aware()
            } else {
                kzg_bn254_profile_bench()
            }
        }
        Some("single") => {
            if cpu_aware {
                kzg_bn254_profile_single_cpu_aware()
            } else {
                kzg_bn254_profile_single()
            }
        }
        Some("prod") => {
            if cpu_aware {
                kzg_bn254_profile_prod_cpu_aware()
            } else {
                kzg_bn254_profile_prod()
            }
        }
        None => {
            if cpu_aware {
                kzg_bn254_profile_prod_cpu_aware()
            } else {
                kzg_bn254_profile_prod()
            }
        }
        Some(other) => {
            eprintln!("unknown GLYPH_KZG_BN254_PROFILE={other}, falling back to prod");
            if cpu_aware {
                kzg_bn254_profile_prod_cpu_aware()
            } else {
                kzg_bn254_profile_prod()
            }
        }
    };
    apply_adapter_profile(profile);
}

pub fn apply_ivc_profile_defaults() {
    deny_legacy_env();
    let profile = match std::env::var("GLYPH_IVC_PROFILE").ok().as_deref() {
        Some("fast") => ivc_profile_fast(),
        Some("bench") => ivc_profile_bench(),
        Some("prod") => ivc_profile_prod(),
        None => ivc_profile_fast(),
        Some(other) => {
            eprintln!("unknown GLYPH_IVC_PROFILE={other}, falling back to fast");
            ivc_profile_fast()
        }
    };
    apply_adapter_profile(profile);
}

pub fn apply_ipa_profile_defaults() {
    deny_legacy_env();
    apply_accel_profile();
}

#[cfg(any(
    feature = "stark-babybear",
    feature = "stark-goldilocks",
    feature = "stark-m31"
))]
pub fn apply_stark_profile_defaults() {
    deny_legacy_env();
    let profile = match std::env::var("GLYPH_STARK_PROFILE").ok().as_deref() {
        Some("fast") => stark_profile_fast(),
        Some("bench") => stark_profile_bench(),
        Some("prod") => stark_profile_prod(),
        None => stark_profile_fast(),
        Some(other) => {
            eprintln!("unknown GLYPH_STARK_PROFILE={other}, falling back to fast");
            stark_profile_fast()
        }
    };
    apply_adapter_profile(profile);
}

pub fn apply_hash_profile_defaults() {
    deny_legacy_env();
    let profile = match std::env::var("GLYPH_HASH_PROFILE").ok().as_deref() {
        Some("fast") => hash_profile_fast(),
        Some("bench") => hash_profile_bench(),
        Some("prod") => hash_profile_prod(),
        None => hash_profile_fast(),
        Some(other) => {
            eprintln!("unknown GLYPH_HASH_PROFILE={other}, falling back to fast");
            hash_profile_fast()
        }
    };
    apply_adapter_profile(profile);
}

pub fn apply_sp1_profile_defaults() {
    deny_legacy_env();
    let profile = match std::env::var("GLYPH_SP1_PROFILE").ok().as_deref() {
        Some("fast") => hash_profile_fast(),
        Some("bench") => hash_profile_bench(),
        Some("prod") => hash_profile_prod(),
        None => hash_profile_fast(),
        Some(other) => {
            eprintln!("unknown GLYPH_SP1_PROFILE={other}, falling back to fast");
            hash_profile_fast()
        }
    };
    apply_adapter_profile(profile);
}

pub fn apply_plonk_profile_defaults() {
    deny_legacy_env();
    let profile = match std::env::var("GLYPH_PLONK_PROFILE").ok().as_deref() {
        Some("fast") => kzg_bn254_profile_fast(),
        Some("bench") => kzg_bn254_profile_bench(),
        Some("prod") => kzg_bn254_profile_prod(),
        None => kzg_bn254_profile_fast(),
        Some(other) => {
            eprintln!("unknown GLYPH_PLONK_PROFILE={other}, falling back to fast");
            kzg_bn254_profile_fast()
        }
    };
    apply_adapter_profile(profile);
}

pub fn apply_binius_profile_defaults() {
    deny_legacy_env();
    apply_accel_profile();
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Groth16Bn254VkBasic {
    pub snark_id: u8,
    pub curve_id: u8,
    pub vk_hash: [u8; 32],
    pub input_layout_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Groth16Bn254VkG2Precomp {
    pub snark_id: u8,
    pub curve_id: u8,
    pub vk_hash: [u8; 32],
    pub input_layout_hash: [u8; 32],
    pub beta_precomp: Vec<u8>,
    pub gamma_precomp: Vec<u8>,
    pub delta_precomp: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Groth16Bn254IcPrecomp {
    pub base_precomp: Vec<u8>,
    pub phi_precomp: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Groth16Bn254VkFullPrecomp {
    pub snark_id: u8,
    pub curve_id: u8,
    pub vk_hash: [u8; 32],
    pub input_layout_hash: [u8; 32],
    pub beta_precomp: Vec<u8>,
    pub gamma_precomp: Vec<u8>,
    pub delta_precomp: Vec<u8>,
    pub ic_precomp_window: u8,
    pub ic_precomp: Vec<Groth16Bn254IcPrecomp>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Groth16Bn254Vk {
    Basic(Groth16Bn254VkBasic),
    G2Precomp(Groth16Bn254VkG2Precomp),
    FullPrecomp(Groth16Bn254VkFullPrecomp),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Groth16Bn254StatementV1 {
    pub input_layout_hash: [u8; 32],
    pub public_inputs_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KzgBn254VkBasic {
    pub snark_id: u8,
    pub curve_id: u8,
    pub kzg_params_hash: [u8; 32],
    pub vk_hash: [u8; 32],
    pub input_layout_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KzgBn254VkG2Precomp {
    pub snark_id: u8,
    pub curve_id: u8,
    pub kzg_params_hash: [u8; 32],
    pub vk_hash: [u8; 32],
    pub input_layout_hash: [u8; 32],
    pub g2_s_precomp: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KzgBn254Vk {
    Basic(KzgBn254VkBasic),
    G2Precomp(KzgBn254VkG2Precomp),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KzgBn254StatementV1 {
    pub input_layout_hash: [u8; 32],
    pub public_inputs_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IvcVk {
    pub gkr_arity: u8,
    pub gkr_rounds: u8,
    pub claim_bits: u16,
    pub proof_type: IvcProofType,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IvcStatement {
    pub commitment_tag: [u8; 32],
    pub point_tag: [u8; 32],
    pub claim128: u128,
    pub proof_type: IvcProofType,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BiniusVk {
    pub log_inv_rate: u8,
    pub security_bits: u16,
    pub cs_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BiniusStatement {
    pub boundaries_bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IvcProofType {
    BaseFoldTransparent = 0x00,
    Nova = 0x01,
    SuperNova = 0x02,
    HyperNova = 0x03,
    Sangria = 0x04,
}

impl IvcProofType {
    pub fn from_u8(value: u8) -> Result<Self, String> {
        match value {
            0x00 => Ok(Self::BaseFoldTransparent),
            0x01 => Ok(Self::Nova),
            0x02 => Ok(Self::SuperNova),
            0x03 => Ok(Self::HyperNova),
            0x04 => Ok(Self::Sangria),
            other => Err(format!("unsupported ivc proof_type=0x{other:02x}")),
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

pub fn groth16_bn254_vk_bytes(
    snark_id: u8,
    vk_hash: &[u8; 32],
    input_layout_hash: &[u8; 32],
) -> Vec<u8> {
    // Canonical bytes describing the Groth16 BN254 VK parameters.
    //
    // Layout (fixed):
    //   domain_tag(32 bytes, keccak(label)) ||
    //   snark_id(u8) ||
    //   curve_id(u8) ||
    //   vk_hash(32) ||
    //   input_layout_hash(32) ||
    //   reserved(u16 BE = 0)
    let domain_tag = keccak256(SNARK_GROTH16_BN254_VK_BYTES_LABEL);
    let mut out = Vec::with_capacity(32 + 1 + 1 + 32 + 32 + 2);
    out.extend_from_slice(&domain_tag);
    out.push(snark_id);
    out.push(SNARK_GROTH16_BN254_CURVE_ID);
    out.extend_from_slice(vk_hash);
    out.extend_from_slice(input_layout_hash);
    out.extend_from_slice(&0u16.to_be_bytes());
    out
}

pub fn groth16_bn254_vk_bytes_g2_precomp(
    snark_id: u8,
    vk_hash: &[u8; 32],
    input_layout_hash: &[u8; 32],
    beta_precomp: &[u8],
    gamma_precomp: &[u8],
    delta_precomp: &[u8],
) -> Vec<u8> {
    // Canonical bytes describing the Groth16 BN254 VK parameters with
    // precomputed G2 Miller loop coefficients for beta/gamma/delta.
    //
    // Layout (fixed):
    //   domain_tag(32 bytes, keccak(label)) ||
    //   snark_id(u8) ||
    //   curve_id(u8) ||
    //   vk_hash(32) ||
    //   input_layout_hash(32) ||
    //   beta_precomp_len(u32 BE) || beta_precomp ||
    //   gamma_precomp_len(u32 BE) || gamma_precomp ||
    //   delta_precomp_len(u32 BE) || delta_precomp ||
    //   reserved(u16 BE = 0)
    let domain_tag = keccak256(SNARK_GROTH16_BN254_VK_BYTES_G2_PRECOMP_LABEL);
    let mut out = Vec::with_capacity(
        32 + 1 + 1 + 32 + 32 + 4 + beta_precomp.len() + 4 + gamma_precomp.len() + 4
            + delta_precomp.len()
            + 2,
    );
    out.extend_from_slice(&domain_tag);
    out.push(snark_id);
    out.push(SNARK_GROTH16_BN254_CURVE_ID);
    out.extend_from_slice(vk_hash);
    out.extend_from_slice(input_layout_hash);
    out.extend_from_slice(&(beta_precomp.len() as u32).to_be_bytes());
    out.extend_from_slice(beta_precomp);
    out.extend_from_slice(&(gamma_precomp.len() as u32).to_be_bytes());
    out.extend_from_slice(gamma_precomp);
    out.extend_from_slice(&(delta_precomp.len() as u32).to_be_bytes());
    out.extend_from_slice(delta_precomp);
    out.extend_from_slice(&0u16.to_be_bytes());
    out
}

#[allow(clippy::too_many_arguments)]
pub fn groth16_bn254_vk_bytes_full_precomp(
    snark_id: u8,
    vk_hash: &[u8; 32],
    input_layout_hash: &[u8; 32],
    beta_precomp: &[u8],
    gamma_precomp: &[u8],
    delta_precomp: &[u8],
    ic_precomp_window: u8,
    ic_precomp: &[Groth16Bn254IcPrecomp],
) -> Vec<u8> {
    // Canonical bytes describing the Groth16 BN254 VK parameters with
    // G2 Miller loop precomp and IC wNAF precomp tables.
    //
    // Layout (fixed):
    //   domain_tag(32 bytes, keccak(label)) ||
    //   snark_id(u8) ||
    //   curve_id(u8) ||
    //   vk_hash(32) ||
    //   input_layout_hash(32) ||
    //   beta_precomp_len(u32 BE) || beta_precomp ||
    //   gamma_precomp_len(u32 BE) || gamma_precomp ||
    //   delta_precomp_len(u32 BE) || delta_precomp ||
    //   ic_precomp_window(u8) ||
    //   ic_precomp_count(u32 BE) ||
    //   repeated ic_precomp_count:
    //     base_precomp_len(u32 BE) || base_precomp ||
    //     phi_precomp_len(u32 BE) || phi_precomp ||
    //   reserved(u16 BE = 0)
    let domain_tag = keccak256(SNARK_GROTH16_BN254_VK_BYTES_FULL_PRECOMP_LABEL);
    let mut cap = 32 + 1 + 1 + 32 + 32 + 4 + beta_precomp.len() + 4 + gamma_precomp.len()
        + 4
        + delta_precomp.len()
        + 1
        + 4
        + 2;
    for entry in ic_precomp {
        cap = cap
            .saturating_add(4)
            .saturating_add(entry.base_precomp.len())
            .saturating_add(4)
            .saturating_add(entry.phi_precomp.len());
    }
    let mut out = Vec::with_capacity(cap);
    out.extend_from_slice(&domain_tag);
    out.push(snark_id);
    out.push(SNARK_GROTH16_BN254_CURVE_ID);
    out.extend_from_slice(vk_hash);
    out.extend_from_slice(input_layout_hash);
    out.extend_from_slice(&(beta_precomp.len() as u32).to_be_bytes());
    out.extend_from_slice(beta_precomp);
    out.extend_from_slice(&(gamma_precomp.len() as u32).to_be_bytes());
    out.extend_from_slice(gamma_precomp);
    out.extend_from_slice(&(delta_precomp.len() as u32).to_be_bytes());
    out.extend_from_slice(delta_precomp);
    out.push(ic_precomp_window);
    out.extend_from_slice(&(ic_precomp.len() as u32).to_be_bytes());
    for entry in ic_precomp {
        out.extend_from_slice(&(entry.base_precomp.len() as u32).to_be_bytes());
        out.extend_from_slice(&entry.base_precomp);
        out.extend_from_slice(&(entry.phi_precomp.len() as u32).to_be_bytes());
        out.extend_from_slice(&entry.phi_precomp);
    }
    out.extend_from_slice(&0u16.to_be_bytes());
    out
}

pub fn groth16_bn254_statement_bytes(
    input_layout_hash: &[u8; 32],
    public_inputs_hash: &[u8; 32],
) -> Vec<u8> {
    // Canonical bytes describing the Groth16 BN254 statement.
    //
    // Layout (fixed):
    //   domain_tag(32 bytes, keccak(label)) ||
    //   input_layout_hash(32) ||
    //   public_inputs_hash(32)
    let domain_tag = keccak256(SNARK_GROTH16_BN254_STATEMENT_BYTES_LABEL);
    let mut out = Vec::with_capacity(32 + 32 + 32);
    out.extend_from_slice(&domain_tag);
    out.extend_from_slice(input_layout_hash);
    out.extend_from_slice(public_inputs_hash);
    out
}

pub fn kzg_bn254_vk_bytes(
    snark_id: u8,
    kzg_params_hash: &[u8; 32],
    vk_hash: &[u8; 32],
    input_layout_hash: &[u8; 32],
) -> Vec<u8> {
    // Canonical bytes describing the KZG BN254 adapter parameters.
    //
    // Layout (fixed):
    //   domain_tag(32 bytes, keccak(label)) ||
    //   snark_id(u8) ||
    //   reserved(u8 = 0) ||
    //   curve_id(u8 = 1) ||
    //   reserved2(u8 = 0) ||
    //   kzg_params_hash(32) ||
    //   vk_hash(32) ||
    //   input_layout_hash(32)
    let domain_tag = keccak256(SNARK_KZG_BN254_VK_BYTES_LABEL);
    let mut out = Vec::with_capacity(32 + 1 + 1 + 1 + 1 + 32 + 32 + 32);
    out.extend_from_slice(&domain_tag);
    out.push(snark_id);
    out.push(0u8);
    out.push(SNARK_KZG_BN254_CURVE_ID);
    out.push(0u8);
    out.extend_from_slice(kzg_params_hash);
    out.extend_from_slice(vk_hash);
    out.extend_from_slice(input_layout_hash);
    out
}

pub fn kzg_bn254_vk_bytes_g2s_precomp(
    snark_id: u8,
    kzg_params_hash: &[u8; 32],
    vk_hash: &[u8; 32],
    input_layout_hash: &[u8; 32],
    g2_s_precomp: &[u8],
) -> Vec<u8> {
    // Canonical bytes describing the KZG BN254 VK parameters with
    // precomputed G2 Miller loop coefficients for g2_s.
    //
    // Layout (fixed):
    //   domain_tag(32 bytes, keccak(label)) ||
    //   snark_id(u8) ||
    //   curve_id(u8) ||
    //   kzg_params_hash(32) ||
    //   vk_hash(32) ||
    //   input_layout_hash(32) ||
    //   g2_s_precomp_len(u32 BE) || g2_s_precomp ||
    //   reserved(u16 BE = 0)
    let domain_tag = keccak256(SNARK_KZG_BN254_VK_BYTES_G2S_PRECOMP_LABEL);
    let mut out = Vec::with_capacity(
        32 + 1 + 1 + 32 + 32 + 32 + 4 + g2_s_precomp.len() + 2,
    );
    out.extend_from_slice(&domain_tag);
    out.push(snark_id);
    out.push(SNARK_KZG_BN254_CURVE_ID);
    out.extend_from_slice(kzg_params_hash);
    out.extend_from_slice(vk_hash);
    out.extend_from_slice(input_layout_hash);
    out.extend_from_slice(&(g2_s_precomp.len() as u32).to_be_bytes());
    out.extend_from_slice(g2_s_precomp);
    out.extend_from_slice(&0u16.to_be_bytes());
    out
}

pub fn kzg_bn254_statement_bytes(
    input_layout_hash: &[u8; 32],
    public_inputs_hash: &[u8; 32],
) -> Vec<u8> {
    // Canonical bytes describing the KZG BN254 statement.
    //
    // Layout (fixed):
    //   domain_tag(32 bytes, keccak(label)) ||
    //   input_layout_hash(32) ||
    //   public_inputs_hash(32)
    let domain_tag = keccak256(SNARK_KZG_BN254_STATEMENT_BYTES_LABEL);
    let mut out = Vec::with_capacity(32 + 32 + 32);
    out.extend_from_slice(&domain_tag);
    out.extend_from_slice(input_layout_hash);
    out.extend_from_slice(public_inputs_hash);
    out
}

pub fn decode_groth16_bn254_vk_bytes_basis(bytes: &[u8]) -> Result<Groth16Bn254VkBasic, String> {
    let mut off = 0usize;
    let domain = read_bytes32(bytes, &mut off)?;
    if domain != keccak256(SNARK_GROTH16_BN254_VK_BYTES_LABEL) {
        return Err("groth16 bn254 vk bytes domain tag mismatch".to_string());
    }
    let snark_id = read_u8(bytes, &mut off)?;
    let curve_id = read_u8(bytes, &mut off)?;
    let vk_hash = read_bytes32(bytes, &mut off)?;
    let input_layout_hash = read_bytes32(bytes, &mut off)?;
    let reserved = read_u16_be(bytes, &mut off)?;
    if reserved != 0 {
        return Err("groth16 bn254 vk bytes reserved field must be zero".to_string());
    }
    if curve_id != SNARK_GROTH16_BN254_CURVE_ID {
        return Err("groth16 bn254 vk bytes curve_id mismatch".to_string());
    }
    if off != bytes.len() {
        return Err("groth16 bn254 vk bytes trailing data".to_string());
    }
    Ok(Groth16Bn254VkBasic {
        snark_id,
        curve_id,
        vk_hash,
        input_layout_hash,
    })
}

pub fn decode_groth16_bn254_vk_bytes_g2_precomp(
    bytes: &[u8],
) -> Result<Groth16Bn254VkG2Precomp, String> {
    let mut off = 0usize;
    let domain = read_bytes32(bytes, &mut off)?;
    if domain != keccak256(SNARK_GROTH16_BN254_VK_BYTES_G2_PRECOMP_LABEL) {
        return Err("groth16 bn254 g2-precomp bytes domain tag mismatch".to_string());
    }
    let snark_id = read_u8(bytes, &mut off)?;
    let curve_id = read_u8(bytes, &mut off)?;
    let vk_hash = read_bytes32(bytes, &mut off)?;
    let input_layout_hash = read_bytes32(bytes, &mut off)?;
    let beta_len = read_u32_be(bytes, &mut off)? as usize;
    let beta_precomp = read_vec(bytes, &mut off, beta_len)?;
    let gamma_len = read_u32_be(bytes, &mut off)? as usize;
    let gamma_precomp = read_vec(bytes, &mut off, gamma_len)?;
    let delta_len = read_u32_be(bytes, &mut off)? as usize;
    let delta_precomp = read_vec(bytes, &mut off, delta_len)?;
    let reserved = read_u16_be(bytes, &mut off)?;
    if reserved != 0 {
        return Err("groth16 bn254 g2-precomp bytes reserved field must be zero".to_string());
    }
    if curve_id != SNARK_GROTH16_BN254_CURVE_ID {
        return Err("groth16 bn254 g2-precomp bytes curve_id mismatch".to_string());
    }
    if off != bytes.len() {
        return Err("groth16 bn254 g2-precomp bytes trailing data".to_string());
    }
    Ok(Groth16Bn254VkG2Precomp {
        snark_id,
        curve_id,
        vk_hash,
        input_layout_hash,
        beta_precomp,
        gamma_precomp,
        delta_precomp,
    })
}

pub fn decode_groth16_bn254_vk_bytes_full_precomp(
    bytes: &[u8],
) -> Result<Groth16Bn254VkFullPrecomp, String> {
    let mut off = 0usize;
    let domain = read_bytes32(bytes, &mut off)?;
    if domain != keccak256(SNARK_GROTH16_BN254_VK_BYTES_FULL_PRECOMP_LABEL) {
        return Err("groth16 bn254 full-precomp bytes domain tag mismatch".to_string());
    }
    let snark_id = read_u8(bytes, &mut off)?;
    let curve_id = read_u8(bytes, &mut off)?;
    let vk_hash = read_bytes32(bytes, &mut off)?;
    let input_layout_hash = read_bytes32(bytes, &mut off)?;
    let beta_len = read_u32_be(bytes, &mut off)? as usize;
    let beta_precomp = read_vec(bytes, &mut off, beta_len)?;
    let gamma_len = read_u32_be(bytes, &mut off)? as usize;
    let gamma_precomp = read_vec(bytes, &mut off, gamma_len)?;
    let delta_len = read_u32_be(bytes, &mut off)? as usize;
    let delta_precomp = read_vec(bytes, &mut off, delta_len)?;
    let ic_precomp_window = read_u8(bytes, &mut off)?;
    let ic_count = read_u32_be(bytes, &mut off)? as usize;
    let mut ic_precomp = Vec::with_capacity(ic_count);
    for _ in 0..ic_count {
        let base_len = read_u32_be(bytes, &mut off)? as usize;
        let base_precomp = read_vec(bytes, &mut off, base_len)?;
        let phi_len = read_u32_be(bytes, &mut off)? as usize;
        let phi_precomp = read_vec(bytes, &mut off, phi_len)?;
        ic_precomp.push(Groth16Bn254IcPrecomp {
            base_precomp,
            phi_precomp,
        });
    }
    let reserved = read_u16_be(bytes, &mut off)?;
    if reserved != 0 {
        return Err("groth16 bn254 full-precomp bytes reserved field must be zero".to_string());
    }
    if curve_id != SNARK_GROTH16_BN254_CURVE_ID {
        return Err("groth16 bn254 full-precomp bytes curve_id mismatch".to_string());
    }
    if off != bytes.len() {
        return Err("groth16 bn254 full-precomp bytes trailing data".to_string());
    }
    Ok(Groth16Bn254VkFullPrecomp {
        snark_id,
        curve_id,
        vk_hash,
        input_layout_hash,
        beta_precomp,
        gamma_precomp,
        delta_precomp,
        ic_precomp_window,
        ic_precomp,
    })
}

pub fn decode_groth16_bn254_vk_bytes(bytes: &[u8]) -> Result<Groth16Bn254Vk, String> {
    if bytes.len() < 32 {
        return Err("groth16 bn254 vk bytes too short".to_string());
    }
    let mut off = 0usize;
    let domain = read_bytes32(bytes, &mut off)?;
    if domain == keccak256(SNARK_GROTH16_BN254_VK_BYTES_LABEL) {
        decode_groth16_bn254_vk_bytes_basis(bytes).map(Groth16Bn254Vk::Basic)
    } else if domain == keccak256(SNARK_GROTH16_BN254_VK_BYTES_G2_PRECOMP_LABEL) {
        decode_groth16_bn254_vk_bytes_g2_precomp(bytes).map(Groth16Bn254Vk::G2Precomp)
    } else if domain == keccak256(SNARK_GROTH16_BN254_VK_BYTES_FULL_PRECOMP_LABEL) {
        decode_groth16_bn254_vk_bytes_full_precomp(bytes).map(Groth16Bn254Vk::FullPrecomp)
    } else {
        Err("groth16 bn254 vk bytes domain tag mismatch".to_string())
    }
}

pub fn decode_groth16_bn254_statement_bytes(
    bytes: &[u8],
) -> Result<Groth16Bn254StatementV1, String> {
    let mut off = 0usize;
    let domain = read_bytes32(bytes, &mut off)?;
    if domain != keccak256(SNARK_GROTH16_BN254_STATEMENT_BYTES_LABEL) {
        return Err("groth16 bn254 statement bytes domain tag mismatch".to_string());
    }
    let input_layout_hash = read_bytes32(bytes, &mut off)?;
    let public_inputs_hash = read_bytes32(bytes, &mut off)?;
    if off != bytes.len() {
        return Err("groth16 bn254 statement bytes trailing data".to_string());
    }
    Ok(Groth16Bn254StatementV1 {
        input_layout_hash,
        public_inputs_hash,
    })
}

pub fn decode_kzg_bn254_vk_bytes_basis(bytes: &[u8]) -> Result<KzgBn254VkBasic, String> {
    let mut off = 0usize;
    let domain = read_bytes32(bytes, &mut off)?;
    if domain != keccak256(SNARK_KZG_BN254_VK_BYTES_LABEL) {
        return Err("kzg bn254 vk bytes domain tag mismatch".to_string());
    }
    let snark_id = read_u8(bytes, &mut off)?;
    let reserved = read_u8(bytes, &mut off)?;
    if reserved != 0 {
        return Err("kzg bn254 vk bytes reserved field must be zero".to_string());
    }
    let curve_id = read_u8(bytes, &mut off)?;
    let reserved2 = read_u8(bytes, &mut off)?;
    if reserved2 != 0 {
        return Err("kzg bn254 vk bytes reserved2 field must be zero".to_string());
    }
    let kzg_params_hash = read_bytes32(bytes, &mut off)?;
    let vk_hash = read_bytes32(bytes, &mut off)?;
    let input_layout_hash = read_bytes32(bytes, &mut off)?;
    if curve_id != SNARK_KZG_BN254_CURVE_ID {
        return Err("kzg bn254 vk bytes curve_id mismatch".to_string());
    }
    if off != bytes.len() {
        return Err("kzg bn254 vk bytes trailing data".to_string());
    }
    Ok(KzgBn254VkBasic {
        snark_id,
        curve_id,
        kzg_params_hash,
        vk_hash,
        input_layout_hash,
    })
}

pub fn decode_kzg_bn254_vk_bytes_g2s_precomp(
    bytes: &[u8],
) -> Result<KzgBn254VkG2Precomp, String> {
    let mut off = 0usize;
    let domain = read_bytes32(bytes, &mut off)?;
    if domain != keccak256(SNARK_KZG_BN254_VK_BYTES_G2S_PRECOMP_LABEL) {
        return Err("kzg bn254 g2s-precomp bytes domain tag mismatch".to_string());
    }
    let snark_id = read_u8(bytes, &mut off)?;
    let curve_id = read_u8(bytes, &mut off)?;
    let kzg_params_hash = read_bytes32(bytes, &mut off)?;
    let vk_hash = read_bytes32(bytes, &mut off)?;
    let input_layout_hash = read_bytes32(bytes, &mut off)?;
    let g2_s_precomp_len = read_u32_be(bytes, &mut off)? as usize;
    let g2_s_precomp = read_vec(bytes, &mut off, g2_s_precomp_len)?;
    let reserved = read_u16_be(bytes, &mut off)?;
    if reserved != 0 {
        return Err("kzg bn254 g2s-precomp bytes reserved field must be zero".to_string());
    }
    if curve_id != SNARK_KZG_BN254_CURVE_ID {
        return Err("kzg bn254 g2s-precomp bytes curve_id mismatch".to_string());
    }
    if off != bytes.len() {
        return Err("kzg bn254 g2s-precomp bytes trailing data".to_string());
    }
    Ok(KzgBn254VkG2Precomp {
        snark_id,
        curve_id,
        kzg_params_hash,
        vk_hash,
        input_layout_hash,
        g2_s_precomp,
    })
}

pub fn decode_kzg_bn254_vk_bytes(bytes: &[u8]) -> Result<KzgBn254Vk, String> {
    if bytes.len() < 32 {
        return Err("kzg bn254 vk bytes too short".to_string());
    }
    let mut off = 0usize;
    let domain = read_bytes32(bytes, &mut off)?;
    if domain == keccak256(SNARK_KZG_BN254_VK_BYTES_LABEL) {
        decode_kzg_bn254_vk_bytes_basis(bytes).map(KzgBn254Vk::Basic)
    } else if domain == keccak256(SNARK_KZG_BN254_VK_BYTES_G2S_PRECOMP_LABEL) {
        decode_kzg_bn254_vk_bytes_g2s_precomp(bytes).map(KzgBn254Vk::G2Precomp)
    } else {
        Err("kzg bn254 vk bytes domain tag mismatch".to_string())
    }
}

pub fn decode_kzg_bn254_statement_bytes(bytes: &[u8]) -> Result<KzgBn254StatementV1, String> {
    let mut off = 0usize;
    let domain = read_bytes32(bytes, &mut off)?;
    if domain != keccak256(SNARK_KZG_BN254_STATEMENT_BYTES_LABEL) {
        return Err("kzg bn254 statement bytes domain tag mismatch".to_string());
    }
    let input_layout_hash = read_bytes32(bytes, &mut off)?;
    let public_inputs_hash = read_bytes32(bytes, &mut off)?;
    if off != bytes.len() {
        return Err("kzg bn254 statement bytes trailing data".to_string());
    }
    Ok(KzgBn254StatementV1 {
        input_layout_hash,
        public_inputs_hash,
    })
}

pub fn ivc_vk_bytes(gkr_rounds: u8, proof_type: IvcProofType) -> Vec<u8> {
    // Canonical bytes describing the IVC backend parameters for AdapterFamily::Ivc.
    //
    // Layout (fixed):
    //   domain_tag(32 bytes, keccak(label)) ||
    //   gkr_arity(u8 = 4) ||
    //   gkr_rounds(u8) ||
    //   claim_bits(u16 BE = 128) ||
    //   proof_type(u8) ||
    //   reserved(u8 = 0)
    let domain_tag = keccak256(IVC_VK_BYTES_LABEL);
    let mut out = Vec::with_capacity(32 + 1 + 1 + 2 + 1 + 1);
    out.extend_from_slice(&domain_tag);
    out.push(4u8);
    out.push(gkr_rounds);
    out.extend_from_slice(&128u16.to_be_bytes());
    out.push(proof_type.as_u8());
    out.push(0u8);
    out
}

pub fn ivc_statement_bytes(
    commitment_tag: &[u8; 32],
    point_tag: &[u8; 32],
    claim128: u128,
    proof_type: IvcProofType,
) -> Vec<u8> {
    // Canonical bytes describing the IVC public statement for AdapterFamily::Ivc.
    //
    // Layout (fixed):
    //   domain_tag(32 bytes, keccak(label)) ||
    //   proof_type(u8) ||
    //   reserved(u8 = 0) ||
    //   commitment_tag(32) ||
    //   point_tag(32) ||
    //   claim128(16 bytes BE)
    let domain_tag = keccak256(IVC_STATEMENT_BYTES_LABEL);
    let mut out = Vec::with_capacity(32 + 1 + 1 + 32 + 32 + 16);
    out.extend_from_slice(&domain_tag);
    out.push(proof_type.as_u8());
    out.push(0u8);
    out.extend_from_slice(commitment_tag);
    out.extend_from_slice(point_tag);
    out.extend_from_slice(&claim128.to_be_bytes());
    out
}

pub fn binius_vk_bytes(
    log_inv_rate: u8,
    security_bits: u16,
    cs_bytes: &[u8],
) -> Vec<u8> {
    // Canonical bytes describing the Binius adapter parameters.
    //
    // Layout (fixed):
    //   domain_tag(32 bytes, keccak(label)) ||
    //   log_inv_rate(u8) ||
    //   security_bits(u16 BE) ||
    //   reserved(u8 = 0) ||
    //   cs_len(u32 BE) || cs_bytes
    let domain_tag = keccak256(BINIUS_VK_BYTES_LABEL);
    let mut out = Vec::with_capacity(32 + 1 + 2 + 1 + 4 + cs_bytes.len());
    out.extend_from_slice(&domain_tag);
    out.push(log_inv_rate);
    out.extend_from_slice(&security_bits.to_be_bytes());
    out.push(0u8);
    out.extend_from_slice(&(cs_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(cs_bytes);
    out
}

pub fn binius_statement_bytes(boundaries_bytes: &[u8]) -> Vec<u8> {
    // Canonical bytes describing the Binius adapter statement.
    //
    // Layout (fixed):
    //   domain_tag(32 bytes, keccak(label)) ||
    //   boundaries_len(u32 BE) || boundaries_bytes
    let domain_tag = keccak256(BINIUS_STATEMENT_BYTES_LABEL);
    let mut out = Vec::with_capacity(32 + 4 + boundaries_bytes.len());
    out.extend_from_slice(&domain_tag);
    out.extend_from_slice(&(boundaries_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(boundaries_bytes);
    out
}

pub fn decode_ivc_vk_bytes(bytes: &[u8]) -> Result<IvcVk, String> {
    let mut off = 0usize;
    let domain = read_bytes32(bytes, &mut off)?;
    if domain != keccak256(IVC_VK_BYTES_LABEL) {
        return Err("ivc vk bytes domain tag mismatch".to_string());
    }
    let gkr_arity = read_u8(bytes, &mut off)?;
    let gkr_rounds = read_u8(bytes, &mut off)?;
    let claim_bits = read_u16_be(bytes, &mut off)?;
    let proof_type = read_u8(bytes, &mut off)?;
    let reserved = read_u8(bytes, &mut off)?;
    if reserved != 0 {
        return Err("ivc vk bytes reserved field must be zero".to_string());
    }
    let proof_type = IvcProofType::from_u8(proof_type)?;
    if off != bytes.len() {
        return Err("ivc vk bytes trailing data".to_string());
    }
    Ok(IvcVk {
        gkr_arity,
        gkr_rounds,
        claim_bits,
        proof_type,
    })
}

pub fn decode_ivc_statement_bytes(bytes: &[u8]) -> Result<IvcStatement, String> {
    let mut off = 0usize;
    let domain = read_bytes32(bytes, &mut off)?;
    if domain != keccak256(IVC_STATEMENT_BYTES_LABEL) {
        return Err("ivc statement bytes domain tag mismatch".to_string());
    }
    let proof_type = read_u8(bytes, &mut off)?;
    let reserved = read_u8(bytes, &mut off)?;
    if reserved != 0 {
        return Err("ivc statement bytes reserved field must be zero".to_string());
    }
    let proof_type = IvcProofType::from_u8(proof_type)?;
    let commitment_tag = read_bytes32(bytes, &mut off)?;
    let point_tag = read_bytes32(bytes, &mut off)?;
    let claim_bytes = read_vec(bytes, &mut off, 16)?;
    let claim128 = u128::from_be_bytes(
        claim_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "ivc claim128 bytes length mismatch".to_string())?,
    );
    if off != bytes.len() {
        return Err("ivc statement bytes trailing data".to_string());
    }
    Ok(IvcStatement {
        commitment_tag,
        point_tag,
        claim128,
        proof_type,
    })
}

pub fn decode_binius_vk_bytes(bytes: &[u8]) -> Result<BiniusVk, String> {
    let mut off = 0usize;
    let domain = read_bytes32(bytes, &mut off)?;
    if domain != keccak256(BINIUS_VK_BYTES_LABEL) {
        return Err("binius vk bytes domain tag mismatch".to_string());
    }
    let log_inv_rate = read_u8(bytes, &mut off)?;
    let security_bits = read_u16_be(bytes, &mut off)?;
    let reserved = read_u8(bytes, &mut off)?;
    if reserved != 0 {
        return Err("binius vk bytes reserved field must be zero".to_string());
    }
    let cs_len = read_u32_be(bytes, &mut off)? as usize;
    let cs_bytes = read_vec(bytes, &mut off, cs_len)?;
    if off != bytes.len() {
        return Err("binius vk bytes trailing data".to_string());
    }
    Ok(BiniusVk {
        log_inv_rate,
        security_bits,
        cs_bytes,
    })
}

pub fn decode_binius_statement_bytes(bytes: &[u8]) -> Result<BiniusStatement, String> {
    let mut off = 0usize;
    let domain = read_bytes32(bytes, &mut off)?;
    if domain != keccak256(BINIUS_STATEMENT_BYTES_LABEL) {
        return Err("binius statement bytes domain tag mismatch".to_string());
    }
    let boundaries_len = read_u32_be(bytes, &mut off)? as usize;
    let boundaries_bytes = read_vec(bytes, &mut off, boundaries_len)?;
    if off != bytes.len() {
        return Err("binius statement bytes trailing data".to_string());
    }
    Ok(BiniusStatement { boundaries_bytes })
}

pub fn hash_vk_bytes(hash_id: u8, msg_len: u32) -> Vec<u8> {
    // Canonical bytes describing the hash adapter parameters.
    //
    // Layout (fixed):
    //   domain_tag(32 bytes, keccak(label)) ||
    //   hash_id(u8) ||
    //   reserved(u8 = 0) ||
    //   msg_len(u32 BE)
    let domain_tag = keccak256(HASH_VK_BYTES_LABEL);
    let mut out = Vec::with_capacity(32 + 1 + 1 + 4);
    out.extend_from_slice(&domain_tag);
    out.push(hash_id);
    out.push(0u8);
    out.extend_from_slice(&msg_len.to_be_bytes());
    out
}

pub fn hash_statement_bytes(
    hash_id: u8,
    msg_len: u32,
    left: &[u8; 32],
    right: &[u8; 32],
    digest: &[u8; 32],
) -> Vec<u8> {
    // Canonical bytes describing the hash adapter statement for a 64-byte merge.
    //
    // Layout (fixed):
    //   domain_tag(32 bytes, keccak(label)) ||
    //   hash_id(u8) ||
    //   reserved(u8 = 0) ||
    //   msg_len(u32 BE) ||
    //   left(32) ||
    //   right(32) ||
    //   digest(32)
    let domain_tag = keccak256(HASH_STATEMENT_BYTES_LABEL);
    let mut out = Vec::with_capacity(32 + 1 + 1 + 4 + 32 + 32 + 32);
    out.extend_from_slice(&domain_tag);
    out.push(hash_id);
    out.push(0u8);
    out.extend_from_slice(&msg_len.to_be_bytes());
    out.extend_from_slice(left);
    out.extend_from_slice(right);
    out.extend_from_slice(digest);
    out
}

impl AdapterFamily {
    pub fn family_id(self) -> u32 {
        match self {
            AdapterFamily::Hash => 1,
            AdapterFamily::Snark => 2,
            AdapterFamily::StarkGoldilocks => 3,
            AdapterFamily::StarkBabyBear => 4,
            AdapterFamily::StarkM31 => 5,
            AdapterFamily::Ivc => 6,
            AdapterFamily::Binius => 7,
        }
    }

    pub fn domain_tag(self) -> [u8; 32] {
        let label = match self {
            AdapterFamily::Hash => b"GLYPH_ADAPTER_HASH".as_slice(),
            AdapterFamily::Snark => b"GLYPH_ADAPTER_SNARK".as_slice(),
            AdapterFamily::StarkGoldilocks => b"GLYPH_ADAPTER_STARK_GOLDILOCKS".as_slice(),
            AdapterFamily::StarkBabyBear => b"GLYPH_ADAPTER_STARK_BABYBEAR".as_slice(),
            AdapterFamily::StarkM31 => b"GLYPH_ADAPTER_STARK_M31".as_slice(),
            AdapterFamily::Ivc => b"GLYPH_ADAPTER_IVC".as_slice(),
            AdapterFamily::Binius => b"GLYPH_ADAPTER_BINIUS".as_slice(),
        };
        keccak256(label)
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "hash" => Some(AdapterFamily::Hash),
            "snark" => Some(AdapterFamily::Snark),
            "stark-goldilocks" => Some(AdapterFamily::StarkGoldilocks),
            "stark-babybear" => Some(AdapterFamily::StarkBabyBear),
            "stark-m31" => Some(AdapterFamily::StarkM31),
            "ivc" => Some(AdapterFamily::Ivc),
            "binius" => Some(AdapterFamily::Binius),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterBinding {
    pub family: AdapterFamily,
    pub sub_id: u8,
    pub chain_id: u64,
    pub verifier_addr: [u8; 20],
    pub vk_hash: [u8; 32],
    pub statement_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterDigests {
    pub proof_hash: [u8; 32],
    pub pub_hash: [u8; 32],
    pub digest: [u8; 32],
}

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut keccak = Keccak::v256();
    keccak.update(data);
    let mut out = [0u8; 32];
    keccak.finalize(&mut out);
    out
}

pub fn keccak256_concat(parts: &[&[u8]]) -> [u8; 32] {
    let mut keccak = Keccak::v256();
    for part in parts {
        keccak.update(part);
    }
    let mut out = [0u8; 32];
    keccak.finalize(&mut out);
    out
}

fn vk_hash_domain() -> &'static [u8; 32] {
    static DOMAIN: OnceLock<[u8; 32]> = OnceLock::new();
    DOMAIN.get_or_init(|| keccak256(b"GLYPH_VK_HASH"))
}

fn statement_hash_domain() -> &'static [u8; 32] {
    static DOMAIN: OnceLock<[u8; 32]> = OnceLock::new();
    DOMAIN.get_or_init(|| keccak256(b"GLYPH_STATEMENT_HASH"))
}

pub fn vk_hash_from_bytes(
    family: AdapterFamily,
    sub_id: u8,
    vk_bytes: &[u8],
) -> [u8; 32] {
    let family_id = family.family_id().to_be_bytes();
    keccak256_concat(&[vk_hash_domain(), &family_id, &[sub_id], vk_bytes])
}

pub fn statement_hash_from_bytes(
    family: AdapterFamily,
    sub_id: u8,
    statement_bytes: &[u8],
) -> [u8; 32] {
    let family_id = family.family_id().to_be_bytes();
    keccak256_concat(&[statement_hash_domain(), &family_id, &[sub_id], statement_bytes])
}

pub fn binding_from_bytes(
    family: AdapterFamily,
    sub_id: u8,
    chain_id: u64,
    verifier_addr: [u8; 20],
    vk_bytes: &[u8],
    statement_bytes: &[u8],
) -> AdapterBinding {
    AdapterBinding {
        family,
        sub_id,
        chain_id,
        verifier_addr,
        vk_hash: vk_hash_from_bytes(family, sub_id, vk_bytes),
        statement_hash: statement_hash_from_bytes(family, sub_id, statement_bytes),
    }
}

pub fn compute_adapter_digest(
    binding: &AdapterBinding,
    proof_bytes: &[u8],
    pub_bytes: &[u8],
) -> AdapterDigests {
    let proof_hash = keccak256(proof_bytes);
    let pub_hash = keccak256(pub_bytes);

    let family_id = binding.family.family_id().to_be_bytes();
    let sub_id = [binding.sub_id];
    let chain_id = binding.chain_id.to_be_bytes();
    let digest = keccak256_concat(&[
        &binding.family.domain_tag(),
        &family_id,
        &sub_id,
        &chain_id,
        &binding.verifier_addr,
        &binding.vk_hash,
        &binding.statement_hash,
        &proof_hash,
        &pub_hash,
    ]);

    AdapterDigests {
        proof_hash,
        pub_hash,
        digest,
    }
}

pub fn detect_family_guess(proof_bytes: &[u8]) -> Option<(AdapterFamily, u8)> {
    let n = proof_bytes.len();
    if proof_bytes.starts_with(b"GLYPH_BINIUS_PROOF") {
        return Some((AdapterFamily::Binius, SUB_ID_NONE));
    }
    if n == 128 {
        return Some((AdapterFamily::Snark, SNARK_SUB_GROTH16_BN254));
    }
    if (384..=2048).contains(&n) {
        return Some((AdapterFamily::Snark, SNARK_SUB_KZG_BN254));
    }
    if (2049..=8192).contains(&n) {
        return Some((AdapterFamily::Ivc, SUB_ID_NONE));
    }
    if n >= 8193 {
        return Some((AdapterFamily::StarkGoldilocks, SUB_ID_NONE));
    }
    None
}

fn read_u8(bytes: &[u8], off: &mut usize) -> Result<u8, String> {
    let v = bytes
        .get(*off)
        .copied()
        .ok_or_else(|| "unexpected EOF".to_string())?;
    *off += 1;
    Ok(v)
}

fn read_u16_be(bytes: &[u8], off: &mut usize) -> Result<u16, String> {
    let s = bytes
        .get(*off..*off + 2)
        .ok_or_else(|| "unexpected EOF".to_string())?;
    *off += 2;
    Ok(u16::from_be_bytes([s[0], s[1]]))
}

fn read_u32_be(bytes: &[u8], off: &mut usize) -> Result<u32, String> {
    let s = bytes
        .get(*off..*off + 4)
        .ok_or_else(|| "unexpected EOF".to_string())?;
    *off += 4;
    Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_bytes32(bytes: &[u8], off: &mut usize) -> Result<[u8; 32], String> {
    let s = bytes
        .get(*off..*off + 32)
        .ok_or_else(|| "unexpected EOF".to_string())?;
    *off += 32;
    let mut out = [0u8; 32];
    out.copy_from_slice(s);
    Ok(out)
}

fn read_vec(bytes: &[u8], off: &mut usize, len: usize) -> Result<Vec<u8>, String> {
    let s = bytes
        .get(*off..*off + len)
        .ok_or_else(|| "unexpected EOF".to_string())?;
    *off += len;
    Ok(s.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::G2Affine;
    use ark_ec::AffineRepr;

    fn binding(chain_id: u64) -> AdapterBinding {
        AdapterBinding {
            family: AdapterFamily::Hash,
            sub_id: SUB_ID_NONE,
            chain_id,
            verifier_addr: [0x11u8; 20],
            vk_hash: [0x22u8; 32],
            statement_hash: [0x33u8; 32],
        }
    }

    #[test]
    fn test_digest_binds_chain_id() {
        let proof = b"proof";
        let pub_bytes = b"pub";

        let d1 = compute_adapter_digest(&binding(1), proof, pub_bytes);
        let d2 = compute_adapter_digest(&binding(2), proof, pub_bytes);
        assert_ne!(d1.digest, d2.digest);
    }

    #[test]
    fn test_digest_binds_verifier_addr() {
        let proof = b"proof";
        let pub_bytes = b"pub";

        let b1 = binding(1);
        let mut b2 = binding(1);
        b2.verifier_addr = [0x12u8; 20];

        let d1 = compute_adapter_digest(&b1, proof, pub_bytes);
        let d2 = compute_adapter_digest(&b2, proof, pub_bytes);
        assert_ne!(d1.digest, d2.digest);
    }

    #[test]
    fn test_digest_binds_vk_hash_and_statement_hash() {
        let proof = b"proof";
        let pub_bytes = b"pub";

        let b1 = binding(1);
        let mut b2 = binding(1);
        b2.vk_hash = [0x23u8; 32];

        let d1 = compute_adapter_digest(&b1, proof, pub_bytes);
        let d2 = compute_adapter_digest(&b2, proof, pub_bytes);
        assert_ne!(d1.digest, d2.digest);

        let mut b3 = binding(1);
        b3.statement_hash = [0x34u8; 32];
        let d3 = compute_adapter_digest(&b3, proof, pub_bytes);
        assert_ne!(d1.digest, d3.digest);
    }

    #[test]
    fn test_digest_binds_proof_and_pub_bytes() {
        let pub_bytes = b"pub";
        let d1 = compute_adapter_digest(&binding(1), b"proof", pub_bytes);
        let d2 = compute_adapter_digest(&binding(1), b"proof2", pub_bytes);
        assert_ne!(d1.digest, d2.digest);

        let proof = b"proof";
        let d3 = compute_adapter_digest(&binding(1), proof, b"pub");
        let d4 = compute_adapter_digest(&binding(1), proof, b"pub2");
        assert_ne!(d3.digest, d4.digest);
    }

    #[test]
    fn test_vk_hash_binds_family_and_sub_id() {
        let vk = b"vk";
        let h1 = vk_hash_from_bytes(AdapterFamily::Snark, SNARK_SUB_GROTH16_BN254, vk);
        let h2 = vk_hash_from_bytes(AdapterFamily::Snark, SNARK_SUB_KZG_BN254, vk);
        let h3 = vk_hash_from_bytes(AdapterFamily::Ivc, SUB_ID_NONE, vk);
        assert_ne!(h1, h2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_statement_hash_binds_family_and_sub_id() {
        let stmt = b"statement";
        let h1 = statement_hash_from_bytes(AdapterFamily::Ivc, SUB_ID_NONE, stmt);
        let h2 = statement_hash_from_bytes(AdapterFamily::StarkGoldilocks, SUB_ID_NONE, stmt);
        let h3 = statement_hash_from_bytes(AdapterFamily::Snark, SNARK_SUB_GROTH16_BN254, stmt);
        assert_ne!(h1, h2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_digest_vectors_across_families() {
        let proof = b"proof";
        let pub_bytes = b"pub";

        let chain_id = 1u64;
        let verifier_addr = [0x11u8; 20];
        let vk_hash = [0x22u8; 32];
        let statement_hash = [0x33u8; 32];

        let cases = [
            (AdapterFamily::Snark, SNARK_SUB_GROTH16_BN254),
            (AdapterFamily::Snark, SNARK_SUB_KZG_BN254),
            (AdapterFamily::Ivc, SUB_ID_NONE),
            (AdapterFamily::StarkGoldilocks, SUB_ID_NONE),
            (AdapterFamily::Hash, SUB_ID_NONE),
        ];

        let mut digests = Vec::new();
        for (family, sub_id) in cases {
            let binding = AdapterBinding {
                family,
                sub_id,
                chain_id,
                verifier_addr,
                vk_hash,
                statement_hash,
            };
            let digest_pack = compute_adapter_digest(&binding, proof, pub_bytes);
            digests.push(digest_pack.digest);
        }
        for i in 0..digests.len() {
            for j in (i + 1)..digests.len() {
                assert_ne!(digests[i], digests[j]);
            }
        }
    }

    #[test]
    fn test_ivc_vk_bytes_roundtrip_and_binding() {
        let vk5 = ivc_vk_bytes(5, IvcProofType::BaseFoldTransparent);
        let vk6 = ivc_vk_bytes(6, IvcProofType::BaseFoldTransparent);
        assert_eq!(vk5.len(), 38);
        assert_eq!(vk6.len(), 38);
        assert_ne!(vk5, vk6);

        let h5 = vk_hash_from_bytes(AdapterFamily::Ivc, SUB_ID_NONE, &vk5);
        let h6 = vk_hash_from_bytes(AdapterFamily::Ivc, SUB_ID_NONE, &vk6);
        assert_ne!(h5, h6);
    }

    #[test]
    fn test_ivc_statement_bytes_roundtrip_and_binding() {
        let commitment_tag = [0x11u8; 32];
        let point_tag = [0x22u8; 32];
        let s1 = ivc_statement_bytes(
            &commitment_tag,
            &point_tag,
            1u128,
            IvcProofType::BaseFoldTransparent,
        );
        let s2 = ivc_statement_bytes(
            &commitment_tag,
            &point_tag,
            2u128,
            IvcProofType::BaseFoldTransparent,
        );
        assert_eq!(s1.len(), 114);
        assert_eq!(s2.len(), 114);
        assert_ne!(s1, s2);

        let h1 = statement_hash_from_bytes(AdapterFamily::Ivc, SUB_ID_NONE, &s1);
        let h2 = statement_hash_from_bytes(AdapterFamily::Ivc, SUB_ID_NONE, &s2);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_ivc_vk_bytes_roundtrip_and_tamper() {
        let bytes = ivc_vk_bytes(7, IvcProofType::BaseFoldTransparent);
        let parsed = match decode_ivc_vk_bytes(&bytes) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "ivc vk decode");
                return;
            }
        };
        assert_eq!(parsed.gkr_arity, 4);
        assert_eq!(parsed.gkr_rounds, 7);
        assert_eq!(parsed.claim_bits, 128);
        assert_eq!(parsed.proof_type, IvcProofType::BaseFoldTransparent);

        let mut tampered = bytes.clone();
        tampered[0] ^= 1;
        assert!(decode_ivc_vk_bytes(&tampered).is_err());

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode_ivc_vk_bytes(&trailing).is_err());
    }

    #[test]
    fn test_ivc_statement_bytes_roundtrip_and_tamper() {
        let commitment_tag = [0x55u8; 32];
        let point_tag = [0x66u8; 32];
        let bytes = ivc_statement_bytes(
            &commitment_tag,
            &point_tag,
            42u128,
            IvcProofType::BaseFoldTransparent,
        );
        let parsed = match decode_ivc_statement_bytes(&bytes) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "ivc stmt decode");
                return;
            }
        };
        assert_eq!(parsed.commitment_tag, commitment_tag);
        assert_eq!(parsed.point_tag, point_tag);
        assert_eq!(parsed.claim128, 42u128);
        assert_eq!(parsed.proof_type, IvcProofType::BaseFoldTransparent);

        let mut tampered = bytes.clone();
        tampered[0] ^= 1;
        assert!(decode_ivc_statement_bytes(&tampered).is_err());

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode_ivc_statement_bytes(&trailing).is_err());
    }

    #[test]
    fn test_binius_vk_bytes_roundtrip_and_tamper() {
        let cs_bytes = vec![0xAAu8; 64];
        let bytes = binius_vk_bytes(4, 96, &cs_bytes);
        let parsed = match decode_binius_vk_bytes(&bytes) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "binius vk decode");
                return;
            }
        };
        assert_eq!(parsed.log_inv_rate, 4);
        assert_eq!(parsed.security_bits, 96);
        assert_eq!(parsed.cs_bytes, cs_bytes);

        let mut tampered = bytes.clone();
        tampered[0] ^= 1;
        assert!(decode_binius_vk_bytes(&tampered).is_err());

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode_binius_vk_bytes(&trailing).is_err());
    }

    #[test]
    fn test_binius_statement_bytes_roundtrip_and_tamper() {
        let boundaries = vec![0x11u8; 48];
        let bytes = binius_statement_bytes(&boundaries);
        let parsed = match decode_binius_statement_bytes(&bytes) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "binius stmt decode");
                return;
            }
        };
        assert_eq!(parsed.boundaries_bytes, boundaries);

        let mut tampered = bytes.clone();
        tampered[0] ^= 1;
        assert!(decode_binius_statement_bytes(&tampered).is_err());

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode_binius_statement_bytes(&trailing).is_err());
    }

    #[test]
    fn test_groth16_bn254_vk_bytes_basis_roundtrip_and_tamper() {
        let vk_hash = [0x11u8; 32];
        let layout_hash = [0x22u8; 32];
        let bytes = groth16_bn254_vk_bytes(SNARK_GROTH16_BN254_ID, &vk_hash, &layout_hash);
        let parsed = match decode_groth16_bn254_vk_bytes_basis(&bytes) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "groth16 vk decode");
                return;
            }
        };
        assert_eq!(parsed.snark_id, SNARK_GROTH16_BN254_ID);
        assert_eq!(parsed.curve_id, SNARK_GROTH16_BN254_CURVE_ID);
        assert_eq!(parsed.vk_hash, vk_hash);
        assert_eq!(parsed.input_layout_hash, layout_hash);

        let mut tampered = bytes.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(decode_groth16_bn254_vk_bytes_basis(&tampered).is_err());
    }

    #[test]
    fn test_groth16_bn254_vk_bytes_g2_precomp_roundtrip_and_tamper() {
        let vk_hash = [0x33u8; 32];
        let layout_hash = [0x44u8; 32];
        let beta_precomp = vec![0x10u8; 12];
        let gamma_precomp = vec![0x22u8; 16];
        let delta_precomp = vec![0x33u8; 8];
        let bytes = groth16_bn254_vk_bytes_g2_precomp(
            SNARK_GROTH16_BN254_ID,
            &vk_hash,
            &layout_hash,
            &beta_precomp,
            &gamma_precomp,
            &delta_precomp,
        );
        let parsed = match decode_groth16_bn254_vk_bytes_g2_precomp(&bytes) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "groth16 vk decode");
                return;
            }
        };
        assert_eq!(parsed.snark_id, SNARK_GROTH16_BN254_ID);
        assert_eq!(parsed.curve_id, SNARK_GROTH16_BN254_CURVE_ID);
        assert_eq!(parsed.vk_hash, vk_hash);
        assert_eq!(parsed.input_layout_hash, layout_hash);
        assert_eq!(parsed.beta_precomp, beta_precomp);
        assert_eq!(parsed.gamma_precomp, gamma_precomp);
        assert_eq!(parsed.delta_precomp, delta_precomp);

        let mut tampered = bytes.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(decode_groth16_bn254_vk_bytes_g2_precomp(&tampered).is_err());
    }

    #[test]
    fn test_groth16_bn254_vk_bytes_full_precomp_roundtrip_and_tamper() {
        let vk_hash = [0x55u8; 32];
        let layout_hash = [0x66u8; 32];
        let beta_precomp = vec![0x10u8; 12];
        let gamma_precomp = vec![0x22u8; 16];
        let delta_precomp = vec![0x33u8; 8];
        let ic_precomp = vec![
            Groth16Bn254IcPrecomp {
                base_precomp: vec![0x42u8; 64],
                phi_precomp: vec![0x24u8; 64],
            },
            Groth16Bn254IcPrecomp {
                base_precomp: vec![0x11u8; 64],
                phi_precomp: vec![0x22u8; 64],
            },
        ];
        let bytes = groth16_bn254_vk_bytes_full_precomp(
            SNARK_GROTH16_BN254_ID,
            &vk_hash,
            &layout_hash,
            &beta_precomp,
            &gamma_precomp,
            &delta_precomp,
            6,
            &ic_precomp,
        );
        let parsed = match decode_groth16_bn254_vk_bytes_full_precomp(&bytes) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "groth16 vk decode");
                return;
            }
        };
        assert_eq!(parsed.snark_id, SNARK_GROTH16_BN254_ID);
        assert_eq!(parsed.curve_id, SNARK_GROTH16_BN254_CURVE_ID);
        assert_eq!(parsed.vk_hash, vk_hash);
        assert_eq!(parsed.input_layout_hash, layout_hash);
        assert_eq!(parsed.beta_precomp, beta_precomp);
        assert_eq!(parsed.gamma_precomp, gamma_precomp);
        assert_eq!(parsed.delta_precomp, delta_precomp);
        assert_eq!(parsed.ic_precomp_window, 6);
        assert_eq!(parsed.ic_precomp, ic_precomp);

        let mut tampered = bytes.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(decode_groth16_bn254_vk_bytes_full_precomp(&tampered).is_err());
    }

    #[test]
    fn test_groth16_bn254_statement_bytes_roundtrip() {
        let layout_hash = [0x55u8; 32];
        let inputs_hash = [0x66u8; 32];
        let bytes = groth16_bn254_statement_bytes(&layout_hash, &inputs_hash);
        let parsed = match decode_groth16_bn254_statement_bytes(&bytes) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "groth16 stmt decode");
                return;
            }
        };
        assert_eq!(parsed.input_layout_hash, layout_hash);
        assert_eq!(parsed.public_inputs_hash, inputs_hash);
    }

    #[test]
    fn test_kzg_bn254_vk_bytes_basis_roundtrip_and_tamper() {
        let params_hash = [0x66u8; 32];
        let vk_hash = [0x77u8; 32];
        let layout_hash = [0x88u8; 32];
        let bytes = kzg_bn254_vk_bytes(
            SNARK_KZG_PLONK_ID,
            &params_hash,
            &vk_hash,
            &layout_hash,
        );
        let parsed = match decode_kzg_bn254_vk_bytes_basis(&bytes) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "kzg vk decode");
                return;
            }
        };
        assert_eq!(parsed.snark_id, SNARK_KZG_PLONK_ID);
        assert_eq!(parsed.curve_id, SNARK_KZG_BN254_CURVE_ID);
        assert_eq!(parsed.kzg_params_hash, params_hash);
        assert_eq!(parsed.vk_hash, vk_hash);
        assert_eq!(parsed.input_layout_hash, layout_hash);

        let mut tampered = bytes.clone();
        tampered[0] ^= 1;
        assert!(decode_kzg_bn254_vk_bytes_basis(&tampered).is_err());
    }

    #[test]
    fn test_kzg_bn254_vk_bytes_g2s_precomp_roundtrip_and_tamper() {
        let params_hash = [0x66u8; 32];
        let vk_hash = [0x77u8; 32];
        let layout_hash = [0x88u8; 32];
        let g2_s_precomp = crate::glyph_pairing::encode_g2_precomp_bytes(G2Affine::generator());
        let bytes = kzg_bn254_vk_bytes_g2s_precomp(
            SNARK_KZG_PLONK_ID,
            &params_hash,
            &vk_hash,
            &layout_hash,
            &g2_s_precomp,
        );
        let parsed = match decode_kzg_bn254_vk_bytes_g2s_precomp(&bytes) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "kzg vk decode");
                return;
            }
        };
        assert_eq!(parsed.snark_id, SNARK_KZG_PLONK_ID);
        assert_eq!(parsed.curve_id, SNARK_KZG_BN254_CURVE_ID);
        assert_eq!(parsed.kzg_params_hash, params_hash);
        assert_eq!(parsed.vk_hash, vk_hash);
        assert_eq!(parsed.input_layout_hash, layout_hash);
        assert_eq!(parsed.g2_s_precomp, g2_s_precomp);

        let mut tampered = bytes.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(decode_kzg_bn254_vk_bytes_g2s_precomp(&tampered).is_err());
    }

    #[test]
    fn test_kzg_bn254_statement_bytes_roundtrip() {
        let layout_hash = [0x77u8; 32];
        let inputs_hash = [0x88u8; 32];
        let bytes = kzg_bn254_statement_bytes(&layout_hash, &inputs_hash);
        let parsed = match decode_kzg_bn254_statement_bytes(&bytes) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "kzg stmt decode");
                return;
            }
        };
        assert_eq!(parsed.input_layout_hash, layout_hash);
        assert_eq!(parsed.public_inputs_hash, inputs_hash);
    }
}
