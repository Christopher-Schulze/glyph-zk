use crate::adapters::{AdapterFamily, SnarkKind, StarkField};

#[derive(Clone, Copy, Debug)]
pub struct AdapterFamilyInfo {
    pub family: AdapterFamily,
    pub name: &'static str,
    pub enabled: bool,
    pub feature: &'static str,
    pub reason: &'static str,
}

#[derive(Clone, Copy, Debug)]
pub struct SnarkKindInfo {
    pub kind: SnarkKind,
    pub name: &'static str,
    pub enabled: bool,
    pub feature: &'static str,
    pub reason: &'static str,
}

#[derive(Clone, Copy, Debug)]
pub struct StarkFieldInfo {
    pub field: StarkField,
    pub name: &'static str,
    pub enabled: bool,
    pub feature: &'static str,
    pub reason: &'static str,
}

pub fn registry() -> Vec<AdapterFamilyInfo> {
    vec![
        AdapterFamilyInfo {
            family: AdapterFamily::Hash,
            name: "hash",
            enabled: cfg!(feature = "hash"),
            feature: "hash",
            reason: if cfg!(feature = "hash") { "enabled" } else { "feature disabled" },
        },
        AdapterFamilyInfo {
            family: AdapterFamily::Snark,
            name: "snark",
            enabled: cfg!(feature = "snark"),
            feature: "snark",
            reason: if cfg!(feature = "snark") { "enabled" } else { "feature disabled" },
        },
        AdapterFamilyInfo {
            family: AdapterFamily::StarkGoldilocks,
            name: "stark-goldilocks",
            enabled: cfg!(feature = "stark-goldilocks"),
            feature: "stark-goldilocks",
            reason: if cfg!(feature = "stark-goldilocks") { "enabled" } else { "feature disabled" },
        },
        AdapterFamilyInfo {
            family: AdapterFamily::StarkBabyBear,
            name: "stark-babybear",
            enabled: cfg!(feature = "stark-babybear"),
            feature: "stark-babybear",
            reason: if cfg!(feature = "stark-babybear") { "enabled" } else { "feature disabled" },
        },
        AdapterFamilyInfo {
            family: AdapterFamily::StarkM31,
            name: "stark-m31",
            enabled: cfg!(feature = "stark-m31"),
            feature: "stark-m31",
            reason: if cfg!(feature = "stark-m31") { "enabled" } else { "feature disabled" },
        },
        AdapterFamilyInfo {
            family: AdapterFamily::Ivc,
            name: "ivc",
            enabled: cfg!(feature = "ivc"),
            feature: "ivc",
            reason: if cfg!(feature = "ivc") { "enabled" } else { "feature disabled" },
        },
        AdapterFamilyInfo {
            family: AdapterFamily::Binius,
            name: "binius",
            enabled: cfg!(feature = "binius"),
            feature: "binius",
            reason: if cfg!(feature = "binius") { "enabled" } else { "feature disabled" },
        },
    ]
}

pub fn family_info(family: AdapterFamily) -> Option<AdapterFamilyInfo> {
    registry().into_iter().find(|info| info.family == family)
}

pub fn is_enabled(family: AdapterFamily) -> bool {
    family_info(family).map(|info| info.enabled).unwrap_or(false)
}

pub fn any_stark_enabled() -> bool {
    is_enabled(AdapterFamily::StarkGoldilocks)
        || is_enabled(AdapterFamily::StarkBabyBear)
        || is_enabled(AdapterFamily::StarkM31)
}

pub fn family_name(family: AdapterFamily) -> &'static str {
    match family {
        AdapterFamily::Hash => "hash",
        AdapterFamily::Snark => "snark",
        AdapterFamily::StarkGoldilocks => "stark-goldilocks",
        AdapterFamily::StarkBabyBear => "stark-babybear",
        AdapterFamily::StarkM31 => "stark-m31",
        AdapterFamily::Ivc => "ivc",
        AdapterFamily::Binius => "binius",
    }
}

pub fn snark_kind_registry() -> Vec<SnarkKindInfo> {
    let enabled = cfg!(feature = "snark");
    let reason = if enabled { "enabled" } else { "feature disabled" };
    vec![
        SnarkKindInfo { kind: SnarkKind::Groth16Bn254, name: "groth16-bn254", enabled, feature: "snark", reason },
        SnarkKindInfo { kind: SnarkKind::KzgBn254, name: "kzg-bn254", enabled, feature: "snark", reason },
        SnarkKindInfo { kind: SnarkKind::Plonk, name: "plonk", enabled, feature: "snark", reason },
        SnarkKindInfo { kind: SnarkKind::Halo2Kzg, name: "halo2-kzg", enabled, feature: "snark", reason },
        SnarkKindInfo { kind: SnarkKind::IpaBn254, name: "ipa-bn254", enabled, feature: "snark", reason },
        SnarkKindInfo { kind: SnarkKind::IpaBls12381, name: "ipa-bls12381", enabled, feature: "snark", reason },
        SnarkKindInfo { kind: SnarkKind::Sp1, name: "sp1", enabled, feature: "snark", reason },
    ]
}

pub fn snark_kind_info(kind: SnarkKind) -> Option<SnarkKindInfo> {
    snark_kind_registry().into_iter().find(|info| info.kind == kind)
}

pub fn snark_kind_name(kind: SnarkKind) -> &'static str {
    match kind {
        SnarkKind::Groth16Bn254 => "groth16-bn254",
        SnarkKind::KzgBn254 => "kzg-bn254",
        SnarkKind::Plonk => "plonk",
        SnarkKind::Halo2Kzg => "halo2-kzg",
        SnarkKind::IpaBn254 => "ipa-bn254",
        SnarkKind::IpaBls12381 => "ipa-bls12381",
        SnarkKind::Sp1 => "sp1",
    }
}

#[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
pub fn stark_field_registry() -> Vec<StarkFieldInfo> {
    let mut out = Vec::new();
    #[cfg(feature = "stark-goldilocks")]
    {
        out.push(StarkFieldInfo { field: StarkField::F128, name: "f128", enabled: true, feature: "stark-goldilocks", reason: "enabled" });
        out.push(StarkFieldInfo { field: StarkField::F64, name: "f64", enabled: true, feature: "stark-goldilocks", reason: "enabled" });
        out.push(StarkFieldInfo { field: StarkField::Goldilocks, name: "goldilocks", enabled: true, feature: "stark-goldilocks", reason: "enabled" });
        out.push(StarkFieldInfo { field: StarkField::Plonky3Goldilocks, name: "plonky3-goldilocks", enabled: true, feature: "stark-goldilocks", reason: "enabled" });
        out.push(StarkFieldInfo { field: StarkField::MidenGoldilocks, name: "miden", enabled: true, feature: "stark-goldilocks", reason: "enabled" });
    }
    #[cfg(feature = "stark-babybear")]
    {
        out.push(StarkFieldInfo { field: StarkField::BabyBear, name: "babybear", enabled: true, feature: "stark-babybear", reason: "enabled" });
        out.push(StarkFieldInfo { field: StarkField::Plonky3BabyBear, name: "plonky3-babybear", enabled: true, feature: "stark-babybear", reason: "enabled" });
        out.push(StarkFieldInfo { field: StarkField::BabyBearStd, name: "babybear-std", enabled: true, feature: "stark-babybear", reason: "enabled" });
        out.push(StarkFieldInfo { field: StarkField::KoalaBear, name: "koalabear", enabled: true, feature: "stark-babybear", reason: "enabled" });
        out.push(StarkFieldInfo { field: StarkField::Plonky3KoalaBear, name: "plonky3-koalabear", enabled: true, feature: "stark-babybear", reason: "enabled" });
    }
    #[cfg(feature = "stark-m31")]
    {
        out.push(StarkFieldInfo { field: StarkField::CairoPrime, name: "cairo", enabled: true, feature: "stark-m31", reason: "enabled" });
        out.push(StarkFieldInfo { field: StarkField::M31, name: "m31", enabled: true, feature: "stark-m31", reason: "enabled" });
        out.push(StarkFieldInfo { field: StarkField::Plonky3M31, name: "plonky3-m31", enabled: true, feature: "stark-m31", reason: "enabled" });
    }
    out
}

#[cfg(not(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31")))]
pub fn stark_field_registry() -> Vec<StarkFieldInfo> {
    Vec::new()
}

pub fn stark_field_info(field: StarkField) -> Option<StarkFieldInfo> {
    stark_field_registry().into_iter().find(|info| info.field == field)
}

pub fn stark_field_name(field: StarkField) -> &'static str {
    match field {
        #[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
        StarkField::F128 => "f128",
        #[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
        StarkField::F64 => "f64",
        #[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
        StarkField::Goldilocks => "goldilocks",
        #[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
        StarkField::Plonky3Goldilocks => "plonky3-goldilocks",
        #[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
        StarkField::MidenGoldilocks => "miden",
        #[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
        StarkField::CairoPrime => "cairo",
        #[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
        StarkField::M31 => "m31",
        #[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
        StarkField::Plonky3M31 => "plonky3-m31",
        #[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
        StarkField::BabyBear => "babybear",
        #[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
        StarkField::Plonky3BabyBear => "plonky3-babybear",
        #[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
        StarkField::BabyBearStd => "babybear-std",
        #[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
        StarkField::KoalaBear => "koalabear",
        #[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
        StarkField::Plonky3KoalaBear => "plonky3-koalabear",
        #[cfg(not(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31")))]
        StarkField::Disabled => "disabled",
    }
}

pub fn available_families() -> Vec<AdapterFamilyInfo> {
    registry().into_iter().filter(|info| info.enabled).collect()
}

pub fn available_snark_kinds() -> Vec<SnarkKindInfo> {
    snark_kind_registry()
        .into_iter()
        .filter(|info| info.enabled)
        .collect()
}

pub fn available_stark_fields() -> Vec<StarkFieldInfo> {
    stark_field_registry()
        .into_iter()
        .filter(|info| info.enabled)
        .collect()
}

#[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
pub fn stark_field_supported_by_family(family: AdapterFamily, field: StarkField) -> bool {
    match family {
        AdapterFamily::StarkGoldilocks => matches!(
            field,
            StarkField::F128
                | StarkField::F64
                | StarkField::Goldilocks
                | StarkField::Plonky3Goldilocks
                | StarkField::MidenGoldilocks
        ),
        AdapterFamily::StarkBabyBear => matches!(
            field,
            StarkField::BabyBear
                | StarkField::Plonky3BabyBear
                | StarkField::BabyBearStd
                | StarkField::KoalaBear
                | StarkField::Plonky3KoalaBear
        ),
        AdapterFamily::StarkM31 => matches!(field, StarkField::CairoPrime | StarkField::M31 | StarkField::Plonky3M31),
        _ => false,
    }
}

#[cfg(not(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31")))]
pub fn stark_field_supported_by_family(_family: AdapterFamily, _field: StarkField) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_family_registry_flags() {
        let hash = match family_info(AdapterFamily::Hash) {
            Some(info) => info,
            None => {
                assert!(false, "hash family missing");
                return;
            }
        };
        assert_eq!(hash.enabled, cfg!(feature = "hash"));
        let snark = match family_info(AdapterFamily::Snark) {
            Some(info) => info,
            None => {
                assert!(false, "snark family missing");
                return;
            }
        };
        assert_eq!(snark.enabled, cfg!(feature = "snark"));
        let ivc = match family_info(AdapterFamily::Ivc) {
            Some(info) => info,
            None => {
                assert!(false, "ivc family missing");
                return;
            }
        };
        assert_eq!(ivc.enabled, cfg!(feature = "ivc"));
        let binius = match family_info(AdapterFamily::Binius) {
            Some(info) => info,
            None => {
                assert!(false, "binius family missing");
                return;
            }
        };
        assert_eq!(binius.enabled, cfg!(feature = "binius"));
        let stark_goldilocks = match family_info(AdapterFamily::StarkGoldilocks) {
            Some(info) => info,
            None => {
                assert!(false, "stark-goldilocks family missing");
                return;
            }
        };
        assert_eq!(stark_goldilocks.enabled, cfg!(feature = "stark-goldilocks"));
        let stark_babybear = match family_info(AdapterFamily::StarkBabyBear) {
            Some(info) => info,
            None => {
                assert!(false, "stark-babybear family missing");
                return;
            }
        };
        assert_eq!(stark_babybear.enabled, cfg!(feature = "stark-babybear"));
        let stark_m31 = match family_info(AdapterFamily::StarkM31) {
            Some(info) => info,
            None => {
                assert!(false, "stark-m31 family missing");
                return;
            }
        };
        assert_eq!(stark_m31.enabled, cfg!(feature = "stark-m31"));
    }

    #[test]
    fn test_snark_kind_registry_flags() {
        for info in snark_kind_registry() {
            assert_eq!(info.enabled, cfg!(feature = "snark"));
        }
    }

    #[test]
    fn test_stark_field_registry_flags() {
        let fields = stark_field_registry();
        let has_goldilocks = fields.iter().any(|info| info.feature == "stark-goldilocks");
        let has_babybear = fields.iter().any(|info| info.feature == "stark-babybear");
        let has_m31 = fields.iter().any(|info| info.feature == "stark-m31");
        assert_eq!(has_goldilocks, cfg!(feature = "stark-goldilocks"));
        assert_eq!(has_babybear, cfg!(feature = "stark-babybear"));
        assert_eq!(has_m31, cfg!(feature = "stark-m31"));
    }
}
