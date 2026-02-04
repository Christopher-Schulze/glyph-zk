use crate::adapter_registry;
use crate::adapters::{AdapterFamily, SnarkKind, StarkField};

pub fn ensure_family_enabled(family: AdapterFamily) -> Result<(), String> {
    let info = adapter_registry::family_info(family)
        .ok_or_else(|| format!("unknown adapter family: {:?}", family))?;
    if info.enabled {
        Ok(())
    } else {
        Err(format!(
            "adapter family {} disabled (enable with --features {})",
            info.name, info.feature
        ))
    }
}

pub fn ensure_snark_kind_enabled(kind: SnarkKind) -> Result<(), String> {
    let info = adapter_registry::snark_kind_info(kind)
        .ok_or_else(|| format!("unknown snark kind: {:?}", kind))?;
    if info.enabled {
        Ok(())
    } else {
        Err(format!(
            "snark kind {} disabled (enable with --features {})",
            info.name, info.feature
        ))
    }
}

pub fn ensure_any_stark_enabled() -> Result<(), String> {
    if adapter_registry::any_stark_enabled() {
        Ok(())
    } else {
        Err(
            "stark adapter disabled (enable with --features stark-babybear,stark-goldilocks,stark-m31)"
                .to_string(),
        )
    }
}

pub fn parse_stark_field(raw: &str) -> Result<StarkField, String> {
    StarkField::parse(raw).ok_or_else(|| {
        let enabled = adapter_registry::available_stark_fields();
        if enabled.is_empty() {
            "stark fields disabled (enable with --features stark-babybear,stark-goldilocks,stark-m31)".to_string()
        } else {
            let names: Vec<&str> = enabled.iter().map(|info| info.name).collect();
            format!(
                "invalid --stark-field (use {})",
                names.join("|")
            )
        }
    })
}

pub fn ensure_stark_field_enabled(field: StarkField) -> Result<(), String> {
    let info = adapter_registry::stark_field_info(field)
        .ok_or_else(|| "stark field disabled (enable with --features stark-babybear,stark-goldilocks,stark-m31)".to_string())?;
    if info.enabled {
        Ok(())
    } else {
        Err(format!(
            "stark field {} disabled (enable with --features {})",
            info.name, info.feature
        ))
    }
}

pub fn ensure_stark_field_allowed(family: AdapterFamily, field: StarkField) -> Result<(), String> {
    if adapter_registry::stark_field_supported_by_family(family, field) {
        Ok(())
    } else {
        Err(format!(
            "stark field {} is not valid for family {}",
            adapter_registry::stark_field_name(field),
            adapter_registry::family_name(family)
        ))
    }
}
