use crate::adapter_registry;
use crate::adapters::AdapterFamily;

pub fn join_list(items: &[&str]) -> String {
    if items.is_empty() {
        "none".to_string()
    } else {
        items.join(", ")
    }
}

pub fn format_feature_status(feature: &str, enabled: bool) -> String {
    let status = if enabled { "enabled" } else { "disabled" };
    format!("{feature} ({status})")
}

pub fn family_feature_enabled(family: AdapterFamily) -> bool {
    adapter_registry::family_info(family)
        .map(|info| info.enabled)
        .unwrap_or(false)
}

pub fn snark_feature_enabled() -> bool {
    adapter_registry::snark_kind_registry()
        .first()
        .map(|info| info.enabled)
        .unwrap_or(false)
}

pub fn enabled_families() -> Vec<&'static str> {
    adapter_registry::available_families()
        .iter()
        .map(|info| info.name)
        .collect()
}

pub fn enabled_snark_kinds() -> Vec<&'static str> {
    adapter_registry::available_snark_kinds()
        .iter()
        .map(|info| info.name)
        .collect()
}

pub fn enabled_stark_fields() -> Vec<&'static str> {
    adapter_registry::available_stark_fields()
        .iter()
        .map(|info| info.name)
        .collect()
}
