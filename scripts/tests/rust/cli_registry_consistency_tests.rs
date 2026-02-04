use glyph::adapter_registry;
use glyph::cli_registry;

#[test]
fn cli_enabled_lists_match_registry_inventory() {
    let families: Vec<&str> = adapter_registry::available_families()
        .iter()
        .map(|info| info.name)
        .collect();
    assert_eq!(cli_registry::enabled_families(), families);

    let snark_kinds: Vec<&str> = adapter_registry::available_snark_kinds()
        .iter()
        .map(|info| info.name)
        .collect();
    assert_eq!(cli_registry::enabled_snark_kinds(), snark_kinds);

    let stark_fields: Vec<&str> = adapter_registry::available_stark_fields()
        .iter()
        .map(|info| info.name)
        .collect();
    assert_eq!(cli_registry::enabled_stark_fields(), stark_fields);
}

#[test]
fn cli_snark_feature_flag_matches_registry() {
    let cli_flag = cli_registry::snark_feature_enabled();
    let all_match = adapter_registry::snark_kind_registry()
        .iter()
        .all(|info| info.enabled == cli_flag);
    assert!(all_match, "cli snark flag must match registry entries");
}

