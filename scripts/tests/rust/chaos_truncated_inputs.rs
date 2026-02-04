#[test]
fn packed_calldata_rejects_truncated_inputs() {
    let cases: &[&[u8]] = &[
        &[],
        &[0u8],
        &[0u8; 4],
        &[0u8; 16],
        &[0u8; 32],
        &[0u8; 48],
        &[0u8; 64],
    ];
    for case in cases {
        assert!(
            !glyph::glyph_gkr::verify_packed_calldata_be(case),
            "truncated calldata should be rejected"
        );
    }
}
