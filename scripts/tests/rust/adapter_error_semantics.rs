#[cfg(feature = "snark")]
fn assert_prefix(err: String, prefix: &str) {
    assert!(
        err.starts_with(prefix),
        "expected prefix {prefix}, got {err}"
    );
}

#[cfg(feature = "snark")]
#[test]
fn error_prefix_plonk() {
    let err = glyph::plonk_adapter::verify_plonk_receipt(&[]).unwrap_err();
    assert_prefix(err, "adapter::plonk:");
}

#[cfg(feature = "snark")]
#[test]
fn error_prefix_halo2() {
    let err = glyph::halo2_receipt::verify_halo2_receipt(&[]).unwrap_err();
    assert_prefix(err, "adapter::halo2:");
}

#[cfg(feature = "snark")]
#[test]
fn error_prefix_sp1() {
    let err = glyph::sp1_adapter::verify_sp1_receipt(&[]).unwrap_err();
    assert_prefix(err, "adapter::sp1:");
}

#[cfg(feature = "snark")]
#[test]
fn error_prefix_groth16_bls12381() {
    let err = glyph::groth16_bls12381::verify_groth16_bls12381_receipt(&[])
        .unwrap_err();
    assert_prefix(err, "adapter::groth16_bls12381:");
}

#[cfg(feature = "snark")]
#[test]
fn error_prefix_kzg_bls12381() {
    let err = glyph::kzg_bls12381::verify_kzg_bls12381_receipt(&[]).unwrap_err();
    assert_prefix(err, "adapter::kzg_bls12381:");
}

#[cfg(feature = "snark")]
#[test]
fn error_prefix_ipa() {
    let err = glyph::ipa_adapter::verify_ipa_receipt(&[]).unwrap_err();
    assert_prefix(err, "adapter::ipa:");
}
