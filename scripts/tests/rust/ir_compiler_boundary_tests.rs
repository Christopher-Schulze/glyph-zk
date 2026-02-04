#[cfg(feature = "snark")]
#[test]
fn compile_sp1_rejects_empty_receipt() {
    let err = glyph::glyph_ir_compiler::compile_sp1(&[]).expect_err("empty sp1 should error");
    match err {
        glyph::glyph_ir_compiler::CompileError::VerificationFailed(_) => {}
        _ => panic!("unexpected error kind"),
    }
}

#[cfg(feature = "snark")]
#[test]
fn compile_plonk_rejects_empty_receipt() {
    let err = glyph::glyph_ir_compiler::compile_plonk(&[]).expect_err("empty plonk should error");
    match err {
        glyph::glyph_ir_compiler::CompileError::VerificationFailed(_) => {}
        _ => panic!("unexpected error kind"),
    }
}

#[cfg(feature = "snark")]
#[test]
fn compile_ipa_rejects_empty_receipt() {
    let err = glyph::glyph_ir_compiler::compile_ipa(&[]).expect_err("empty ipa should error");
    match err {
        glyph::glyph_ir_compiler::CompileError::VerificationFailed(_) => {}
        _ => panic!("unexpected error kind"),
    }
}
