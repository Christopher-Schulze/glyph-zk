//! Cross-implementation checks for Risc0 fixtures.

use glyph::risc_zero_bundle::{decode_risc_zero_receipt_input, RiscZeroReceiptInput};
use glyph::stark_receipt::CanonicalStarkVk;
use glyph::standard_stark::StandardStarkProgram;

fn load_fixture(path: &str) -> Vec<u8> {
    std::fs::read(path).expect("fixture must be readable")
}

fn decode_fixture(path: &str) -> (glyph::stark_receipt::CanonicalStarkReceipt, StandardStarkProgram) {
    let raw = load_fixture(path);
    let input = decode_risc_zero_receipt_input(&raw).expect("decode");
    match input {
        RiscZeroReceiptInput::Bundle(bundle) => bundle.into_receipt_and_program().expect("bundle"),
        RiscZeroReceiptInput::External(receipt) => receipt.into_receipt_and_program().expect("receipt"),
    }
}

#[test]
fn risc_zero_bundle_fixture_decodes() {
    let (receipt, program) =
        decode_fixture("scripts/tools/fixtures/risc_zero_bundle.json");
    let vk = CanonicalStarkVk::decode(&receipt.vk_bytes).expect("vk decode");
    let program_from_vk =
        StandardStarkProgram::decode(&vk.program_bytes).expect("program decode");
    assert_eq!(program_from_vk, program);
}

#[test]
fn risc_zero_external_fixture_decodes() {
    let (receipt, program) =
        decode_fixture("scripts/tools/fixtures/risc_zero_external_receipt.json");
    let vk = CanonicalStarkVk::decode(&receipt.vk_bytes).expect("vk decode");
    let program_from_vk =
        StandardStarkProgram::decode(&vk.program_bytes).expect("program decode");
    assert_eq!(program_from_vk, program);
}
