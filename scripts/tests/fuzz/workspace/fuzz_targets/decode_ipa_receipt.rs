#![no_main]
use libfuzzer_sys::fuzz_target;
use glyph::ipa_adapter::IpaReceipt;

fuzz_target!(|data: &[u8]| {
    // Should not panic
    let _ = glyph::ipa_adapter::decode_ipa_receipt(data);
});
