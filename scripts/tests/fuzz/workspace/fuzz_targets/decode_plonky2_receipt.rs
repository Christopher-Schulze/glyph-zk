#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the Plonky2 receipt decoder
    let _ = glyph::plonky2_receipt::decode_plonky2_receipt(data);
});
