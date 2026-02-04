#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the Stark receipt decoder
    // We expect errors for invalid data, but NO PANICS.
    let _ = glyph::stark_receipt::CanonicalStarkReceipt::decode(data);
});
