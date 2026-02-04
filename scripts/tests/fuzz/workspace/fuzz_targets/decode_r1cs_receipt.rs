#![no_main]

use libfuzzer_sys::fuzz_target;

#[cfg(feature = "ivc")]
use glyph::ivc_r1cs::decode_r1cs_receipt;

#[cfg(feature = "ivc")]
fn run(data: &[u8]) {
    let _ = decode_r1cs_receipt(data);
}

#[cfg(not(feature = "ivc"))]
fn run(_data: &[u8]) {}

fuzz_target!(|data: &[u8]| {
    run(data);
});
