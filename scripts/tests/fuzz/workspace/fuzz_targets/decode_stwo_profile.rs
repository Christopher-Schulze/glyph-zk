#![no_main]

use libfuzzer_sys::fuzz_target;

#[cfg(feature = "stark-m31")]
use glyph::stwo_verifier::StwoProfile;

#[cfg(feature = "stark-m31")]
fn run(data: &[u8]) {
    let _ = StwoProfile::decode(data);
}

#[cfg(not(feature = "stark-m31"))]
fn run(_data: &[u8]) {}

fuzz_target!(|data: &[u8]| {
    run(data);
});
