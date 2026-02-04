#![no_main]

use libfuzzer_sys::fuzz_target;

#[cfg(all(feature = "ivc", feature = "ivc-supernova"))]
use glyph::ivc_supernova::decode_supernova_external_proof_bytes;

#[cfg(all(feature = "ivc", feature = "ivc-supernova"))]
fn run(data: &[u8]) {
    let _ = decode_supernova_external_proof_bytes(data);
}

#[cfg(not(all(feature = "ivc", feature = "ivc-supernova")))]
fn run(_data: &[u8]) {}

fuzz_target!(|data: &[u8]| {
    run(data);
});
