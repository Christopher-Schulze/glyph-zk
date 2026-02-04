#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Exercise packed calldata verifiers with canonical (small) field elements so we reach
    // the inner sumcheck loop instead of failing u256 canonicality checks immediately.
    if data.is_empty() {
        return;
    }

    let rounds = (data[0] % 4) as usize + 1;
    let is_full = data.get(1).copied().unwrap_or(0) & 1 == 0;
    let stride_words = if is_full { 4 } else { 3 };
    let words = 1 + rounds * stride_words + 1;

    let mut payload = vec![0u8; words * 32];
    for i in 0..words {
        let v = data.get(2 + i).copied().unwrap_or(0) as u64;
        // canonical u256: all zeros except last 8 bytes
        payload[i * 32 + 24..i * 32 + 32].copy_from_slice(&v.to_be_bytes());
    }

    let _ = glyph::glyph_gkr::verify_packed_calldata_be(&payload);

    // Also test statement-bound verifier wrapper. We use canonical small header words to avoid
    // immediate fallback failure.
    let mut statement_bound = vec![0u8; 64 + payload.len()];
    // meta (canonical small)
    statement_bound[56..64].copy_from_slice(&(data.get(9).copied().unwrap_or(0) as u64).to_be_bytes());
    // statement (canonical small)
    statement_bound[88..96].copy_from_slice(&(data.get(10).copied().unwrap_or(0) as u64).to_be_bytes());
    statement_bound[64..].copy_from_slice(&payload);

    let chainid = 31337u64;
    let addr = [0x11u8; 20];
    let _ = glyph::glyph_gkr::verify_packed_calldata_be_with_binding_env(&statement_bound, chainid, addr);
});
