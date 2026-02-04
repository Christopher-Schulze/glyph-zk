#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Build a structurally valid CanonicalStarkVk encoding so we exercise deeper decode paths
    // (length parsing + program_hash binding), then optionally corrupt a byte.
    let consts_len = (data.get(0).copied().unwrap_or(0) as usize).min(128);
    let program_len = (data.get(1).copied().unwrap_or(0) as usize).min(128);

    let mut off = 2usize;
    let consts_end = off.saturating_add(consts_len).min(data.len());
    let consts_bytes = data.get(off..consts_end).unwrap_or(&[]).to_vec();
    off = consts_end;

    let program_end = off.saturating_add(program_len).min(data.len());
    let program_bytes = data.get(off..program_end).unwrap_or(&[]).to_vec();

    let vk = glyph::stark_receipt::CanonicalStarkVk {
        version: 1,
        field_id: data.get(2).copied().unwrap_or(0),
        hash_id: data.get(3).copied().unwrap_or(0),
        commitment_scheme_id: data.get(4).copied().unwrap_or(0),
        consts_bytes,
        program_bytes,
    };

    let mut enc = vk.encode();

    if !enc.is_empty() && data.len() > 8 {
        let idx = (data[5] as usize) % enc.len();
        enc[idx] ^= data[6];
    }

    let _ = glyph::stark_receipt::CanonicalStarkVk::decode(&enc);
});
