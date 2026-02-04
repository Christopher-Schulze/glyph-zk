#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Exercise circle proof decoding (including nested CircleFriProof decoding).
    use glyph::circle_fri::CircleFriProof;
    use glyph::circle_stark::{CircleStarkProof, FIELD_M31_CIRCLE_ID, HASH_SHA3_ID, VC_MERKLE_ID};

    let trace_width = (data.get(0).copied().unwrap_or(1) as u16).max(1).min(8);
    let trace_length = (data.get(1).copied().unwrap_or(1) as u32).max(1);

    let mut trace_root = [0u8; 32];
    if data.len() >= 34 {
        trace_root.copy_from_slice(&data[2..34]);
    }

    let row_len = trace_width as usize;
    let mut first_row = vec![0u32; row_len];
    let mut last_row = vec![0u32; row_len];
    for i in 0..row_len {
        first_row[i] = data.get(34 + i).copied().unwrap_or(0) as u32;
        last_row[i] = data.get(42 + i).copied().unwrap_or(0) as u32;
    }

    let fri = CircleFriProof {
        version: 1,
        log_domain_size: (data.get(2).copied().unwrap_or(1) % 8).max(1),
        layers: Vec::new(),
        final_value: 0,
    };

    let proof = CircleStarkProof {
        version: 1,
        trace_length,
        trace_width,
        trace_root,
        first_row,
        first_row_proof: Vec::new(),
        last_row,
        last_row_proof: Vec::new(),
        queries: Vec::new(),
        fri_proof: fri,
    };

    let mut enc = proof.encode();
    if !enc.is_empty() && data.len() > 6 {
        let idx = (data.get(3).copied().unwrap_or(0) as usize) % enc.len();
        enc[idx] ^= data.get(4).copied().unwrap_or(0);
    }

    // decode path
    let _ = glyph::circle_stark::CircleStarkProof::decode(&enc);

    // also try to decode a CanonicalStarkVk that embeds a circle program (to reach nested decode paths)
    let program_bytes = glyph::circle_stark::decode_circle_stark_program;
    let _ = program_bytes;

    let _ = (FIELD_M31_CIRCLE_ID, HASH_SHA3_ID, VC_MERKLE_ID);
});
