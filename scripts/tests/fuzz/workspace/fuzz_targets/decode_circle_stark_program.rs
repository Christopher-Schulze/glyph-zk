#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Exercise circle program decoding via encode->decode with minimal valid structures.
    use glyph::circle_stark::{
        CircleStarkExprProgram, CircleStarkSimpleProgram, decode_circle_stark_program,
        FIELD_M31_CIRCLE_ID, HASH_SHA3_ID, VC_MERKLE_ID,
    };

    let trace_width = (data.get(0).copied().unwrap_or(1) as u16).max(1).min(8);
    let trace_length = (data.get(1).copied().unwrap_or(1) as u32).max(1);
    let air_len = (data.get(2).copied().unwrap_or(0) as usize).min(32);
    let air_id = data.get(3..3 + air_len).unwrap_or(&[]).to_vec();

    let use_expr = data.get(3 + air_len).copied().unwrap_or(0) & 1 == 1;

    let mut enc = if use_expr {
        let p = CircleStarkExprProgram {
            version: 2,
            field_id: FIELD_M31_CIRCLE_ID,
            hash_id: HASH_SHA3_ID,
            commitment_scheme_id: VC_MERKLE_ID,
            trace_width,
            trace_length,
            constraints: Vec::new(),
            air_id,
        };
        p.encode()
    } else {
        let p = CircleStarkSimpleProgram {
            version: 1,
            field_id: FIELD_M31_CIRCLE_ID,
            hash_id: HASH_SHA3_ID,
            commitment_scheme_id: VC_MERKLE_ID,
            trace_width,
            trace_length,
            constraints: Vec::new(),
            air_id,
        };
        p.encode()
    };

    if !enc.is_empty() && data.len() > 8 {
        let idx = (data.get(4).copied().unwrap_or(0) as usize) % enc.len();
        enc[idx] ^= data.get(5).copied().unwrap_or(0);
    }

    let _ = decode_circle_stark_program(&enc);
});
