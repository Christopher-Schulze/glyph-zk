#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Exercise WinterfellStarkProgram decoding including nested StarkVerifierIr decoding.
    use glyph::stark_ir::StarkVerifierIr;
    use glyph::stark_program::WinterfellStarkProgram;

    let air_len = (data.get(0).copied().unwrap_or(0) as usize).min(64);
    let ir_op_count = (data.get(1).copied().unwrap_or(0) % 3) as usize;

    let air_id = data.get(2..2 + air_len).unwrap_or(&[]).to_vec();

    let ir = StarkVerifierIr { version: 1, ops: Vec::with_capacity(ir_op_count) };
    let ir_bytes = ir.encode();

    let mut impl_id = [0u8; 16];
    if data.len() >= 18 {
        impl_id.copy_from_slice(&data[2..18]);
    }

    let program = WinterfellStarkProgram {
        version: 1,
        impl_id,
        field_id: data.get(18).copied().unwrap_or(0),
        hash_id: data.get(19).copied().unwrap_or(0),
        commitment_scheme_id: data.get(20).copied().unwrap_or(0),
        air_id,
        ir_bytes,
    };

    let mut enc = program.encode();
    if !enc.is_empty() && data.len() > 24 {
        let idx = (data[21] as usize) % enc.len();
        enc[idx] ^= data[22];
    }

    let _ = WinterfellStarkProgram::decode(&enc);
});
