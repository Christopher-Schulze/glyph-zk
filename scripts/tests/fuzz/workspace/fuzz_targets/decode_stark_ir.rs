#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Exercise STARK verifier IR decoding with a structurally valid encoding.
    use glyph::stark_ir::{IrOp, StarkVerifierIr};
    use glyph::stark_ir::kernel_id;

    let op_count = (data.get(0).copied().unwrap_or(0) % 4) as usize;
    let kernel_ids: [u16; 8] = [
        kernel_id::WINTERFELL_SHA3_TRANSCRIPT,
        kernel_id::WINTERFELL_SHA3_TRACE_OPENINGS,
        kernel_id::WINTERFELL_SHA3_CONSTRAINT_OPENINGS,
        kernel_id::WINTERFELL_SHA3_FRI_OPENINGS,
        kernel_id::WINTERFELL_SHA3_FRI_REMAINDER,
        kernel_id::WINTERFELL_FRI_VERIFY,
        kernel_id::WINTERFELL_AIR_VERIFY,
        kernel_id::WINTERFELL_DEEP_COMPOSITION,
    ];

    let mut ops = Vec::with_capacity(op_count);
    let mut off = 1usize;
    for _ in 0..op_count {
        let kid = kernel_ids[(data.get(off).copied().unwrap_or(0) as usize) % kernel_ids.len()];
        off = off.saturating_add(1);

        let take = (data.get(off).copied().unwrap_or(0) as usize).min(192);
        off = off.saturating_add(1);
        let end = off.saturating_add(take).min(data.len());
        let args = data.get(off..end).unwrap_or(&[]).to_vec();
        off = end;

        ops.push(IrOp { kernel_id: kid, args });

        if off >= data.len() {
            off = 1;
        }
    }

    let ir = StarkVerifierIr { version: 1, ops };
    let mut enc = ir.encode();

    if !enc.is_empty() && data.len() > 2 {
        let idx = (data[1] as usize) % enc.len();
        enc[idx] ^= data[2];
    }

    let _ = StarkVerifierIr::decode(&enc);
});
