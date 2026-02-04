#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Generate a valid AdapterIr encoding (so decode reaches deep parsing), then optionally corrupt.
    use glyph::adapter_ir::{AdapterIr, AdapterIrOp};
    use glyph::adapter_ir::kernel_id;

    let op_count = (data.get(0).copied().unwrap_or(0) % 3) as usize + 1;
    let kernel_ids: [u16; 5] = [
        kernel_id::HASH_SHA3_MERGE,
        kernel_id::GROTH16_BN254_VERIFY,
        kernel_id::KZG_BN254_VERIFY,
        kernel_id::IVC_VERIFY,
        kernel_id::IPA_VERIFY,
    ];

    let mut ops = Vec::with_capacity(op_count);
    let mut off = 1usize;
    for i in 0..op_count {
        let kid = kernel_ids[(data.get(off).copied().unwrap_or(0) as usize) % kernel_ids.len()];
        off = off.saturating_add(1);

        let take = (data.get(off).copied().unwrap_or(0) as usize).min(192);
        off = off.saturating_add(1);
        let end = off.saturating_add(take).min(data.len());
        let args = data.get(off..end).unwrap_or(&[]).to_vec();
        off = end;

        ops.push(AdapterIrOp { kernel_id: kid, args });

        if i + 1 < op_count && off >= data.len() {
            off = 1;
        }
    }

    let ir = AdapterIr { version: glyph::adapter_ir::ADAPTER_IR_VERSION, ops };
    let mut enc = ir.encode();

    if !enc.is_empty() && data.len() > 2 {
        let idx = (data[1] as usize) % enc.len();
        enc[idx] ^= data[2];
    }

    let _ = AdapterIr::decode(&enc);
});
