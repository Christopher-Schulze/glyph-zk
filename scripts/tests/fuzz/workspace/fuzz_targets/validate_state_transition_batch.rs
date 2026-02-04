#![no_main]
use libfuzzer_sys::fuzz_target;

use glyph::state_transition_vm::{
    compile_state_transition_batch, validate_batch, MerkleProof, StateTransitionBatch, StateUpdate,
    VmOpKind,
};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let depth = (data[0] % 8) as usize + 1;
    let updates = (data.get(1).copied().unwrap_or(1) % 8) as usize + 1;
    let mut off = 2usize;
    let mut updates_vec = Vec::with_capacity(updates);

    for _ in 0..updates {
        let key = read_bytes32(data, &mut off);
        let old_value = read_bytes32(data, &mut off);
        let new_value = read_bytes32(data, &mut off);
        let operand = read_bytes32(data, &mut off);

        let mut siblings = Vec::with_capacity(depth);
        let mut path_bits = Vec::with_capacity(depth);
        for _ in 0..depth {
            siblings.push(read_bytes32(data, &mut off));
            path_bits.push((next_byte(data, &mut off) & 1) as u8);
        }

        let op = if next_byte(data, &mut off) & 1 == 0 {
            VmOpKind::Store
        } else {
            VmOpKind::Add
        };

        updates_vec.push(StateUpdate {
            key,
            old_value,
            new_value,
            proof: MerkleProof { siblings, path_bits },
            op,
            operand,
        });
    }

    let old_root = read_bytes32(data, &mut off);
    let batch = StateTransitionBatch {
        old_root,
        updates: updates_vec,
    };

    let _ = validate_batch(&batch);
    let _ = compile_state_transition_batch(&batch);
});

fn read_bytes32(data: &[u8], off: &mut usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    if data.is_empty() {
        return out;
    }
    for i in 0..32 {
        out[i] = data[*off % data.len()];
        *off = off.wrapping_add(1);
    }
    out
}

fn next_byte(data: &[u8], off: &mut usize) -> u8 {
    if data.is_empty() {
        return 0;
    }
    let b = data[*off % data.len()];
    *off = off.wrapping_add(1);
    b
}
