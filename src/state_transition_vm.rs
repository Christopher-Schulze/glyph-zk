use crate::adapters::keccak256;
use crate::glyph_field_simd::Goldilocks;
use crate::glyph_ir::{
    ArithmeticGate, CustomGate, WRef, WitnessLayout, CUSTOM_GATE_KECCAK_MERGE,
    encode_three_wref_payload,
};
use crate::glyph_ir_compiler::{CompileContext, CompiledUcir, embed_fq_limbs};
use crate::state_diff_merkle::{
    CpuKeccakHasher,
    MerkleHasher,
    state_diff_merkle_root_with_hasher,
};
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct MerkleProof {
    pub siblings: Vec<[u8; 32]>,
    pub path_bits: Vec<u8>,
}

impl MerkleProof {
    pub fn depth(&self) -> Result<usize, String> {
        if self.siblings.len() != self.path_bits.len() {
            return Err("merkle proof siblings and path_bits length mismatch".to_string());
        }
        Ok(self.siblings.len())
    }
}

#[derive(Clone, Debug)]
pub struct StateUpdate {
    pub key: [u8; 32],
    pub old_value: [u8; 32],
    pub new_value: [u8; 32],
    pub proof: MerkleProof,
    pub op: VmOpKind,
    pub operand: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct StateTransitionBatch {
    pub old_root: [u8; 32],
    pub updates: Vec<StateUpdate>,
}

#[derive(Clone, Debug)]
pub struct BatchSummary {
    pub old_root: [u8; 32],
    pub new_root: [u8; 32],
    pub diff_root: [u8; 32],
}

#[derive(Clone, Debug)]
pub enum VmOp {
    Store { key: [u8; 32], value: [u8; 32] },
    Add { key: [u8; 32], delta: [u8; 32] },
}

#[derive(Clone, Debug)]
pub enum VmOpKind {
    Store,
    Add,
}

impl VmOpKind {
    fn bit(&self) -> u8 {
        match self {
            VmOpKind::Store => 0,
            VmOpKind::Add => 1,
        }
    }
}

#[derive(Clone, Debug)]
pub struct GlyphVm {
    tree: StateTree,
}

#[derive(Clone, Debug)]
pub struct VmTraceStep {
    pub op: VmOp,
    pub update: StateUpdate,
    pub old_root: [u8; 32],
    pub new_root: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct VmTrace {
    pub old_root: [u8; 32],
    pub new_root: [u8; 32],
    pub steps: Vec<VmTraceStep>,
}

#[derive(Clone, Debug)]
struct StateTree {
    depth: usize,
    values: HashMap<u32, [u8; 32]>,
    nodes: HashMap<(usize, u32), [u8; 32]>,
    zero_hashes: Vec<[u8; 32]>,
    leaf_domain: [u8; 32],
}

#[derive(Clone, Debug)]
struct UpdateTrace {
    key: [u8; 32],
    old_value: [u8; 32],
    new_value: [u8; 32],
    proof: MerkleProof,
    leaf_old: [u8; 32],
    leaf_new: [u8; 32],
    op: VmOpKind,
    operand: [u8; 32],
}

pub fn state_transition_schema_id() -> [u8; 32] {
    keccak256(b"GLYPH_STATE_TRANSITION_VM_V1")
}

pub fn leaf_domain() -> [u8; 32] {
    keccak256(b"GLYPH_STATE_TRANSITION_LEAF_V1")
}

pub fn leaf_hash(value: &[u8; 32]) -> [u8; 32] {
    let domain = leaf_domain();
    keccak_merge(&domain, value)
}

pub fn apply_update(
    current_root: [u8; 32],
    update: &StateUpdate,
) -> Result<[u8; 32], String> {
    let depth = update.proof.depth()?;
    if depth == 0 {
        return Err("merkle proof depth must be > 0".to_string());
    }
    key_matches_path_bits(&update.key, &update.proof.path_bits)?;
    let leaf_old = leaf_hash(&update.old_value);
    let root_old = root_from_proof(&leaf_old, &update.proof)?;
    if root_old != current_root {
        return Err("old root mismatch for update".to_string());
    }
    let leaf_new = leaf_hash(&update.new_value);
    let root_new = root_from_proof(&leaf_new, &update.proof)?;
    Ok(root_new)
}

pub fn apply_updates(batch: &StateTransitionBatch) -> Result<[u8; 32], String> {
    let mut current = batch.old_root;
    for update in &batch.updates {
        current = apply_update(current, update)?;
    }
    Ok(current)
}

pub fn validate_batch(batch: &StateTransitionBatch) -> Result<BatchSummary, String> {
    for update in &batch.updates {
        match update.op {
            VmOpKind::Store => {
                if update.new_value != update.operand {
                    return Err("store op new_value must equal operand".to_string());
                }
            }
            VmOpKind::Add => {
                let expected = add_u256_be(&update.old_value, &update.operand);
                if update.new_value != expected {
                    return Err("add op new_value mismatch".to_string());
                }
            }
        }
    }
    let new_root = apply_updates(batch)?;
    let diff_root = diff_root_from_updates(&batch.updates);
    Ok(BatchSummary {
        old_root: batch.old_root,
        new_root,
        diff_root,
    })
}

pub fn diff_root_from_updates(updates: &[StateUpdate]) -> [u8; 32] {
    let bytes = diff_bytes_from_updates(updates);
    let (root, _) = state_diff_merkle_root_with_hasher(&bytes, &CpuKeccakHasher);
    root
}

pub fn diff_root_from_updates_with_hasher(
    updates: &[StateUpdate],
    hasher: &dyn MerkleHasher,
) -> [u8; 32] {
    let bytes = diff_bytes_from_updates(updates);
    let (root, _) = state_diff_merkle_root_with_hasher(&bytes, hasher);
    root
}

pub fn compile_state_transition_batch(batch: &StateTransitionBatch) -> Result<CompiledUcir, String> {
    if batch.updates.is_empty() {
        return Err("state transition batch must include at least one update".to_string());
    }

    let depth = batch.updates[0].proof.depth()?;
    if depth == 0 {
        return Err("merkle proof depth must be > 0".to_string());
    }

    let mut traces = Vec::with_capacity(batch.updates.len());
    let mut current_root = batch.old_root;
    for update in &batch.updates {
        if update.proof.depth()? != depth {
            return Err("all updates must use the same merkle depth".to_string());
        }
        key_matches_path_bits(&update.key, &update.proof.path_bits)?;
        let leaf_old = leaf_hash(&update.old_value);
        let leaf_new = leaf_hash(&update.new_value);
        let root_old = root_from_proof(&leaf_old, &update.proof)?;
        if root_old != current_root {
            return Err("old root mismatch for update".to_string());
        }
        let root_new = root_from_proof(&leaf_new, &update.proof)?;
        traces.push(UpdateTrace {
            key: update.key,
            old_value: update.old_value,
            new_value: update.new_value,
            proof: update.proof.clone(),
            leaf_old,
            leaf_new,
            op: update.op.clone(),
            operand: update.operand,
        });
        current_root = root_new;
    }
    let new_root = current_root;
    let diff_root = diff_root_from_updates(&batch.updates);

    let mut public_inputs = Vec::with_capacity(12);
    public_inputs.extend_from_slice(&embed_fq_limbs(&batch.old_root));
    public_inputs.extend_from_slice(&embed_fq_limbs(&new_root));
    public_inputs.extend_from_slice(&embed_fq_limbs(&diff_root));

    let pub_count = public_inputs.len() as u32;
    let mut ctx = CompileContext::new(pub_count);
    let mut wire_values: Vec<Goldilocks> = Vec::new();

    let one = alloc_constant(&mut ctx, &mut wire_values, Goldilocks::ONE);
    let zero = alloc_constant(&mut ctx, &mut wire_values, Goldilocks::ZERO);

    let mut current_root_ref = WRef(0);
    let final_root_ref = WRef(4);
    let diff_root_ref = WRef(8);

    let mut diff_leaf_refs: Vec<WRef> = Vec::with_capacity(traces.len());

    let leaf_domain_val = leaf_domain();
    let leaf_domain_ref = alloc_node(&mut ctx, &mut wire_values, &leaf_domain_val);

    for trace in &traces {
        let key_ref = alloc_node(&mut ctx, &mut wire_values, &trace.key);
        let old_ref = alloc_node(&mut ctx, &mut wire_values, &trace.old_value);
        let new_ref = alloc_node(&mut ctx, &mut wire_values, &trace.new_value);
        let operand_ref = alloc_node(&mut ctx, &mut wire_values, &trace.operand);

        let op_bit = trace.op.bit();
        let op_wire = alloc_wire_value(&mut ctx, &mut wire_values, Goldilocks(op_bit as u64));
        ctx.bit(op_wire);

        let leaf_old_ref = alloc_node(&mut ctx, &mut wire_values, &trace.leaf_old);
        add_keccak_gate(&mut ctx, leaf_domain_ref, old_ref, leaf_old_ref);

        let leaf_new_ref = alloc_node(&mut ctx, &mut wire_values, &trace.leaf_new);
        add_keccak_gate(&mut ctx, leaf_domain_ref, new_ref, leaf_new_ref);

        diff_leaf_refs.push(key_ref);
        diff_leaf_refs.push(old_ref);
        diff_leaf_refs.push(new_ref);

        if trace.proof.path_bits.len() > 32 {
            return Err("merkle depth must be <= 32".to_string());
        }

        let mut bit_wires = Vec::with_capacity(trace.proof.path_bits.len());
        let mut bit_vals = Vec::with_capacity(trace.proof.path_bits.len());
        for bit_val in &trace.proof.path_bits {
            if *bit_val > 1 {
                return Err("path_bits must be 0 or 1".to_string());
            }
            let bit_wire = alloc_wire_value(&mut ctx, &mut wire_values, Goldilocks(*bit_val as u64));
            ctx.bit(bit_wire);
            bit_wires.push(bit_wire);
            bit_vals.push(*bit_val);
        }

        let index_wire = alloc_index_from_bits(&mut ctx, &mut wire_values, zero, &bit_wires, &bit_vals);
        ctx.copy(index_wire, key_ref);
        for i in 1..4 {
            ctx.copy(zero, WRef(key_ref.0 + i));
        }

        let mut old_curr_ref = leaf_old_ref;
        let mut new_curr_ref = leaf_new_ref;
        let mut old_curr_val = trace.leaf_old;
        let mut new_curr_val = trace.leaf_new;

        for (level, sibling) in trace.proof.siblings.iter().enumerate() {
            let bit_wire = bit_wires[level];
            let one_minus_bit = alloc_one_minus_bit(
                &mut ctx,
                &mut wire_values,
                pub_count,
                bit_wire,
                one,
            );

            let sibling_ref = alloc_node(&mut ctx, &mut wire_values, sibling);

            let (old_left_ref, old_right_ref, old_left_val, old_right_val) =
                select_left_right(
                    &mut ctx,
                    &mut wire_values,
                    pub_count,
                    bit_wire,
                    one_minus_bit,
                    old_curr_ref,
                    &old_curr_val,
                    sibling_ref,
                    sibling,
                );
            let old_parent = keccak_merge(&old_left_val, &old_right_val);
            let old_parent_ref = alloc_node(&mut ctx, &mut wire_values, &old_parent);
            add_keccak_gate(&mut ctx, old_left_ref, old_right_ref, old_parent_ref);
            old_curr_ref = old_parent_ref;
            old_curr_val = old_parent;

            let (new_left_ref, new_right_ref, new_left_val, new_right_val) =
                select_left_right(
                    &mut ctx,
                    &mut wire_values,
                    pub_count,
                    bit_wire,
                    one_minus_bit,
                    new_curr_ref,
                    &new_curr_val,
                    sibling_ref,
                    sibling,
                );
            let new_parent = keccak_merge(&new_left_val, &new_right_val);
            let new_parent_ref = alloc_node(&mut ctx, &mut wire_values, &new_parent);
            add_keccak_gate(&mut ctx, new_left_ref, new_right_ref, new_parent_ref);
            new_curr_ref = new_parent_ref;
            new_curr_val = new_parent;
        }

        for i in 0..4 {
            ctx.copy(WRef(old_curr_ref.0 + i), WRef(current_root_ref.0 + i));
        }
        current_root_ref = new_curr_ref;

        let (add_limbs, carry_bits) = add_u256_le_limbs(&trace.old_value, &trace.operand);
        enforce_add_select(
            &mut ctx,
            &mut wire_values,
            pub_count,
            op_wire,
            old_ref,
            operand_ref,
            new_ref,
            &add_limbs,
            &carry_bits,
        );
    }

    for i in 0..4 {
        ctx.copy(WRef(current_root_ref.0 + i), WRef(final_root_ref.0 + i));
    }

    let mut diff_leaves = diff_leaf_refs;
    if diff_leaves.is_empty() {
        let zero_leaf = alloc_node(&mut ctx, &mut wire_values, &[0u8; 32]);
        enforce_zero_node(&mut ctx, zero, zero_leaf);
        diff_leaves.push(zero_leaf);
    }
    let target = diff_leaves.len().next_power_of_two();
    while diff_leaves.len() < target {
        let zero_leaf = alloc_node(&mut ctx, &mut wire_values, &[0u8; 32]);
        enforce_zero_node(&mut ctx, zero, zero_leaf);
        diff_leaves.push(zero_leaf);
    }

    let mut diff_layer_refs = diff_leaves;
    while diff_layer_refs.len() > 1 {
        let mut next_layer = Vec::with_capacity(diff_layer_refs.len() / 2);
        for pair in diff_layer_refs.chunks(2) {
            let left_ref = pair[0];
            let right_ref = pair[1];
            let left_val = read_node_bytes(&wire_values, pub_count, left_ref);
            let right_val = read_node_bytes(&wire_values, pub_count, right_ref);
            let parent = keccak_merge(&left_val, &right_val);
            let parent_ref = alloc_node(&mut ctx, &mut wire_values, &parent);
            add_keccak_gate(&mut ctx, left_ref, right_ref, parent_ref);
            next_layer.push(parent_ref);
        }
        diff_layer_refs = next_layer;
    }

    let diff_root_wire = diff_layer_refs[0];
    for i in 0..4 {
        ctx.copy(WRef(diff_root_wire.0 + i), WRef(diff_root_ref.0 + i));
    }

    let mut ucir = ctx.finalize();
    ucir.witness_layout = WitnessLayout::fast_mode(
        public_inputs.len() as u32,
        wire_values.len() as u32,
        0,
    );

    Ok(CompiledUcir {
        ucir,
        public_inputs,
        wire_values,
    })
}

impl GlyphVm {
    pub fn new(depth: usize) -> Result<Self, String> {
        let tree = StateTree::new(depth)?;
        Ok(Self { tree })
    }

    pub fn root(&self) -> [u8; 32] {
        self.tree.root()
    }

    pub fn execute(&mut self, ops: &[VmOp]) -> Result<StateTransitionBatch, String> {
        let (batch, _) = self.execute_with_trace(ops)?;
        Ok(batch)
    }

    pub fn execute_with_trace(&mut self, ops: &[VmOp]) -> Result<(StateTransitionBatch, VmTrace), String> {
        let old_root = self.tree.root();
        let mut updates = Vec::with_capacity(ops.len());
        let mut steps = Vec::with_capacity(ops.len());
        for op in ops {
            let root_before = self.tree.root();
            let (key, new_value) = match op {
                VmOp::Store { key, value } => (*key, *value),
                VmOp::Add { key, delta } => {
                    let idx = index_from_key(key, self.tree.depth)?;
                    let old = self.tree.value_at(idx);
                    (*key, add_u256_be(&old, delta))
                }
            };
            let idx = index_from_key(&key, self.tree.depth)?;
            let update = match op {
                VmOp::Store { value, .. } => {
                    self.tree.update_with_op(idx, new_value, VmOpKind::Store, *value)?
                }
                VmOp::Add { delta, .. } => {
                    self.tree.update_with_op(idx, new_value, VmOpKind::Add, *delta)?
                }
            };
            let root_after = self.tree.root();
            updates.push(update.clone());
            steps.push(VmTraceStep {
                op: op.clone(),
                update,
                old_root: root_before,
                new_root: root_after,
            });
        }
        let batch = StateTransitionBatch { old_root, updates };
        let trace = VmTrace {
            old_root,
            new_root: self.tree.root(),
            steps,
        };
        Ok((batch, trace))
    }
}

impl StateTree {
    fn new(depth: usize) -> Result<Self, String> {
        if depth == 0 || depth > 32 {
            return Err("state tree depth must be in 1..=32".to_string());
        }
        let leaf_domain = leaf_domain();
        let zero_hashes = build_zero_hashes(depth, &leaf_domain);
        Ok(Self {
            depth,
            values: HashMap::new(),
            nodes: HashMap::new(),
            zero_hashes,
            leaf_domain,
        })
    }

    fn root(&self) -> [u8; 32] {
        self.node_hash(self.depth, 0)
    }

    fn value_at(&self, index: usize) -> [u8; 32] {
        self.values.get(&(index as u32)).cloned().unwrap_or([0u8; 32])
    }

    fn update_with_op(
        &mut self,
        index: usize,
        new_value: [u8; 32],
        op: VmOpKind,
        operand: [u8; 32],
    ) -> Result<StateUpdate, String> {
        let key = index_bytes(index as u32);
        let old_value = self.values.get(&(index as u32)).cloned().unwrap_or([0u8; 32]);
        let proof = self.proof_for_index(index);
        if new_value == [0u8; 32] {
            self.values.remove(&(index as u32));
        } else {
            self.values.insert(index as u32, new_value);
        }
        let leaf = self.leaf_hash_value(&new_value);
        self.recompute_path(index, leaf);
        Ok(StateUpdate {
            key,
            old_value,
            new_value,
            proof,
            op,
            operand,
        })
    }

    fn proof_for_index(&self, index: usize) -> MerkleProof {
        let mut siblings = Vec::with_capacity(self.depth);
        let mut path_bits = Vec::with_capacity(self.depth);
        let mut idx = index;
        for level in 0..self.depth {
            let sibling_idx = if idx.is_multiple_of(2) { idx + 1 } else { idx - 1 };
            siblings.push(self.node_hash(level, sibling_idx as u32));
            path_bits.push((idx % 2) as u8);
            idx /= 2;
        }
        MerkleProof { siblings, path_bits }
    }

    fn recompute_path(&mut self, index: usize, leaf: [u8; 32]) {
        self.set_node(0, index as u32, leaf);
        let mut idx = index as u32;
        for level in 0..self.depth {
            let parent_idx = idx / 2;
            let left = self.node_hash(level, parent_idx * 2);
            let right = self.node_hash(level, parent_idx * 2 + 1);
            let parent = keccak_merge(&left, &right);
            self.set_node(level + 1, parent_idx, parent);
            idx = parent_idx;
        }
    }

    fn leaf_hash_value(&self, value: &[u8; 32]) -> [u8; 32] {
        keccak_merge(&self.leaf_domain, value)
    }

    fn node_hash(&self, level: usize, index: u32) -> [u8; 32] {
        self.nodes
            .get(&(level, index))
            .cloned()
            .unwrap_or(self.zero_hashes[level])
    }

    fn set_node(&mut self, level: usize, index: u32, value: [u8; 32]) {
        if value == self.zero_hashes[level] {
            self.nodes.remove(&(level, index));
        } else {
            self.nodes.insert((level, index), value);
        }
    }
}

fn keccak_merge(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(left);
    input[32..].copy_from_slice(right);
    keccak256(&input)
}

fn root_from_proof(leaf: &[u8; 32], proof: &MerkleProof) -> Result<[u8; 32], String> {
    if proof.siblings.len() != proof.path_bits.len() {
        return Err("merkle proof siblings and path_bits length mismatch".to_string());
    }
    let mut current = *leaf;
    for (sibling, bit) in proof.siblings.iter().zip(proof.path_bits.iter()) {
        current = if *bit == 0 {
            keccak_merge(&current, sibling)
        } else if *bit == 1 {
            keccak_merge(sibling, &current)
        } else {
            return Err("path_bits must be 0 or 1".to_string());
        };
    }
    Ok(current)
}

pub fn diff_bytes_from_updates(updates: &[StateUpdate]) -> Vec<u8> {
    let mut out = Vec::with_capacity(updates.len() * 96);
    for u in updates {
        out.extend_from_slice(&u.key);
        out.extend_from_slice(&u.old_value);
        out.extend_from_slice(&u.new_value);
    }
    out
}

fn index_from_key(key: &[u8; 32], depth: usize) -> Result<usize, String> {
    if depth == 0 || depth > 32 {
        return Err("depth must be in 1..=32".to_string());
    }
    if key[4..].iter().any(|b| *b != 0) {
        return Err("key must be a 32-byte index value (little-endian u32 in bytes 0..4)".to_string());
    }
    let mut low = [0u8; 4];
    low.copy_from_slice(&key[0..4]);
    let raw = u32::from_le_bytes(low);
    let mask = if depth == 32 { u32::MAX } else { (1u32 << depth) - 1 };
    Ok((raw & mask) as usize)
}

fn index_bytes(index: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0..4].copy_from_slice(&index.to_le_bytes());
    out
}

fn build_zero_hashes(depth: usize, leaf_domain: &[u8; 32]) -> Vec<[u8; 32]> {
    let mut zeros = Vec::with_capacity(depth + 1);
    let zero_leaf = keccak_merge(leaf_domain, &[0u8; 32]);
    zeros.push(zero_leaf);
    for level in 0..depth {
        let parent = keccak_merge(&zeros[level], &zeros[level]);
        zeros.push(parent);
    }
    zeros
}

fn index_from_path_bits(path_bits: &[u8]) -> Result<u32, String> {
    if path_bits.is_empty() || path_bits.len() > 32 {
        return Err("path_bits length must be in 1..=32".to_string());
    }
    let mut acc: u32 = 0;
    for (i, bit) in path_bits.iter().enumerate() {
        if *bit > 1 {
            return Err("path_bits must be 0 or 1".to_string());
        }
        acc |= (*bit as u32) << i;
    }
    Ok(acc)
}

pub fn key_matches_path_bits(key: &[u8; 32], path_bits: &[u8]) -> Result<(), String> {
    if key[4..].iter().any(|b| *b != 0) {
        return Err("key must be a 32-byte index value (little-endian u32 in bytes 0..4)".to_string());
    }
    let idx = index_from_path_bits(path_bits)?;
    let mut low = [0u8; 4];
    low.copy_from_slice(&key[0..4]);
    let key_idx = u32::from_le_bytes(low);
    if idx != key_idx {
        return Err("key index does not match path_bits".to_string());
    }
    Ok(())
}

fn add_u256_be(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for i in (0..32).rev() {
        let sum = a[i] as u16 + b[i] as u16 + carry;
        out[i] = (sum & 0xFF) as u8;
        carry = sum >> 8;
    }
    out
}

fn add_u256_le_limbs(a: &[u8; 32], b: &[u8; 32]) -> ([u64; 4], [u8; 4]) {
    let a_limbs = bytes_to_limbs(a);
    let b_limbs = bytes_to_limbs(b);
    let mut out = [0u64; 4];
    let mut carry = 0u128;
    let mut carries = [0u8; 4];
    for i in 0..4 {
        let sum = a_limbs[i] as u128 + b_limbs[i] as u128 + carry;
        out[i] = (sum & 0xFFFF_FFFF_FFFF_FFFF) as u64;
        carry = sum >> 64;
        carries[i] = carry as u8;
    }
    (out, carries)
}

fn bytes_to_limbs(bytes: &[u8; 32]) -> [u64; 4] {
    let mut out = [0u64; 4];
    for (i, limb) in out.iter_mut().enumerate() {
        let start = i * 8;
        let mut limb_bytes = [0u8; 8];
        limb_bytes.copy_from_slice(&bytes[start..start + 8]);
        *limb = u64::from_le_bytes(limb_bytes);
    }
    out
}

fn alloc_constant(
    ctx: &mut CompileContext,
    wire_values: &mut Vec<Goldilocks>,
    val: Goldilocks,
) -> WRef {
    let w = ctx.alloc_wire_with_value(wire_values, val);
    ctx.ucir.add_arithmetic_gate(ArithmeticGate::constant(w, val));
    w
}

fn alloc_wire_value(
    ctx: &mut CompileContext,
    wire_values: &mut Vec<Goldilocks>,
    val: Goldilocks,
) -> WRef {
    ctx.alloc_wire_with_value(wire_values, val)
}

fn alloc_node(
    ctx: &mut CompileContext,
    wire_values: &mut Vec<Goldilocks>,
    bytes: &[u8; 32],
) -> WRef {
    let limbs = bytes_to_limbs(bytes);
    ctx.alloc_fq_limbs(wire_values, limbs)
}

fn add_keccak_gate(ctx: &mut CompileContext, left: WRef, right: WRef, out: WRef) {
    let payload = encode_three_wref_payload(left, right, out);
    ctx.ucir.add_custom_gate(CustomGate::new(CUSTOM_GATE_KECCAK_MERGE, payload));
}

fn alloc_one_minus_bit(
    ctx: &mut CompileContext,
    wire_values: &mut Vec<Goldilocks>,
    pub_count: u32,
    bit: WRef,
    one: WRef,
) -> WRef {
    let bit_val = read_wire_value(wire_values, pub_count, bit);
    let one_val = read_wire_value(wire_values, pub_count, one);
    let out_val = one_val.sub(bit_val);
    let out = ctx.alloc_wire_with_value(wire_values, out_val);
    ctx.ucir.add_arithmetic_gate(ArithmeticGate::add(bit, out, one));
    out
}

#[allow(clippy::too_many_arguments)]
fn select_left_right(
    ctx: &mut CompileContext,
    wire_values: &mut Vec<Goldilocks>,
    pub_count: u32,
    bit: WRef,
    one_minus_bit: WRef,
    current_ref: WRef,
    current_bytes: &[u8; 32],
    sibling_ref: WRef,
    sibling_bytes: &[u8; 32],
) -> (WRef, WRef, [u8; 32], [u8; 32]) {
    let (left_bytes, right_bytes) = if read_wire_value(wire_values, pub_count, bit).0 == 0 {
        (*current_bytes, *sibling_bytes)
    } else {
        (*sibling_bytes, *current_bytes)
    };
    let left_ref = alloc_node(ctx, wire_values, &left_bytes);
    let right_ref = alloc_node(ctx, wire_values, &right_bytes);

    for i in 0..4 {
        let curr = WRef(current_ref.0 + i);
        let sib = WRef(sibling_ref.0 + i);
        let left = WRef(left_ref.0 + i);
        let right = WRef(right_ref.0 + i);

        let curr_val = read_wire_value(wire_values, pub_count, curr);
        let sib_val = read_wire_value(wire_values, pub_count, sib);
        let bit_val = read_wire_value(wire_values, pub_count, bit);
        let one_minus_val = read_wire_value(wire_values, pub_count, one_minus_bit);

        let t1_val = bit_val.mul(sib_val);
        let t2_val = one_minus_val.mul(curr_val);
        let t1 = alloc_wire_value(ctx, wire_values, t1_val);
        let t2 = alloc_wire_value(ctx, wire_values, t2_val);
        ctx.ucir.add_arithmetic_gate(ArithmeticGate::mul(bit, sib, t1));
        ctx.ucir.add_arithmetic_gate(ArithmeticGate::mul(one_minus_bit, curr, t2));
        let sum_val = t1_val.add(t2_val);
        let sum = alloc_wire_value(ctx, wire_values, sum_val);
        ctx.ucir.add_arithmetic_gate(ArithmeticGate::add(t1, t2, sum));
        ctx.copy(sum, left);

        let t3_val = bit_val.mul(curr_val);
        let t4_val = one_minus_val.mul(sib_val);
        let t3 = alloc_wire_value(ctx, wire_values, t3_val);
        let t4 = alloc_wire_value(ctx, wire_values, t4_val);
        ctx.ucir.add_arithmetic_gate(ArithmeticGate::mul(bit, curr, t3));
        ctx.ucir.add_arithmetic_gate(ArithmeticGate::mul(one_minus_bit, sib, t4));
        let sum2_val = t3_val.add(t4_val);
        let sum2 = alloc_wire_value(ctx, wire_values, sum2_val);
        ctx.ucir.add_arithmetic_gate(ArithmeticGate::add(t3, t4, sum2));
        ctx.copy(sum2, right);
    }

    (left_ref, right_ref, left_bytes, right_bytes)
}

fn alloc_index_from_bits(
    ctx: &mut CompileContext,
    wire_values: &mut Vec<Goldilocks>,
    zero: WRef,
    bit_wires: &[WRef],
    bit_vals: &[u8],
) -> WRef {
    let mut acc_wire = zero;
    let mut acc_val = Goldilocks::ZERO;
    for (i, bit_wire) in bit_wires.iter().enumerate() {
        let k = 1u64 << i;
        let bit_val = Goldilocks(bit_vals[i] as u64);
        let term_val = bit_val.mul(Goldilocks::new(k));
        let term_wire = alloc_mul_const(ctx, wire_values, *bit_wire, k, term_val);
        let sum_val = acc_val.add(term_val);
        let sum_wire = alloc_wire_value(ctx, wire_values, sum_val);
        ctx.ucir.add_arithmetic_gate(ArithmeticGate::add(acc_wire, term_wire, sum_wire));
        acc_wire = sum_wire;
        acc_val = sum_val;
    }
    acc_wire
}

fn alloc_mul_const(
    ctx: &mut CompileContext,
    wire_values: &mut Vec<Goldilocks>,
    a: WRef,
    k: u64,
    out_val: Goldilocks,
) -> WRef {
    let out = alloc_wire_value(ctx, wire_values, out_val);
    ctx.ucir.add_arithmetic_gate(ArithmeticGate {
        a,
        b: WRef(0),
        c: out,
        q_mul: Goldilocks::ZERO,
        q_l: Goldilocks::new(k),
        q_r: Goldilocks::ZERO,
        q_o: Goldilocks::ONE.neg(),
        q_c: Goldilocks::ZERO,
    });
    out
}

fn alloc_add(
    ctx: &mut CompileContext,
    wire_values: &mut Vec<Goldilocks>,
    a: WRef,
    b: WRef,
    out_val: Goldilocks,
) -> WRef {
    let out = alloc_wire_value(ctx, wire_values, out_val);
    ctx.ucir.add_arithmetic_gate(ArithmeticGate::add(a, b, out));
    out
}

#[allow(clippy::too_many_arguments)]
fn enforce_add_select(
    ctx: &mut CompileContext,
    wire_values: &mut Vec<Goldilocks>,
    pub_count: u32,
    op_wire: WRef,
    old_ref: WRef,
    operand_ref: WRef,
    new_ref: WRef,
    add_limbs: &[u64; 4],
    carry_bits: &[u8; 4],
) {
    let one = Goldilocks::ONE;
    let one_wire = alloc_constant(ctx, wire_values, one);
    let op_val = read_wire_value(wire_values, pub_count, op_wire);
    let one_minus_val = one.sub(op_val);
    let one_minus_wire = alloc_wire_value(ctx, wire_values, one_minus_val);
    ctx.ucir
        .add_arithmetic_gate(ArithmeticGate::add(op_wire, one_minus_wire, one_wire));

    let carry_base = Goldilocks::new((1u64 << 32) - 1);

    let mut carry_in = alloc_constant(ctx, wire_values, Goldilocks::ZERO);
    for i in 0..4 {
        let old_limb = WRef(old_ref.0 + i as u32);
        let operand_limb = WRef(operand_ref.0 + i as u32);
        let new_limb = WRef(new_ref.0 + i as u32);

        let add_limb_val = Goldilocks::new(add_limbs[i]);
        let add_limb = alloc_wire_value(ctx, wire_values, add_limb_val);

        let carry_out_val = Goldilocks::new(carry_bits[i] as u64);
        let carry_out = alloc_wire_value(ctx, wire_values, carry_out_val);
        ctx.bit(carry_out);

        let sum1_val = read_wire_value(wire_values, pub_count, old_limb)
            .add(read_wire_value(wire_values, pub_count, operand_limb));
        let sum1 = alloc_add(ctx, wire_values, old_limb, operand_limb, sum1_val);

        let sum2_val = sum1_val.add(read_wire_value(wire_values, pub_count, carry_in));
        let sum2 = alloc_add(ctx, wire_values, sum1, carry_in, sum2_val);

        let carry_term_val = carry_out_val.mul(carry_base);
        let carry_term = alloc_mul_const(ctx, wire_values, carry_out, carry_base.0, carry_term_val);
        let add_plus_carry_val = add_limb_val.add(carry_term_val);
        let add_plus_carry = alloc_add(ctx, wire_values, add_limb, carry_term, add_plus_carry_val);

        ctx.copy(sum2, add_plus_carry);

        let t1_val = op_val.mul(add_limb_val);
        let t1 = alloc_wire_value(ctx, wire_values, t1_val);
        ctx.ucir.add_arithmetic_gate(ArithmeticGate::mul(op_wire, add_limb, t1));

        let t2_val = one_minus_val.mul(read_wire_value(wire_values, pub_count, operand_limb));
        let t2 = alloc_wire_value(ctx, wire_values, t2_val);
        ctx.ucir.add_arithmetic_gate(ArithmeticGate::mul(one_minus_wire, operand_limb, t2));

        let mix_val = t1_val.add(t2_val);
        let mix = alloc_wire_value(ctx, wire_values, mix_val);
        ctx.ucir.add_arithmetic_gate(ArithmeticGate::add(t1, t2, mix));
        ctx.copy(mix, new_limb);

        carry_in = carry_out;
    }
}

fn read_wire_value(wire_values: &[Goldilocks], pub_count: u32, w: WRef) -> Goldilocks {
    if w.0 < pub_count {
        debug_assert!(false, "attempted to read public input from wire values");
        return Goldilocks::ZERO;
    }
    let idx = (w.0 - pub_count) as usize;
    wire_values[idx]
}

fn read_node_bytes(wire_values: &[Goldilocks], pub_count: u32, node: WRef) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0u32..4 {
        let limb = read_wire_value(wire_values, pub_count, WRef(node.0 + i)).0;
        let bytes = limb.to_le_bytes();
        let start = (i as usize) * 8;
        out[start..start + 8].copy_from_slice(&bytes);
    }
    out
}

fn enforce_zero_node(ctx: &mut CompileContext, zero: WRef, node: WRef) {
    for i in 0..4 {
        ctx.copy(zero, WRef(node.0 + i));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::glyph_ir_compiler::embed_fq_limbs;

    fn proof_for_index(leaves: &[[u8; 32]], index: usize) -> MerkleProof {
        let mut siblings = Vec::new();
        let mut path_bits = Vec::new();
        let mut idx = index;
        let mut layer = leaves.to_vec();
        while layer.len() > 1 {
            let sibling_idx = if idx.is_multiple_of(2) { idx + 1 } else { idx - 1 };
            siblings.push(layer[sibling_idx]);
            path_bits.push((idx % 2) as u8);
            idx /= 2;
            let mut next = Vec::with_capacity(layer.len() / 2);
            for pair in layer.chunks(2) {
                next.push(keccak_merge(&pair[0], &pair[1]));
            }
            layer = next;
        }
        MerkleProof { siblings, path_bits }
    }

    #[test]
    fn test_apply_updates_simple() {
        let key0 = index_bytes(0);
        let _key1 = index_bytes(1);
        let val0 = [3u8; 32];
        let val1 = [4u8; 32];
        let val2 = [5u8; 32];

        let leaf0 = leaf_hash(&val0);
        let leaf1 = leaf_hash(&val1);
        let leaves = vec![leaf0, leaf1];
        let old_root = keccak_merge(&leaves[0], &leaves[1]);

        let proof0 = proof_for_index(&leaves, 0);
        let update0 = StateUpdate {
            key: key0,
            old_value: val0,
            new_value: val2,
            proof: proof0,
            op: VmOpKind::Store,
            operand: val2,
        };

        let batch = StateTransitionBatch {
            old_root,
            updates: vec![update0],
        };

        let new_root = match apply_updates(&batch) {
            Ok(new_root) => new_root,
            Err(err) => {
                assert!(false, "apply: {err}");
                return;
            }
        };
        let leaf0_new = leaf_hash(&val2);
        let expected_root = keccak_merge(&leaf0_new, &leaf1);
        assert_eq!(new_root, expected_root);
    }

    #[test]
    fn test_vm_execute_add() {
        let mut vm = match GlyphVm::new(4) {
            Ok(vm) => vm,
            Err(err) => {
                assert!(false, "vm: {err}");
                return;
            }
        };
        let key = index_bytes(7);
        let delta = [0u8; 32];
        let mut delta2 = [0u8; 32];
        delta2[31] = 5;

        let ops = vec![
            VmOp::Store { key, value: delta },
            VmOp::Add { key, delta: delta2 },
        ];
        let batch = match vm.execute(&ops) {
            Ok(batch) => batch,
            Err(err) => {
                assert!(false, "execute: {err}");
                return;
            }
        };
        let new_root = match apply_updates(&batch) {
            Ok(new_root) => new_root,
            Err(err) => {
                assert!(false, "apply: {err}");
                return;
            }
        };
        assert_eq!(new_root, vm.root());
    }

    #[test]
    fn test_key_matches_path_bits() {
        let mut key = [0u8; 32];
        key[0] = 0b1011;
        let bits = vec![1, 1, 0, 1];
        if let Err(err) = key_matches_path_bits(&key, &bits) {
            assert!(false, "match: {err}");
            return;
        }

        let bad_bits = vec![0, 0, 1, 0];
        assert!(key_matches_path_bits(&key, &bad_bits).is_err());
    }

    #[test]
    fn test_add_u256_le_limbs() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a[31] = 255;
        b[31] = 1;
        let (sum_limbs, carries) = add_u256_le_limbs(&a, &b);
        assert_eq!(sum_limbs[3], 0);
        assert_eq!(carries[3], 1);
    }

    #[test]
    fn test_validate_batch_add() {
        let key = index_bytes(0);
        let old = [1u8; 32];
        let mut delta = [0u8; 32];
        delta[31] = 5;
        let new_val = add_u256_be(&old, &delta);

        let leaf_old = leaf_hash(&old);
        let _leaf_new = leaf_hash(&new_val);
        let old_root = keccak_merge(&leaf_old, &leaf_old);
        let proof = MerkleProof {
            siblings: vec![leaf_old],
            path_bits: vec![0],
        };
        let update = StateUpdate {
            key,
            old_value: old,
            new_value: new_val,
            proof,
            op: VmOpKind::Add,
            operand: delta,
        };
        let batch = StateTransitionBatch {
            old_root,
            updates: vec![update],
        };
        if let Err(err) = validate_batch(&batch) {
            assert!(false, "validate: {err}");
            return;
        }
    }

    #[test]
    fn test_compile_state_transition_public_inputs() {
        let mut vm = match GlyphVm::new(2) {
            Ok(vm) => vm,
            Err(err) => {
                assert!(false, "vm: {err}");
                return;
            }
        };
        let key = index_bytes(0);
        let value = [7u8; 32];
        let ops = vec![VmOp::Store { key, value }];
        let batch = match vm.execute(&ops) {
            Ok(batch) => batch,
            Err(err) => {
                assert!(false, "execute: {err}");
                return;
            }
        };
        let summary = match validate_batch(&batch) {
            Ok(summary) => summary,
            Err(err) => {
                assert!(false, "validate: {err}");
                return;
            }
        };
        let compiled = match compile_state_transition_batch(&batch) {
            Ok(compiled) => compiled,
            Err(err) => {
                assert!(false, "compile: {err}");
                return;
            }
        };
        assert_eq!(compiled.public_inputs.len(), 12);
        assert_eq!(
            &compiled.public_inputs[0..4],
            &embed_fq_limbs(&summary.old_root)
        );
        assert_eq!(
            &compiled.public_inputs[4..8],
            &embed_fq_limbs(&summary.new_root)
        );
        assert_eq!(
            &compiled.public_inputs[8..12],
            &embed_fq_limbs(&summary.diff_root)
        );
    }

    #[test]
    fn test_compile_rejects_invalid_path_bits() {
        let key = index_bytes(0);
        let old = [1u8; 32];
        let new_val = [2u8; 32];
        let leaf_old = leaf_hash(&old);
        let old_root = keccak_merge(&leaf_old, &leaf_old);
        let proof = MerkleProof {
            siblings: vec![leaf_old],
            path_bits: vec![2],
        };
        let update = StateUpdate {
            key,
            old_value: old,
            new_value: new_val,
            proof,
            op: VmOpKind::Store,
            operand: new_val,
        };
        let batch = StateTransitionBatch {
            old_root,
            updates: vec![update],
        };
        assert!(compile_state_transition_batch(&batch).is_err());
    }
}
