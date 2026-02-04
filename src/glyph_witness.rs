//! Witness Stream Engine for GLYPH-PROVER.
//!
//! Implements streaming witness generation per Prover-Blueprint.md Section 10.
//! Two-pass design for cache locality and deterministic ordering.

use crate::arena::Arena;
use crate::glyph_field_simd::Goldilocks;
use crate::glyph_ir::{
    Ucir2, Gate, WRef, WitnessLayout,
    CUSTOM_GATE_BN254_ADD, CUSTOM_GATE_BN254_SUB, CUSTOM_GATE_BN254_MUL,
    CUSTOM_GATE_KECCAK_MERGE,
    CUSTOM_GATE_IVC_VERIFY,
    CUSTOM_GATE_STARK_VERIFY,
    CUSTOM_GATE_IPA_VERIFY,
    CUSTOM_GATE_SP1_VERIFY,
    CUSTOM_GATE_PLONK_VERIFY,
    CUSTOM_GATE_BINIUS_VERIFY,
    CUSTOM_GATE_GROTH16_BLS12381_VERIFY,
    CUSTOM_GATE_KZG_BLS12381_VERIFY,
    decode_three_wref_payload,
    custom_gate_wrefs,
    ensure_custom_gate_enabled,
};
use crate::glyph_transcript::{Transcript, DOMAIN_UCIR};
use crate::bn254_field::{
    bn254_add_mod,
    bn254_add_mod_batch,
    bn254_mul_mod,
    bn254_mul_mod_batch,
    bn254_sub_mod,
    bn254_sub_mod_batch,
    is_canonical_limbs,
};
use crate::adapters::keccak256;
use crate::glyph_field_simd::{prefetch_read, ensure_two_thread_pool, goldilocks_mul_batch_into};
use rayon::prelude::*;
use std::cell::RefCell;

// ============================================================
//                    WITNESS BUFFER
// ============================================================

/// Witness buffer with streaming capabilities
#[derive(Clone, Debug)]
pub struct WitnessBuffer {
    /// Witness values
    pub values: Vec<Goldilocks>,
    /// Assignment flags (true if value is explicitly set)
    assigned: Vec<bool>,
    /// Fast-path enabled after validation
    validated: bool,
    /// Layout information
    pub layout: WitnessLayout,
    /// Lookup multiplicity counts per table (aligned to table values)
    pub table_multiplicities: Vec<TableMultiplicity>,
}

impl Drop for WitnessBuffer {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl WitnessBuffer {
    /// Create new witness buffer from layout
    pub fn new(layout: WitnessLayout) -> Self {
        let total_len = layout.total_len() as usize;
        Self {
            values: vec![Goldilocks::ZERO; total_len],
            assigned: vec![false; total_len],
            validated: false,
            layout,
            table_multiplicities: Vec::new(),
        }
    }

    pub fn zeroize(&mut self) {
        for v in self.values.iter_mut() {
            *v = Goldilocks::ZERO;
        }
        for flag in self.assigned.iter_mut() {
            *flag = false;
        }
        for table in self.table_multiplicities.iter_mut() {
            for count in table.counts.iter_mut() {
                *count = 0;
            }
        }
        self.validated = false;
    }

    /// Set public input value
    pub fn set_public(&mut self, idx: usize, val: Goldilocks) {
        let abs_idx = self.layout.public_start as usize + idx;
        if abs_idx < self.values.len() {
            self.values[abs_idx] = val;
            self.assigned[abs_idx] = true;
        }
    }

    /// Set wire value
    pub fn set_wire(&mut self, idx: usize, val: Goldilocks) {
        let abs_idx = self.layout.wire_start as usize + idx;
        if abs_idx < self.values.len() {
            self.values[abs_idx] = val;
            self.assigned[abs_idx] = true;
        }
    }

    /// Get value by reference
    pub fn get(&self, wref: WRef) -> Goldilocks {
        let idx = wref.0 as usize;
        if idx < self.values.len() {
            self.values[idx]
        } else {
            Goldilocks::ZERO
        }
    }

    #[inline(always)]
    pub fn get_unchecked(&self, wref: WRef) -> Goldilocks {
        let idx = wref.0 as usize;
        if idx >= self.values.len() {
            return Goldilocks::ZERO;
        }
        unsafe { *self.values.get_unchecked(idx) }
    }

    /// Set value by reference
    pub fn set(&mut self, wref: WRef, val: Goldilocks) {
        let idx = wref.0 as usize;
        if idx < self.values.len() {
            self.values[idx] = val;
            self.assigned[idx] = true;
        }
    }

    /// Check if a witness reference is assigned
    pub fn is_assigned(&self, wref: WRef) -> bool {
        let idx = wref.0 as usize;
        idx < self.assigned.len() && self.assigned[idx]
    }

    /// Get value by reference, error if unassigned
    pub fn get_checked(&self, wref: WRef) -> Result<Goldilocks, WitnessError> {
        let idx = wref.0 as usize;
        if idx >= self.values.len() {
            return Err(WitnessError::InvalidReference { wref: wref.0 });
        }
        if !self.assigned[idx] {
            return Err(WitnessError::InvalidReference { wref: wref.0 });
        }
        Ok(self.values[idx])
    }

    /// Get public inputs slice
    pub fn public_inputs(&self) -> &[Goldilocks] {
        let start = self.layout.public_start as usize;
        let end = start + self.layout.public_len as usize;
        &self.values[start..end.min(self.values.len())]
    }

    /// Set wire values from slice in canonical order
    pub fn set_wires_from_slice(&mut self, wire_values: &[Goldilocks]) -> Result<(), WitnessError> {
        let expected = self.layout.wire_len as usize;
        if wire_values.len() != expected {
            return Err(WitnessError::InvalidReference { wref: wire_values.len() as u32 });
        }
        let start = self.layout.wire_start as usize;
        for (i, val) in wire_values.iter().enumerate() {
            let idx = start + i;
            self.values[idx] = *val;
            self.assigned[idx] = true;
        }
        Ok(())
    }

    /// Append blinding values (ZK mode)
    pub fn append_blinding(&mut self, vals: &[Goldilocks]) -> Result<(), WitnessError> {
        if vals.is_empty() {
            return Ok(());
        }
        if self.layout.blind_len != 0 {
            return Err(WitnessError::InvalidReference { wref: self.layout.blind_len });
        }
        let start = self.values.len();
        self.values.extend_from_slice(vals);
        self.assigned.resize(self.assigned.len() + vals.len(), true);
        self.layout.blind_start = start as u32;
        self.layout.blind_len = vals.len() as u32;
        Ok(())
    }
}

// ============================================================
//                    WITNESS STREAM ENGINE
// ============================================================

#[derive(Debug)]
struct GoldilocksScratch {
    a: Vec<Goldilocks>,
    b: Vec<Goldilocks>,
    c: Vec<Goldilocks>,
    ab: Vec<Goldilocks>,
}

impl GoldilocksScratch {
    fn new() -> Self {
        Self {
            a: Vec::new(),
            b: Vec::new(),
            c: Vec::new(),
            ab: Vec::new(),
        }
    }

    fn ensure_len(&mut self, n: usize) {
        if self.a.len() < n {
            self.a.resize(n, Goldilocks::ZERO);
        }
        if self.b.len() < n {
            self.b.resize(n, Goldilocks::ZERO);
        }
        if self.c.len() < n {
            self.c.resize(n, Goldilocks::ZERO);
        }
        if self.ab.len() < n {
            self.ab.resize(n, Goldilocks::ZERO);
        }
    }
}

#[derive(Debug)]
struct WitnessScratch {
    bn254_scratch: Arena<[u64; 4]>,
}

impl WitnessScratch {
    fn new() -> Self {
        Self {
            bn254_scratch: Arena::with_capacity(0),
        }
    }
}

thread_local! {
    static GOLDILOCKS_SCRATCH: RefCell<GoldilocksScratch> =
        RefCell::new(GoldilocksScratch::new());
}

/// Streaming witness engine per Blueprint Section 10
pub struct WitnessStream {
    /// The constraint system
    pub ucir: Ucir2,
    /// Witness buffer
    pub witness: WitnessBuffer,
    /// Transcript for hashing
    pub transcript: Transcript,
    /// Memory limit in bytes
    pub memory_limit: usize,
    /// Reusable scratch arenas for witness evaluation
    scratch: WitnessScratch,
}

/// Error type for witness generation
#[derive(Debug, Clone)]
pub enum WitnessError {
    /// Memory limit exceeded
    MemoryLimitExceeded { stage: String, size: usize },
    /// Constraint violation
    ConstraintViolation { gate_idx: usize, message: String },
    /// Lookup violation
    LookupViolation { lookup_idx: usize, value: u64 },
    InvalidTable { table_id: u32, message: String },
    /// Invalid witness reference
    InvalidReference { wref: u32 },
}

/// Multiplicity counts aligned to table values
#[derive(Clone, Debug)]
pub struct TableMultiplicity {
    pub table_id: u32,
    pub counts: Vec<u64>,
}

fn bn254_custom_gate_batch_enabled() -> bool {
    std::env::var("GLYPH_BN254_WITNESS_BATCH")
        .ok()
        .as_deref()
        .map(|v| v != "0")
        .unwrap_or(true)
}

fn bn254_custom_gate_batch_min() -> usize {
    std::env::var("GLYPH_BN254_WITNESS_BATCH_MIN")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(256)
}

fn is_bn254_custom_gate(custom_id: u16) -> bool {
    matches!(
        custom_id,
        CUSTOM_GATE_BN254_ADD | CUSTOM_GATE_BN254_SUB | CUSTOM_GATE_BN254_MUL
    )
}

fn witness_bytes_for_len(len: usize) -> usize {
    let per_elem = std::mem::size_of::<Goldilocks>() + std::mem::size_of::<bool>();
    len.saturating_mul(per_elem)
}

impl WitnessStream {
    /// Create new witness stream
    pub fn new(ucir: Ucir2, memory_limit: usize) -> Result<Self, WitnessError> {
        Self::try_new(ucir, memory_limit)
    }

    /// Create new witness stream with a strict pre-allocation memory check
    pub fn try_new(ucir: Ucir2, memory_limit: usize) -> Result<Self, WitnessError> {
        let layout = ucir.witness_layout.clone();
        let required = witness_bytes_for_len(layout.total_len() as usize);
        if required > memory_limit {
            return Err(WitnessError::MemoryLimitExceeded {
                stage: "Init".to_string(),
                size: required,
            });
        }
        let witness = WitnessBuffer::new(layout);
        let transcript = Transcript::new();
        Ok(Self {
            ucir,
            witness,
            transcript,
            memory_limit,
            scratch: WitnessScratch::new(),
        })
    }

    fn batch_eval_bn254_custom_gates(
        &mut self,
        gate_indices: &[usize],
    ) -> Result<Vec<(usize, bool)>, WitnessError> {
        let mut add_a = Vec::new();
        let mut add_b = Vec::new();
        let mut add_out = Vec::new();
        let mut add_idx = Vec::new();

        let mut sub_a = Vec::new();
        let mut sub_b = Vec::new();
        let mut sub_out = Vec::new();
        let mut sub_idx = Vec::new();

        let mut mul_a = Vec::new();
        let mut mul_b = Vec::new();
        let mut mul_out = Vec::new();
        let mut mul_idx = Vec::new();

        for &gate_idx in gate_indices {
            let gate = &self.ucir.gates[gate_idx];
            let cg = match gate {
                Gate::Custom(cg) => cg,
                _ => continue,
            };
            if !is_bn254_custom_gate(cg.custom_id) {
                continue;
            }
            let (a_start, b_start, out_start) =
                decode_three_wref_payload(&cg.payload).ok_or_else(|| {
                    WitnessError::ConstraintViolation {
                        gate_idx,
                        message: "Invalid custom gate payload".to_string(),
                    }
                })?;
            let a = self.read_limbs_u64(a_start)?;
            let b = self.read_limbs_u64(b_start)?;
            let out = self.read_limbs_u64(out_start)?;
            if !is_canonical_limbs(a) || !is_canonical_limbs(b) || !is_canonical_limbs(out) {
                return Err(WitnessError::ConstraintViolation {
                    gate_idx,
                    message: "BN254 op on non-canonical limbs".to_string(),
                });
            }
            match cg.custom_id {
                CUSTOM_GATE_BN254_ADD => {
                    add_a.push(a);
                    add_b.push(b);
                    add_out.push(out);
                    add_idx.push(gate_idx);
                }
                CUSTOM_GATE_BN254_SUB => {
                    sub_a.push(a);
                    sub_b.push(b);
                    sub_out.push(out);
                    sub_idx.push(gate_idx);
                }
                CUSTOM_GATE_BN254_MUL => {
                    mul_a.push(a);
                    mul_b.push(b);
                    mul_out.push(out);
                    mul_idx.push(gate_idx);
                }
                _ => {}
            }
        }

        let mut results = Vec::with_capacity(gate_indices.len());
        self.scratch.bn254_scratch.reset();
        if !add_a.is_empty() {
            let scratch = self.scratch.bn254_scratch.alloc_slice(add_a.len());
            bn254_add_mod_batch(&add_a, &add_b, scratch).map_err(|e| {
                WitnessError::ConstraintViolation {
                    gate_idx: add_idx[0],
                    message: format!("BN254 add batch failed: {e}"),
                }
            })?;
            for (pos, expected) in add_out.iter().enumerate() {
                results.push((add_idx[pos], scratch[pos] == *expected));
            }
        }
        if !sub_a.is_empty() {
            let scratch = self.scratch.bn254_scratch.alloc_slice(sub_a.len());
            bn254_sub_mod_batch(&sub_a, &sub_b, scratch).map_err(|e| {
                WitnessError::ConstraintViolation {
                    gate_idx: sub_idx[0],
                    message: format!("BN254 sub batch failed: {e}"),
                }
            })?;
            for (pos, expected) in sub_out.iter().enumerate() {
                results.push((sub_idx[pos], scratch[pos] == *expected));
            }
        }
        if !mul_a.is_empty() {
            let scratch = self.scratch.bn254_scratch.alloc_slice(mul_a.len());
            bn254_mul_mod_batch(&mul_a, &mul_b, scratch).map_err(|e| {
                WitnessError::ConstraintViolation {
                    gate_idx: mul_idx[0],
                    message: format!("BN254 mul batch failed: {e}"),
                }
            })?;
            for (pos, expected) in mul_out.iter().enumerate() {
                results.push((mul_idx[pos], scratch[pos] == *expected));
            }
        }

        Ok(results)
    }

    /// Phase W1: Witness production per Blueprint 10
    /// - Compute witness values in canonical gate order
    /// - Update transcript hash while streaming
    /// - Count lookup multiplicities
    pub fn phase_w1_produce(
        &mut self,
        public_inputs: &[Goldilocks],
        wire_values: Option<&[Goldilocks]>,
    ) -> Result<(), WitnessError> {
        ensure_two_thread_pool();
        if public_inputs.len() != self.witness.layout.public_len as usize {
            return Err(WitnessError::InvalidReference { wref: public_inputs.len() as u32 });
        }
        // Set public inputs
        for (i, val) in public_inputs.iter().enumerate() {
            self.witness.set_public(i, *val);
        }

        if let Some(values) = wire_values {
            self.witness.set_wires_from_slice(values)?;
        }

        // Absorb UCIR hash
        let ucir_hash = self.ucir.hash();
        self.transcript.absorb_bytes32(DOMAIN_UCIR, &ucir_hash);

        // Process gates using a dependency-driven queue to avoid fixed-point scans.
        if wire_values.is_none() {
            let total = self.witness.values.len();
            let mut watchers: Vec<Vec<usize>> = vec![Vec::new(); total];
            let mut pending: Vec<u8> = vec![0; self.ucir.gates.len()];
            let mut in_queue: Vec<bool> = vec![false; self.ucir.gates.len()];
            let mut queue: std::collections::VecDeque<usize> = std::collections::VecDeque::new();

            let watcher_max_edges = std::env::var("GLYPH_WITNESS_WATCHERS_MAX_EDGES")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or_else(|| {
                    let per = std::mem::size_of::<usize>().max(1);
                    (self.memory_limit / per).max(1)
                });
            let watcher_max_fanout = std::env::var("GLYPH_WITNESS_WATCHER_FANOUT")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(1_000_000);
            let mut watcher_edges: usize = 0;

            for (gate_idx, gate) in self.ucir.gates.iter().enumerate() {
                let mut refs = Vec::new();
                match gate {
                    Gate::Arithmetic(ag) => {
                        refs.push(ag.a);
                        refs.push(ag.b);
                        refs.push(ag.c);
                    }
                    Gate::Copy(cg) => {
                        refs.push(cg.left);
                        refs.push(cg.right);
                    }
                    Gate::Custom(cg) => {
                        let wrefs = custom_gate_wrefs(cg.custom_id, &cg.payload).map_err(|e| {
                            WitnessError::ConstraintViolation {
                                gate_idx,
                                message: format!("Custom gate invalid: {e}"),
                            }
                        })?;
                        refs.extend_from_slice(&wrefs);
                    }
                }

                let mut miss = 0u8;
                for wref in refs.iter() {
                    let idx = wref.0 as usize;
                    if idx < total {
                        if watchers[idx].len() >= watcher_max_fanout {
                            return Err(WitnessError::MemoryLimitExceeded {
                                stage: "W1_watchers_fanout".to_string(),
                                size: watchers[idx].len(),
                            });
                        }
                        watcher_edges = watcher_edges.saturating_add(1);
                        if watcher_edges > watcher_max_edges {
                            return Err(WitnessError::MemoryLimitExceeded {
                                stage: "W1_watchers_edges".to_string(),
                                size: watcher_edges,
                            });
                        }
                        watchers[idx].push(gate_idx);
                    }
                    if !self.witness.is_assigned(*wref) {
                        miss = miss.saturating_add(1);
                    }
                }
                pending[gate_idx] = miss;
                let ready = match gate {
                    Gate::Custom(_) => miss == 0,
                    _ => miss <= 1,
                };
                if ready {
                    queue.push_back(gate_idx);
                    in_queue[gate_idx] = true;
                }
            }

            #[allow(clippy::too_many_arguments)]
            fn assign_value(
                witness: &mut WitnessBuffer,
                ucir: &Ucir2,
                wref: WRef,
                val: Goldilocks,
                watchers: &[Vec<usize>],
                pending: &mut [u8],
                in_queue: &mut [bool],
                queue: &mut std::collections::VecDeque<usize>,
            ) {
                if witness.is_assigned(wref) {
                    return;
                }
                witness.set(wref, val);
                let idx = wref.0 as usize;
                if idx >= watchers.len() {
                    return;
                }
                for &gate_idx in &watchers[idx] {
                    if pending[gate_idx] > 0 {
                        pending[gate_idx] -= 1;
                    }
                    let gate = &ucir.gates[gate_idx];
                    let ready = match gate {
                        Gate::Custom(_) => pending[gate_idx] == 0,
                        _ => pending[gate_idx] <= 1,
                    };
                    if ready && !in_queue[gate_idx] {
                        in_queue[gate_idx] = true;
                        queue.push_back(gate_idx);
                    }
                }
            }

            let batch_bn254 = bn254_custom_gate_batch_enabled();
            let batch_bn254_min = bn254_custom_gate_batch_min();
            let mut bn254_custom_gates: Vec<usize> = Vec::new();

            while let Some(gate_idx) = queue.pop_front() {
                in_queue[gate_idx] = false;
                let gate = &self.ucir.gates[gate_idx];
                match gate {
                    Gate::Arithmetic(ag) => {
                        let a_set = self.witness.is_assigned(ag.a);
                        let b_set = self.witness.is_assigned(ag.b);
                        let c_set = self.witness.is_assigned(ag.c);

                        if a_set && b_set && !c_set && ag.q_o != Goldilocks::ZERO {
                            let a = self.witness.get_checked(ag.a)?;
                            let b = self.witness.get_checked(ag.b)?;
                            let rhs = ag.q_mul * a * b + ag.q_l * a + ag.q_r * b + ag.q_c;
                            let neg_rhs = rhs.neg();
                            if let Some(q_o_inv) = ag.q_o.inverse() {
                                let c_solved = neg_rhs * q_o_inv;
                                assign_value(&mut self.witness, &self.ucir, ag.c, c_solved, &watchers, &mut pending, &mut in_queue, &mut queue);
                            } else {
                                return Err(WitnessError::ConstraintViolation {
                                    gate_idx,
                                    message: "q_o inverse missing".to_string(),
                                });
                            }
                        } else if b_set && c_set && !a_set {
                            let b = self.witness.get_checked(ag.b)?;
                            let c = self.witness.get_checked(ag.c)?;
                            let denom = ag.q_mul * b + ag.q_l;
                            if denom != Goldilocks::ZERO {
                                let rhs = ag.q_r * b + ag.q_o * c + ag.q_c;
                                let neg_rhs = rhs.neg();
                                if let Some(inv) = denom.inverse() {
                                    let a_solved = neg_rhs * inv;
                                    assign_value(&mut self.witness, &self.ucir, ag.a, a_solved, &watchers, &mut pending, &mut in_queue, &mut queue);
                                } else {
                                    return Err(WitnessError::ConstraintViolation {
                                        gate_idx,
                                        message: "denom inverse missing".to_string(),
                                    });
                                }
                            }
                        } else if a_set && c_set && !b_set {
                            let a = self.witness.get_checked(ag.a)?;
                            let c = self.witness.get_checked(ag.c)?;
                            let denom = ag.q_mul * a + ag.q_r;
                            if denom != Goldilocks::ZERO {
                                let rhs = ag.q_l * a + ag.q_o * c + ag.q_c;
                                let neg_rhs = rhs.neg();
                                if let Some(inv) = denom.inverse() {
                                    let b_solved = neg_rhs * inv;
                                    assign_value(&mut self.witness, &self.ucir, ag.b, b_solved, &watchers, &mut pending, &mut in_queue, &mut queue);
                                } else {
                                    return Err(WitnessError::ConstraintViolation {
                                        gate_idx,
                                        message: "denom inverse missing".to_string(),
                                    });
                                }
                            }
                        } else if a_set && b_set && c_set {
                            let a = self.witness.get_checked(ag.a)?;
                            let b = self.witness.get_checked(ag.b)?;
                            let c = self.witness.get_checked(ag.c)?;
                            let lhs = ag.q_mul * a * b + ag.q_l * a + ag.q_r * b + ag.q_o * c + ag.q_c;
                            if lhs != Goldilocks::ZERO {
                                return Err(WitnessError::ConstraintViolation {
                                    gate_idx,
                                    message: format!("Constraint violated: {:?} != 0", lhs),
                                });
                            }
                        }
                    }
                    Gate::Copy(cg) => {
                        let left_set = self.witness.is_assigned(cg.left);
                        let right_set = self.witness.is_assigned(cg.right);

                        if left_set && !right_set {
                            let left = self.witness.get_checked(cg.left)?;
                            assign_value(&mut self.witness, &self.ucir, cg.right, left, &watchers, &mut pending, &mut in_queue, &mut queue);
                        } else if right_set && !left_set {
                            let right = self.witness.get_checked(cg.right)?;
                            assign_value(&mut self.witness, &self.ucir, cg.left, right, &watchers, &mut pending, &mut in_queue, &mut queue);
                        } else if left_set && right_set {
                            let left = self.witness.get_checked(cg.left)?;
                            let right = self.witness.get_checked(cg.right)?;
                            if left != right {
                                return Err(WitnessError::ConstraintViolation {
                                    gate_idx,
                                    message: format!("Copy constraint failed: {:?} != {:?}", left, right),
                                });
                            }
                        }
                    }
                    Gate::Custom(_) => {
                        let custom_id = match gate {
                            Gate::Custom(cg) => cg.custom_id,
                            _ => 0u16,
                        };
                        if batch_bn254 && is_bn254_custom_gate(custom_id) {
                            bn254_custom_gates.push(gate_idx);
                        } else {
                            let eval = self.evaluate_custom_gate(gate_idx, gate)?;
                            if eval != Goldilocks::ZERO {
                                return Err(WitnessError::ConstraintViolation {
                                    gate_idx,
                                    message: "Custom gate constraint failed".to_string(),
                                });
                            }
                        }
                    }
                }
            }

            if batch_bn254 && !bn254_custom_gates.is_empty() {
                if bn254_custom_gates.len() >= batch_bn254_min {
                    let results = self.batch_eval_bn254_custom_gates(&bn254_custom_gates)?;
                    for (gate_idx, ok) in results {
                        if !ok {
                            return Err(WitnessError::ConstraintViolation {
                                gate_idx,
                                message: "Custom gate constraint failed".to_string(),
                            });
                        }
                    }
                } else {
                    for gate_idx in bn254_custom_gates {
                        let gate = &self.ucir.gates[gate_idx];
                        let eval = self.evaluate_custom_gate(gate_idx, gate)?;
                        if eval != Goldilocks::ZERO {
                            return Err(WitnessError::ConstraintViolation {
                                gate_idx,
                                message: "Custom gate constraint failed".to_string(),
                            });
                        }
                    }
                }
            }
        }

        for (gate_idx, gate) in self.ucir.gates.iter().enumerate() {
            match gate {
                Gate::Arithmetic(ag) => {
                    if !self.witness.is_assigned(ag.a)
                        || !self.witness.is_assigned(ag.b)
                        || !self.witness.is_assigned(ag.c)
                    {
                        return Err(WitnessError::InvalidReference { wref: gate_idx as u32 });
                    }
                }
                Gate::Copy(cg) => {
                    if !self.witness.is_assigned(cg.left) || !self.witness.is_assigned(cg.right) {
                        return Err(WitnessError::InvalidReference { wref: gate_idx as u32 });
                    }
                }
                Gate::Custom(cg) => {
                    if let Err(e) = custom_gate_wrefs(cg.custom_id, &cg.payload) {
                        return Err(WitnessError::ConstraintViolation {
                            gate_idx,
                            message: format!("Custom gate invalid: {e}"),
                        });
                    }
                }
            }
        }

        self.witness.validated = true;

        // Count lookup multiplicities
        self.count_multiplicities()?;

        // Check memory limit
        let current_size = witness_bytes_for_len(self.witness.values.len());
        if current_size > self.memory_limit {
            return Err(WitnessError::MemoryLimitExceeded {
                stage: "W1".to_string(),
                size: current_size,
            });
        }

        Ok(())
    }

    /// Append blinding values to witness and UCIR layout (ZK mode)
    pub fn add_blinding_values(&mut self, vals: &[Goldilocks]) -> Result<(), WitnessError> {
        if vals.is_empty() {
            return Ok(());
        }
        if self.witness.layout.blind_len != 0 {
            return Err(WitnessError::InvalidReference { wref: self.witness.layout.blind_len });
        }
        let base_layout = WitnessLayout::fast_mode(
            self.ucir.witness_layout.public_len,
            self.ucir.witness_layout.wire_len,
            self.ucir.witness_layout.lookup_len,
        );
        self.ucir.witness_layout = base_layout.clone();
        self.witness.layout = base_layout;
        self.witness.append_blinding(vals)?;
        self.ucir.witness_layout = self.witness.layout.clone();
        Ok(())
    }

    /// Count lookup multiplicities aligned to table values
    fn count_multiplicities(&mut self) -> Result<(), WitnessError> {
        let table_len = self.ucir.tables.len();
        let mut table_indices = std::collections::HashMap::with_capacity(table_len);
        let mut counts = Vec::with_capacity(table_len);
        let mut index_maps: Vec<Option<std::collections::HashMap<Goldilocks, usize>>> = Vec::with_capacity(table_len);

        let mut bit_lookup_idx: Option<usize> = None;
        let mut range8_lookup_idx: Option<usize> = None;
        let mut range16_lookup_idx: Option<usize> = None;
        for (lookup_idx, lookup) in self.ucir.lookups.iter().enumerate() {
            match lookup.table_id {
                crate::glyph_ir::TABLE_BIT => {
                    if bit_lookup_idx.is_none() {
                        bit_lookup_idx = Some(lookup_idx);
                    }
                }
                crate::glyph_ir::TABLE_RANGE8 => {
                    if range8_lookup_idx.is_none() {
                        range8_lookup_idx = Some(lookup_idx);
                    }
                }
                crate::glyph_ir::TABLE_RANGE16 => {
                    if range16_lookup_idx.is_none() {
                        range16_lookup_idx = Some(lookup_idx);
                    }
                }
                _ => {}
            }
        }

        for (idx, table) in self.ucir.tables.iter().enumerate() {
            table_indices.insert(table.table_id, idx);
            counts.push(vec![0u64; table.values.len()]);
            if table.table_id != crate::glyph_ir::TABLE_BIT
                && table.table_id != crate::glyph_ir::TABLE_RANGE8
                && table.table_id != crate::glyph_ir::TABLE_RANGE16
            {
                let mut idx_map = std::collections::HashMap::new();
                for (i, v) in table.values.iter().enumerate() {
                    idx_map.insert(*v, i);
                }
                index_maps.push(Some(idx_map));
            } else {
                index_maps.push(None);
            }
        }

        let validate_standard = |table: &crate::glyph_ir::Table,
                                 table_id: u32,
                                 expected_len: usize|
         -> Result<(), WitnessError> {
            if table.width != 1 {
                return Err(WitnessError::InvalidTable {
                    table_id,
                    message: "standard table width must be 1".to_string(),
                });
            }
            if table.values.len() != expected_len {
                return Err(WitnessError::InvalidTable {
                    table_id,
                    message: format!(
                        "standard table length mismatch: got {}, expected {}",
                        table.values.len(),
                        expected_len
                    ),
                });
            }
            match table_id {
                crate::glyph_ir::TABLE_BIT => {
                    if table.values.len() != 2
                        || table.values[0] != Goldilocks::ZERO
                        || table.values[1] != Goldilocks::ONE
                    {
                        return Err(WitnessError::InvalidTable {
                            table_id,
                            message: "bit table values must be [0,1]".to_string(),
                        });
                    }
                }
                crate::glyph_ir::TABLE_RANGE8 => {
                    for (i, v) in table.values.iter().enumerate() {
                        if v.0 != i as u64 {
                            return Err(WitnessError::InvalidTable {
                                table_id,
                                message: "range8 table values must be 0..255".to_string(),
                            });
                        }
                    }
                }
                crate::glyph_ir::TABLE_RANGE16 => {
                    for (i, v) in table.values.iter().enumerate() {
                        if v.0 != i as u64 {
                            return Err(WitnessError::InvalidTable {
                                table_id,
                                message: "range16 table values must be 0..65535".to_string(),
                            });
                        }
                    }
                }
                _ => {}
            }
            Ok(())
        };

        if let Some(lookup_idx) = bit_lookup_idx {
            let table_idx = table_indices
                .get(&crate::glyph_ir::TABLE_BIT)
                .copied()
                .ok_or(WitnessError::LookupViolation {
                    lookup_idx,
                    value: 0,
                })?;
            validate_standard(&self.ucir.tables[table_idx], crate::glyph_ir::TABLE_BIT, 2)?;
        }
        if let Some(lookup_idx) = range8_lookup_idx {
            let table_idx = table_indices
                .get(&crate::glyph_ir::TABLE_RANGE8)
                .copied()
                .ok_or(WitnessError::LookupViolation {
                    lookup_idx,
                    value: 0,
                })?;
            validate_standard(&self.ucir.tables[table_idx], crate::glyph_ir::TABLE_RANGE8, 256)?;
        }
        if let Some(lookup_idx) = range16_lookup_idx {
            let table_idx = table_indices
                .get(&crate::glyph_ir::TABLE_RANGE16)
                .copied()
                .ok_or(WitnessError::LookupViolation {
                    lookup_idx,
                    value: 0,
                })?;
            validate_standard(&self.ucir.tables[table_idx], crate::glyph_ir::TABLE_RANGE16, 65536)?;
        }

        for (lookup_idx, lookup) in self.ucir.lookups.iter().enumerate() {
            let val = self.witness.get_checked(lookup.value)?;
            let table_idx = match table_indices.get(&lookup.table_id) {
                Some(idx) => *idx,
                None => {
                    return Err(WitnessError::LookupViolation { lookup_idx, value: val.0 });
                }
            };
            let table = &self.ucir.tables[table_idx];

            let idx = if table.table_id == crate::glyph_ir::TABLE_BIT {
                if val.0 <= 1 {
                    val.0 as usize
                } else {
                    return Err(WitnessError::LookupViolation { lookup_idx, value: val.0 });
                }
            } else if table.table_id == crate::glyph_ir::TABLE_RANGE8 {
                if val.0 < 256 {
                    val.0 as usize
                } else {
                    return Err(WitnessError::LookupViolation { lookup_idx, value: val.0 });
                }
            } else if table.table_id == crate::glyph_ir::TABLE_RANGE16 {
                if val.0 < 65536 {
                    val.0 as usize
                } else {
                    return Err(WitnessError::LookupViolation { lookup_idx, value: val.0 });
                }
            } else {
                let idx_map = index_maps[table_idx].as_ref().ok_or(WitnessError::LookupViolation {
                    lookup_idx,
                    value: val.0,
                })?;
                *idx_map.get(&val).ok_or(WitnessError::LookupViolation {
                    lookup_idx,
                    value: val.0,
                })?
            };

            if idx >= counts[table_idx].len() {
                return Err(WitnessError::InvalidTable {
                    table_id: table.table_id,
                    message: "lookup multiplicity index out of bounds".to_string(),
                });
            }

            let table_counts = &mut counts[table_idx];
            table_counts[idx] = table_counts[idx].saturating_add(1);
        }

        let mut table_multiplicities = Vec::with_capacity(table_len);
        for (table, table_counts) in self.ucir.tables.iter().zip(counts.into_iter()) {
            table_multiplicities.push(TableMultiplicity {
                table_id: table.table_id,
                counts: table_counts,
            });
        }

        self.witness.table_multiplicities = table_multiplicities;
        Ok(())
    }

    /// Phase W2: Constraint evaluation per Blueprint 10
    /// - Iterate witness buffer sequentially
    /// - Compute constraint evaluations with SIMD batches
    pub fn phase_w2_evaluate(&mut self) -> Result<Vec<Goldilocks>, WitnessError> {
        ensure_two_thread_pool();
        let validated = self.witness.validated;
        let values = &self.witness.values;
        let gates_len = self.ucir.gates.len();
        let batch_bn254 = bn254_custom_gate_batch_enabled();
        let batch_bn254_min = bn254_custom_gate_batch_min();
        let mut bn254_custom_gates: Vec<usize> = Vec::new();
        let mut other_custom_gates: Vec<usize> = Vec::new();
        let mut evaluations = vec![Goldilocks::ZERO; gates_len];
        {
            let gates = &self.ucir.gates;
            let has_custom = gates.iter().any(|g| matches!(g, Gate::Custom(_)));
            if has_custom {
                for (idx, gate) in gates.iter().enumerate() {
                    if let Gate::Custom(cg) = gate {
                        if batch_bn254 && is_bn254_custom_gate(cg.custom_id) {
                            bn254_custom_gates.push(idx);
                        } else {
                            other_custom_gates.push(idx);
                        }
                    }
                }
            }

            if validated && gates_len > 1024 {
                let chunk = 1024usize;

                evaluations
                    .par_chunks_mut(chunk)
                    .enumerate()
                    .for_each(|(chunk_idx, out_chunk)| {
                        let start = chunk_idx * chunk;
                        let end = (start + chunk).min(gates_len);
                        let n = end - start;
                        GOLDILOCKS_SCRATCH.with(|scratch_cell| {
                            let mut scratch = scratch_cell.borrow_mut();
                            scratch.ensure_len(n);
                            let (a_buf, b_buf, c_buf, ab_buf) = {
                                let scratch = &mut *scratch;
                                (
                                    &mut scratch.a[..n],
                                    &mut scratch.b[..n],
                                    &mut scratch.c[..n],
                                    &mut scratch.ab[..n],
                                )
                            };

                            for (i, gate) in gates[start..end].iter().enumerate() {
                                match gate {
                                    Gate::Arithmetic(ag) => {
                                        let a_idx = ag.a.0 as usize;
                                        let b_idx = ag.b.0 as usize;
                                        let c_idx = ag.c.0 as usize;
                                        let base = values.as_ptr();
                                        unsafe {
                                            prefetch_read(base.add(a_idx));
                                            prefetch_read(base.add(b_idx));
                                            prefetch_read(base.add(c_idx));
                                            a_buf[i] = *values.get_unchecked(a_idx);
                                            b_buf[i] = *values.get_unchecked(b_idx);
                                            c_buf[i] = *values.get_unchecked(c_idx);
                                        }
                                    }
                                    Gate::Copy(cg) => {
                                        let l_idx = cg.left.0 as usize;
                                        let r_idx = cg.right.0 as usize;
                                        let base = values.as_ptr();
                                        unsafe {
                                            prefetch_read(base.add(l_idx));
                                            prefetch_read(base.add(r_idx));
                                            a_buf[i] = *values.get_unchecked(l_idx);
                                            b_buf[i] = *values.get_unchecked(r_idx);
                                            c_buf[i] = Goldilocks::ZERO;
                                        }
                                    }
                                    Gate::Custom(_) => {
                                        a_buf[i] = Goldilocks::ZERO;
                                        b_buf[i] = Goldilocks::ZERO;
                                        c_buf[i] = Goldilocks::ZERO;
                                        out_chunk[i] = Goldilocks::ONE;
                                    }
                                }
                            }

                            goldilocks_mul_batch_into(a_buf, b_buf, ab_buf);

                            for (i, gate) in gates[start..end].iter().enumerate() {
                                match gate {
                                    Gate::Arithmetic(ag) => {
                                        out_chunk[i] =
                                            ag.q_mul * ab_buf[i]
                                                + ag.q_l * a_buf[i]
                                                + ag.q_r * b_buf[i]
                                                + ag.q_o * c_buf[i]
                                                + ag.q_c;
                                    }
                                    Gate::Copy(_) => {
                                        out_chunk[i] = a_buf[i] - b_buf[i];
                                    }
                                    Gate::Custom(_) => {}
                                }
                            }
                        });
                    });

                if !has_custom {
                    return Ok(evaluations);
                }
            }

            if !(validated && gates_len > 1024) {
                for (idx, gate) in gates.iter().enumerate() {
                    match gate {
                        Gate::Arithmetic(ag) => {
                            let a_idx = ag.a.0 as usize;
                            let b_idx = ag.b.0 as usize;
                            let c_idx = ag.c.0 as usize;

                            if validated {
                                let base = values.as_ptr();
                                unsafe {
                                    prefetch_read(base.add(a_idx));
                                    prefetch_read(base.add(b_idx));
                                    prefetch_read(base.add(c_idx));
                                    let a = *values.get_unchecked(a_idx);
                                    let b = *values.get_unchecked(b_idx);
                                    let c = *values.get_unchecked(c_idx);
                                    let eval = ag.q_mul * a * b + ag.q_l * a + ag.q_r * b + ag.q_o * c + ag.q_c;
                                    evaluations[idx] = eval;
                                }
                            } else {
                                let a = self.witness.get_checked(ag.a)?;
                                let b = self.witness.get_checked(ag.b)?;
                                let c = self.witness.get_checked(ag.c)?;
                                let eval = ag.q_mul * a * b + ag.q_l * a + ag.q_r * b + ag.q_o * c + ag.q_c;
                                evaluations[idx] = eval;
                            }
                        }
                        Gate::Copy(cg) => {
                            if validated {
                                let l = self.witness.get_unchecked(cg.left);
                                let r = self.witness.get_unchecked(cg.right);
                                evaluations[idx] = l - r;
                            } else {
                                let left = self.witness.get_checked(cg.left)?;
                                let right = self.witness.get_checked(cg.right)?;
                                evaluations[idx] = left - right;
                            }
                        }
                        Gate::Custom(_) => {
                            evaluations[idx] = Goldilocks::ONE;
                        }
                    }
                }
            }
        }


        if batch_bn254 && !bn254_custom_gates.is_empty() {
            if bn254_custom_gates.len() >= batch_bn254_min {
                let results = self.batch_eval_bn254_custom_gates(&bn254_custom_gates)?;
                for (gate_idx, ok) in results {
                    evaluations[gate_idx] = if ok { Goldilocks::ZERO } else { Goldilocks::ONE };
                }
            } else {
                let gates = &self.ucir.gates;
                for gate_idx in bn254_custom_gates {
                    let eval = self.evaluate_custom_gate(gate_idx, &gates[gate_idx])?;
                    evaluations[gate_idx] = eval;
                }
            }
        }

        if !other_custom_gates.is_empty() {
            if validated && other_custom_gates.len() >= 512 && rayon::current_num_threads() > 1 {
                let gates = &self.ucir.gates;
                let evals = other_custom_gates
                    .par_iter()
                    .map(|&gate_idx| self.evaluate_custom_gate(gate_idx, &gates[gate_idx]))
                    .collect::<Result<Vec<_>, WitnessError>>()?;
                for (gate_idx, eval) in other_custom_gates.iter().copied().zip(evals) {
                    evaluations[gate_idx] = eval;
                }
            } else {
                let gates = &self.ucir.gates;
                for gate_idx in other_custom_gates {
                    let eval = self.evaluate_custom_gate(gate_idx, &gates[gate_idx])?;
                    evaluations[gate_idx] = eval;
                }
            }
        }

        Ok(evaluations)
    }

    /// Release witness buffers to reduce peak memory after evaluation.
    pub fn release_witness(&mut self) {
        self.witness.zeroize();
        self.witness.values.clear();
        self.witness.assigned.clear();
        self.witness.table_multiplicities.clear();
        self.witness.validated = false;
    }

    fn read_limbs_u64(&self, start: WRef) -> Result<[u64; 4], WitnessError> {
        let base = start.0 as usize;
        let end = match base.checked_add(4) {
            Some(v) => v,
            None => return Err(WitnessError::InvalidReference { wref: start.0 }),
        };
        if end > self.witness.values.len() {
            return Err(WitnessError::InvalidReference { wref: start.0 });
        }
        let mut limbs = [0u64; 4];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let wref = WRef((base + i) as u32);
            let val = self.witness.get_checked(wref)?;
            *limb = val.0;
        }
        Ok(limbs)
    }

    fn read_u64_pair(&self, start: WRef) -> Result<[u64; 2], WitnessError> {
        let base = start.0 as usize;
        let end = match base.checked_add(2) {
            Some(v) => v,
            None => return Err(WitnessError::InvalidReference { wref: start.0 }),
        };
        if end > self.witness.values.len() {
            return Err(WitnessError::InvalidReference { wref: start.0 });
        }
        let mut limbs = [0u64; 2];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let wref = WRef((base + i) as u32);
            let val = self.witness.get_checked(wref)?;
            *limb = val.0;
        }
        Ok(limbs)
    }

    fn limbs_to_bytes_le(&self, limbs: [u64; 4]) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, limb) in limbs.iter().enumerate() {
            out[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
        }
        out
    }

    fn compare_artifact_tags(
        &self,
        commitment_start: WRef,
        point_start: WRef,
        claim_start: WRef,
        derived: ([u8; 32], [u8; 32], u128),
    ) -> Result<Goldilocks, WitnessError> {
        let commitment_limbs = self.read_limbs_u64(commitment_start)?;
        let point_limbs = self.read_limbs_u64(point_start)?;
        let claim_limbs = self.read_u64_pair(claim_start)?;
        let commitment_tag = self.limbs_to_bytes_le(commitment_limbs);
        let point_tag = self.limbs_to_bytes_le(point_limbs);
        let claim128 = ((claim_limbs[0] as u128) << 64) | (claim_limbs[1] as u128);
        if derived.0 == commitment_tag && derived.1 == point_tag && derived.2 == claim128 {
            Ok(Goldilocks::ZERO)
        } else {
            Ok(Goldilocks::ONE)
        }
    }

    #[cfg(feature = "ivc")]
    fn verify_ivc_custom_gate(
        &self,
        gate_idx: usize,
        payload_bytes: &[u8],
    ) -> Result<Goldilocks, WitnessError> {
        let payload = crate::glyph_ir::decode_ivc_verify_payload(payload_bytes).map_err(|e| {
            WitnessError::ConstraintViolation {
                gate_idx,
                message: format!("IVC payload decode failed: {e}"),
            }
        })?;
        let derived = crate::ivc_adapter::derive_glyph_artifact_from_ivc_direct(
            &payload.adapter_vk_bytes,
            &payload.adapter_statement_bytes,
            &payload.proof_bytes,
        )
        .map_err(|e| WitnessError::ConstraintViolation {
            gate_idx,
            message: format!("IVC verify failed: {e}"),
        })?;
        self.compare_artifact_tags(
            payload.commitment_start,
            payload.point_start,
            payload.claim_start,
            derived,
        )
    }

    #[cfg(not(feature = "ivc"))]
    fn verify_ivc_custom_gate(
        &self,
        gate_idx: usize,
        _payload_bytes: &[u8],
    ) -> Result<Goldilocks, WitnessError> {
        Err(WitnessError::ConstraintViolation {
            gate_idx,
            message: "adapter family ivc disabled (enable with --features ivc)".to_string(),
        })
    }

    #[cfg(feature = "binius")]
    fn verify_binius_custom_gate(
        &self,
        gate_idx: usize,
        payload_bytes: &[u8],
    ) -> Result<Goldilocks, WitnessError> {
        let payload =
            crate::glyph_ir::decode_binius_verify_payload(payload_bytes).map_err(|e| {
                WitnessError::ConstraintViolation {
                    gate_idx,
                    message: format!("Binius payload decode failed: {e}"),
                }
            })?;
        let derived = crate::binius_adapter::derive_glyph_artifact_from_binius_receipt(
            &payload.adapter_vk_bytes,
            &payload.adapter_statement_bytes,
            &payload.proof_bytes,
        )
        .map_err(|e| WitnessError::ConstraintViolation {
            gate_idx,
            message: format!("Binius verify failed: {e}"),
        })?;
        self.compare_artifact_tags(
            payload.commitment_start,
            payload.point_start,
            payload.claim_start,
            derived,
        )
    }

    #[cfg(not(feature = "binius"))]
    fn verify_binius_custom_gate(
        &self,
        gate_idx: usize,
        _payload_bytes: &[u8],
    ) -> Result<Goldilocks, WitnessError> {
        Err(WitnessError::ConstraintViolation {
            gate_idx,
            message: "adapter family binius disabled (enable with --features binius)".to_string(),
        })
    }

    #[cfg(any(
        feature = "stark-babybear",
        feature = "stark-goldilocks",
        feature = "stark-m31"
    ))]
    fn verify_stark_custom_gate(
        &self,
        gate_idx: usize,
        payload_bytes: &[u8],
    ) -> Result<Goldilocks, WitnessError> {
        let payload = crate::glyph_ir::decode_stark_verify_payload(payload_bytes).map_err(|e| {
            WitnessError::ConstraintViolation {
                gate_idx,
                message: format!("STARK payload decode failed: {e}"),
            }
        })?;
        let receipt = crate::stark_receipt::CanonicalStarkReceipt::decode(&payload.receipt_bytes)
            .map_err(|e| WitnessError::ConstraintViolation {
                gate_idx,
                message: format!("STARK receipt decode failed: {e}"),
            })?;
        let derived = crate::stark_adapter::verified_canonical_stark_receipts_to_glyph_artifact(
            &payload.seed_bytes,
            &[receipt],
        )
        .map_err(|e| WitnessError::ConstraintViolation {
            gate_idx,
            message: format!("STARK verify failed: {e}"),
        })?;
        self.compare_artifact_tags(
            payload.commitment_start,
            payload.point_start,
            payload.claim_start,
            derived,
        )
    }

    #[cfg(not(any(
        feature = "stark-babybear",
        feature = "stark-goldilocks",
        feature = "stark-m31"
    )))]
    fn verify_stark_custom_gate(
        &self,
        gate_idx: usize,
        _payload_bytes: &[u8],
    ) -> Result<Goldilocks, WitnessError> {
        Err(WitnessError::ConstraintViolation {
            gate_idx,
            message:
                "stark adapter disabled (enable with --features stark-babybear,stark-goldilocks,stark-m31)"
                    .to_string(),
        })
    }

    #[cfg(feature = "snark")]
    fn verify_ipa_custom_gate(
        &self,
        gate_idx: usize,
        payload_bytes: &[u8],
    ) -> Result<Goldilocks, WitnessError> {
        let payload = crate::glyph_ir::decode_ipa_verify_payload(payload_bytes).map_err(|e| {
            WitnessError::ConstraintViolation {
                gate_idx,
                message: format!("IPA payload decode failed: {e}"),
            }
        })?;
        let derived = crate::ipa_adapter::derive_glyph_artifact_from_ipa_receipt(
            &payload.receipt_bytes,
        )
        .map_err(|e| WitnessError::ConstraintViolation {
            gate_idx,
            message: format!("IPA verify failed: {e}"),
        })?;
        self.compare_artifact_tags(
            payload.commitment_start,
            payload.point_start,
            payload.claim_start,
            derived,
        )
    }

    #[cfg(not(feature = "snark"))]
    fn verify_ipa_custom_gate(
        &self,
        gate_idx: usize,
        _payload_bytes: &[u8],
    ) -> Result<Goldilocks, WitnessError> {
        Err(WitnessError::ConstraintViolation {
            gate_idx,
            message: "adapter family snark disabled (enable with --features snark)".to_string(),
        })
    }

    #[cfg(feature = "snark")]
    fn verify_sp1_custom_gate(
        &self,
        gate_idx: usize,
        payload_bytes: &[u8],
    ) -> Result<Goldilocks, WitnessError> {
        let payload = crate::glyph_ir::decode_sp1_verify_payload(payload_bytes).map_err(|e| {
            WitnessError::ConstraintViolation {
                gate_idx,
                message: format!("SP1 payload decode failed: {e}"),
            }
        })?;
        let derived = crate::sp1_adapter::derive_glyph_artifact_from_sp1_receipt(
            &payload.receipt_bytes,
        )
        .map_err(|e| WitnessError::ConstraintViolation {
            gate_idx,
            message: format!("SP1 verify failed: {e}"),
        })?;
        self.compare_artifact_tags(
            payload.commitment_start,
            payload.point_start,
            payload.claim_start,
            derived,
        )
    }

    #[cfg(not(feature = "snark"))]
    fn verify_sp1_custom_gate(
        &self,
        gate_idx: usize,
        _payload_bytes: &[u8],
    ) -> Result<Goldilocks, WitnessError> {
        Err(WitnessError::ConstraintViolation {
            gate_idx,
            message: "adapter family snark disabled (enable with --features snark)".to_string(),
        })
    }

    #[cfg(feature = "snark")]
    fn verify_plonk_custom_gate(
        &self,
        gate_idx: usize,
        payload_bytes: &[u8],
    ) -> Result<Goldilocks, WitnessError> {
        let payload = crate::glyph_ir::decode_plonk_verify_payload(payload_bytes).map_err(|e| {
            WitnessError::ConstraintViolation {
                gate_idx,
                message: format!("PLONK payload decode failed: {e}"),
            }
        })?;
        let derived = crate::plonk_halo2_adapter::derive_glyph_artifact_from_plonk_halo2_receipt(
            &payload.receipt_bytes,
        )
        .map_err(|e| WitnessError::ConstraintViolation {
            gate_idx,
            message: format!("PLONK verify failed: {e}"),
        })?;
        self.compare_artifact_tags(
            payload.commitment_start,
            payload.point_start,
            payload.claim_start,
            derived,
        )
    }

    #[cfg(not(feature = "snark"))]
    fn verify_plonk_custom_gate(
        &self,
        gate_idx: usize,
        _payload_bytes: &[u8],
    ) -> Result<Goldilocks, WitnessError> {
        Err(WitnessError::ConstraintViolation {
            gate_idx,
            message: "adapter family snark disabled (enable with --features snark)".to_string(),
        })
    }

    #[cfg(feature = "snark")]
    fn verify_groth16_bls12381_custom_gate(
        &self,
        gate_idx: usize,
        payload_bytes: &[u8],
    ) -> Result<Goldilocks, WitnessError> {
        let payload = crate::glyph_ir::decode_groth16_bls12381_verify_payload(payload_bytes)
            .map_err(|e| WitnessError::ConstraintViolation {
                gate_idx,
                message: format!("Groth16 BLS12381 payload decode failed: {e}"),
            })?;
        let derived = crate::groth16_bls12381::derive_glyph_artifact_from_groth16_bls12381_receipt(
            &payload.receipt_bytes,
        )
        .map_err(|e| WitnessError::ConstraintViolation {
            gate_idx,
            message: format!("Groth16 BLS12381 verify failed: {e}"),
        })?;
        self.compare_artifact_tags(
            payload.commitment_start,
            payload.point_start,
            payload.claim_start,
            derived,
        )
    }

    #[cfg(not(feature = "snark"))]
    fn verify_groth16_bls12381_custom_gate(
        &self,
        gate_idx: usize,
        _payload_bytes: &[u8],
    ) -> Result<Goldilocks, WitnessError> {
        Err(WitnessError::ConstraintViolation {
            gate_idx,
            message: "adapter family snark disabled (enable with --features snark)".to_string(),
        })
    }

    #[cfg(feature = "snark")]
    fn verify_kzg_bls12381_custom_gate(
        &self,
        gate_idx: usize,
        payload_bytes: &[u8],
    ) -> Result<Goldilocks, WitnessError> {
        let payload = crate::glyph_ir::decode_kzg_bls12381_verify_payload(payload_bytes)
            .map_err(|e| WitnessError::ConstraintViolation {
                gate_idx,
                message: format!("KZG BLS12381 payload decode failed: {e}"),
            })?;
        let derived = crate::kzg_bls12381::derive_glyph_artifact_from_kzg_bls12381_receipt(
            &payload.receipt_bytes,
        )
        .map_err(|e| WitnessError::ConstraintViolation {
            gate_idx,
            message: format!("KZG BLS12381 verify failed: {e}"),
        })?;
        self.compare_artifact_tags(
            payload.commitment_start,
            payload.point_start,
            payload.claim_start,
            derived,
        )
    }

    #[cfg(not(feature = "snark"))]
    fn verify_kzg_bls12381_custom_gate(
        &self,
        gate_idx: usize,
        _payload_bytes: &[u8],
    ) -> Result<Goldilocks, WitnessError> {
        Err(WitnessError::ConstraintViolation {
            gate_idx,
            message: "adapter family snark disabled (enable with --features snark)".to_string(),
        })
    }

    fn evaluate_custom_gate(&self, gate_idx: usize, gate: &Gate) -> Result<Goldilocks, WitnessError> {
        let cg = match gate {
            Gate::Custom(cg) => cg,
            _ => {
                return Err(WitnessError::ConstraintViolation {
                    gate_idx,
                    message: "Non-custom gate passed to custom evaluator".to_string(),
                });
            }
        };

        ensure_custom_gate_enabled(cg.custom_id).map_err(|e| WitnessError::ConstraintViolation {
            gate_idx,
            message: e,
        })?;

        match cg.custom_id {
            CUSTOM_GATE_BN254_ADD | CUSTOM_GATE_BN254_SUB | CUSTOM_GATE_BN254_MUL => {
                let (a_start, b_start, out_start) = decode_three_wref_payload(&cg.payload)
                    .ok_or_else(|| WitnessError::ConstraintViolation {
                        gate_idx,
                        message: "Invalid custom gate payload".to_string(),
                    })?;
                let a = self.read_limbs_u64(a_start)?;
                let b = self.read_limbs_u64(b_start)?;
                let out = self.read_limbs_u64(out_start)?;

                let expected = match cg.custom_id {
                    CUSTOM_GATE_BN254_ADD => bn254_add_mod(a, b),
                    CUSTOM_GATE_BN254_SUB => bn254_sub_mod(a, b),
                    CUSTOM_GATE_BN254_MUL => bn254_mul_mod(a, b),
                    _ => None,
                };

                match expected {
                    Some(exp) if exp == out => Ok(Goldilocks::ZERO),
                    Some(_) => Ok(Goldilocks::ONE),
                    None => Err(WitnessError::ConstraintViolation {
                        gate_idx,
                        message: "BN254 op on non-canonical limbs".to_string(),
                    }),
                }
            }
            CUSTOM_GATE_KECCAK_MERGE => {
                let (a_start, b_start, out_start) = decode_three_wref_payload(&cg.payload)
                    .ok_or_else(|| WitnessError::ConstraintViolation {
                        gate_idx,
                        message: "Invalid custom gate payload".to_string(),
                    })?;
                let left = self.read_limbs_u64(a_start)?;
                let right = self.read_limbs_u64(b_start)?;
                let out = self.read_limbs_u64(out_start)?;

                let mut input = [0u8; 64];
                for i in 0..4 {
                    input[i * 8..(i + 1) * 8].copy_from_slice(&left[i].to_le_bytes());
                    input[32 + i * 8..32 + (i + 1) * 8].copy_from_slice(&right[i].to_le_bytes());
                }
                let digest = keccak256(&input);
                let mut out_bytes = [0u8; 32];
                for i in 0..4 {
                    out_bytes[i * 8..(i + 1) * 8].copy_from_slice(&out[i].to_le_bytes());
                }
                if digest == out_bytes {
                    Ok(Goldilocks::ZERO)
                } else {
                    Ok(Goldilocks::ONE)
                }
            }
            CUSTOM_GATE_IVC_VERIFY => self.verify_ivc_custom_gate(gate_idx, &cg.payload),
            CUSTOM_GATE_BINIUS_VERIFY => self.verify_binius_custom_gate(gate_idx, &cg.payload),
            CUSTOM_GATE_STARK_VERIFY => self.verify_stark_custom_gate(gate_idx, &cg.payload),
            CUSTOM_GATE_IPA_VERIFY => self.verify_ipa_custom_gate(gate_idx, &cg.payload),
            CUSTOM_GATE_SP1_VERIFY => self.verify_sp1_custom_gate(gate_idx, &cg.payload),
            CUSTOM_GATE_PLONK_VERIFY => self.verify_plonk_custom_gate(gate_idx, &cg.payload),
            CUSTOM_GATE_GROTH16_BLS12381_VERIFY => {
                self.verify_groth16_bls12381_custom_gate(gate_idx, &cg.payload)
            }
            CUSTOM_GATE_KZG_BLS12381_VERIFY => {
                self.verify_kzg_bls12381_custom_gate(gate_idx, &cg.payload)
            }
            _ => Err(WitnessError::ConstraintViolation {
                gate_idx,
                message: "Unknown custom gate id".to_string(),
            }),
        }
    }

    /// Get transcript state for continuation
    pub fn transcript_state(&self) -> [u8; 32] {
        self.transcript.state()
    }

    /// Finalize and return witness
    pub fn finalize(self) -> WitnessBuffer {
        self.witness
    }
}

// ============================================================
//                    TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fq;
    use ark_ec::CurveGroup;
    use ark_ff::UniformRand;
    use ark_std::rand::SeedableRng;
    use binius_field::underlier::WithUnderlier;
    use crate::glyph_ir::{
        ArithmeticGate, CustomGate, encode_three_wref_payload, encode_ivc_verify_payload,
        encode_stark_verify_payload, encode_ipa_verify_payload, CUSTOM_GATE_KECCAK_MERGE,
        CUSTOM_GATE_IVC_VERIFY, CUSTOM_GATE_STARK_VERIFY, CUSTOM_GATE_IPA_VERIFY,
        TABLE_RANGE8, Table,
    };

    fn witness_err(err: WitnessError) -> String {
        format!("{:?}", err)
    }

    #[test]
    fn test_witness_buffer_basic() {
        let layout = WitnessLayout::fast_mode(2, 10, 5);
        let mut buffer = WitnessBuffer::new(layout);

        buffer.set_public(0, Goldilocks(42));
        buffer.set_public(1, Goldilocks(100));

        assert_eq!(buffer.get(WRef(0)), Goldilocks(42));
        assert_eq!(buffer.get(WRef(1)), Goldilocks(100));

        println!("Witness buffer basic test passed.");
    }

    #[test]
    fn test_get_unchecked_oob_is_safe() {
        let layout = WitnessLayout::fast_mode(0, 0, 0);
        let buffer = WitnessBuffer::new(layout);
        let v = buffer.get_unchecked(WRef(0));
        assert_eq!(v, Goldilocks::ZERO);
    }

    #[test]
    fn test_witness_watchers_edge_cap_trips() -> Result<(), String> {
        let mut ucir = Ucir2::new();
        ucir.witness_layout = WitnessLayout::fast_mode(2, 1, 0);

        for _ in 0..64 {
            ucir.add_arithmetic_gate(ArithmeticGate::mul(WRef(0), WRef(1), WRef(2)));
        }

        let mut stream = WitnessStream::try_new(ucir, 64).map_err(witness_err)?;
        let public_inputs = vec![Goldilocks(3), Goldilocks(7)];
        let err = match stream.phase_w1_produce(&public_inputs, None) {
            Err(err) => err,
            Ok(_) => {
                assert!(false, "expected error");
                return Err("expected error".to_string());
            }
        };
        match err {
            WitnessError::MemoryLimitExceeded { stage, .. } => {
                assert!(stage.starts_with("W1_watchers"));
            }
            _ => {
                assert!(false, "unexpected error");
                return Err("unexpected error".to_string());
            }
        }
        Ok(())
    }

    #[test]
    fn test_witness_stream_init_memory_guard() -> Result<(), String> {
        let mut ucir = Ucir2::new();
        ucir.witness_layout = WitnessLayout::fast_mode(0, 4, 0);
        let required = witness_bytes_for_len(ucir.witness_layout.total_len() as usize);
        let limit = required.saturating_sub(1);
        let err = match WitnessStream::try_new(ucir, limit) {
            Err(err) => err,
            Ok(_) => {
                assert!(false, "expected error");
                return Err("expected error".to_string());
            }
        };
        match err {
            WitnessError::MemoryLimitExceeded { stage, .. } => {
                assert_eq!(stage, "Init");
            }
            _ => {
                assert!(false, "unexpected error");
                return Err("unexpected error".to_string());
            }
        }
        Ok(())
    }

    #[test]
    fn test_custom_gate_read_limbs_bounds_error() -> Result<(), String> {
        let mut ucir = Ucir2::new();
        ucir.witness_layout = WitnessLayout::fast_mode(0, 3, 0);
        let payload = encode_three_wref_payload(WRef(0), WRef(0), WRef(0));
        ucir.add_custom_gate(CustomGate::new(CUSTOM_GATE_KECCAK_MERGE, payload));

        let mut stream = WitnessStream::try_new(ucir, 1024 * 1024).map_err(witness_err)?;
        let public_inputs: Vec<Goldilocks> = Vec::new();
        if let Err(err) = stream.phase_w1_produce(&public_inputs, Some(&[])) {
            match err {
                WitnessError::InvalidReference { .. } => return Ok(()),
                _ => {
                    assert!(false, "unexpected error");
                    return Err("unexpected error".to_string());
                }
            }
        }
        let err = match stream.phase_w2_evaluate() {
            Err(err) => err,
            Ok(_) => {
                assert!(false, "expected error");
                return Err("expected error".to_string());
            }
        };
        match err {
            WitnessError::InvalidReference { .. } => {}
            _ => {
                assert!(false, "unexpected error");
                return Err("unexpected error".to_string());
            }
        }
        Ok(())
    }

    #[test]
    fn test_witness_stream_simple() -> Result<(), String> {
        let mut ucir = Ucir2::new();
        ucir.witness_layout = WitnessLayout::fast_mode(2, 1, 0);

        // Add: a * b = c (where a=WRef(0), b=WRef(1), c=WRef(2))
        ucir.add_arithmetic_gate(ArithmeticGate::mul(WRef(0), WRef(1), WRef(2)));

        let mut stream = WitnessStream::try_new(ucir, 1024 * 1024).map_err(witness_err)?;

        // Set public inputs
        let public_inputs = vec![Goldilocks(3), Goldilocks(7)];
        let result = stream.phase_w1_produce(&public_inputs, None);
        assert!(result.is_ok(), "phase_w1_produce failed: {:?}", result.err());

        // Set the expected output
        stream.witness.set(WRef(2), Goldilocks(21)); // 3 * 7 = 21

        // Evaluate constraints
        let evals = stream.phase_w2_evaluate().map_err(witness_err)?;
        assert_eq!(evals.len(), 1);
        assert_eq!(evals[0], Goldilocks::ZERO); // Constraint satisfied

        println!("Witness stream simple test passed.");
        Ok(())
    }

    #[test]
    fn test_count_multiplicities_rejects_malformed_range8_table() -> Result<(), String> {
        let mut ucir = Ucir2::new();
        ucir.witness_layout = WitnessLayout::fast_mode(1, 1, 1);

        ucir.add_copy_gate(WRef(0), WRef(1));
        ucir.add_lookup(WRef(1), TABLE_RANGE8);
        ucir.add_table(Table::new(TABLE_RANGE8, 1, vec![Goldilocks::ZERO]));

        let mut stream = WitnessStream::try_new(ucir, 1024 * 1024).map_err(witness_err)?;
        let public_inputs = vec![Goldilocks(7)];
        let err = match stream.phase_w1_produce(&public_inputs, None) {
            Ok(_) => {
                assert!(false, "expected error");
                return Err("expected error".to_string());
            }
            Err(err) => err,
        };
        match err {
            WitnessError::InvalidTable { table_id, .. } => {
                assert_eq!(table_id, TABLE_RANGE8);
            }
            _ => {
                assert!(false, "unexpected error");
                return Err("unexpected error".to_string());
            }
        }
        Ok(())
    }

    #[test]
    #[cfg(feature = "ivc")]
    fn test_custom_gate_ivc_verify_roundtrip() -> Result<(), String> {
        let inst = crate::adapters::keccak256(b"ivc-custom-gate");
        let instance_digests = vec![inst];
        let weights = crate::glyph_basefold::derive_basefold_weights(&instance_digests)
            .map_err(|err| format!("weights: {err}"))?;
        let n_vars = 4usize;
        let eval_point =
            crate::glyph_basefold::derive_binius_eval_point(b"ivc-custom-gate", 0, n_vars);
        let evals: Vec<binius_field::BinaryField128b> = (0..(1usize << n_vars))
            .map(|i| binius_field::BinaryField128b::from_underlier((i as u128) + 1))
            .collect();
        let prover = crate::pcs_basefold::BaseFoldProver::commit(
            &evals,
            n_vars,
            crate::pcs_basefold::BaseFoldConfig::default(),
        )
        .map_err(|err| format!("basefold commit: {err}"))?;
        let commitment = prover.commitment();
        let opening = prover.open(&eval_point).map_err(|err| format!("basefold open: {err}"))?;
        let opening = crate::ivc_adapter::BaseFoldPcsOpeningProof {
            instance_digests,
            weights,
            commitment,
            eval_point,
            claimed_eval: opening.eval,
            proofs: opening.proofs,
        };
        let proof_bytes = crate::ivc_adapter::encode_ivc_basefold_proof_bytes(&opening)
            .map_err(|err| format!("ivc proof bytes: {err}"))?;

        let commitment_tag = crate::pcs_basefold::derive_basefold_commitment_tag(&opening.commitment);
        let point_tag = crate::pcs_basefold::derive_basefold_point_tag(&commitment_tag, &opening.eval_point);
        let claim128 = opening.claimed_eval.to_underlier();
        let vk_bytes = crate::adapters::ivc_vk_bytes(
            4,
            crate::adapters::IvcProofType::BaseFoldTransparent,
        );
        let stmt_bytes = crate::adapters::ivc_statement_bytes(
            &commitment_tag,
            &point_tag,
            claim128,
            crate::adapters::IvcProofType::BaseFoldTransparent,
        );
        let (commitment_tag, point_tag, claim128) =
            crate::ivc_adapter::derive_glyph_artifact_from_ivc_direct(
                &vk_bytes,
                &stmt_bytes,
                &proof_bytes,
            )
            .map_err(|err| format!("ivc artifact: {err}"))?;

        let mut ucir = Ucir2::new();
        ucir.witness_layout = WitnessLayout::fast_mode(10, 0, 0);
        let payload = encode_ivc_verify_payload(
            WRef(0),
            WRef(4),
            WRef(8),
            &vk_bytes,
            &stmt_bytes,
            &proof_bytes,
        );
        ucir.add_custom_gate(CustomGate::new(CUSTOM_GATE_IVC_VERIFY, payload));

        let mut public_inputs = Vec::new();
        public_inputs.extend_from_slice(&crate::glyph_ir_compiler::embed_fq_limbs(&commitment_tag));
        public_inputs.extend_from_slice(&crate::glyph_ir_compiler::embed_fq_limbs(&point_tag));
        public_inputs.push(Goldilocks((claim128 >> 64) as u64));
        public_inputs.push(Goldilocks(claim128 as u64));

        let mut recon_commit = [0u8; 32];
        for i in 0..4 {
            recon_commit[i * 8..(i + 1) * 8].copy_from_slice(&public_inputs[i].0.to_le_bytes());
        }
        let mut recon_point = [0u8; 32];
        for i in 0..4 {
            recon_point[i * 8..(i + 1) * 8].copy_from_slice(&public_inputs[4 + i].0.to_le_bytes());
        }
        let recon_claim =
            ((public_inputs[8].0 as u128) << 64) | (public_inputs[9].0 as u128);
        assert_eq!(recon_commit, commitment_tag);
        assert_eq!(recon_point, point_tag);
        assert_eq!(recon_claim, claim128);

        let mut stream = WitnessStream::try_new(ucir, 1024 * 1024).map_err(witness_err)?;
        stream.phase_w1_produce(&public_inputs, None)
            .map_err(witness_err)?;
        let evals = stream.phase_w2_evaluate().map_err(witness_err)?;
        assert_eq!(evals.len(), 1);
        assert_eq!(evals[0], Goldilocks::ZERO);

        let mut tampered = public_inputs.clone();
        tampered[0] = Goldilocks(tampered[0].0 ^ 1);
        let mut stream =
            WitnessStream::try_new(stream.ucir.clone(), 1024 * 1024).map_err(witness_err)?;
        stream.phase_w1_produce(&tampered, Some(&[]))
            .map_err(witness_err)?;
        let evals = stream.phase_w2_evaluate().map_err(witness_err)?;
        assert_eq!(evals.len(), 1);
        assert_ne!(evals[0], Goldilocks::ZERO);
        Ok(())
    }

    #[test]
    #[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
    fn test_custom_gate_stark_verify_roundtrip() -> Result<(), String> {
        let seed = b"stark-custom-gate";
        let trace_length = 64usize;
        let receipts =
            crate::stark_winterfell::seeded_do_work_receipts_sha3(seed, trace_length, 1)
                .map_err(|err| format!("receipts: {err}"))?;
        let canonical =
            crate::stark_winterfell::canonical_stark_receipt_from_upstream_do_work(&receipts[0])
                .map_err(|err| format!("canonical receipt: {err}"))?;
        let receipt_bytes = canonical.encode_for_hash();
        let (commitment_tag, point_tag, claim128) =
            crate::stark_adapter::verified_canonical_stark_receipts_to_glyph_artifact(
                seed,
                &[canonical],
            )
            .map_err(|err| format!("artifact: {err}"))?;

        let mut ucir = Ucir2::new();
        ucir.witness_layout = WitnessLayout::fast_mode(10, 0, 0);
        let payload = encode_stark_verify_payload(
            WRef(0),
            WRef(4),
            WRef(8),
            seed,
            &receipt_bytes,
        );
        ucir.add_custom_gate(CustomGate::new(CUSTOM_GATE_STARK_VERIFY, payload));

        let mut public_inputs = Vec::new();
        public_inputs.extend_from_slice(&crate::glyph_ir_compiler::embed_fq_limbs(&commitment_tag));
        public_inputs.extend_from_slice(&crate::glyph_ir_compiler::embed_fq_limbs(&point_tag));
        public_inputs.push(Goldilocks((claim128 >> 64) as u64));
        public_inputs.push(Goldilocks(claim128 as u64));

        let mut stream = WitnessStream::try_new(ucir, 1024 * 1024).map_err(witness_err)?;
        stream.phase_w1_produce(&public_inputs, Some(&[]))
            .map_err(witness_err)?;
        let evals = stream.phase_w2_evaluate().map_err(witness_err)?;
        assert_eq!(evals.len(), 1);
        assert_eq!(evals[0], Goldilocks::ZERO);

        let mut tampered = public_inputs.clone();
        tampered[4] = Goldilocks(tampered[4].0 ^ 1);
        let mut stream =
            WitnessStream::try_new(stream.ucir.clone(), 1024 * 1024).map_err(witness_err)?;
        stream.phase_w1_produce(&tampered, Some(&[]))
            .map_err(witness_err)?;
        let evals = stream.phase_w2_evaluate().map_err(witness_err)?;
        assert_eq!(evals.len(), 1);
        assert_ne!(evals[0], Goldilocks::ZERO);
        Ok(())
    }

    #[test]
    #[cfg(feature = "snark")]
    fn test_custom_gate_ipa_verify_roundtrip() -> Result<(), String> {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(0xface_cafe);
        let n = 4usize;
        let params = crate::ipa_bn254::IPAParams::new(n);
        let prover = crate::ipa_bn254::IPAProver { params: &params };
        let a: Vec<ark_bn254::Fr> = (0..n).map(|_| ark_bn254::Fr::rand(&mut rng)).collect();
        let b: Vec<ark_bn254::Fr> = (0..n).map(|_| ark_bn254::Fr::rand(&mut rng)).collect();
        let public_inputs = a[..2].to_vec();
        let statement_hash = crate::ipa_adapter::ipa_statement_hash_bn254(&public_inputs);
        let (commitment, _c, proof) = prover
            .prove_optimized_with_statement(&a, &b, &statement_hash)
            .map_err(|err| format!("prove: {err:?}"))?;
        let receipt_bytes = crate::ipa_adapter::build_ipa_receipt_bn254(
            crate::ipa_adapter::IPA_BACKEND_HALO2,
            crate::ipa_adapter::IPA_TRANSCRIPT_GLYPH,
            n,
            &public_inputs,
            &commitment.into_affine(),
            &proof,
        );
        let (commitment_tag, point_tag, claim128) =
            crate::ipa_adapter::derive_glyph_artifact_from_ipa_receipt(&receipt_bytes)
                .map_err(|err| format!("artifact: {err}"))?;

        let mut ucir = Ucir2::new();
        ucir.witness_layout = WitnessLayout::fast_mode(10, 0, 0);
        let payload = encode_ipa_verify_payload(
            WRef(0),
            WRef(4),
            WRef(8),
            &receipt_bytes,
        );
        ucir.add_custom_gate(CustomGate::new(CUSTOM_GATE_IPA_VERIFY, payload));

        let mut public_inputs = Vec::new();
        public_inputs.extend_from_slice(&crate::glyph_ir_compiler::embed_fq_limbs(&commitment_tag));
        public_inputs.extend_from_slice(&crate::glyph_ir_compiler::embed_fq_limbs(&point_tag));
        public_inputs.push(Goldilocks((claim128 >> 64) as u64));
        public_inputs.push(Goldilocks(claim128 as u64));

        let mut stream = WitnessStream::try_new(ucir, 1024 * 1024).map_err(witness_err)?;
        stream.phase_w1_produce(&public_inputs, Some(&[]))
            .map_err(witness_err)?;
        let evals = stream.phase_w2_evaluate().map_err(witness_err)?;
        assert_eq!(evals.len(), 1);
        assert_eq!(evals[0], Goldilocks::ZERO);
        Ok(())
    }

    #[test]
    fn test_custom_gate_bn254_batch_eval() -> Result<(), String> {
        let _env_lock = crate::test_utils::lock_env();
        let _batch = crate::test_utils::EnvVarGuard::set("GLYPH_BN254_WITNESS_BATCH", "1");
        let _min = crate::test_utils::EnvVarGuard::set("GLYPH_BN254_WITNESS_BATCH_MIN", "1");

        let mut ucir = Ucir2::new();
        ucir.witness_layout = WitnessLayout::fast_mode(0, 12, 0);
        let payload = encode_three_wref_payload(WRef(0), WRef(4), WRef(8));
        ucir.add_custom_gate(CustomGate::new(CUSTOM_GATE_BN254_ADD, payload));

        let mut wire_values = Vec::new();
        wire_values.extend_from_slice(&[
            Goldilocks(1),
            Goldilocks(0),
            Goldilocks(0),
            Goldilocks(0),
        ]);
        wire_values.extend_from_slice(&[
            Goldilocks(2),
            Goldilocks(0),
            Goldilocks(0),
            Goldilocks(0),
        ]);
        wire_values.extend_from_slice(&[
            Goldilocks(3),
            Goldilocks(0),
            Goldilocks(0),
            Goldilocks(0),
        ]);

        let mut stream = WitnessStream::try_new(ucir.clone(), 1024 * 1024).map_err(witness_err)?;
        stream.phase_w1_produce(&[], Some(&wire_values))
            .map_err(witness_err)?;
        let evals = stream.phase_w2_evaluate().map_err(witness_err)?;
        assert_eq!(evals.len(), 1);
        assert_eq!(evals[0], Goldilocks::ZERO);

        let mut bad_values = wire_values.clone();
        bad_values[8] = Goldilocks(4);
        let mut stream = WitnessStream::try_new(ucir, 1024 * 1024).map_err(witness_err)?;
        stream.phase_w1_produce(&[], Some(&bad_values))
            .map_err(witness_err)?;
        let evals = stream.phase_w2_evaluate().map_err(witness_err)?;
        assert_eq!(evals.len(), 1);
        assert_eq!(evals[0], Goldilocks::ONE);

        Ok(())
    }

    #[test]
    fn test_custom_gate_bn254_batch_parity() -> Result<(), String> {
        let _env_lock = crate::test_utils::lock_env();
        let _min = crate::test_utils::EnvVarGuard::set("GLYPH_BN254_WITNESS_BATCH_MIN", "1");

        let mut ucir = Ucir2::new();
        ucir.witness_layout = WitnessLayout::fast_mode(0, 36, 0);
        let payload_add = encode_three_wref_payload(WRef(0), WRef(4), WRef(8));
        let payload_sub = encode_three_wref_payload(WRef(12), WRef(16), WRef(20));
        let payload_mul = encode_three_wref_payload(WRef(24), WRef(28), WRef(32));
        ucir.add_custom_gate(CustomGate::new(CUSTOM_GATE_BN254_ADD, payload_add));
        ucir.add_custom_gate(CustomGate::new(CUSTOM_GATE_BN254_SUB, payload_sub));
        ucir.add_custom_gate(CustomGate::new(CUSTOM_GATE_BN254_MUL, payload_mul));

        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(0xdead_beef);
        let add_a = crate::bn254_field::limbs_from_fq(Fq::rand(&mut rng));
        let add_b = crate::bn254_field::limbs_from_fq(Fq::rand(&mut rng));
        let add_out = match crate::bn254_field::bn254_add_mod(add_a, add_b) {
            Some(value) => value,
            None => {
                assert!(false, "add failed");
                return Err("add failed".to_string());
            }
        };
        let sub_a = crate::bn254_field::limbs_from_fq(Fq::rand(&mut rng));
        let sub_b = crate::bn254_field::limbs_from_fq(Fq::rand(&mut rng));
        let sub_out = match crate::bn254_field::bn254_sub_mod(sub_a, sub_b) {
            Some(value) => value,
            None => {
                assert!(false, "sub failed");
                return Err("sub failed".to_string());
            }
        };
        let mul_a = crate::bn254_field::limbs_from_fq(Fq::rand(&mut rng));
        let mul_b = crate::bn254_field::limbs_from_fq(Fq::rand(&mut rng));
        let mul_out = match crate::bn254_field::bn254_mul_mod(mul_a, mul_b) {
            Some(value) => value,
            None => {
                assert!(false, "mul failed");
                return Err("mul failed".to_string());
            }
        };

        let mut wire_values = Vec::new();
        for limb in add_a {
            wire_values.push(Goldilocks(limb));
        }
        for limb in add_b {
            wire_values.push(Goldilocks(limb));
        }
        for limb in add_out {
            wire_values.push(Goldilocks(limb));
        }
        for limb in sub_a {
            wire_values.push(Goldilocks(limb));
        }
        for limb in sub_b {
            wire_values.push(Goldilocks(limb));
        }
        for limb in sub_out {
            wire_values.push(Goldilocks(limb));
        }
        for limb in mul_a {
            wire_values.push(Goldilocks(limb));
        }
        for limb in mul_b {
            wire_values.push(Goldilocks(limb));
        }
        for limb in mul_out {
            wire_values.push(Goldilocks(limb));
        }

        let run_eval = |batch: bool, values: &[Goldilocks]| -> Result<Vec<Goldilocks>, String> {
            let _batch = crate::test_utils::EnvVarGuard::set(
                "GLYPH_BN254_WITNESS_BATCH",
                if batch { "1" } else { "0" },
            );
            let mut stream = WitnessStream::try_new(ucir.clone(), 1024 * 1024).map_err(witness_err)?;
            stream.phase_w1_produce(&[], Some(values))
                .map_err(witness_err)?;
            stream.phase_w2_evaluate().map_err(witness_err)
        };

        let evals_batch = run_eval(true, &wire_values)?;
        let evals_single = run_eval(false, &wire_values)?;
        assert_eq!(evals_batch, evals_single);
        assert!(evals_batch.iter().all(|v| *v == Goldilocks::ZERO));

        let mut bad_values = wire_values.clone();
        bad_values[8] = Goldilocks(bad_values[8].0 ^ 1);
        let evals_batch_bad = run_eval(true, &bad_values)?;
        let evals_single_bad = run_eval(false, &bad_values)?;
        assert_eq!(evals_batch_bad, evals_single_bad);
        assert!(evals_batch_bad.iter().any(|v| *v != Goldilocks::ZERO));
        Ok(())
    }
}
