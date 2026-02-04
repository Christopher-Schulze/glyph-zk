# GLYPH State Transition VM Specification

## Scope
This document specifies the GLYPH state transition VM used by the state diff layer. The VM is gas-neutral on-chain and provides deterministic execution, trace generation, and proof-friendly constraints. The on-chain verifier and statement binding remain unchanged.

## Design Goals
- Gas neutrality: no on-chain verifier changes and no calldata growth beyond existing bound inputs.
- Soundness: the circuit proves that a batch of state operations transforms `old_root` into `new_root`.
- Determinism: identical inputs always produce identical trace and roots.
- Performance: optimized for witness generation, SIMD, and concurrency.

## State Model
- Keys are index-encoded, little-endian `u32` in bytes `[0..4)` and zero elsewhere.
- Values are 32-byte words.
- Leaf hash: `keccak256(LEAF_DOMAIN || value)` where `LEAF_DOMAIN = keccak256("GLYPH_STATE_TRANSITION_LEAF_V1")`.
- State root: binary Keccak Merkle tree, depth in `1..=32`, padded via zero hashes.
- Zero hashes are deterministic per depth, computed from `LEAF_DOMAIN`.

## Operations
### Store
- Input: key, value
- Semantics: `new_value = value`

### Add
- Input: key, delta
- Semantics: `new_value = old_value + delta mod 2^256`

## Batch Execution
- A batch contains an `old_root` and a list of updates derived from operations.
- Each update includes key, old_value, new_value, proof, op_kind, operand.
- All updates in a batch must use the same Merkle depth.
- `proof.siblings.len == proof.path_bits.len`.
- `path_bits` length must be in `1..=32`.
- The VM enforces key-to-path binding and Merkle proof correctness for each update.

## Trace Format
Per step:
- op_kind: `store` or `add`
- key: 32-byte index key
- operand: 32-byte (value for store, delta for add)
- old_value: 32-byte value before update
- new_value: 32-byte value after update
- proof: Merkle proof (siblings, path_bits)
- old_root, new_root: roots before and after the step

## Circuit Constraints
For each update:
1. Key-to-path binding: path bits reconstruct the key index (LSB-first) and key upper bytes are zero.
2. Merkle correctness: old root equals proof path for `leaf(old_value)`; new root equals proof path for `leaf(new_value)`.
3. Operation semantics:
   - Store: `new_value = operand`
   - Add: `new_value = old_value + operand` with carry constraints per 64-bit limb.
4. Roots chain: each update consumes the previous root and produces the next root.

## Diff Commitment
- Diff bytes are `key || old_value || new_value` per update.
- Diff root is computed by the canonical state diff merkle function used by `state_diff_merkle`.
- The diff root is bound to the GLYPH artifact via the extended statement binding.

## Schema ID
- `state_transition_schema_id = keccak256("GLYPH_STATE_TRANSITION_VM_V1")`.
- This value is supplied as `extra_schema_id` alongside `extra_commitment`.

## Security and Interop
- Keccak hashing remains unchanged to preserve interoperability.
- The VM does not introduce additional on-chain data or verification steps.
- Any change to hashing or statement binding requires explicit gas-neutral approval.

## Determinism Requirements
- All hash inputs are canonical.
- Update ordering is deterministic and must be fixed by the caller.
- No nondeterministic host calls are permitted.
