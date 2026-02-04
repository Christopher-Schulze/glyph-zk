# Formal Proof Pack - State Diff Binding

## Definitions
State diffs are serialized into bytes and committed via a Merkle root. The root is bound into the statement hash as an extra commitment in the extended binding flow. This extra commitment is carried as `extra_commitment` in the statement and is included in the chain binding.

Let D be the ordered diff list. Let R = MerkleRoot(D). Let H be Keccak256. Let S be the statement hash computed by the L2 statement logic. Let Tag be the artifact tag derived from S.

State model: A state is a mapping from keys to values, with keys for account nonces, balances, code hashes, and storage slots. Keys and values are encoded as 32-byte words. A transaction batch induces a transition from old_root to new_root with a diff set D that records all changed leaves.

Diff extraction function (VM update flow):
1) Produce a deterministic ordered list of updates during VM execution.
2) For each update, append `key || old_value || new_value` (each 32 bytes) to the byte stream.
3) Chunk the byte stream into 32-byte leaves, padding the final chunk with zeros.
4) If the byte stream is empty, use a single zero leaf.
5) Pad the leaf list with zero leaves to the next power of two.
The ordering is the VM update order and is deterministic for a fixed execution trace.

Diff extraction function (JSON state diff flow):
1) Build the diff JSON as emitted by `glyph_state_diff`, with top-level `"version": 1`
   and an `accounts` array ordered by address. Each account's `storage` array is ordered by slot.
2) Canonicalize by sorting all object keys lexicographically. Array order is preserved.
3) Serialize the canonical JSON to bytes.
4) Apply the same 32-byte chunking and padding rules as above.

Merkle root definition:
- Let L_0 be the list of leaves (padded to power of two).
- For each level k, define L_{k+1}[i] = H(L_k[2i] || L_k[2i+1]).
- The root R is the single element of the final level.

## Lemmas
1. **Diff Root Determinism**: The diff root is deterministic given the ordered byte stream and padding rules.
2. **Statement Binding**: The extended statement hash binds the diff root into the transcript.
3. **Replay Resistance**: A proof bound to one diff root cannot be reused for another.
4. **Diff Extraction Correctness**: The diff extraction produces a unique byte stream for the
transition from old_root to new_root: VM updates or canonical JSON diff.

## Theorem 5: State Diff Binding
Assuming A1 and A2, if a proof verifies under the extended statement hash, then the diff
root R is the one provided to the prover, and cannot be swapped without invalidating the proof.

## Theorem 5b: State Diff Circuit Correctness
Assuming A7, if the VM executes a batch from old_root to new_root and produces diff list D, then
the circuit output state_diff_root equals MerkleRoot(D) as defined by `src/state_diff_merkle.rs`.

## Proof (Formal Sketch)
1. Diff extraction is deterministic by construction. VM updates use execution order, while JSON diffs are canonicalized with sorted object keys and deterministic account and storage ordering. Both are encoded into 32-byte leaves with zero padding to the next power of two.
2. The Merkle root function in the circuit matches the Rust implementation on each level, including padding and hashing rules.
3. Therefore the computed root in the circuit matches MerkleRoot(D), and the bound statement ensures the proof ties to this root.

## Expanded Correctness Argument
Let exec(old_root, txs) -> (new_root, updates) be the VM execution. The update
order is deterministic for a fixed execution trace. The byte stream is formed by
concatenating `key || old_value || new_value` for each update. The leaf encoding
is fixed-length (32-byte chunks) and deterministic. The Merkle tree construction
uses zero padding to the next power of two and Keccak hashing on each internal node.

The circuit implements the same leaf encoding and the same Merkle reduction on
the produced byte stream. By induction on tree depth, each internal node in the
circuit matches the corresponding internal node in the Rust implementation.
Therefore the final root matches MerkleRoot(D).

## Proof Sketch
The prover computes the diff root and includes it as `extra_commitment`.
The statement hash and artifact tags include this value, and the schema id
is hashed alongside to prevent cross-schema replays. For state diff flow,
`extra_schema_id = keccak256("GLYPH_STATE_DIFF_MERKLE_V1")`. Any modification
to the diff root changes the artifact tag, causing verification to fail.

## Assumptions
- Fiat-Shamir transcript behaves as a random oracle (A1).
- Keccak256 collision resistance (A2).
- Correctness of statement hash derivation.

## Proof-to-Code Map
- Diff root computation: `src/state_diff_merkle.rs`
- Statement hash derivation: `src/bin/glyph_l2_statement.rs`
- Extended binding verifier: `contracts/GLYPHRootUpdaterExtended.sol`
- State transition VM: `src/state_transition_vm.rs`

## Implementation Invariants
- Merkle root uses zero padding to power of two.
- Statement hash includes extra_commitment and schema id.
- Verifier checks artifact tag derived from the statement hash.
- Diff list ordering and leaf encoding are canonical and deterministic.
