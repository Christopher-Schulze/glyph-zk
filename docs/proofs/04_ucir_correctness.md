# Formal Proof Pack - UCIR Correctness

## Definitions
UCIR is the Universal Constraint IR. The UCIR decoder enforces structure, bounds, and canonical
field elements.

Let D be the UCIR decoder. Let C be the UCIR compiler for a given adapter family. Let E be the
UCIR execution engine (witness evaluation). Let V be the upstream verifier for a receipt.

Define the UCIR semantics as a relation:
UCIR_SAT(ucir, w) == all gates evaluate to zero over the witness w, with the
witness layout constraints satisfied.

Define adapter correctness as:
ADAPTER_OK(receipt) == V(receipt) == true.

Gate semantics:
- Arithmetic gate enforces: q_mul*a*b + q_l*a + q_r*b + q_o*c + q_c = 0.
- Copy gate enforces: left == right.
- Lookup gate enforces: witness value is in the specified table.
- Custom gates encode adapter specific verifier relations.

## Lemmas
1. **Decoder Safety**: `Ucir2::from_bytes` rejects malformed encodings and out-of-range values.
2. **Compiler Correctness**: Each adapter compiler produces UCIR that faithfully represents the upstream verification logic for that receipt family.
3. **Execution Soundness**: UCIR execution enforces all constraints; any mismatch between public inputs and adapter proof logic yields a non-zero constraint and cannot be satisfied.
4. **Gate Semantics Preservation**: Each gate type in UCIR implements its algebraic meaning exactly as specified in `docs/specs/ucir_spec.md`.

## Theorem 4: UCIR Adapter Equivalence
Assuming A6 and A7, if a receipt verifies under the upstream verifier V, then the UCIR produced by compiler C is satisfiable under E. If V rejects, the UCIR constraints are unsatisfiable.

## Proof (Formal Sketch)
For a given adapter family F, the compiler C_F emits UCIR constraints encoding the verifier
equations of V_F. By A6, V_F is correct, so any accepting receipt satisfies those equations.
By Lemma 4, each UCIR gate enforces the exact algebraic semantics.
Therefore there exists a witness w derived from the receipt such that UCIR_SAT(ucir, w) holds.

Conversely, if V_F rejects, then the verifier equations are unsatisfied, and any UCIR witness must
violate at least one gate, so UCIR_SAT is false. This establishes equivalence.

Adapter-specific obligations:
- Groth16 and PLONK adapters: pairing and transcript equations must be mapped to UCIR gates.
- STARK adapters: FRI and constraint evaluation equations must be mapped to UCIR gates.
- IVC and Binius adapters: recursive verification relations must be mapped to UCIR gates.
- BLS12-381 SNARK/KZG adapters: commitment and pairing checks must be mapped to UCIR gates.

## Proof Obligations Checklist
For each adapter family F:
1) Receipt parsing yields the same public inputs as upstream.
2) UCIR emission matches verifier algebraic checks.
3) Witness layout respects UCIR invariants.
4) All custom gate payloads are validated and length checked.

## Expanded Equivalence Argument
For each adapter family F, define predicate R_F where R_F(receipt, public_inputs) holds iff upstream V_F accepts.
The compiler C_F emits UCIR such that: UCIR_SAT(ucir, w) <-> R_F(receipt, public_inputs).

This equivalence is established by:
1) Parsing correctness: receipt bytes map to the same public inputs as upstream.
2) Gate correctness: each UCIR gate enforces the same algebraic constraint.
3) Witness completeness: the witness produced by the adapter contains all intermediate values
required by the constraints. Therefore UCIR_SAT holds iff the upstream verifier relation holds.

## Assumptions
- Upstream verifier logic is correct for its receipt format. UCIR execution is faithful to the defined gate semantics.

## Proof-to-Code Map
- UCIR encoding and invariants: `docs/specs/ucir_spec.md`, `src/glyph_ir.rs`
- Adapter IR byte encoding and routing: `docs/specs/adapter_ir_spec.md`, `src/adapter_ir.rs`
- Custom gate IDs, gating, and payloads: `docs/specs/custom_gates_spec.md`, `src/glyph_ir.rs`
- Canonical STARK receipt encoding: `docs/specs/stark_receipt_spec.md`, `src/stark_receipt.rs`
- Adapter compilation: `src/glyph_ir_compiler.rs`
- UCIR execution: `src/glyph_witness.rs`
- Equivalence tests: `scripts/tests/rust/ucir_compiler_equivalence.rs`

## Implementation Invariants
- UCIR decoder rejects trailing bytes and non canonical field elements. Custom gate payload sizes are validated. Witness evaluation returns zero for all constraints on valid receipts.
