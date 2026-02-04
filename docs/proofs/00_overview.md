# Formal Proof Pack - Overview

## Purpose
This pack provides a complete internal proof chain for GLYPH with explicit assumptions, lemmas, and a proof-to-code map. It is designed to withstand scrutiny from cryptography reviewers without relying on external audits.

## Security Model
We assume:
1. Random Oracle Model for Fiat-Shamir transforms.
2. Collision resistance of Keccak256.
3. Soundness of the GKR protocol.
4. Binding and correctness of the PCS commitment and opening scheme.
5. Correctness of adapter verification logic for each supported receipt format.

## Adversary Model
We consider a polynomial time adversary who:
- Controls all prover inputs, including transcripts and intermediate values.
- Can choose statements adaptively and submit arbitrary proofs.
- Has oracle access to the Fiat-Shamir transcript.
- Is bounded by standard cryptographic security parameters.

We target negligible soundness error in the security parameter lambda, with
explicit epsilon bounds derived in `06_end_to_end.md`.

## Formal Assumptions Registry
We reference the following assumptions in all proofs:
- A1: Fiat Shamir Random Oracle Model. Transcript outputs are indistinguishable from random.
- A2: Keccak256 collision resistance. Finding collisions is infeasible.
- A3: GKR soundness. A prover cannot convince the verifier of a false claim except with negligible probability.
- A4: PCS binding. Commitment and opening do not allow equivocation.
- A5: PCS correctness. Openings verify iff the committed polynomial evaluates to the claimed value.
- A6: Adapter upstream verifier correctness. Each receipt format verifies the intended statement.
- A7: UCIR/VM correctness. UCIR matches defined gates; VM/Merkle matches hashing and padding rules.

We explicitly do not assume any cryptographic property beyond A1..A7. All proofs must reduce to these assumptions or to standard algebraic facts about finite fields.

## Security Parameters
- Field size: |F| = 2^128 - 159 (packed verifier field).
- Sumcheck rounds: r = number of packed rounds derived from calldata length.
- Transcript security: modeled as a random oracle with domain separation tags.

All explicit bounds are computed for the above defaults and parameterized for
alternative configurations.

## Notation
- F: 128-bit prime field used by the packed verifier (p = 2^128 - 159).
- H: Keccak256.
- S: sumcheck claim.
- T: transcript state.
- C: PCS commitment.
- O: PCS opening.
- Tag: artifact tag = H(commitment_tag || point_tag).
Note: Goldilocks appears in off-chain prover and adapter receipts, but the packed
on-chain sumcheck uses the 128-bit field above.

## Dependency Graph
01_sumcheck depends on A1.
02_gkr_binding depends on A1, A2, A3.
03_pcs_basefold depends on A1, A4, A5.
04_ucir_correctness depends on A6, A7.
05_state_diff_binding depends on A1, A2, A7.
06_end_to_end depends on all A1..A7 and the composition of their bounds.

## System Statement
For any accepted proof, the on-chain verifier accepts only if the statement hash and bound artifact tags correspond to a valid execution of the intended verification logic and constraints. This is formalized in `06_end_to_end.md`.

## Artifacts
- UCIR encoding and invariants: `docs/specs/ucir_spec.md`
- Adapter IR encoding and kernel routing: `docs/specs/adapter_ir_spec.md`
- Custom gate IDs, gating, and payloads: `docs/specs/custom_gates_spec.md`
- Verifier calldata and memory spec: `docs/specs/verifier_spec.md`
- Artifact tag and chain binding: `docs/specs/artifact_tag_spec.md`
- Canonical STARK receipt and VK encoding: `docs/specs/stark_receipt_spec.md`
- State transition VM spec: `docs/specs/state_transition_vm_spec.md`

## Proof Pack Index
1. `01_sumcheck.md`
2. `02_gkr_binding.md`
3. `03_pcs_basefold.md`
4. `04_ucir_correctness.md`
5. `05_state_diff_binding.md`
6. `06_end_to_end.md`
7. `07_mechanized_proof_plan.md`

## Mechanized Proof Scope
The written proofs are complete. Mechanized proofs are planned for the core
theorems using a proof assistant; the roadmap is documented separately.

## Proof-to-Code Map
The detailed mapping is in `06_end_to_end.md` and repeated in each chapter.
