# Formal Proof Pack - End to End Soundness

## Theorem
If the prover generates a GLYPH proof accepted by `GLYPHVerifier.sol`, then the
statement encoded by `(commitment_tag, point_tag, claim128)` corresponds to a
valid execution of the intended verification logic and bound inputs, except with
negligible probability under the stated assumptions.

Formally, for any accepted proof P and statement S, under A1..A7, there exists a
witness W such that UCIR constraints hold and the bound commitments correspond
to the same statement S. The on-chain header also checks claim128 and
initial_claim are canonical field elements and binds them into the chain hash.

## Proof Outline
1. By `01_sumcheck.md`, the sumcheck chain is sound under Fiat-Shamir.
2. By `03_pcs_basefold.md`, the PCS opening binds the evaluation table to the derived point.
3. By `02_gkr_binding.md`, the artifact tag is bound into the transcript and cannot be altered.
4. By `04_ucir_correctness.md`, adapter compilers and UCIR execution correctly encode upstream verification logic.
5. By `05_state_diff_binding.md`, the state diff root is bound into the statement hash and artifact
tags. Therefore, any accepted proof implies a valid statement consistent with the bound inputs.

## Expanded Proof
Assume a proof is accepted on-chain. The verifier recomputes the artifact tag
from commitment_tag and point_tag and verifies the packed GKR proof. By Theorem
2, the tag and transcript binding are correct, so the statement hash is fixed.
By Theorem 1, the sumcheck chain is sound for the claimed evaluation.
By Theorem 3, PCS openings bind the evaluation table to the transcript-derived
point. By Theorem 4, UCIR satisfiability is equivalent to upstream verification.
By Theorem 5, the state diff root bound into the statement corresponds to the
actual VM transition. Therefore the accepted proof implies a valid statement.
Transcript domains are fixed, so all challenges and tags are domain separated.

## Assumptions Registry
- Random Oracle Model for Fiat-Shamir.
- Collision resistance of Keccak256.
- Soundness of GKR and PCS binding.
- Correctness of adapter verification logic for each supported receipt format.
- UCIR and state-diff execution correctness.

## Soundness Error
Let epsilon_sumcheck be the sumcheck soundness error. Let epsilon_gkr be the GKR
soundness error. Let epsilon_pcs be the PCS binding error. The total soundness
error is bounded by:
epsilon_total <= epsilon_sumcheck + epsilon_gkr + epsilon_pcs + epsilon_hash
where epsilon_hash is negligible under A2.

## Explicit Error Composition
Define failure events:
- E_sumcheck: sumcheck accepts with a false claim.
- E_pcs: PCS opening verifies for an incorrect evaluation.
- E_gkr: GKR artifact proof verifies for a false transcript claim.
- E_ucir: UCIR constraints accept a receipt that upstream verifier rejects.
- E_state_diff: state_diff_root is bound but does not correspond to the real transition.
- E_hash: a collision in Keccak256 breaks binding.

Then:
Pr[accepts false statement] <= Pr[E_sumcheck] + Pr[E_pcs] + Pr[E_gkr] + Pr[E_ucir] + Pr[E_state_diff] + Pr[E_hash]

Under A1..A7, each event is negligible and the sum is negligible.

## Assumption Mapping Table
| Failure event | Bound term                     | Depends on |
| :---          | :---                           | :---       |
| E_sumcheck    | 2r/\|F\|                       | A1         |
| E_pcs         | Adv_PCS_Binding + Adv_PCS_Corr | A1, A4, A5 |
| E_gkr         | Adv_GKR + Adv_RO + Adv_Hash    | A1, A2, A3 |
| E_ucir        | Adv_Adapter                    | A6, A7     |
| E_state_diff  | Adv_Diff_Correctness           | A7         |
| E_hash        | Adv_Hash                       | A2         |


## Quantitative Bounds (Default Parameters)
Let |F| = 2^128 - 159 and r be the number of packed rounds.
- epsilon_sumcheck <= 2r / |F|
- epsilon_pcs <= Adv_PCS_Binding
- epsilon_gkr <= Adv_GKR + Adv_RO + Adv_Hash
- epsilon_ucir <= Adv_Adapter
- epsilon_state_diff <= Adv_Diff_Correctness
- epsilon_hash negligible under A2

For default configs, epsilon_sumcheck is dominated by 2r/|F| and is far below 2^-80 for typical r.
The remaining terms are cryptographic assumptions. Example numeric bounds:
- r = 32: epsilon_sumcheck <= 1.88079096131566e-37
- r = 64: epsilon_sumcheck <= 3.76158192263132e-37

## Reproducible Calculation Method
To reproduce epsilon_sumcheck: 1) Set |F| = 2^128 - 159. 2) Set r from calldata
length. 3) Compute epsilon_sumcheck = 2r / |F|.

No other terms have concrete numeric values without selecting explicit
cryptographic security parameters for A1..A7.

## Reference Configuration (Non-Normative)
To provide a concrete numeric bound without constraining the protocol, we define
one reference instance for reporting:
- r_ref = 32 (reporting baseline).
- N_ref = 8^r_ref.
- epsilon_sumcheck_ref = 2 * r_ref / |F|.

This reference is used only for reporting. The protocol remains parameterized
by N, and the formal bound stays `2 * r / |F|`.

## Default Numeric Instantiation (Reference)
To instantiate concrete epsilon values without constraining the protocol, fix
the reference configuration r_ref = 32 and assume 128-bit security for the
cryptographic terms (Keccak256, PCS binding, and GKR transcript binding). Under
A6 and A7, epsilon_ucir and epsilon_state_diff are zero.

- epsilon_sumcheck_ref = 64 / (2^128 - 159) = 1.88079096131566e-37
- epsilon_crypto_ref <= 3 * 2^-128 = 8.81620763116716e-39
- epsilon_total_ref <= 1.96895303762733e-37

For r_ref = 64, epsilon_total_ref <= 3.84974399894299e-37 under the same assumptions.

## Parameter Table (Default)
| Parameter       | Symbol | Default                          |
| :---            | :---   | :---                             |
| Field size      | \|F\|  | 2^128 - 159                      |
| Sumcheck rounds | r      | number of packed rounds          |
| GKR rounds      | g      | derived from sumcheck challenges |
| Transcript hash | H      | Keccak256                        |
| Statement hash  | S      | Keccak256                        |


## Proof-to-Code Trace
The following invariants are enforced at the code level:
- Transcript absorption order in `src/glyph_transcript.rs`.
- Tag computation in `src/glyph_gkr.rs` and `contracts/GLYPHVerifier.sol`.
- Statement binding in `src/l2_statement.rs` and `contracts/GLYPHRootUpdaterExtended.sol`.

## Proof-to-Code Map
- Sumcheck: `src/glyph_core/sumcheck.rs`, `src/glyph_core.rs`, `src/glyph_gkr.rs`
- PCS: `src/glyph_pcs_basefold.rs`, `src/pcs_common.rs`
- GKR artifact: `src/glyph_gkr.rs`, `contracts/GLYPHVerifier.sol`
- UCIR: `src/glyph_ir.rs`, `src/glyph_ir_compiler.rs`, `src/glyph_witness.rs`
- State diff binding: `src/state_diff_merkle.rs`, `src/bin/glyph_l2_statement.rs`
- Spec boundaries: `docs/specs/verifier_spec.md`, `docs/specs/artifact_tag_spec.md`, `docs/specs/ucir_spec.md`, `docs/specs/adapter_ir_spec.md`, `docs/specs/custom_gates_spec.md`, `docs/specs/stark_receipt_spec.md`, `docs/specs/state_transition_vm_spec.md`

## Implementation Invariants
- Transcript order is fixed for all absorbed domains.
- Public inputs are committed prior to PCS opening.
- Artifact tags are recomputed on-chain.
