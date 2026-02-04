# Formal Proof Pack - Mechanized Proof Plan

## Purpose
Provide a machine-checkable proof roadmap without constraining the protocol
implementation. This plan fixes theorem statements, dependencies, and the proof
structure required by a proof assistant.

## Target Assistants
Lean4 primary, Coq fallback.

## Proof Structure
Files: `sumcheck.lean`, `pcs_basefold.lean`, `gkr_binding.lean`,
`ucir_semantics.lean`, `state_diff_correctness.lean`, `end_to_end.lean`.

## Formal Statements (Lean-style sketches)
Sumcheck:
```
theorem sumcheck_soundness (f : F^n -> F) (S : F) :
  Pr[VerifierAcceptsFalse] <= (2 * r) / |F|
```
PCS Binding:
```
theorem pcs_binding (C : Commitment) (r : Point) :
  Adv_open_two_values <= Adv_RO + Adv_Bind + Adv_Corr
```
GKR Binding:
```
theorem gkr_tag_binding (Tag : Hash) (Proof : PackedProof) :
  Adv_mismatch <= Adv_RO + Adv_Hash + Adv_GKR
```
UCIR Equivalence:
```
theorem ucir_equivalence (receipt : Receipt) (ucir : UCIR) :
  VerifierOK(receipt) <-> UCIR_SAT(ucir)
```
State Diff Correctness:
```
theorem state_diff_root_correct (old_root new_root : Hash) :
  VM_exec -> circuit_root = MerkleRoot(diff_set)
```
End-to-End Composition:
```
theorem end_to_end_soundness :
  Adv_total <= sum(Adv_sumcheck, Adv_pcs, Adv_gkr, Adv_ucir, Adv_state_diff, Adv_hash)
```

## Proof Dependencies
A1..A7 from `docs/proofs/00_overview.md`, UCIR gate semantics from
`docs/specs/ucir_spec.md`, state diff rules from
`docs/specs/state_transition_vm_spec.md`, transcript domains from
`src/glyph_transcript.rs`.

## Acceptance Criteria
- Each theorem is encoded with explicit parameters and bound terms.
- Proof assistant builds without external edits to protocol code.
- Each lemma is mapped to the corresponding proof section in `docs/proofs/`.
