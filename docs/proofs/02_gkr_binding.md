# Formal Proof Pack - GKR Binding

## Definitions
The GLYPH artifact contains `(commitment_tag, point_tag, claim128, initial_claim)`. The artifact tag is `artifact_tag = keccak256(commitment_tag || point_tag)`.

The packed proof binds the artifact tag and claim values into the transcript before the final sumcheck polynomial is produced.

Let Tag = H(commitment_tag || point_tag). Let the transcript include Tag, claim128, and
initial_claim before challenge sampling. Let Proof be the packed GKR artifact proof.

Let FS be the Fiat-Shamir transcript function that maps absorbed bytes to challenges. The transcript input stream is fixed and domain-separated.

Statement binding for L2 updates uses the extended statement hash produced by
`statement_hash_extended` in `src/l2_statement.rs`. The exact preimage is:
`L2_STATE_DOMAIN || u256_be(chainid) || contract_addr || old_root || new_root || da_commitment || batch_id_be || extra_commitment || extra_schema_id` where `contract_addr` is 20 bytes and
`batch_id_be` is a big-endian u64. The minimal flow uses statement_hash_minimal and omits
`extra_commitment` and `extra_schema_id`.

Tags are derived as:
`commitment_tag = H(L2_COMMIT_DOMAIN || statement_hash)`,
`point_tag = H(L2_POINT_DOMAIN || commitment_tag)`,
`artifact_tag = H(commitment_tag || point_tag)`.

## Lemmas
1. **Artifact Tag Integrity**: If `artifact_tag` does not match `commitment_tag` and `point_tag`, the verifier rejects.
2. **Statement Binding**: The transcript absorbs the statement-derived tags. A proof generated for one statement cannot be replayed for another without breaking the hash or GKR soundness.
3. **Non-Malleability**: For any two distinct statements s != s', the derived tags differ except with negligible probability under A2. Therefore a proof bound to s cannot verify under s'.

## Theorem 2: Artifact Binding
Assuming A1, A2, A3, any proof that verifies on-chain implies that Tag matches the commitment and point tags, and that the claim was generated under the same transcript.

## Proof (Formal Sketch)
Let s be the statement and (ct, pt) the derived tags. The on-chain verifier checks:
1) artifact_tag == H(ct || pt), and
2) the packed GKR proof is valid under the transcript that absorbed Tag and claim.

If an adversary attempts to use a proof for s' under s, then either:
- H(ct || pt) collides, violating A2, or
- the transcript challenges differ, and by A3 the proof is rejected.

By ROM (A1), challenges are uniformly random conditioned on transcript state, and any deviation from the correct Tag changes the transcript inputs, making acceptance probability negligible.

## Game-Hopping Outline
Game 0: Real transcript with Tag and claim absorbed.
Game 1: Replace transcript hash with a random oracle (A1).
Game 2: Adversary forges Tag collision to reuse proof (A2).
Game 3: Adversary forges a valid GKR proof under a mismatched transcript (A3).

Each transition is negligible under the corresponding assumption, yielding binding.

## Formal Reduction Statement
Let Adv_bind be the advantage of producing a proof that verifies under a mismatched statement. Then: Adv_bind <= Adv_RO + Adv_Hash + Adv_GKR
where:
- Adv_RO is the advantage of distinguishing the transcript from random (A1).
- Adv_Hash is the advantage of finding a Keccak256 collision on Tag (A2).
- Adv_GKR is the advantage of breaking GKR soundness under the transcript (A3).

## Domain Separation Justification
All transcript inputs are tagged by domain bytes:
- DOMAIN_SUMCHECK and DOMAIN_SUMCHECK_MIX separate sumcheck stages.
- L2_COMMIT_DOMAIN and L2_POINT_DOMAIN separate statement binding tags.
- Artifact tag derivation is applied before challenge sampling.
Under A1, the transcript behaves as a random oracle per domain. This prevents cross-protocol collisions between sumcheck and GKR stages.

## ROM Proof Sketch
We model the transcript as an oracle H. The prover's view is a sequence of oracle queries determined by absorbed tags and claims.
1) Replace H with a uniformly random oracle (A1).
2) Any change in Tag or claim changes the query inputs.
3) Therefore challenges are independent of adversarial choices except with negligible probability.
4) Under these conditions, a false claim reduces to a violation of A2 or A3.

## Expanded Reduction
Assume an adversary outputs a proof that verifies under statement s but was constructed for statement s'. If s != s', then the statement hash differs unless Keccak collision occurs. If the statement hash differs, then tags differ.
Case 1: Tag collision. This implies a collision in H(commitment_tag || point_tag), breaking A2.
Case 2: Tag mismatch without collision. The transcript input stream differs at the tag absorption step. Under A1, the resulting challenges are independent of the adversary's prior view. The adversary must produce a valid GKR proof under the wrong transcript, which breaks A3.

## Proof Sketch
The verifier checks the tag consistency and the sumcheck chain. Since the transcript is derived from the tags and claim values, a prover cannot change the statement without invalidating the proof.

## Assumptions
- Keccak256 is collision resistant.
- GKR soundness holds under Fiat-Shamir.
- Transcript challenges are modeled under ROM.

## Proof-to-Code Map
- Artifact construction: `src/glyph_gkr.rs`
- Packed calldata: `src/glyph_gkr.rs`, `src/glyph_core.rs`
- On-chain verification: `contracts/GLYPHVerifier.sol`
- Calldata and memory layout: `docs/specs/verifier_spec.md`
- Artifact tag and chain binding: `docs/specs/artifact_tag_spec.md`
- Extended statement binding tags: `src/l2_statement.rs`

## Implementation Invariants
- Tag computed as keccak256 of commitment_tag and point_tag.
- Transcript absorbs Tag and claim in a fixed order.
- On-chain verifier recomputes tag and rejects mismatches.
- Extended statement binding includes chainid and verifier address to prevent cross-domain replay.
