# Formal Proof Pack - PCS Commitment (BaseFold)

## Definitions
The PCS commitment binds an evaluation table to a commitment and opening proof at a verifier
point derived from sumcheck challenges. The evaluation table is the binary-field encoding of
the Goldilocks evaluations used by the packed prover, and the commitment is computed over it.
Let C be the commitment to polynomial P. Let r be the evaluation point derived from the transcript
after absorbing the PCS commitment and any masking data. Let O be the opening proof for P(r).

Binding definition:
A PCS is binding if no PPT adversary can produce (C, r, v, v', O, O') such that v != v' and both
openings verify for the same commitment C and point r, except with negligible probability.

Correctness definition:
For any committed polynomial P and point r, the verifier accepts the opening O if and only if O proves P(r).

## Lemmas
1. **Commitment Binding**: A commitment binds the evaluation table to a unique polynomial.
2. **Opening Correctness**: The opening proof verifies that the committed polynomial evaluates to the claimed value at the verifier point.
3. **ZK Mode Hiding**: When ZK mode is enabled, the masking rows and salt prevent leakage of witness values.
4. **Transcript Binding**: The evaluation point r is derived from sumcheck challenges, which are transcript-bound under A1.

## Theorem 3: PCS Binding
Assuming A1, A4, A5, a prover cannot open a commitment to two different values at
the same point except with negligible probability.

## Proof (Reduction Sketch)
Suppose an adversary produces two valid openings for the same commitment C and
point r. Then either:
1) It breaks PCS binding (A4), or
2) It breaks PCS correctness (A5), or
3) It exploits a transcript deviation to force r, contradicting A1.
Thus the adversary advantage is bounded by the sum of advantages against A4, A5, and A1.

## Game-Hopping Outline
Game 0: Real PCS commitment and opening with transcript-derived r.
Game 1: Replace transcript hash with random oracle (A1).
Game 2: If the adversary opens C to two values, reduce to A4.
Game 3: If opening verifies but value is incorrect, reduce to A5.

## Formal Reduction Statement
Let Adv_pcs be the adversary advantage to open a commitment to an incorrect value.
Then: Adv_pcs <= Adv_RO + Adv_Bind + Adv_Corr
where:
- Adv_RO bounds adversary influence on r under A1.
- Adv_Bind bounds PCS binding under A4.
- Adv_Corr bounds PCS correctness under A5.

## Expanded Reduction
Assume an adversary outputs (C, r, v, O) such that verify(C, r, v, O) = true but v != P(r).
Then either:
1) C does not bind P to a unique polynomial, breaking A4, or
2) The verification accepts an incorrect value, breaking A5, or
3) The adversary biases r by influencing the transcript beyond A1.

These cases are mutually exclusive by definition of the PCS interface and the transcript binding
logic.


## Proof Sketch
The prover commits to the evaluation table and opens at a deterministic point r
derived from the transcript challenges. The verifier checks the opening using
BaseFold, and binding prevents a different polynomial from matching the opening
without breaking the PCS binding property. When ZK mode is enabled, the masking
rows and salt are absorbed before r is sampled.

## Assumptions
- Binding and correctness properties of the PCS scheme.
- Fiat-Shamir for deriving evaluation points from transcript challenges.

## Proof-to-Code Map
- PCS commitment and opening: `src/glyph_pcs_basefold.rs`
- Common PCS helpers: `src/pcs_common.rs`
- Transcript binding: `src/glyph_transcript.rs`

## Implementation Invariants
- Evaluation point derived from sumcheck challenges.
- ZK mode uses masking rows and salt for hiding.
- Opening verification returns false and callers treat it as failure.
- BaseFold commit and open are the only commitment interfaces used on the critical path.
