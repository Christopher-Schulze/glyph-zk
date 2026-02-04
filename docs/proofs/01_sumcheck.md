# Formal Proof Pack - Sumcheck

## Definitions
Let `f` be the packed GLYPH statement polynomial over the 128-bit prime field `F`
(p = 2^128 - 159), defined on the arity-8 domain `{0..7}^r`.

The packed sumcheck protocol proves a claim `S = sum_{x in {0..7}^r} f(x)` by reducing it to a sequence of univariate claims. Here r is the packed round count determined by the statement length in calldata, and the verifier runs exactly r rounds.

Let F be the 128-bit prime field. Let r be the number of packed rounds.

For round i, the prover constructs a univariate polynomial g_i(t) such that:
g_i(t) = sum_{x in {0..7}^{r-i-1}} f(r_0, ..., r_{i-1}, t, x)
where r_0..r_{i-1} are transcript challenges. This is the partial sum of f over the remaining coordinates, leaving t as the only free variable.

In GLYPH, each round sends (c0, c1) and recovers c2 by enforcing the arity-8 sum constraint.

The verifier checks a degree-2 polynomial g_i(t) = c0 + c1*t + c2*t^2 over t in {0..7}, and it rejects immediately if c0 or c1 is non-canonical. Only (c0, c1) are transmitted, so the arity-8 sum check fully determines the quadratic.

## Protocol (Non-Interactive via Fiat-Shamir)
For i = 0..r-1:

1. Prover computes g_i(t) such that: g_i(t) = sum_{x in {0..7}^{r-i-1}} f(r_0, ..., r_{i-1}, t, x)

2. Prover sends coefficients (c0, c1).

3. Verifier enforces the arity-8 sum constraint:
   g_i(0) + g_i(1) + ... + g_i(7) = claim_i,
   recovers c2, and rejects if c0 or c1 is non-canonical.

4. Verifier samples r_i = H(transcript).

5. Updates claim_{i+1} = g_i(r_i).

Final check: claim_r equals f(r_0..r_{r-1}).

## Adversary Model
The prover is any PPT adversary that chooses f and the round polynomials g_i adaptively, with access to the Fiat-Shamir transcript oracle.

The verifier is deterministic given transcript outputs and treats the transcript as a random oracle under A1.

## Formal Definitions
Let f be the packed statement polynomial over {0..7}^r. Let claim_0 be the initial claim from the packed proof header.

Define the partial sum polynomial at round i:
g_i^*(t) = sum_{x in {0..7}^{r-i-1}} f(r_0,...,r_{i-1},t,x)

The prover sends (c0, c1) defining g_i(t). The verifier enforces:
sum_{t=0..7} g_i(t) = claim_i,
recovers c2, and sets claim_{i+1} = g_i(r_i).

## Lemmas
1. **Round Consistency**: For each round `i`, the verifier checks sum_{t=0..7} g_i(t) = claim_i.
2. **Claim Reduction**: The next claim is `claim_{i+1} = g_i(r_i)` where `r_i` is derived from the transcript.
3. **Degree Bound**: In GLYPH, g_i is degree <= 2, because it is quadratic.
4. **Soundness**: If `f` is not consistent with the claimed sum, acceptance probability is bounded by (deg(g) / |F|) per round.

## Theorem 1: Sumcheck Soundness
Assuming A1, if a prover convinces the verifier of an incorrect claim, the
probability of acceptance is at most 2r / |F| for r packed rounds over field F.

For standard sumcheck, the bound is r * deg(g) / |F|. In GLYPH's packed arity-8 check, each round uses a quadratic polynomial, so the bound is r * 2 / |F|.

## Proof (Formal Sketch with Explicit Bound)
Define the ideal polynomial g_i^*(t) derived from the true f and the challenger prefix
r_0..r_{i-1}. The prover sends g_i(t). If g_i != g_i^*, 
then h(t) = g_i(t) - g_i^*(t) is non-zero with degree <= 2.

The verifier checks sum_{t=0..7} g_i(t) = claim_i. If this passes, then the only way for a cheating prover to continue is for h(r_i) = 0, where r_i is uniformly random in F under A1. By Schwartz Zippel, Pr[h(r_i)=0] <= deg(h)/|F| <= 2/|F|.

By union bound over r rounds, the total soundness error is <= 2r/|F|.

## Fully Expanded Proof
If the claim_0 is false, then at least one round i must have g_i != g_i^*. Define h_i = g_i - g_i^*. Since g_i is degree <= 2 by construction, h_i has degree <= 2 and is non-zero.

The verifier accepts round i only if h_i(r_i) = 0. By Schwartz-Zippel:
Pr[h_i(r_i)=0] <= deg(h_i)/|F| <= 2/|F|.
By union bound across r rounds, the total failure probability is <= 2r/|F|.

## Formal Bound Statement
Let Adv_sc be the adversary advantage to make the verifier accept an incorrect claim. 
Then: Adv_sc <= 2r/|F|.

This is the exact bound used in the end-to-end composition.

## Assumptions
- Fiat-Shamir transcript behaves as a random oracle.
- Field size is large enough for the required soundness error.

## Quantitative Bound (Default Parameters)
Let |F| = 2^128 - 159. For r packed rounds, the soundness error is:
epsilon_sumcheck <= 2 * r / |F|.
This bound is explicit and composed in `06_end_to_end.md`. For typical r up to 64, the bound is far below 2^-80.

## Proof-to-Code Map
- Packed sumcheck rounds and arity-8 constraint: `src/glyph_gkr.rs`
- Packed verifier implementation: `contracts/GLYPHVerifier.sol`

## Implementation Invariants
- Round polynomial is quadratic with c2 recovered from the arity-8 sum constraint via `INV140` in `src/glyph_gkr.rs`.
- Claim update uses `g_i(r_i)` with transcript challenges derived from Keccak.
- Each round validates sum_{t=0..7} g_i(t) equals the current claim.
