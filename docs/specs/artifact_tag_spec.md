# Artifact Tag and Chain Binding Specification

This specification defines how GLYPH derives:
- `point_tag`
- `artifact_tag`
- The initial on-chain challenge `r0`

It also documents the exact binding inputs and fail-closed invariants.

## Terminology
- `commitment_tag`: a 32-byte PCS commitment digest.
- `point_tag`: a 32-byte digest binding the evaluation point to the commitment.
- `artifact_tag`: a 32-byte digest binding commitment and evaluation point.
- `claim128`: a 128-bit canonical field element used by the on-chain verifier.
- `initial_claim`: the first sumcheck claim used to seed the verifier chain.

## Point Tag Derivation
Point tags are derived in `src/pcs_common.rs` via `derive_point_tag`.

Domain:
- `PCS_POINT_TAG_DOMAIN = b"GLYPH_PCS_POINT_TAG"`

Encoding:
```
point_tag = keccak256(
  PCS_POINT_TAG_DOMAIN ||
  commitment_tag ||
  eval_point_words
)
```

Each evaluation point element is encoded as 16 bytes big-endian:
- Upper 8 bytes: zero.
- Lower 8 bytes: the Goldilocks element as `u64` big-endian.

This yields a deterministic binding from the evaluation point to the commitment.

## Artifact Tag Derivation
Artifact tags are derived in `src/glyph_gkr.rs`:

```
artifact_tag = keccak256(commitment_tag || point_tag)
```

This is the value placed in calldata word 0 by
`encode_artifact_poly_bound_packed_calldata_be`.

## Claim Canonicalization
`claim128` is derived from the final evaluation vector and canonicalized:
- Derivation site: `src/glyph_core.rs`
- Canonicalization helper: `gkr_canonicalize_u128` in `src/glyph_gkr.rs`

The canonicalization requirement is:
- `claim128 < MODULUS`

Non-canonical claims must be rejected.

## On-Chain Initial Challenge r0
The verifier computes the initial Fiat-Shamir challenge as:

```
r0 = keccak256(
  chainid ||
  address(this) ||
  artifact_tag ||
  claim128_be16 ||
  initial_claim_be16
) mod MODULUS
```

Specification source:
- `contracts/GLYPHVerifier.sol` comments and assembly.

Important encoding detail:
- `claim128` and `initial_claim` are hashed as 16-byte big-endian values.

This establishes chain binding to:
- The target chain via `chainid`.
- The verifier contract instance via `address(this)`.
- The full off-chain statement via `artifact_tag`.

## Lin Hash Binding
The verifier also derives lin coefficients from:

```
lin_hash = keccak256(LIN_DOMAIN || artifact_tag || claim128_be16)
lin_0 = canonicalize_u128(lin_hash[0..16])
lin_step = canonicalize_u128(lin_hash[16..32])
```

This is used to construct the public polynomial evaluated in the final check.
Reference:
- `contracts/GLYPHVerifier.sol`
- `src/glyph_gkr.rs` (`derive_artifact_poly_lin_base_and_step`)

## Binding Invariants (Fail Closed)
The following invariants are mandatory:

1) `artifact_tag` must be computed from the supplied `commitment_tag` and
   `point_tag` exactly as specified.

2) `point_tag` must be derived from the actual evaluation point used by the PCS
   opening, not from any external or user-supplied point.

3) `claim128` and `initial_claim` must be canonical field elements.

4) Any mismatch between on-chain recomputation and off-chain derivation must
   result in rejection.

## Code References
- `src/pcs_common.rs` (`derive_point_tag`)
- `src/glyph_gkr.rs` (`artifact_tag`, calldata encoding, lin hash derivation)
- `src/glyph_core.rs` (artifact construction)
- `contracts/GLYPHVerifier.sol` (on-chain challenge and lin binding)
