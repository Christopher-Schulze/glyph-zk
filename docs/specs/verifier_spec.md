# GLYPH Verifier Assembly Specification

This specification is duplicated verbatim in `docs/documentation.md` (Specifications section).

## Scope
This document specifies the calldata layout, memory layout, and invariants for
`contracts/GLYPHVerifier.sol`. It is a byte-accurate reference for the inline
assembly verifier and is intended to be reviewed alongside the Rust reference
implementation in `src/glyph_gkr.rs`.

## Calldata Layout
The verifier expects tightly packed calldata without a selector.

### Header (64 bytes)
| Offset | Size | Name | Description |
| --- | --- | --- | --- |
| 0x00 | 32 | `artifact_tag` | bytes32 = keccak256(commitment_tag || point_tag) |
| 0x20 | 32 | `claim_initial` | `claim128` (hi 16 bytes) || `initial_claim` (lo 16 bytes) |

Constraints:
- `claim128 < MODULUS`
- `initial_claim < MODULUS`

### Per-round Coefficients (32 bytes each)
For each round i:
| Offset | Size | Name | Description |
| --- | --- | --- | --- |
| 0x00 | 16 | `c0` | 128-bit field element |
| 0x10 | 16 | `c1` | 128-bit field element |

Constraints:
- `c0 < MODULUS`
- `c1 < MODULUS`

Derived:
```
c2 = (current_claim - (8*c0 + 28*c1)) * INV140 mod MODULUS
```

### Calldata Size Constraints
- `calldatasize >= 96`
- `(calldatasize - 64) % 32 == 0`

## Memory Layout
The verifier uses two non-overlapping scratch regions.

### Fiat-Shamir Hash Scratch (0x00..0x7f)
Used for the initial challenge and per-round updates:
```
r0 = keccak256(chainid || address(this) || artifact_tag || claim128 || initial_claim)
```
Per-round updates reuse the 0x00..0x1f range for `r || (c0 xor c1 xor c2)`.

| Offset | Size | Value |
| --- | --- | --- |
| 0x00 | 32 | chainid |
| 0x20 | 32 | address(this) |
| 0x40 | 32 | artifact_tag |
| 0x60 | 32 | claim_initial |

### Lin Hash Scratch (0xa0..0xef)
Used only for:
```
lin_hash = keccak256(LIN_DOMAIN || artifact_tag || claim128_be16)
```

| Offset | Size | Value |
| --- | --- | --- |
| 0xa0 | 32 | LIN_DOMAIN |
| 0xc0 | 32 | artifact_tag |
| 0xe0 | 16 | claim128 (big endian, high half) |

No memory overlap occurs between the two scratch regions.

## Fiat-Shamir and Polynomial Invariants

### Challenge Derivation
```
r0 = keccak256(chainid || address(this) || artifact_tag || claim128 || initial_claim) mod MODULUS
ri+1 = keccak256(ri || (c0 xor c1 xor c2)) mod MODULUS
```
Encoding:
- `ri` occupies the high 16 bytes of the keccak input.
- `mix = c0 xor c1 xor c2` occupies the low 16 bytes.

### Public Polynomial
Let `R` be the number of rounds.
```
f(x_0..x_{R-1}) = (lin_0 + claim128 + sum_{i=0..R-1} lin_{i+1} * x_i)^2
```
Where:
```
lin_hash = keccak256(LIN_DOMAIN || artifact_tag || claim128_be16)
lin_0 = canonicalize_u128(lin_hash[0..16])
lin_step = canonicalize_u128(lin_hash[16..32])
lin_{i+1} = lin_i * lin_step
```
`canonicalize_u128(x)` means `x` if `x < MODULUS`, else `x - MODULUS`.

### Sumcheck Polynomial
```
g(t) = c0 + c1*t + c2*t^2
```
Constraint:
```
g(0) + g(1) + ... + g(7) = current_claim
```
With:
```
current_claim_{i+1} = g(r_i)
```

### Final Check
```
expected_final = (lin_0 + claim128 + eval_lin)^2
require current_claim == expected_final
```
Where:
```
eval_lin = sum_{i=0..R-1} lin_{i+1} * r_i
```

## Safety Invariants
1. All scalar values must be canonical in the field (`< MODULUS`).
2. Calldata lengths must be validated before any coefficient parsing.
3. Memory scratch regions are disjoint and do not overlap with the ABI return word.
4. No out-of-bounds calldata or memory accesses are permitted.

## Reference Mapping
- Solidity: `contracts/GLYPHVerifier.sol`
- Rust: `src/glyph_gkr.rs`
- Domain constant: `GLYPH_GKR_ARTIFACT_LIN_DOMAIN` in Rust, `LIN_DOMAIN` in Solidity

## Notes for Formal Verification
Key properties to encode:
- Calldata bounds checks are sufficient for all `calldataload` accesses.
- All `mload` and `mstore` addresses fall in the documented scratch regions.
- `current_claim` update matches Horner evaluation of `g(t)` at each `r_i`.
