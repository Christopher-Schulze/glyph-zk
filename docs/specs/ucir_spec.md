# UCIR Specification

This specification is duplicated verbatim in `docs/documentation.md` (Specifications section).

## Overview
UCIR is the Universal Constraint IR for GLYPH-PROVER. It provides a compact,
deterministic, byte-encoded constraint system that adapters emit and the prover
consumes. This spec documents the encoding, semantics, and invariants enforced
by the decoder (`Ucir2::from_bytes`) in `src/glyph_ir.rs`.

## Versioning and Field
- All integer fields are little-endian unless explicitly noted.
- `version` (u16 LE) must equal `UCIR_VERSION` (1).
- `field_id` (u8) must equal `FIELD_ID_GOLDILOCKS` (0x01).
- All scalar coefficients and table values are Goldilocks field elements and
  must be canonical (`< GOLDILOCKS_MODULUS`).

## Witness Layout
Witness layout is a 32-byte structure encoded as 8 u32 LE values:
```
public_start, public_len,
wire_start, wire_len,
lookup_start, lookup_len,
blind_start, blind_len
```
Invariants:
- `public_start == 0`
- `wire_start == public_len`
- `lookup_start == wire_start + wire_len`
- If `blind_len == 0`, then `blind_start == 0`
- If `blind_len > 0`, then `blind_start == lookup_start + lookup_len`

The total witness length is computed as:
- `blind_start + blind_len` if `blind_len > 0`
- Else `lookup_start + lookup_len` if `lookup_len > 0`
- Else `wire_start + wire_len` if `wire_len > 0`
- Else `public_len`

## UCIR Container Encoding
UCIR is serialized in the following order:

### Header
| Field | Size | Encoding |
| --- | --- | --- |
| `version` | 2 | u16 LE |
| `field_id` | 1 | u8 |
| `gate_count` | 4 | u32 LE |
| `lookup_count` | 4 | u32 LE |
| `copy_count` | 4 | u32 LE |
| `table_count` | 4 | u32 LE |
| `witness_layout` | 32 | 8 x u32 LE |

### Gates (Sorted by Type)
Gates are encoded in the following order:
1. Arithmetic gates
2. Copy gates
3. Custom gates

Gate tags:
- Arithmetic: `GATE_TAG_ARITHMETIC` (0x01)
- Copy: `GATE_TAG_COPY` (0x02)
- Custom: `GATE_TAG_CUSTOM_BASE` (0x80)

#### Arithmetic Gate
Encoding:
```
tag (1 byte)
a (u32 LE)
b (u32 LE)
c (u32 LE)
q_mul (u64 LE)
q_l (u64 LE)
q_r (u64 LE)
q_o (u64 LE)
q_c (u64 LE)
```
Semantics:
```
q_mul*a*b + q_l*a + q_r*b + q_o*c + q_c = 0
```
All wire references must be `< witness_total`.

#### Copy Gate
Encoding:
```
tag (1 byte)
left (u32 LE)
right (u32 LE)
```
Semantics:
```
left == right
```
All wire references must be `< witness_total`.

#### Custom Gate
Encoding:
```
tag (1 byte, 0x80)
custom_id (u16 LE)
payload_len (u32 LE)
payload (payload_len bytes)
```
Legacy tag compatibility:
- A legacy tag computed as `0x80 + (custom_id >> 8)` or `0x80 | ((custom_id >> 8) & 0x7F)`
  is accepted for backward compatibility.

The custom gate payload is gate-specific and interpreted by the verifier or adapter
logic. Payload decoding is validated with strict size checks (see per-gate decode
helpers in `src/glyph_ir.rs`).

### Lookups
Each lookup entry:
```
value (u32 LE)
table_id (u32 LE)
```
Constraints:
- `value < witness_total`

### Tables
Each table entry:
```
table_id (u32 LE)
width (u8)
value_count (u32 LE)
values (value_count x u64 LE)
```
All table values must be canonical Goldilocks elements.

## Standard Tables
- `TABLE_RANGE8 = 1`
- `TABLE_RANGE16 = 2`
- `TABLE_BIT = 3`
- `TABLE_CHI5 = 4`

## Custom Gate IDs
Custom gate IDs are defined in `src/glyph_ir.rs`. Notable IDs:
- `CUSTOM_GATE_KECCAK_MERGE = 0x0004`
- `CUSTOM_GATE_IVC_VERIFY = 0x0010`
- `CUSTOM_GATE_STARK_VERIFY = 0x0011`
- `CUSTOM_GATE_IPA_VERIFY = 0x0012`
- `CUSTOM_GATE_GROTH16_BLS12381_VERIFY = 0x0013`
- `CUSTOM_GATE_KZG_BLS12381_VERIFY = 0x0014`
- `CUSTOM_GATE_SP1_VERIFY = 0x0015`
- `CUSTOM_GATE_PLONK_VERIFY = 0x0016`
- `CUSTOM_GATE_BINIUS_VERIFY = 0x0017`

## Decoder Invariants
The decoder enforces:
1. Version and field ID match.
2. Witness layout is internally consistent.
3. Copy gates must not appear after custom gates. Canonical encoding sorts gates as arithmetic, copy, custom.
4. All witness references are in range.
5. All coefficients and table values are canonical.
6. Custom gate tags are valid (base tag or legacy tag).
7. No trailing bytes remain after decoding.
8. Copy count in header equals decoded copy gates.

## Audit Narrative
The correctness chain for adapters is:
```
Upstream proof -> Adapter verification -> UCIR emission -> UCIR decode and invariants -> GLYPH proof -> GLYPHVerifier
```
The UCIR decoder is the critical boundary. Any malformed or out-of-bounds UCIR must
be rejected by `Ucir2::from_bytes`.

## References
- UCIR implementation: `src/glyph_ir.rs`
- UCIR compiler: `src/glyph_ir_compiler.rs`
- Adapters: `src/*_adapter.rs`
