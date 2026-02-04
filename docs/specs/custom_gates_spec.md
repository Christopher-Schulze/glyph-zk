# Custom Gates Specification

This specification defines the custom gate identifier surface, gating semantics,
and payload encoding rules enforced by:
- `src/glyph_ir.rs`
- `src/glyph_witness.rs`
- `src/adapter_gate.rs`

## Gate Identifier Surface
Custom gate IDs are stable protocol surface:

- `0x0001` `CUSTOM_GATE_BN254_ADD`
- `0x0002` `CUSTOM_GATE_BN254_SUB`
- `0x0003` `CUSTOM_GATE_BN254_MUL`
- `0x0004` `CUSTOM_GATE_KECCAK_MERGE`
- `0x0010` `CUSTOM_GATE_IVC_VERIFY`
- `0x0011` `CUSTOM_GATE_STARK_VERIFY`
- `0x0012` `CUSTOM_GATE_IPA_VERIFY`
- `0x0013` `CUSTOM_GATE_GROTH16_BLS12381_VERIFY`
- `0x0014` `CUSTOM_GATE_KZG_BLS12381_VERIFY`
- `0x0015` `CUSTOM_GATE_SP1_VERIFY`
- `0x0016` `CUSTOM_GATE_PLONK_VERIFY`
- `0x0017` `CUSTOM_GATE_BINIUS_VERIFY`

Source: `src/glyph_ir.rs`

## Availability Gating (Fail Closed)
Custom gate availability is enforced centrally via:
- `ensure_custom_gate_enabled(custom_id)` in `src/glyph_ir.rs`
- `adapter_gate` helpers in `src/adapter_gate.rs`

Availability rules:
1) BN254 arithmetic gates are always available.
2) SNARK-family gates require the SNARK family to be enabled.
3) Hash, IVC, and Binius gates require their respective families.
4) STARK verification requires that at least one STARK field feature is enabled.

Any unavailable gate must be rejected before witness evaluation.

## Payload Encoding Rules
Payloads are strictly encoded and strictly decoded.

### Witness Reference Encoding
Witness references (`WRef`) are `u32` little-endian:
- `WRef::to_bytes` uses `u32::to_le_bytes`
- `WRef::from_bytes` uses `u32::from_le_bytes`
Exception: SP1 and PLONK verification payloads encode `WRef` and length fields as big-endian
u32 values and are decoded with `read_u32_be` in `decode_sp1_verify_payload` and
`decode_plonk_verify_payload`.

### Common Payload Shape
Most verification gates follow a length-delimited layout:

```
payload =
  commitment_start    // WRef, 4 bytes LE
  point_start         // WRef, 4 bytes LE
  claim_start         // WRef, 4 bytes LE
  len_0               // u32 LE
  len_1               // u32 LE (if needed)
  len_2               // u32 LE (if needed)
  bytes_0
  bytes_1
  bytes_2
```
SP1 and PLONK verification payloads follow the same shape but use big-endian `u32`
fields for `commitment_start`, `point_start`, `claim_start`, and `len_0`.

Decoders reject:
- Out-of-bounds reads
- Length mismatches
- Trailing bytes

Representative decode errors include:
- `payload EOF`
- `payload wref`
- `payload trailing bytes`

### Gate-Specific Payloads
Payload encode and decode functions are the canonical spec surface:
- BN254 arithmetic and Keccak merge:
  - `encode_three_wref_payload`
  - `decode_three_wref_payload`
- IVC verification:
  - `encode_ivc_verify_payload`
  - `decode_ivc_verify_payload`
- STARK verification:
  - `encode_stark_verify_payload`
  - `decode_stark_verify_payload`
- IPA, SP1, PLONK, Binius, Groth16 BLS12-381, KZG BLS12-381:
  - `encode_*_verify_payload`
  - `decode_*_verify_payload`

All decoders must be treated as the byte-accurate boundary.

## Witness Evaluation Invariants
Witness evaluation is fail closed:
- `custom_gate_wrefs` calls `ensure_custom_gate_enabled` first.
- `glyph_witness` gates custom gate evaluation through the same helper.
- Feature-specific verification code is isolated behind gate helpers and
  compile-time guards, but the core match logic remains uniform.

This ensures that:
- Unavailable adapters reject cleanly.
- Payload drift cannot silently bypass gating.

## Code References
- `src/glyph_ir.rs`
- `src/glyph_witness.rs`
- `src/adapter_gate.rs`
- `src/adapter_registry.rs`
