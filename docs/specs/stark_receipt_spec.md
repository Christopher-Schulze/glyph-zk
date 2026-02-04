# Canonical STARK Receipt and VK Specification

This specification defines the canonical STARK receipt and verifier key byte
encodings enforced by `src/stark_receipt.rs`.

## Domain Tags
The canonical domains are:
- `CANONICAL_STARK_RECEIPT_DOMAIN = b"CANONICAL_STARK_RECEIPT"`
- `CANONICAL_STARK_VK_DOMAIN = b"CANONICAL_STARK_VK"`
- `CANONICAL_STARK_VK_PROGRAM_DOMAIN = b"CANONICAL_STARK_VK_PROGRAM"`

All multi-byte integers are big-endian.

## Canonical STARK Verifier Key (VK)
Structure:
```
vk =
  vk_domain                // bytes, canonical VK domain tag
  version                  // u16 BE
  field_id                 // u8
  hash_id                  // u8
  commitment_scheme_id     // u8
  consts_len               // u32 BE
  consts_bytes             // consts_len bytes
  program_len              // u32 BE
  program_bytes            // program_len bytes
  program_hash             // bytes32
```

Program hash derivation:
```
program_hash = keccak256(CANONICAL_STARK_VK_PROGRAM_DOMAIN || program_bytes)
```

Decoding rules:
1) Domain prefix must be present.
- Error: `vk bytes missing CANONICAL_STARK_VK_DOMAIN prefix`

2) All fields are length delimited and bounds checked.

3) Trailing bytes are rejected.
- Error: `vk bytes have trailing data`

4) Program hash must match the recomputed value.
- Mismatch yields a program-hash error and rejection, except for the explicit suffix-compatibility cases described below.

## Canonical STARK Receipt
Structure:
```
receipt =
  receipt_domain           // bytes, canonical receipt domain tag
  proof_len                // u32 BE
  proof_bytes              // proof_len bytes
  pub_inputs_len           // u32 BE
  pub_inputs_bytes         // pub_inputs_len bytes
  vk_len                   // u32 BE
  vk_bytes                 // vk_len bytes
```

Encoding reference: `CanonicalStarkReceipt::encode_for_hash`.
Decoding reference: `CanonicalStarkReceipt::decode`.

Decoding rules:
1) Domain prefix must be present.
- Error: `receipt bytes missing CANONICAL_STARK_RECEIPT_DOMAIN prefix`

2) All sections are length delimited and bounds checked.

3) Trailing bytes are rejected.
- Error: `receipt bytes have trailing data`

## Version Suffix Handling
The decoder accepts domain tags with numeric suffixes of the form `_V<digits>`.
Suffixes may appear on the VK domain tag or on the leading program tag inside
`program_bytes`. When a suffix is present, program hashing binds to the suffixed
program domain. This is implemented via:
- `tag_offset`
- `tag_version_suffix`
- `suffix_from_tag_prefix`
- `domain_with_suffix`
- `matches_program_hash`

For suffixed tags, the decoder accepts program hashes computed as:
- `keccak256(program_domain || program_bytes)`
- `keccak256(keccak256(program_domain) || program_bytes)`
- `keccak256(program_bytes)` (legacy binding, only when a suffix is present)

The fail-closed rule remains: any non-canonical structure is rejected. Program
hash mismatch is only accepted for the explicit suffix-compatibility cases above.

## Validation Pipeline
Receipt validation is staged:
1) `CanonicalStarkReceipt::decode`
2) `CanonicalStarkVk::decode` on the embedded `vk_bytes`
3) Program hash recomputation and comparison

Helper:
- `CanonicalStarkReceipt::decode_and_validate_vk`

## Invariants and Security Notes
Mandatory invariants:
- Domain tags must match the canonical domains (optionally with version suffix).
- Length fields must exactly match the byte layout.
- No trailing data is permitted.
- `program_hash` must bind the exact `program_bytes`.

Security consequence:
- Any tampering in program bytes, lengths, or the program hash must be rejected
  before adapter verification logic executes.

## Code References
- `src/stark_receipt.rs`
- `src/stark_adapter.rs`
- Fuzz and decode tests under `scripts/tests/rust/*stark*`
