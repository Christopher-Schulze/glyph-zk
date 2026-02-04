# Adapter IR Specification

This specification defines the canonical Adapter IR byte encoding, kernel ID
surface, and fail-closed decoding rules enforced by `src/adapter_ir.rs`.

## Scope
Adapter IR is a stable byte-level interface for adapter kernels. It is used to:
- Route adapter-specific verification kernels.
- Bind adapter outputs into the GLYPH artifact boundary.
- Enforce strict decoding and kernel selection invariants.

## Domain Tag and Version
- Domain tag: `ADAPTER_IR_TAG = b"ADAPTER_IR"`
- Version: `ADAPTER_IR_VERSION = 1`

All multi-byte integers in Adapter IR are big-endian.

## Container Encoding
The Adapter IR container encodes a sequence of kernel operations:

```
adapter_ir =
  tag                // bytes, literal "ADAPTER_IR"
  version            // u16 BE, must equal 1
  op_count           // u16 BE
  ops[op_count]

op =
  kernel_id          // u16 BE
  args_len           // u32 BE
  args               // args_len bytes
```

Encoding reference: `AdapterIr::encode`.
Decoding reference: `AdapterIrView::decode` (zero-copy) and `AdapterIr::decode` (owned).

## Kernel Identifier Surface
Kernel identifiers are protocol surface and must be treated as stable.
They are defined in `adapter_ir::kernel_id`:

- `0x0101` `HASH_SHA3_MERGE`: Keccak-256 merge of two 32-byte inputs.
- `0x0201` `GROTH16_BN254_VERIFY`: Groth16 BN254 verification trace.
- `0x0202` `KZG_BN254_VERIFY`: KZG BN254 opening verification trace.
- `0x0203` `IVC_VERIFY`: IVC or folding proof verification.
- `0x0204` `IPA_VERIFY`: IPA verification (BN254 or BLS12-381).
- `0x0205` `STARK_VERIFY`: STARK generic verification.
- `0x0206` `BINIUS_VERIFY`: Binius native proof verification.
- `0x0301` `WINTERFELL_SHA3_TRANSCRIPT`: Winterfell SHA3 transcript kernel.
- `0x0302` `CIRCLE_STARK_TRANSCRIPT`: Circle STARK transcript kernel.

## Strict Decoding Rules (Fail Closed)
`AdapterIrView::decode` is the canonical boundary and enforces:

1) Domain tag prefix must match exactly.
- Error: `adapter ir bytes missing ADAPTER_IR_TAG prefix`

2) Version must match exactly.
- Error: `unsupported adapter ir version={version} (expected 1)`

3) Operation decoding is length driven and bounded by the input slice.
- All reads are performed via bounded helpers.

4) Trailing bytes are rejected.
- Error: `adapter ir bytes have trailing data`

These rules ensure that any malformed, truncated, or non-canonical Adapter IR
is rejected before adapter execution or artifact derivation. `AdapterIr::decode`
materializes owned args from the zero-copy view when needed.

## Kernel Routing Invariants
Each adapter entry point validates that the IR selects the expected kernel ID.
Representative checks:
- `execute_hash_sha3_merge_ir` requires `HASH_SHA3_MERGE`
- `execute_groth16_bn254_ir` and batch variants require `GROTH16_BN254_VERIFY`
- `execute_kzg_bn254_ir` and batch variants require `KZG_BN254_VERIFY`
- `execute_ivc_ir` requires `IVC_VERIFY`
- `execute_binius_ir` requires `BINIUS_VERIFY`

Wrong-kernel rejections are explicit and include both the observed and expected
kernel IDs.

## Binding to the GLYPH Artifact
Adapter IR is not only a routing surface. It also participates in binding:
- Each `derive_glyph_artifact_from_*_ir` path decodes the IR and enforces the
  kernel routing invariant.
- Adapter outputs are bound into `commitment_tag`, `point_tag`, and `claim128`
  and then into `artifact_tag`.

The artifact binding rules and on-chain chain binding are specified in:
- `docs/specs/artifact_tag_spec.md`
- `docs/specs/verifier_spec.md`

## Tests and Evidence
Adapter IR decoding and routing invariants are covered in:
- `src/adapter_ir.rs` unit tests (wrong kernel rejection and artifact parity).
- `scripts/tests/rust/adapter_ir_property_tests.rs`
- `scripts/tests/rust/adapter_error_semantics.rs`
