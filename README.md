Links: [Documentation](docs/documentation.md) | [Quickstart](docs/QUICKSTART.md) | [Whitepaper](docs/whitepaper/glyph-whitepaper.pdf) | [Proof Appendix](docs/whitepaper/glyph-proof-appendix.pdf) | [Specs](docs/specs/) | [Proof Pack](docs/proofs/) | [Map](docs/map.md)

# GLYPH

A Universal Transparent Verification Layer for Heterogeneous Zero-Knowledge Proof Systems on Ethereum. GLYPH compiles upstream proofs into a single, packed on-chain verification surface. It preserves proof-system diversity while reducing verification cost and integration surface, and it is transparent by default.

> **Key metrics**  
> ≈29,450 total tx gas (receipt-backed), ≈7.7x vs Groth16, transparent and setup-free.  
> Soundness assumptions and bounds are explicit in the proof pack.
>
> **Built for integration & extension**  
> GLYPH is designed to be easy to adopt, while keeping your existing toolchains intact.

## Reading Order

1) README for the high-level system view.
2) `docs/QUICKSTART.md` for build, test, deploy, and bench commands.
3) `docs/documentation.md` for the complete technical reference.
4) `docs/whitepaper/glyph-whitepaper.pdf` for the protocol narrative.
5) `docs/proofs/` and the proof appendix for formal assumptions and bounds.

## Key Capabilities

- GLYPH achieves **≈29,450 total tx gas** (receipt-backed), **≈7.7x cheaper than Groth16**, with receipt-backed benchmarks **while remaining transparent and setup-free** (upstream trusted setups remain upstream and explicit).
- Compact calldata and stateless verification: 224 bytes for the packed artifact (receipt-backed) and no storage writes (calldata-only).
- Single packed verifier surface on-chain: packed GKR arity-8 sumcheck over `p = 2^128 - 159`, with cost scaling by packed rounds rather than upstream proof size.
- **Adapter coverage spans eight families**, unifying Groth16, KZG/PLONK/Halo2, IPA, IVC/Folding, STARK, Hash, SP1, and Binius, with no vendor lock-in and preserved toolchains.
- Full tooling stack for tests, benchmarks, deployments, and DA workflows under `scripts/`.
- UCIR and the artifact boundary define the canonical interface between off-chain receipts and on-chain verification.
- BaseFold PCS commitments and openings provide binding for packed evaluations.
- SIMD acceleration by default (AVX-512, AVX2, NEON) with opt-in CUDA.

## System Overview

GLYPH is a four-layer pipeline:

```
┌─────────────────────────────────────────────────────────────────┐
│                         GLYPH PIPELINE                          │
├─────────────────────────────────────────────────────────────────┤
│ 1. ADAPTER LAYER                                                │
│    ├── Verifies upstream receipts off-chain                     │
│    └── Emits UCIR constraints                                   │
├─────────────────────────────────────────────────────────────────┤
│ 2. UCIR (Universal Constraint IR)                               │
│    └── Arithmetic, Copy, Lookup, Custom Gates                   │
├─────────────────────────────────────────────────────────────────┤
│ 3. GLYPH-PROVER (off-chain)                                     │
│    ├── Witness Generation                                       │
│    ├── LogUp GKR                                                │
│    ├── BaseFold PCS                                             │
│    └── Packed Sumcheck                                          │
├─────────────────────────────────────────────────────────────────┤
│ 4. GLYPHVerifier (on-chain)                                     │
│    ├── contracts/GLYPHVerifier.sol                              │
│    └── Packed sumcheck over p = 2^128 - 159                     │
└─────────────────────────────────────────────────────────────────┘
```

1) **Adapter layer**  
   Verifies upstream receipts off-chain and emits UCIR constraints.
2) **UCIR**  
   Canonical constraint boundary emitted by adapters and consumed by GLYPH-Prover.
3) **GLYPH-Prover**  
   Off-chain witness generation, LogUp GKR, BaseFold PCS, packed sumcheck.
4) **GLYPHVerifier**  
   On-chain packed sumcheck verification over `p = 2^128 - 159`.

Core on-chain contract: `contracts/GLYPHVerifier.sol`.

Integration path: verify upstream receipts off-chain, emit a canonical GLYPH artifact and UCIR, and submit the packed proof to `contracts/GLYPHVerifier.sol`.

Normative specs:
- Artifact boundary: `docs/specs/artifact_tag_spec.md`
- UCIR format: `docs/specs/ucir_spec.md`
- Verifier layout: `docs/specs/verifier_spec.md`

## Proof System Coverage

Adapters cover all supported receipt families and field variants:

- **Groth16 SNARK**: BN254, BLS12-381
- **KZG / PLONK / Halo2-KZG**: BN254, BLS12-381 (gnark, dusk, halo2 receipt formats; Halo2 KZG on BN256/BLS12-381)
- **IPA**: BN254, BLS12-381
- **STARK families**:
  - Cairo (M31)
  - Stwo (M31)
  - Winterfell (Goldilocks F64, F128)
  - Plonky2 (Goldilocks)
  - Plonky3 (Goldilocks, BabyBear, KoalaBear, M31)
  - Circle STARK (M31, BabyBear, KoalaBear)
  - Miden (Goldilocks)
  - RISC Zero (BabyBear)
- **IVC / Folding**: BaseFold, Nova, SuperNova, HyperNova, Sangria
- **SP1 receipts**: Groth16 and Plonk
- **Binius**: native M3 proofs
- **Hash receipts**: Keccak-based digests

*Note: Halo2 uses the bn256 curve name for the curve commonly called BN254 or altbn128 in Ethereum tooling.*

Full adapter list, exact receipt formats, and canonical bytes are in `docs/documentation.md`.

## Benchmarks (Receipts)

Receipt-based, authoritative totals are in Section 14.2.1 of the documentation (receipts dated 2026-02-02).
Summary:

| Network | Case | Total Tx Gas |
| --- | --- | --- |
| Sepolia | GLYPH artifact_full | 29,450 |
| Hoodi | GLYPH artifact_full | 29,450 |
| Sepolia | Groth16 verify (3 publics) | 227,128 |
| Hoodi | Groth16 verify (3 publics) | 227,128 |

Measured ratio: 227,128 / 29,450 ≈ 7.7x.

Published receipts are from Sepolia and Hoodi (2026-02-02).

Calldata size:
- GLYPH artifact: 224 bytes
- Groth16 verify (3 publics): 356 bytes

Reproducible outputs are written under `scripts/out/benchmarks/` when bench scripts
are run.

Totals are receipt-based and include base transaction and calldata gas. Benchmark methodology and receipt hashes are listed in Section 14.2.1 of the documentation.

## Security Model (High-Level)

Soundness reduces to:

- Fiat-Shamir in the random oracle model
- Keccak256 collision resistance
- GKR soundness and PCS binding
- Adapter correctness for each supported receipt format

Formal assumptions and soundness bounds are in `docs/proofs/` and `docs/documentation.md`.

## Project Structure

- `src/` - Core Rust code
- `src/bin/` - Rust binaries (bench, gen, tooling)
- `contracts/` - Solidity verifier(s)
- `scripts/` - Tooling, tests, benchmarks, DA, deploy
- `docs/` - Documentation, specs, proofs, whitepaper
- `deployments/` - Deployment artifacts (JSON)
- `vendor/` - Vendored dependencies

## Quickstart

See `docs/QUICKSTART.md` for full build, test, deploy, and benchmark flows.

## Reproducible Workflows

Tests:
- `bash scripts/tests/run_tests.sh`

Benchmarks:
- `bash scripts/benchmarks/run_all.sh <profile>`

Deployments:
- `bash scripts/deploy/deploy_glyph_contract.sh <network>`

All outputs go under `scripts/out/`.

## Contributing

Contributions are welcome. High-impact areas include new adapters, receipt formats, and verification tests.
GLYPH is designed for extension without changing upstream toolchains. The fastest path:

1) Start with the SSOT: `docs/documentation.md`.
2) Use the relevant spec in `docs/specs/` for canonical receipt formats and UCIR rules.
3) Implement adapter logic and UCIR compilation in `src/` (start with `src/adapters.rs`).
4) Add tests and fuzz targets under `scripts/tests/` and update or add fixtures as needed.
5) Update relevant specs, proofs, and documentation entries under `docs/`.

## Contact

Maintainer: Christopher Schulze - snarkamoto.eth | snarkamoto.com

## License

MIT. See `LICENSE`.
