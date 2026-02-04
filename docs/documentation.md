# GLYPH Technical Documentation

**GLYPH: A Transparent Packed Sumcheck Verifier for Universal, Gas-Efficient Verification of Heterogeneous Proof Systems on Ethereum**

---

## Project Evaluation

### Scope
GLYPH-PROVER is a universal verification layer for heterogeneous proof systems (Groth16, KZG, IVC formats with transparent receipts, IPA/Halo2, STARKs) with a single on-chain verifier. Goal: Gas-efficient, trustless on-chain verification without trusted setup. Trustless here means: given adapter correctness, security reduces to UCIR equivalence plus GKR sumcheck soundness and PCS binding for the adapter path.

### Architecture
**Adapter-based (feature groups)**:
- Groth16 SNARK (BN254/BLS12-381)
- KZG/Plonk SNARK (BN254/BLS12-381)
- IVC/Folding (BaseFold PCS + Nova-family receipts)
- IPA (Halo2)
- STARK (Winterfell, Circle, Stwo, RISC Zero, Cairo, Miden)
- Hash merge
- SP1 (Groth16/Plonk BN254 receipts)
- PLONK and Halo2 KZG (gnark BN254, dusk BLS12-381, halo2 backend for BN256/BLS12-381, standard, parametric, and custom circuits)
- Binius constraint-system proofs (official layout, canonical tower serialization)

**Core Pipeline**:
1. Adapter compiles upstream proofs to UCIR (Universal Constraint IR)
2. Prover runs off-chain Goldilocks sumcheck and derives a packed arity-8 proof for on-chain verification
3. Single Solidity verifier (`contracts/GLYPHVerifier.sol`) validates in round-dependent gas, independent of upstream proof size
4. UCIR encoding and invariants are specified in `docs/specs/ucir_spec.md`

**Cryptography**: hybrid fields - Goldilocks for off-chain sumcheck and adapter arithmetic, BaseFold over binary tower fields for PCS, and a packed arity-8 sumcheck over a 128-bit prime on-chain - plus Keccak256 for transcripts (transparent, no trusted setup in GLYPH core; BN254 remains in off-chain adapters)

### Idea
Shift 99% of work off-chain, minimize on-chain gas (execution gas estimate 5,419, total tx gas 29,450 for packed artifact-bound receipts on Sepolia and Hoodi; see Section 14.2.1). Single verifier for all systems. No optimistic games, immediate finality.

### Implementation
- **Rust-based** with SIMD (AVX-512/AVX2/NEON) and optional CUDA acceleration
- **139 Rust source files** under `src/`, 42 CLI binaries under `src/bin/`, and 4 Solidity contracts under `contracts/`
- **Comprehensive tests**: Rust unit/integration/e2e, Foundry Solidity tests
- **Benchmark infrastructure**: 31 benchmark presets in `scripts/benchmarks/registry.json`, plus groth16_compare assets; 15 bench binaries under `src/bin/`
- **Good documentation**: docs/, map.md, changelog.md

### Market Impact
- **≈7.7x cheaper** than Groth16 on Sepolia and Hoodi for the recorded receipt-based cases (Section 14.2.1)
- **Universal** for all common proof systems
- **Multi-chain capable** on EVM networks with Keccak and 128-bit field arithmetic; receipts reported here are Ethereum testnets only (Sepolia, Hoodi)
- **No trusted setup in GLYPH core** - upstream trust assumptions are preserved

Evidence-backed claims are listed in Section 14.2.1 with testnet tx hashes and calldata breakdowns.

### Code Quality
- **Structure**: Clear separation between adapters, UCIR, prover, verifier
- **Documentation**: Blueprint references, domain separation tags, extensive comments
- **Tests**: Roundtrip, tamper tests, KPI benchmarks
- **Performance**: SIMD/CUDA paths with fallback, GLV optimization, precomputed tables. GLV uses a deliberately simplified decomposition to limit complexity.

### Documentation Quality
- **SSOT**: `docs/documentation.md` as canonical reference
- **GitHub entrypoint**: `README.md` as the consolidated project overview and link hub; archived prior draft at `archive/README_NEW.md`
- **Repository map**: `docs/map.md` with wiring and a full ASCII first-party file index
- **Changelog**: Grouped entries per TASK
- **Context.md**: Live buffer for active work

---

## What is GLYPH?

**GLYPH** is a universal off-chain prover and adapter layer that compiles upstream proofs into a compact **GLYPH artifact** and produces a packed sumcheck proof verified by a single on-chain contract (`contracts/GLYPHVerifier.sol`). It is designed for transparent verification with low on-chain gas while keeping upstream proof logic off-chain. By using specialized adapters (Groth16, KZG/Plonk, IVC/Folding, IPA, STARK, Hash, SP1, PLONK/Halo2, Binius), it can wrap heterogeneous proof systems into a uniform verification surface.

### The Problem

Zero-knowledge proofs on Ethereum face a fundamental trade-off:

| Approach           | Gas Cost   							                                              | Trusted Setup | Transparency |
|--------------------|------------------------------------------------------------------------|---------------|--------------|
| **Groth16**        | 227,128 total tx gas (receipts in Section 14.2.1)  		                |      Required |          no  |
| **Trans. SNARKs**  | Varies by system and proof size, not measured in this repo 	          |        None   |         yes  |
| **GLYPH**          | 29,450 total tx gas (packed artifact-bound receipts in Section 14.2.1) |      **None** |         yes  |

Until now, developers had to choose: accept the security risks of a trusted setup (Groth16), or pay significantly higher gas costs for transparency. This affects everyone - users pay more fees, L2 rollups spend more on settlement, and the entire ecosystem operates less efficiently.

### The Solution

GLYPH is designed to address three practical problems at once:

1. **No Trusted Setup.** Fully transparent construction using deterministic hash-to-curve generators. No ceremonies, no toxic waste, no trust assumptions beyond standard cryptographic hardness. Upstream proofs may still require trusted setup, and GLYPH preserves those assumptions rather than removing them.

2. **Lower verification gas.** Execution gas estimate is 5,419 and total tx gas is 29,450 for packed artifact-bound receipts (Section 14.2.1).

3. **Compatibility via an adapter.** GLYPH works as an adapter layer: upstream systems (Groth16, PLONK, STARKs, folding schemes) can compress a public digest into the fixed GLYPH interface off-chain and reuse a single, transparent on-chain verifier without introducing a circuit DSL.

### Who Benefits

- **Users**: Lower transaction fees for ZK-verified operations
- **L2 Rollups**: Reduced settlement costs on L1
- **Protocol Developers**: Transparent security without gas penalties
- **The Ecosystem**: More efficient use of block space

### Positioning in the ZK Landscape

In practical terms, GLYPH targets teams who want transparent verification on
Ethereum without paying the usual gas premium for transparent systems. Instead
of deploying a separate Groth16 verifier for every protocol, different proof
systems can map small summary statements into the GLYPH interface and reuse a
single, setup-free packed sumcheck verifier. This reduces per-proof gas
compared to representative Groth16 verifiers on BN254 while allowing projects
to keep their existing off-chain tooling and add only a thin adapter layer
around GLYPH. GLYPH optimizes on-chain verification cost and adapter universality, not prover throughput. Prover speedups remain upstream and are orthogonal to GLYPH's verification layer.

### Competitor Comparison (Aligned Layer, NEBRA UPA)

Sources are the public docs linked below and were reviewed on 2026-01-26.
This table is intentionally conservative and uses only published figures.

Definitions:
- Model: where verification happens and what is posted on-chain.
- Gas: reported on-chain verification cost, per proof when specified by the source.
- Setup: trusted setup requirement stated in the referenced docs.

| Dimension                       | GLYPH                                                                  | Aligned Layer                                                             | NEBRA UPA                                                                      |
| ------------------------------- | ---------------------------------------------------------------------- | ------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| Verification model              | On-chain packed sumcheck, adapter calldata, Sec 11.5, 14.2.1           | PVL off-chain verify, BLS sig on-chain, Aggregation: recursive proof      | Aggregated proof on-chain, `verifyAggregatedProof`, permissioned submitter     |
| Trusted setup                   | None in core, transparent                                              | BLS sig verify, recursive proof verify                                    | Halo2-KZG agg proof, KZG SRS (PPoT)                                            |
| Proof system coverage           | Adapters: Groth16, KZG, PLONK or Halo2, IVC, IPA, STARK, SP1, Binius   | Groth16, Plonk (gnark), SP1, Risc0, Circom, more via off-chain verifiers  | Groth16 only, batch size 32                                                    |
| On-chain gas                    | 29,450 total tx gas, receipt-backed                                    | ~113k gas BLS sig, ~300k gas agg proof                                    | ~18k gas per proof, ~350k gas per batch                                        |
| Calldata and format constraints | Fixed packed calldata, 64B header + per-round                          | Proofs off-chain, on-chain commitments + sig or proof                     | Aggregated proof on-chain, proofIds + batch metadata                           |
| Transparency and assumptions    | Transparent core, upstream preserved                                   | Restaked operators, BLS quorum                                            | Recursive SNARK agg, permissioned, untrusted                                   |
| Integration surface             | Adapter pipeline, fixed calldata interface                             | CLI or SDK to batcher, on-chain inclusion check                           | `upa` CLI tool                                                                 |
| Evidence and reproducibility    | Sec 14.2.1 receipts, `scripts/out/benchmarks/`                         | Public architecture and cost docs                                         | Gas cost docs + protocol spec                                                  |

Sources (reviewed 2026-01-26):
- Aligned Layer FAQ: https://docs.alignedlayer.com/introduction/3_faq
- NEBRA gas costs: https://docs.nebra.one/developer-guide/gas-costs-on-l1s
- NEBRA protocol specification: https://docs.nebra.one/upa-protocol-specification
- NEBRA security and transparency: https://docs.nebra.one/security-and-transparency
- NEBRA how it works: https://docs.nebra.one/introduction/how-it-works

Short positioning summary:
- GLYPH details: see Section 11.5 and 14.2.1.
- Aligned targets high throughput by moving verification off-chain and posting signatures, with an optional on-chain aggregation mode.
- NEBRA UPA aggregates proofs into a recursive proof verified on-chain, amortizing verification cost.

### Name and Intuition

The name **GLYPH** is chosen by analogy to glyphs as compact symbols carved into
stone: they encode rich meaning in a small, durable pattern. Similarly, a GLYPH
proof compresses the correctness of a larger computation into a short vector of
field elements and a succinct on-chain proof. The adapter interface exposes only
this compact summary, while upstream proof systems are responsible for deriving
the values fed into GLYPH from richer application state.

---

## Technical Summary

| Property                          | Value 									                			                                                      |
|-----------------------------------|-----------------------------------------------------------------------------------------------------|
| **Proof System**                  | Packed sumcheck over the 128-bit prime field `p = 2^128 - 159` (artifact-defined polynomial)        |
| **Sumcheck Rounds**               | R (derived from calldata; packed layout encodes 2 coefficients per round in 32 bytes, c2 recovered) |
| **On-chain Verifier**             | `contracts/GLYPHVerifier.sol`                                                                       |
| **Gas per verify (total tx gas)** | 29,450 (receipt gas on Sepolia and Hoodi; packed artifact-bound, see Section 14.2.1)                |
| **Calldata Payload**              | Header 64 bytes + 32 bytes per round (packed: `c0` and `c1` as 2x16 bytes, c2 recovered)            |
| **Security**                      | ~128-bit field size; soundness depends on Fiat-Shamir and hash collision resistance                 |
| **Trusted Setup**                 | None                                                                                                |

The production on-chain verifier is `contracts/GLYPHVerifier.sol` (packed sumcheck).

### Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    GLYPH System                         │
├─────────────────────────────────────────────────────────┤
│                                                         │
│   Off-Chain (Rust)              On-Chain (Solidity)     │
│   ┌─────────────────┐           ┌───────────────────┐   │
│   │ glyph_core.rs   │           │ GLYPHVerifier.sol │   │
│   │ GLYPH-Prover    │  ──────►  │ packed sumcheck   │   │
│   │ adapters + GKR  │           │ tens of k gas     │   │
│   └─────────────────┘           └───────────────────┘   │
│                                                         │
│   Hardware Acceleration:                                │
│   • SIMD (AVX-512, AVX2, NEON)                          │
│   • Parallel MSM (Rayon)                                │
│   • GLV endomorphism                                    │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Mathematical Foundations](#2-mathematical-foundations)
3. [IPA Adapter: Inner Product Argument (IPA)](#3-ipa-adapter-inner-product-argument-ipa)
4. [Proof Structures](#4-proof-structures)
5. [Prover Implementation](#5-prover-implementation)
6. [Verifier Implementation](#6-verifier-implementation)
7. [GLYPH Adapters and Integration](#11-glyph-adapters-and-integration)
8. [Limitations and Non-Goals](#12-limitations-and-non-goals)
9. [Hardware Acceleration](#7-hardware-acceleration)
10. [Solidity Verifier](#8-solidity-verifier)
11. [Module Reference](#9-module-reference)
12. [Security Analysis](#10-security-analysis)
13. [Appendix A: Rust Dependencies](#appendix-a-rust-dependencies)
14. [Appendix B: Test Coverage (Overview)](#appendix-b-test-coverage-overview)
15. [Appendix C: Benchmarks (Reproducibility)](#appendix-c-benchmarks-reproducibility)
16. [Appendix D: Glossary](#appendix-d-glossary)
17. [Appendix E: Optional Developer Tooling and Quick Reference](#appendix-e-optional-developer-tooling-and-quick-reference)
18. [Appendix F: Adapter Semantics and Digest Layout](#appendix-f-adapter-semantics-and-digest-layout)
19. [Production Readiness Summary](#14-production-readiness-summary)
20. [Proof Sketches](#14-proof-sketches)
21. [Formal Proof Pack](#144-formal-proof-pack)
22. [Tutorials and Guides](#145-tutorials-and-guides)
23. [Repository Meta and Governance](#146-repository-meta-and-governance)
24. [Specifications (Verbatim)](#147-specifications-verbatim)
25. [Proof Pack (Canonical Files and SSOT Mirrors)](#148-proof-pack-canonical-files-and-ssot-mirrors)
26. [Data Availability Profiles and Tooling](#15-data-availability-profiles-and-tooling)
27. [Testnet Deployment Requirements (Normative)](#16-testnet-deployment-requirements-normative)
28. [Test Suite Requirements (Normative)](#17-test-suite-requirements-normative)
29. [Performance Requirements (Normative)](#18-performance-requirements-normative)
30. [Appendix G: Canonical STARK Encodings (SSOT)](#appendix-g-canonical-stark-encodings-ssot)
31. [Appendix H: STARK Validity and Kernels (SSOT)](#appendix-h-stark-validity-and-kernels-ssot)
32. [Appendix I: BaseFold PCS Notes (SSOT)](#appendix-i-basefold-pcs-notes-ssot)
33. [Appendix J: GLYPH Artifact Boundary Specification (SSOT)](#appendix-j-glyph-artifact-boundary-specification-ssot)
34. [Appendix K: Tooling Index (scripts/)](#appendix-k-tooling-index-scripts)
35. [Appendix L: Quickstart & Deployment Guide](#appendix-l-quickstart--deployment-guide)

---

## 1. System Overview

### 1.0 Non-Negotiables (Normative)

The final system MUST satisfy all of the following:

1) **Trustless validity**
   - An on-chain accepted GLYPH proof MUST be constructible only if the upstream proof verification succeeded.
   - "Binding-only" (digest notarization) is insufficient and MUST NOT be the security basis.
2) **No trusted setup**
   - The GLYPH core proof system and commitments MUST be transparent (no per-circuit trusted setup).
   - Upstream proofs retain their original trust assumptions when wrapped by adapters.
3) **No optimistic security**
   - There MUST be no challenge games, fraud proofs, or time delays for validity.
4) **Universal upstream support via adapters**
   - The system MUST support multiple upstream proof families via a stable adapter surface.
   - For STARKs specifically, there MUST be one universal STARK adapter entry point (no Rust hardcoding per upstream STARK system).
5) **Minimal on-chain cost**
   - On-chain verification MUST be a calldata-only check that performs no storage writes, with size scaling only by sumcheck rounds.
6) **Determinism and canonical encodings**
   - All bytes-level formats that cross trust boundaries MUST be canonical and domain-separated.
   - Any malformed encoding MUST be rejected by parsers and MUST NOT be accepted by alternative parsing paths.

### 1.1 Design Goals

GLYPH is a transparent (no trusted setup) ZK verification layer based on packed sumcheck
verification of the GLYPH artifact, optimized for Ethereum verification. The
IPA stack remains off-chain for the IPA adapter and internal modules only.

**Primary objectives:**
- Transparent setup (nothing-up-my-sleeve generators)
- Logarithmic proof size: O(log n) group elements
- Efficient on-chain verification (execution gas in the low thousands; total tx gas in the tens of thousands, see Section 14.2.1 receipts)
- Hardware acceleration for prover (SIMD-enabled CPU backends)

### 1.2 Architecture

```
┌──────────────────────────────────────────────────────┐
│                    GLYPH System                      │
├──────────────────────────────────────────────────────┤
│  Prover Stack                Verifier Stack          │
│  ┌──────────────────┐             ┌─────────────┐    │
│  │ simd_prover      │             │ ipa_bn254   │    │
│  │                  │             │ (Rust)      │    │
│  ├──────────────────┤             ├─────────────┤    │
│  │ glyph_field_simd │             │ Verifier    │    │
│  │ glv              │             │ (Solidity)  │    │
│  └──────────────────┘             └─────────────┘    │
└──────────────────────────────────────────────────────┘
```

### 1.3 Field Choice: Packed Sumcheck Prime

GLYPH uses a hybrid field stack: Goldilocks for off-chain sumcheck and adapter arithmetic,
BaseFold over binary tower fields for PCS commitments, and the packed on-chain verifier in
the 128-bit prime field below.

The packed sumcheck verifier runs over a 128-bit prime field:
```
p = 2^128 - 159
```

Reasons:
1. Two field elements fit cleanly into one 256-bit EVM word.
2. Calldata packing is simple and constant-time to decode.
3. The on-chain verifier needs no elliptic-curve precompiles.

**Note:** BN254 still appears in off-chain modules (IPA adapter, some upstream
adapters), but the production on-chain verifier does not depend on any pairing
curve.

### 1.4 Key Terms

- **GLYPH adapter.** The combination of the GLYPH-Prover pipeline (`src/glyph_core.rs`, `src/glyph_ir_compiler.rs`), adapter digest binding (`src/adapters.rs`), packed sumcheck proving (`src/glyph_gkr.rs`), and the on-chain GLYPHVerifier. This is the production path.
- **IPA adapter.** The IPA-based adapter path uses `src/ipa_bn254.rs`, `src/ipa_bls12381.rs`, and `src/ipa_adapter.rs` for Halo2 and generic IPA receipts on BN254 and BLS12-381 with statement binding. This is off-chain only and feeds the GLYPH artifact.
- **PublicProof / PublicProver / PublicVerifier.** An adapter layer in
  `src/public_inputs.rs` that binds explicit public inputs to an IPA proof
  without changing the core protocol. Applications use this to express
  "what is being proven".
- **Solidity verifier.**
  - `contracts/GLYPHVerifier.sol`: Packed sumcheck verifier for the GLYPH artifact (production contract).

### 1.5 Quickstart for Developers

**JavaScript note:** When JS tooling is required (Arweave Turbo, Groth16 compare),
bun is preferred. Node, npm, and npx are supported fallbacks.

#### Platform Compatibility (Windows and WSL)

- **Linux/macOS:** native support for the full tooling stack.
- **Windows:** use WSL2 for the repository tooling (Bash scripts) and the SP1
  prover workflow and fixture generation, which are Linux/macOS only.

1. **Generate a GLYPH proof off-chain.**
- Use `glyph_prover` with `--family` set to `hash|snark|stark-goldilocks|stark-babybear|stark-m31|ivc|binius`.
  - For SNARKs, also set `--snark-kind <groth16-bn254|kzg-bn254|plonk|halo2-kzg|ipa-bn254|ipa-bls12381|sp1>`.
  - For Groth16 or KZG BLS12-381 receipts, pass `--curve bls12-381` with the matching `--snark-kind`.
   - The pipeline emits the GLYPH artifact plus packed calldata for `contracts/GLYPHVerifier.sol`.
2. **Call the on-chain verifier.**
   - Submit the packed calldata to the `GLYPHVerifier` fallback (no selector).
   - Use `eth_call` for read-only checks, or submit a transaction for stateful flows.
3. **Handle success and failure.**
   - On success, the fallback returns `1`.
   - Malformed calldata or invalid proofs revert. Callers should use try-catch.
4. **IPA path (IPA adapter).**
   - IPA verifies receipts off-chain via `src/ipa_adapter.rs` and feeds the GLYPH artifact for BN254 and BLS12-381.
   - There is no on-chain IPA calldata format in the production pipeline.

### 1.6 Configuration

**Prover Mode:**
- `ProverMode::ZkMode` is the **default** configuration.
- `ProverMode::FastMode` is available for development and testing.
- ZK mode uses salted PCS commitments and mask rows for privacy (BaseFold PCS path).

**Cargo Feature Flags:**
- `dev-tools`: Enables long-running tests that are gated for CI efficiency.
- `cuda`: Enables CUDA backend for GPU acceleration (Linux or Windows, requires `GLYPH_CUDA=1`).
- Native Plonky2 verification is enabled when the STARK Goldilocks feature is on.
- The Plonky2 module is compiled under any STARK feature set, but receipt acceptance requires the Goldilocks field to be enabled in the registry.

**Environment Variables:**
- `GLYPH_CUDA=1`: Enable CUDA backend at runtime.
- `GLYPH_CUDA_MIN_ELEMS=N`: Minimum elements threshold for GPU dispatch.
- `GLYPH_ACCEL_PROFILE=cpu|cuda|cpu-cuda`: Select acceleration profile.

### 1.7 Safety and Panic Handling

**Panic Safety for Untrusted Inputs:**
- All external-facing decode and verify paths are hardened against panics.
- `src/stwo_verifier.rs` wraps verification in `std::panic::catch_unwind` to convert panics to `Result::Err`.
- Malformed receipts return descriptive errors and do not crash the process.
- IPA adapters return explicit `Result` errors for zero challenges instead of panicking on inversion.
- BN254 pairing trace recorder paths avoid runtime panics by using safe fallbacks and error propagation.
- Adapters groth16, kzg, ivc, ipa, stark, hash, sp1, plonk, and binius plus import CLIs use `Result` propagation throughout.

## 2. Mathematical Foundations

### 2.1 Discrete Logarithm Assumption

Security relies on the hardness of the Discrete Logarithm Problem (DLP):
Given `G ∈ 𝔾` and `H = x·G`, find `x`.

For BN254, best known attacks require ~2^100 operations.

### 2.2 Pedersen Commitments

A Pedersen commitment to vector `a = (a₁, ..., aₙ)` with blinding `γ`:

```
C = ⟨a, G⟩ + γ·H = ∑ᵢ aᵢ·Gᵢ + γ·H
```

**Properties:**
- Perfectly hiding: C reveals nothing about `a`
- Computationally binding: cannot open to different `a'` (under DLP)

### 2.3 Inner Product

For vectors `a, b ∈ F_r^n`:

```
⟨a, b⟩ = ∑ᵢ aᵢ · bᵢ
```

**Key identity (used in IPA):**

For any `x ∈ F_r`, if we split vectors:
```
a = (a_lo, a_hi)    where |a_lo| = |a_hi| = n/2
b = (b_lo, b_hi)
```

Then:
```
⟨a, b⟩ = ⟨a_lo, b_lo⟩ + ⟨a_hi, b_hi⟩
⟨a_lo + x·a_hi, b_lo + x⁻¹·b_hi⟩ = ⟨a, b⟩ + x·⟨a_hi, b_lo⟩ + x⁻¹·⟨a_lo, b_hi⟩
```

This allows recursive reduction of the statement size.

### 2.4 Fiat-Shamir Transform

Interactive protocols are made non-interactive via Fiat-Shamir:

```text
challenge = H(transcript || public_data)
```

In the GLYPH implementation we **do not** use an ad-hoc SHA-256 helper
anymore. Instead, `src/ipa_bn254.rs` and `src/ipa_bls12381.rs` define a small
`Transcript` type that mirrors exactly the Keccak-based transcript used by
the Solidity verifier.

```rust
pub struct Transcript {
    seed: [u8; 32],
}

impl Transcript {
    /// Create a new transcript. The label is currently ignored; we start from
    /// a zero seed so that the same Keccak-based transcript can be reproduced
    /// exactly in Solidity.
    pub fn new(_label: &[u8]) -> Self {
        Self { seed: [0u8; 32] }
    }

    fn keccak256(data: &[u8]) -> [u8; 32] { /* see ipa_bn254.rs */ }

    /// Append an affine point (x, y):
    ///   seed = keccak(seed || x || y)
    pub fn append_point(&mut self, point: &G1Affine) { /* see ipa_bn254.rs */ }

    /// Derive a non-zero scalar challenge from the transcript:
    ///   1. seed = keccak(seed)
    ///   2. zero out the high 16 bytes (keep only the low 128 bits)
    ///   3. interpret as big-endian field element in Fr
    ///   4. if the result is 0, replace it by 1
    pub fn challenge_scalar(&mut self) -> Fr { /* see ipa_bn254.rs */ }
}
```

In words:

- Prover and verifier use the exact same `Transcript` mechanism.
- Challenges are **128-bit** Keccak outputs, embedded into `Fr`.
- The Solidity verifier implements the same sequence (seed, `append_point`,
  Keccak, 128-bit truncation, non-zero guard), so that all challenges match the
  Rust implementation bit-for-bit.

---

## 3. IPA Adapter: Inner Product Argument (IPA)

> **Note:** This section details the Inner Product Argument used by the IPA adapter (Halo2 and generic IPA receipts on BN254 and BLS12-381). For the main GLYPH Packed Sumcheck/BaseFold prover, see [Section 11: GLYPH Adapters and Integration](#11-glyph-adapters-and-integration).

### 3.1 Problem Statement

**Input:**
- Commitment `P ∈ 𝔾` to vector `a`
- Public vector `b ∈ F_r^n`
- Claimed inner product `c = ⟨a, b⟩`

**Goal:** Prove that P is a valid commitment to some `a` where `⟨a, b⟩ = c`.

### 3.2 Protocol (Bulletproofs Style, as implemented)

**Notation:**
- `G = (G₁, ..., Gₙ)`: generator vector for `a`
- `H = (H₁, ..., Hₙ)`: generator vector for `b`
- `U`: generator for inner product

**Prover algorithm (one round, matching `IPAProver`):**

```text
Input: P, a, b where P = ⟨a, G⟩ + ⟨b, H⟩ + c·U

1. Split vectors:
   a = (a_lo, a_hi)
   b = (b_lo, b_hi)
   G = (G_lo, G_hi)
   H = (H_lo, H_hi)

2. Compute cross terms (as in `src/ipa_bn254.rs` and `src/ipa_bls12381.rs`):
   L = ⟨a_lo, G_hi⟩ + ⟨b_hi, H_lo⟩ + ⟨a_lo, b_hi⟩·U
   R = ⟨a_hi, G_lo⟩ + ⟨b_lo, H_hi⟩ + ⟨a_hi, b_lo⟩·U

3. Get challenge x via Fiat–Shamir transcript

4. Fold (implementation form):
   a' = a_lo·x     + a_hi·x⁻¹
   b' = b_lo·x⁻¹   + b_hi·x
   G' = G_lo·x⁻¹   + G_hi·x
   H' = H_lo·x     + H_hi·x⁻¹

   (The more common textbook form with `a' = a_lo + x·a_hi` etc. is
    algebraically equivalent after a re-parameterization of x; here we
    document the exact code form that matches `src/ipa_bn254.rs` and `src/ipa_bls12381.rs`.)

5. Recurse with (P, a', b', G', H') and store (L, R) in the proof
```

**Rounds:** log₂(n) for vector size n

**Final proof:** `(L₁, R₁, ..., L_k, R_k, a_final, b_final)`

### 3.3 Verifier Algorithm (as implemented)

```text
Input: P, c, proof = (L₁, R₁, ..., L_k, R_k, a, b)

1. Recompute challenges x₁, ..., x_k from the same transcript

2. Compute folded commitment P' using the implementation form:
   P' = P
   for i in 1..k:
       let x  = xᵢ
       let x² = x * x
       let x⁻² = (x²)⁻¹
       P' = x²·Lᵢ + P' + x⁻²·Rᵢ

3. Compute final generators (standard Bulletproofs weights):
   G_final = ∑ᵢ sᵢ·Gᵢ  where s depends on the bits of the index and xᵢ/xᵢ⁻¹
   H_final = similar (see `compute_final_generators` for exact formula)

4. Verify final equation:
   P' == a·G_final + b·H_final + (a·b)·U
```

### 3.4 Proof Size Analysis

For vector size n:
- L, R pairs: 2·log₂(n) compressed G1 points
- Final scalars: 2 field elements

**Size formula:**

```text
size = 2·log₂(n)·33 + 2·32 bytes
     = 66·log₂(n) + 64 bytes
```

### 3.5 Public Parameters and Generator Seeds

The GLYPH implementation uses a fully transparent parameter generation based on
deterministic hashing (no trusted setup). This is encapsulated in
`IPAParams` in `src/ipa_bn254.rs`:

```rust
#[derive(Clone)]
pub struct IPAParams {
    pub g: Vec<G1Affine>,
    pub h: Vec<G1Affine>,
    pub u: G1Affine,
    pub n: usize,
}

impl IPAParams {
    pub fn new(n: usize) -> Self {
        assert!(n.is_power_of_two());
        let g: Vec<_> = (0..n).map(|i| hash_to_g1_indexed("GLYPH_G", i as u64)).collect();
        let h: Vec<_> = (0..n).map(|i| hash_to_g1_indexed("GLYPH_H", i as u64)).collect();
        let u = hash_to_g1_indexed("GLYPH_U", 0);
        Self { g, h, u, n }
    }
}
```

- `GLYPH_G`: domain-separation label for the i-th generator of `G`, with the index appended as a 64-bit big-endian integer in `hash_to_g1_indexed`.
- `GLYPH_H`: domain-separation label for the i-th generator of `H`, with the index appended as a 64-bit big-endian integer in `hash_to_g1_indexed`.
- `GLYPH_U`: label for the special inner-product generator `U`.

All generators are derived via the helper `hash_to_g1`:

```rust
fn hash_to_g1_indexed(label: &str, index: u64) -> G1Affine {
    let mut counter = 0u64;
    loop {
        let mut hasher = Sha256::new();
        hasher.update(label.as_bytes());
        hasher.update(index.to_be_bytes());
        hasher.update(counter.to_be_bytes());
        let hash = hasher.finalize();
        let x = ark_bn254::Fq::from_be_bytes_mod_order(&hash);
        if let Some(point) = G1Affine::get_point_from_x_unchecked(x, false) {
            if point.is_on_curve() && !point.is_zero() {
                return point;
            }
        }
        counter += 1;
    }
}
```

This uses **SHA-256** as a random oracle into `F_q` to sample a valid, non-zero
BN254 G1 point. The procedure is fully deterministic given the labels above and
does not rely on any external setup.

### 3.6 Public-Inputs Extension (src/public_inputs.rs)

The core IPA backend can be extended with explicit public inputs. The
`public_inputs` module implements a thin wrapper around the optimized IPA
prover/verifier:

```rust
pub struct PublicProof {
    /// Public inputs (verifier knows these)
    pub public_inputs: Vec<Fr>,
    /// The IPA proof
    pub ipa_proof: IPAProofOptimized,
    /// Commitment to full witness
    pub commitment: G1Projective,
}

pub struct PublicProver<'a> {
    pub params: &'a IPAParams,
    pub num_public: usize,
}

impl<'a> PublicProver<'a> {
    /// Create proof where first `num_public` elements are public
    pub fn prove(&self, witness: &[Fr]) -> Result<PublicProof, IPAError> { /* see src/public_inputs.rs */ }
}

pub struct PublicVerifier<'a> {
    pub params: &'a IPAParams,
    pub num_public: usize,
}

impl<'a> PublicVerifier<'a> {
    pub fn verify(&self, proof: &PublicProof, expected_public: &[Fr]) -> Result<bool, IPAError> { /* ... */ }
}
```

High-level behaviour:

- The witness vector is split into a public prefix and a private suffix.
- The prover pads the witness to length `n = params.n` with zeros and uses a
  fixed `b` vector of all ones, so the IPA proves correct aggregation of the
  full witness.
- `PublicProof::size()` accounts for both the IPA proof and the public-input
  vector (32 bytes per input).
- The verifier first checks that the provided public inputs match the expected
  ones and then delegates to `IPAVerifier::verify_optimized` on the underlying
  `ipa_proof` and `commitment` (hints are checked against recomputed generators).

| n    | Rounds | Proof Size (IPAProofOptimized)  |
|------|--------|---------------------------------|
| 8    | 3      | 332 bytes                       |
| 64   | 6      | 530 bytes                       |
| 256  | 8      | 662 bytes                       |
| 1024 | 10     | 794 bytes                       |

### 3.7 Optimization: Generator Hints (Recap)

Section 4.2 defines `IPAProofOptimized`, which extends the standard IPA proof by
adding two **generator hints** `g_final` and `h_final` (both `CompressedG1`).
Conceptually:

- The standard verifier would reconstruct `G_final` and `H_final` via MSM over
  all generators (`O(n)` operations).
- In the optimized mode, the prover sends these final generators as hints,
  obtained by running the same folding procedure as the verifier.
- The verifier then only needs to check the final relation

  ```text
  P' == a·G' + b·H' + (a·b)·U
  ```

  instead of computing `G'` and `H'` itself.

On larger parameter sets (e.g. `n = 16`), this can reduce verification cost
significantly compared to a naive Bulletproofs-IPA verifier that recomputes the
final generators.
In this repository, IPA verification happens off-chain as part of the IPA adapter.
The on-chain verifier is the packed sumcheck in `contracts/GLYPHVerifier.sol`, so IPA
generator hints are a Rust-only optimization.

---

## 4. Proof Structures

### 4.1 Standard IPA Proof

The BN254 core lives in `src/ipa_bn254.rs`. The BLS12-381 core lives in
`src/ipa_bls12381.rs`. Both use the `CompressedG1` representation:

```rust
pub struct IPAProof {
    pub l_vec: Vec<CompressedG1>,
    pub r_vec: Vec<CompressedG1>,
    pub a: Fr,
    pub b: Fr,
}
```

For `k = log₂(n)` rounds (e.g. `k = 4` for `n = 16`) the proof size is

```text
size_bytes(IPAProof) = 4        // number of rounds (u32)
                        + k · 2 · 33
                        + 2 · 32
                      = 4 + 66·k + 64
```

BLS12-381:
```text
size_bytes(IPAProof) = 4        // number of rounds (u32)
                        + k · 2 · 49
                        + 2 · 32
                      = 4 + 98·k + 64
```

### 4.2 Optimized IPA Proof (with generator hints)

The production variant adds two generator hints used by the Rust optimized
verifier. They are not part of any on-chain calldata format, because IPA proofs
are verified off-chain only:

```rust
pub struct IPAProofOptimized {
    pub l_vec: Vec<CompressedG1>,
    pub r_vec: Vec<CompressedG1>,
    pub a: Fr,
    pub b: Fr,
    /// Pre-computed final G (verifier skips MSM!)
    pub g_final: CompressedG1,
    /// Pre-computed final H
    pub h_final: CompressedG1,
}
```

This yields

```text
size_bytes(IPAProofOptimized) = 4            // number of rounds (u32)
                                 + k · 2 · 33
                                 + 2 · 32     // a,b
                                 + 2 · 33     // g_final, h_final
                               ≈ 4 + 66·k + 64 + 66
```

BLS12-381:
```text
size_bytes(IPAProofOptimized) = 4            // number of rounds (u32)
                                 + k · 2 · 49
                                 + 2 · 32     // a,b
                                 + 2 · 49     // g_final, h_final
                               ≈ 4 + 98·k + 64 + 98
```

### 4.3 Compressed Point Format

`CompressedG1` mirrors the implementation in `src/ipa_bn254.rs` and
`src/ipa_bls12381.rs`. Each G1 point is compressed as follows:

BN254:
- 32 bytes: big-endian x-coordinate
- 1 byte: parity bit of y (`0` for even, `1` for odd)

BLS12-381:
- 48 bytes: big-endian x-coordinate
- 1 byte: parity bit of y (`0` for even, `1` for odd)

BN254 example:
```rust
impl CompressedG1 {
    pub fn to_bytes_compressed(&self) -> [u8; 33] {
        let mut bytes = [0u8; 33];
        let x_bytes = self.0.x.into_bigint().to_bytes_be();
        bytes[0..32].copy_from_slice(&x_bytes);
        let y_is_odd = self.0.y.into_bigint().0[0] & 1 == 1;
        bytes[32] = if y_is_odd { 1 } else { 0 };
        bytes
    }
}
```

---

## 5. Prover Implementation

### 5.1 Core Prover Loop

The core prover in `src/ipa_bn254.rs` is implemented as follows. The BLS12-381 prover in `src/ipa_bls12381.rs` mirrors the same flow with 48-byte field elements and 49-byte compressed points:

```rust
impl<'a> IPAProver<'a> {
    /// Standard IPA proof
    pub fn prove(&self, a: &[Fr], b: &[Fr]) -> Result<(G1Projective, Fr, IPAProof), IPAError> {
        let c = inner_product(a, b);
        // Use optimized MSM (Pippenger on CPU, optionally with SIMD backends)
        let p = pippenger_msm(&self.params.g, a)?
              + pippenger_msm(&self.params.h, b)?
              + self.params.u * c;
        
        let mut a = a.to_vec();
        let mut b = b.to_vec();
        let mut g = self.params.g.clone();
        let mut h = self.params.h.clone();
        
        let mut l_vec = Vec::new();
        let mut r_vec = Vec::new();
        
        let mut transcript = Transcript::new_onchain();
        transcript.append_point(&p.into_affine());
        
        while a.len() > 1 {
            let half = a.len() / 2;
            let (a_lo, a_hi) = (&a[..half], &a[half..]);
            let (b_lo, b_hi) = (&b[..half], &b[half..]);
            let (g_lo, g_hi) = (&g[..half], &g[half..]);
            let (h_lo, h_hi) = (&h[..half], &h[half..]);
            
            let c_l = inner_product(a_lo, b_hi);
            let l = pippenger_msm(g_hi, a_lo)
                  + pippenger_msm(h_lo, b_hi)
                  + self.params.u * c_l;
            
            let c_r = inner_product(a_hi, b_lo);
            let r = pippenger_msm(g_lo, a_hi)
                  + pippenger_msm(h_hi, b_lo)
                  + self.params.u * c_r;
            
            let l_aff = l.into_affine();
            let r_aff = r.into_affine();
            
            l_vec.push(CompressedG1(l_aff));
            r_vec.push(CompressedG1(r_aff));
            
            transcript.append_point(&l_aff);
            transcript.append_point(&r_aff);
            let x = transcript.challenge_scalar();
            let x_inv = invert_challenge(x)?;
            
            a = a_lo.iter().zip(a_hi).map(|(lo, hi)| *lo * x + *hi * x_inv).collect();
            b = b_lo.iter().zip(b_hi).map(|(lo, hi)| *lo * x_inv + *hi * x).collect();
            g = g_lo.iter().zip(g_hi).map(|(lo, hi)| 
                (lo.into_group() * x_inv + hi.into_group() * x).into_affine()
            ).collect();
            h = h_lo.iter().zip(h_hi).map(|(lo, hi)| 
                (lo.into_group() * x + hi.into_group() * x_inv).into_affine()
            ).collect();
        }
        
        Ok((p, c, IPAProof { l_vec, r_vec, a: a[0], b: b[0] }))
    }
}
```

### 5.2 Vector Folding

```rust
fn fold_vectors(lo: &[Fr], hi: &[Fr], x: &Fr) -> Vec<Fr> {
    lo.iter()
      .zip(hi.iter())
      .map(|(l, h)| *l + *x * *h)
      .collect()
}
```

### 5.3 Point Folding

```rust
fn fold_points(lo: &[G1Affine], hi: &[G1Affine], x: &Fr) -> Vec<G1Affine> {
    lo.iter()
      .zip(hi.iter())
      .map(|(l, h)| (*l + h.into_group() * x).into_affine())
      .collect()
}
```

### 5.4 Complexity Analysis

**Per round:**
- 4 MSM operations (size n/2 each)
- 2 inner products (n/2 multiplications each)
- 2n scalar multiplications for folding

**Total (log₂(n) rounds):**
- MSM: O(n log n) scalar multiplications
- Inner products: O(n)
- Folding: O(n log n)

**Dominant cost:** MSM operations

---

## 6. Verifier Implementation

### 6.1 Standard Verification

The verifier mirrors the prover transcript and folding logic and then
recomputes the final generators via MSM:

```rust
impl<'a> IPAVerifier<'a> {
    /// Standard verification (computes MSM - expensive)
    pub fn verify(&self, p: &G1Projective, _c: Fr, proof: &IPAProof) -> Result<bool, IPAError> {
        let mut transcript = Transcript::new_onchain();
        transcript.append_point(&p.into_affine());
        
        let mut challenges = Vec::new();
        let mut p_prime = *p;
        
        for (l, r) in proof.l_vec.iter().zip(proof.r_vec.iter()) {
            transcript.append_point(&l.0);
            transcript.append_point(&r.0);
            
            let x = transcript.challenge_scalar();
            challenges.push(x);
            
            let x_sq = x * x;
            let x_inv_sq = invert_challenge(x_sq)?;
            
            // P' = x²·L + P' + x⁻²·R
            p_prime = l.0.into_group() * x_sq + p_prime + r.0.into_group() * x_inv_sq;
        }
        
        // Expensive MSM to compute final generators
        let (g_final, h_final) = self.compute_final_generators(&challenges);
        let expected = g_final * proof.a
                     + h_final * proof.b
                     + self.params.u * (proof.a * proof.b);
        
        Ok(p_prime == expected)
    }
```

### 6.2 Final Generator Computation

The helper `compute_final_generators` matches the standard Bulletproofs-style
weighting of generators and is the **O(n)** bottleneck in the standard path:

```rust
    fn compute_final_generators(&self, challenges: &[Fr]) -> Result<(G1Projective, G1Projective), IPAError> {
        let n = self.params.n;
        let k = challenges.len();
        
        let mut s_g = vec![Fr::one(); n];
        let mut s_h = vec![Fr::one(); n];
        
        for (j, x) in challenges.iter().enumerate() {
            let x_inv = invert_challenge(*x)?;
            for i in 0..n {
                let bit = (i >> (k - 1 - j)) & 1;
                if bit == 1 {
                    s_g[i] *= *x;
                    s_h[i] *= x_inv;
                } else {
                    s_g[i] *= x_inv;
                    s_h[i] *= *x;
                }
            }
        }
        
        Ok((
            G1Projective::msm(&self.params.g, &s_g).map_err(|_| IPAError::MsmFailed)?,
            G1Projective::msm(&self.params.h, &s_h).map_err(|_| IPAError::MsmFailed)?,
        ))
    }
```

This performs two MSMs of size `n` and therefore dominates verifier cost in the
standard (no-hints) mode.

### 6.3 Optimized Verification (with hints)

The optimized verifier uses prover-supplied hints for the final generators.
These hints are validated in Rust. On-chain verification is handled by the
packed sumcheck in `contracts/GLYPHVerifier.sol` and does not consume IPA hints.

```rust
    /// OPTIMIZED: Uses prover hints and verifies them against recomputed
    /// generators in Rust.
    pub fn verify_optimized(&self, p: &G1Projective, _c: Fr, proof: &IPAProofOptimized) -> Result<bool, IPAError> {
        let mut transcript = Transcript::new_onchain();
        transcript.append_point(&p.into_affine());
        
        let mut challenges = Vec::new();
        let mut p_prime = *p;
        
        // Fold the commitment using L, R values
        for (l, r) in proof.l_vec.iter().zip(proof.r_vec.iter()) {
            transcript.append_point(&l.0);
            transcript.append_point(&r.0);
            
            let x = transcript.challenge_scalar();
            challenges.push(x);
            
            let x_sq = x * x;
            let x_inv_sq = invert_challenge(x_sq)?;
            
            // P' = x² * L + P + x⁻² * R
            p_prime = l.0.into_group() * x_sq + p_prime + r.0.into_group() * x_inv_sq;
        }
        
        // OPTIMIZATION: Verify hints are correct
        let g_hint = proof.g_final.0.into_group();
        let h_hint = proof.h_final.0.into_group();
        
        // Recompute final generators from challenges and ensure they
        // match the prover-supplied hints.
        let (g_calc, h_calc) = self.compute_final_generators(&challenges)?;
        if g_calc != g_hint || h_calc != h_hint {
            return Ok(false);
        }

        // Check: P' == a * G' + b * H' + (a*b) * U
        let expected = g_hint * proof.a
                     + h_hint * proof.b
                     + self.params.u * (proof.a * proof.b);
        if p_prime != expected {
            return Ok(false);
        }

        Ok(true)
    }
```

For integration with accumulation schemes there is a more aggressive
variant:

```rust
    /// Trusts hints completely (for use with accumulation schemes)
    pub fn verify_with_trusted_hints(
        &self,
        p: &G1Projective,
        proof: &IPAProofOptimized,
    ) -> Result<bool, IPAError> {
        // Same folding loop as above, then:
        let ab = proof.a * proof.b;
        let expected = shamir_triple_mul(
            &proof.a, &proof.g_final.0,
            &proof.b, &proof.h_final.0,
            &ab, &self.params.u
        );
        Ok(p_prime == expected)
    }
```

### 6.4 Packed Verifier Gas Measurements

The packed-128 layout changed calldata size and execution costs. Re-run the
Foundry and Anvil benches to refresh gas numbers:
- `scripts/tests/foundry/GeneratedRealProofTest.t.sol`
- `scripts/tests/foundry/GLYPHVerifierTest.t.sol`

Benchmark outputs are written under `scripts/out/benchmarks/` when run and are not committed.
Use Section 14.2.1 receipts as the canonical gas evidence.

---

## 7. Hardware Acceleration

### 7.1 SIMD Operations (glyph_field_simd.rs)

#### 7.1.1 Backend Detection

```rust
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SimdBackend {
    Cuda,
    Avx512,
    Avx2,
    Neon,
    Scalar,
}

impl SimdBackend {
    pub fn detect() -> Self {
        let cpu = SimdBackend::detect_cpu();
        #[cfg(all(feature = "cuda", any(target_os = "linux", target_os = "windows")))]
        {
            let prefer_cuda = std::env::var("GLYPH_CUDA")
                .ok()
                .as_deref()
                .map(|v| v != "0")
                .unwrap_or(false);
            if prefer_cuda && cuda_backend::available() {
                return SimdBackend::Cuda;
            }
        }
        cpu
    }

    pub fn detect_cpu() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            if is_x86_feature_detected!("avx512f") && is_x86_feature_detected!("avx512dq") {
                return SimdBackend::Avx512;
            }
            if is_x86_feature_detected!("avx2") {
                return SimdBackend::Avx2;
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            if std::arch::is_aarch64_feature_detected!("neon") {
                return SimdBackend::Neon;
            }
        }
        SimdBackend::Scalar
    }
}
```

The prover selects the first compatible backend at runtime:
- AVX-512 if available
- AVX2 otherwise
- NEON on ARM
- Scalar fallback if no SIMD is supported

CUDA backends are feature-gated and must be explicitly enabled; see Section 7.4.

#### 7.1.2 Goldilocks SIMD Ops

Key SIMD functions are defined in `src/glyph_field_simd.rs`:
- `goldilocks_add_batch`
- `goldilocks_sub_batch`
- `goldilocks_mul_batch`
- `goldilocks_scalar_mul_batch_into`
- `goldilocks_sum`
- `goldilocks_sum_strided`
- `goldilocks_inner_product`

These functions operate on packed `u64` arrays and apply modular reduction per element.
SIMD codepaths are validated in `goldilocks_tests` within the same module.

#### 7.1.3 SIMD Invariants

- All inputs must be reduced mod `p = 2^64 - 2^32 + 1` (Goldilocks).
- SIMD reductions are applied after each vector operation.
- SIMD chunking uses backend-specific Rayon chunk sizes defined in `src/glyph_field_simd.rs`.

### 7.2 Parallel MSM and GLV

High-performance MSM and scalar multiplication kernels live in:
- `src/ipa_bn254.rs` (Pippenger MSM and IPA primitives)
- `src/glv.rs`

Key properties:
- Pippenger window sizes adapt to vector length.
- GLV decomposition is used for BN254 (for speed, with simplified assumptions).
- Off-chain proofs always validate against canonical curve arithmetic.

### 7.3 CUDA Backends

CUDA is implemented for selected hot paths:
- Goldilocks batch arithmetic (add, sub, mul, sum, inner product)
- Sumcheck layer evaluation and LogUp product trees
- PCS column combinations
- Keccak row hashing and Merkle level hashing (batch Keccak)
- BN254 batch add, sub, mul (adapter kernels)

CUDA is **disabled by default**. Enable by setting:
- `GLYPH_CUDA=1`
- Ensure `cargo build --features cuda` (or preset `cuda`) is used.

CUDA tests and KPI runs are explicitly opt-in and must be executed on a CUDA host.

### 7.4 CUDA Configuration

Control CUDA thresholds and engagement with:
- `GLYPH_CUDA_MIN_ELEMS` (Goldilocks)
- `GLYPH_CUDA_BN254_MIN_ELEMS` (BN254 batch kernels)
- `GLYPH_ACCEL_PROFILE=cuda` (sets recommended CUDA defaults)

CUDA benchmarks:
- `scripts/benchmarks/bench_glyph_cuda_kpi.sh`
- `src/bin/bench_glyph_cuda_kpi.rs`

CUDA toolchain check:
- `scripts/utils/cuda/check_cuda_toolkit.sh`

---

## 8. Solidity Verifier

The packed on-chain verifier is the Solidity contract:
- `contracts/GLYPHVerifier.sol`

Key properties:
- Stateless `fallback()` verifier (no selector, no storage).
- Packed calldata: 64-byte header + 32 bytes per round.
- Field: `p = 2^128 - 159`.
- All inputs are checked for canonical field bounds and calldata length.
- Assembly flow is documented in phased comment blocks inside the verifier and its Foundry mirror.

### 8.1 Calldata Layout (Packed)

Header:
- `artifact_tag: bytes32`
- `claim128 || initial_claim` packed as two 16-byte big-endian values

Rounds:
- `c0 || c1` (2 x 16-byte big-endian field elements)
- `c2` recovered from the arity-8 constraint using `inv(140)`

### 8.2 On-Chain Binding Checks

The verifier:
- Binds to `artifact_tag`, `claim128`, `initial_claim`.
- Computes `r0 = keccak256(chainid || address(this) || artifact_tag || claim128 || initial_claim) mod p`.
- Enforces the artifact-defined final check:
  `expected_final = (lin_0 + claim128 + eval_lin)^2`.

---

## 9. Module Reference

### 9.1 Core Modules

| Module              | Purpose                      | Key Functions                                                                                                                   |
|---------------------|------------------------------|---------------------------------------------------------------------------------------------------------------------------------|
| `glyph_core`        | Core prover orchestration    | `prove_universal`, `prove_compiled`, `encode_packed_gkr_calldata`                                                               |
| `glyph_ir_compiler` | UCIR compiler                | `compile_groth16_bn254`, `compile_kzg_bn254`, `compile_ivc`, `compile_binius`, `compile_stark`, `compile_stark_with_validation` |
| `glyph_gkr`         | Packed GKR prover & encoder  | `prove_packed`, `encode_packed_calldata_be`                                                                                     |
| `glyph_pcs_basefold`| BaseFold PCS wrapper         | `commit_zk_owned`, `verify_opening`, `eval_point_from_sumcheck_challenges`                                                      |
| `glyph_logup`       | LogUp products and lookups   | `prove_logup`, `verify_logup`, `logup_constraint_evals_into`                                                                    |

### 9.2 Adapter Modules

| Module           | Purpose                | Key Functions                                                                                                                                                                           |
|------------------|------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `adapter_ir`     | Adapter IR kernel path | `execute_hash_sha3_merge_ir`, `execute_groth16_bn254_ir`, `execute_groth16_bn254_ir_batch`, `execute_kzg_bn254_ir`, `execute_kzg_bn254_ir_batch`, `execute_ivc_ir`, `execute_binius_ir` |
| `ivc_adapter`    | IVC folding adapter    | `derive_glyph_artifact_from_ivc`                                                                                                                                                        |
| `ipa_adapter`    | IPA adapter            | `derive_glyph_artifact_from_ipa_receipt`                                                                                                                                                |
| `binius_adapter` | Binius adapter         | `derive_glyph_artifact_from_binius_receipt`                                                                                                                                             |
| `sp1_adapter`    | SP1 adapter            | `verify_sp1_receipt`, `derive_glyph_artifact_from_sp1_receipt`                                                                                                                          |
| `plonk_adapter`  | PLONK adapter          | `verify_plonk_receipt`, `derive_glyph_artifact_from_plonk_receipt`                                                                                                                      |

### 9.3 Utility and Integration Modules

| Module                        | Purpose                                                     | Key Functions                                                                                                                                                                                                                                                                        |
| ----------------------------- | --------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `precomputed`                 | Precomputed generator tables                        | `PrecomputedTable::new()`, `IPAGeneratorTables::new()`                                                                                                                                       |
| `e2e_proofs`                  | Solidity test proof generation                      | `generate_solidity_test_file()`, `generate_glyph_snark_*_solidity_test_file()`                                                                                                               |
| `glyph_gkr`                   | Packed sumcheck prover and calldata encoder         | `prove_packed()`, `prove_packed_toy_sumcheck*()`, `prove_packed_stmt_poly_sumcheck()`                                                                                                        |
| (cont.)                       |                                                     | `encode_packed_calldata_be()`, `encode_packed_calldata_be_truncated()`, `encode_stmt_poly_bound_packed_calldata_be()`, `verify_packed_calldata_be()`, `verify_stmt_poly_packed_calldata_be()`|
| `pcs_common`                  | PCS domains and tag helpers                         | `PCS_COMMIT_DOMAIN`, `PCS_POINT_TAG_DOMAIN`, `PCS_SALT_DOMAIN`, `pcs_salt_commitment()`, `derive_point_tag()`                                                                                |
| `glyph_basefold`              | BaseFold folding helpers                            | `derive_basefold_root()`, `derive_basefold_alpha()`, `derive_basefold_weights()`                                                                                                             |
| `arena`                       | Bump arena for scratch buffers                      | `Arena::with_capacity()`, `Arena::alloc_slice()`, `Arena::reset()`                                                                                                                           |
| `glyph_bn254_field`           | BN254 to Goldilocks embedding and mod ops           | `EmbeddedFq`, `add_mod()`, `sub_mod()`, `mul_mod()`                                                                                                                                          |
| `stwo_bundle`                 | Stwo receipt bundle decoder                         | `StwoReceiptBundle`, `decode()`, `into_receipt_and_program()`                                                                                                                                |
| `adapters`                    | Adapter profiles and digest helpers                 | `AdapterFamily`, `keccak256()`, `vk_hash_from_bytes()`, profile functions                                                                                                                    |
| `adapter_ir`                  | Adapter IR for non-STARK families                   | `AdapterIr`, `kernel_id::*`, `execute_hash_sha3_merge_ir()`, `execute_groth16_bn254_ir()`                                                                                                    |
| (cont.)                       |                                                     | `execute_groth16_bn254_ir_batch()`, `execute_kzg_bn254_ir()`, `execute_kzg_bn254_ir_batch()`, `execute_ivc_ir()`, `execute_binius_ir()`                                                      |
| `stark_adapter`               | STARK adapter entrypoint                            | `verified_canonical_stark_receipts_to_glyph_artifact()`                                                                                                                                      |
| `snark_groth16_bn254_adapter` | Groth16 BN254 adapter                               | `derive_glyph_artifact_from_groth16_bn254()`                                                                                                                                                 |
| `snark_kzg_bn254_adapter`     | KZG BN254 adapter                                   | `derive_glyph_artifact_from_kzg_bn254()`                                                                                                                                                     |
| `groth16_bls12381`            | Groth16 BLS12-381 receipt verification              | `derive_glyph_artifact_from_groth16_bls12381_receipt()`                                                                                                                                      |
| `kzg_bls12381`                | KZG BLS12-381 receipt verification                  | `derive_glyph_artifact_from_kzg_bls12381_receipt()`                                                                                                                                          |
| `ivc_adapter`                 | IVC or folding adapter                              | `BaseFoldPcsOpeningProof`, `NovaFoldingProof`, `SuperNovaProof`, `HyperNovaProof`, `SangriaProof`                                                                                            |
| `ipa_adapter`                 | IPA BN254 adapter                                   | `derive_glyph_artifact_from_ipa_receipt()`                                                                                                                                                   |
| `binius_adapter`              | Binius adapter                                      | `derive_glyph_artifact_from_binius_receipt()`                                                                                                                                                |
| `sp1_adapter`                 | SP1 Groth16 or Plonk adapter                        | `Sp1Receipt`, `verify_sp1_receipt()`, `derive_glyph_artifact_from_sp1_receipt()`                                                                                                             |
| `plonk_adapter`               | PLONK adapter for gnark, dusk, halo2                | `PlonkReceipt`, `verify_plonk_receipt()`, `derive_glyph_artifact_from_plonk_receipt()`                                                                                                       |
| `halo2_receipt`               | Halo2 KZG receipts                                  | `Halo2Receipt`, `verify_halo2_receipt()`, `derive_glyph_artifact_from_halo2_receipt()`                                                                                                       |
| `circle_stark`                | Circle STARK verifier for M31, BabyBear, KoalaBear  | `CircleStarkProfile`, `CircleStarkProgram`, `verify_circle_stark_receipt()`                                                                                                                  |
| `cairo_stark`                 | Cairo STARK verifier                                | `CairoStarkProgram`, `verify_cairo_receipt()`, `parse_cairo_receipt_from_json()`                                                                                                             |
| `miden_stark`                 | Miden STARK verifier                                | `MidenStarkProgram`, `verify_miden_receipt()`                                                                                                                                                |
| (cont.)                       |                                                     |  Goldilocks, Blake3-192 or 256, RPO256, RPX256, Poseidon2, no precompile requests                                                                                                            |
| `plonky3_stark`               | Plonky3 STARK verifier                              | `Plonky3StarkProgram`, `verify_plonky3_receipt()`                                                                                                                                            |
| (cont.)                       |                                                     |  BabyBear, KoalaBear, Goldilocks, M31, Keccak required for M31                                                                                                                               |
| `stwo_verifier`               | Stwo commitment-scheme verifier for M31 + Blake2s   | `StwoProfile`, `StwoProgram`, `verify_stwo_receipt()`                                                                                                                                        |
| `standard_stark`              | Standard FRI STARK verifier for BabyBear            | `verify_standard_stark_receipt()`                                                                                                                                                            |
| `bn254_pairing`               | BN254 limb arithmetic for adapter kernels           | `FqElem`, `Fq2Elem`, `Fq12Elem`, `pairing_product_is_one()`                                                                                                                                  |


**Circle STARK Field IDs (from `src/circle_stark.rs`):**
- `FIELD_M31_CIRCLE_ID = 0x03`
- `FIELD_BABY_BEAR_CIRCLE_ID = 0x04`
- `FIELD_KOALA_BEAR_CIRCLE_ID = 0x06`
- Constraint types: `CONSTRAINT_CUBE_PLUS_CONST`, `CONSTRAINT_LINEAR_MIX`, `CONSTRAINT_MUL_PLUS_CONST`, `CONSTRAINT_LINEAR_COMBO`, `CONSTRAINT_MUL_ADD`

**Stwo Verifier IDs (from `src/stwo_verifier.rs`):**
- `HASH_BLAKE2S_ID = 0x03`
- `VC_MERKLE_ID = 0x01`
- `STWO_TOOLCHAIN_ID = 0x5354` (ASCII "ST")

| Module                | Purpose                                    | Key Functions                                                                                 |
|-----------------------|--------------------------------------------|-----------------------------------------------------------------------------------------------|
| `bn254_groth16`       | Groth16 parsing and verification for BN254 | `Groth16Proof`, `Groth16VerifyingKey`, `verify_groth16_proof()`                               |
| `glyph_basefold`      | BaseFold helpers for folding weights       | `derive_basefold_root()`, `derive_basefold_alpha()`, `derive_basefold_weights()`              |
| `glyph_pairing`       | High-level pairing kernel for GLYPH-Prover | `verify_groth16()`, `verify_kzg()`, `pairing_product_is_one()`                                |
| `bn254_pairing_trace` | BN254 Groth16 pairing trace recorder       | `FqElem`, `Fq2Elem`, `Fq6Elem`, `Fq12Elem`                                                    |
| (cont.)               |                                            | `G1Affine`, `G2Affine`, `G1WnafPrecomp`                                                       |

**BN254 Pairing Trace (from `src/bn254_pairing_trace.rs`):**
- `FqElem`, `Fq2Elem`, `Fq6Elem`, `Fq12Elem` - tower extension field types
- `G1Affine`, `G2Affine`, `G1Jacobian`, `G2Jacobian` - curve point types
- `G1WnafPrecomp` - wNAF precomputation tables for EC scalar mul
- Environment variables: `GLYPH_BN254_FIXED_BASE_PRECOMP`, `GLYPH_BN254_KZG_JOINT_MSM`, `GLYPH_BN254_TRACE_VALIDATE_BATCH`

---


## 10. Security Analysis

The GLYPH security model relies on the soundness of the GLYPH Packed Sumcheck protocol and the binding of the BaseFold PCS.

**Key Properties:**
- **128-bit Security:** Targeted via field size (Goldilocks/BN254 scalar) and repetition parameters.
- **Fiat-Shamir:** Transcript uses Keccak-256 with 128-bit truncation for challenges.
- **Binding:** The artifact is cryptographically bound to the commitment and claim.
- **No Trusted Setup:** The core protocol (Sumcheck + BaseFold) is transparent.

For the definitive security model and constraints, see the remainder of this section.

---

## 11. GLYPH Adapters and Integration

This section describes how the GLYPH prover, adapters and Solidity
verifier work together as a complete system. The goal is that an
external user can plug in the prover and verifier without reading the
entire codebase.

### 11.0 GLYPH-PROVER Universal Off-Chain Pipeline

GLYPH-PROVER is the default universal off-chain prover core for adapters.
It is the only production path and integrates the packed GKR prover into a single pipeline.

Key properties:
- **Inputs**: adapter-specific proofs and statements (all adapter families) compiled into GLYPH-IR.
- **Core**: GLYPH-IR compilation, streaming witness, LogUp lookups, Sumcheck, and BaseFold PCS (binary tower).
- **PCS Constants**:
  - BaseFold PCS domains (GLYPH): `DOMAIN_PCS_BASEFOLD_COMMIT`, `DOMAIN_PCS_BASEFOLD_OPEN`, `DOMAIN_PCS_RING_SWITCH`, `DOMAIN_PCS_ZK_MASK`.
  - PCS binding domains (shared helpers, BaseFold path):
    - `PCS_COMMIT_DOMAIN = "GLYPH_PCS_COMMIT"`
    - `PCS_POINT_TAG_DOMAIN = "GLYPH_PCS_POINT_TAG"`
    - `PCS_SALT_DOMAIN = "GLYPH_PCS_SALT"` (ZK mode)

- **Outputs**: GLYPH artifact `(commitment_tag, point_tag, claim128)` plus packed GKR calldata.
- **On-chain**: `contracts/GLYPHVerifier.sol` (product name: GLYPH-VERIFIER).
- **Modes**: `fast-mode` and `zk-mode` share identical calldata layout. `zk-mode` uses salted PCS commitments and mask rows, and it redacts off-chain openings and LogUp data from the public output.
- **ZK tuning**: `GLYPH_PCS_MASK_ROWS` sets the number of mask rows for zk-mode (default: 1).
- **GPU**: optional CUDA backend under the `cuda` feature flag, enabled via `GLYPH_CUDA=1` on Linux or Windows hosts. GPU covers Goldilocks batch add, sub, mul, scalar mul, sum, inner product, sumcheck layers, LogUp product trees, PCS column combinations, Keccak row hashing with Merkle level hashing via batch Keccak, plus BN254 batch add, sub, and mul. Use `GLYPH_CUDA_MIN_ELEMS` to tune Goldilocks CUDA thresholds and `GLYPH_CUDA_BN254_MIN_ELEMS` for BN254 batch thresholds.
  - KPI harness: `src/bin/bench_glyph_cuda_kpi.rs` with `scripts/benchmarks/bench_glyph_cuda_kpi.sh` (disabled by policy; set `GLYPH_ENABLE_CUDA_BENCH=1` to run).
- ZK proof-size KPI: `src/bin/bench_glyph_zk_kpi.rs` with `scripts/benchmarks/bench_glyph_zk_kpi.sh` (fast-mode vs zk-mode size breakdown, writes `scripts/out/benchmarks/glyph_zk_kpi.json`).
    - Use `GLYPH_ZK_KPI_REPEAT` to scale the number of hash merge gates in the UCIR workload.
    - Output JSON includes: `kpi`, `seed`, `repeat`, `chainid`, `contract`, `input_digest`, plus `fast` and `zk` objects with `artifact_bytes`, `pcs_commitment_bytes`, `pcs_rho_bytes`, `pcs_salt_bytes`, `pcs_opening_bytes`, `logup_bytes`, `sumcheck_rounds_bytes`, `sumcheck_challenges_bytes`, `final_eval_bytes`, `packed_gkr_bytes`, `packed_calldata_bytes`, and `total_offchain_bytes`.
    - Set `OUT_FILE` to emit alternate outputs (for example, `OUT_FILE=scripts/out/benchmarks/glyph_zk_kpi_large.json` with `GLYPH_ZK_KPI_REPEAT=64`).

KPI outputs are written under `scripts/out/benchmarks/` when run and are not committed.
Run the KPI scripts above to capture current sizes.

The canonical design and module list live in `docs/documentation.md` and `docs/map.md`.

### 11.1 Core Prover API (src/ipa_bn254.rs)

The core prover and verifier live in `src/ipa_bn254.rs`.

- `IPAParams` encapsulates the public parameters:
  - `g: Vec<G1Affine>` and `h: Vec<G1Affine>` are generator vectors.
  - `u: G1Affine` is the Pedersen blinding generator.
  - `n: usize` is the vector length.
- `IPAProver` and `IPAVerifier` implement the standard and optimized
  Bulletproofs IPA protocols on BN254.
  These IPA routines are used **off-chain only** by the IPA adapter. The on-chain
  verifier is the packed sumcheck in `contracts/GLYPHVerifier.sol` and does not
  verify IPA proofs or depend on IPA parameter sizes.

For arbitrary `n` (must be a power of two):

- `IPAParams::new(n)` derives generators using `hash_to_g1_indexed`
  with a fixed domain-separated hash-to-curve construction.
- `IPAProver::prove(a, b)` and `prove_optimized(a, b)` both enforce
  `a.len() == b.len() == params.n` at runtime. This guarantees that the
  inner-product instance matches the parameter set.

### 11.2 Public Input Adapter (src/public_inputs.rs)

The module `src/public_inputs.rs` extends the prover and verifier with
explicit public inputs to avoid the “what is being proven?” gap:

- `PublicProof` contains:
  - `public_inputs: Vec<Fr>` – values known to the verifier.
  - `ipa_proof: IPAProofOptimized` – the underlying IPA proof.
  - `commitment: G1Projective` – the commitment to the full witness.
- `PublicProver` takes a witness vector and a configured
  `num_public` and:
  - Splits `witness[..num_public]` as public inputs.
  - Pads the witness to `params.n` with zeros.
  - Uses a fixed all-ones vector `b` to turn the witness into an
    inner product.
  - Produces a `PublicProof` via `IPAProver::prove_optimized`.
- `PublicVerifier` checks:
  - That the public inputs in the proof match the expected vector.
  - That the IPA proof verifies under the same parameters using
    `IPAVerifier::verify_optimized` (which fully verifies the
    generator hints in Rust).

This adapter is intended for higher-level systems (e.g. circuit or
constraint-layer adapters) that need to bind explicit public state to
the inner-product proof.

A minimal usage example in Rust looks like this:

```rust
use glyph::ipa_bn254::IPAParams;
use glyph::public_inputs::{PublicProver, PublicVerifier};

fn public_inputs_roundtrip() {
    let n = 16;
    let num_public = 4;

    let params = IPAParams::new(n);
    let prover = PublicProver { params: &params, num_public };
    let verifier = PublicVerifier { params: &params, num_public };

    // Witness layout: first num_public entries are public, rest private
    let witness: Vec<Fr> = /* ... fill with field elements ... */;

    let proof = prover.prove(&witness);

    // Verifier receives the expected public inputs explicitly
    let ok = verifier.verify(&proof, &witness[..num_public]);
    assert!(ok, "public input binding failed");
}

### 11.5 Solidity Verifier Interface

The production on-chain interface is `contracts/GLYPHVerifier.sol`. It is a packed sumcheck verifier with a fallback entry point (no selector). The calldata header is minimal and there is no separate `verifyBound` function.

### 11.5.1 Packed Header and Chain Binding

Header fields (64 bytes):
- `artifact_tag` (keccak256(commitment_tag || point_tag))
- `claim128 || initial_claim` (two 16-byte values packed into one 32-byte word)

Chain binding is enforced via the initial Fiat-Shamir challenge:
```
r0 = keccak256(chainid || address(this) || artifact_tag || claim128 || initial_claim) mod p
```
`claim128` and `initial_claim` are hashed as 16-byte big-endian values, in the order shown above.

The chain binding enforces replay protection (chainid and contract address) and ties the packed proof to the artifact boundary via `artifact_tag`. Adapter digests are computed off-chain and mapped into `(commitment_tag, point_tag, claim128)` via the GLYPH-Prover pipeline, and `artifact_tag = keccak256(commitment_tag || point_tag)` is encoded on-chain.

**Scalar canonicality (non-malleability):** Adapter parsers enforce canonical field encodings, and `claim128` is constrained on-chain to fit in 128 bits.

**Family IDs:**
| ID | Family                                                                | Domain Tag                                           |
|----|-----------------------------------------------------------------------|------------------------------------------------------|
| 1  | Hash (Keccak merge)                                                   | `keccak256("GLYPH_ADAPTER_HASH")`                    |
| 2  | SNARK (Groth16, KZG, PLONK, Halo2-KZG, IPA-BN254, SP1)                | `keccak256("GLYPH_ADAPTER_SNARK")`                   |
| 3  | STARK Goldilocks (Winterfell F64, Plonky2, Miden, Plonky3-Goldilocks) | `keccak256("GLYPH_ADAPTER_STARK_GOLDILOCKS")`        |
| 4  | STARK BabyBear (Circle, Plonky3-BabyBear or KoalaBear, RISC Zero)     | `keccak256("GLYPH_ADAPTER_STARK_BABYBEAR")`          |
| 5  | STARK M31 (Cairo, Stwo, Circle M31, Plonky3-M31)                      | `keccak256("GLYPH_ADAPTER_STARK_M31")`               |
| 6  | IVC/Folding (BaseFold, Nova, SuperNova, HyperNova, Sangria)           | `keccak256("GLYPH_ADAPTER_IVC")`                     |
| 7  | Binius (native M3 proofs)                                             | `keccak256("GLYPH_ADAPTER_BINIUS")`                  |

**SNARK sub-ids (inside family 2):**
- `0x01`: Groth16 BN254
- `0x02`: KZG BN254
- `0x03`: PLONK
- `0x04`: Halo2 KZG
- `0x05`: IPA BN254
- `0x06`: SP1
- `0x07`: IPA BLS12-381

**Adapter IR (non-STARK):**
- Canonical Adapter IR lives in `src/adapter_ir.rs` and provides strict decoding.
- Batch IR entrypoints for Groth16 BN254 and KZG BN254 live in `src/adapter_ir.rs` (`execute_groth16_bn254_ir_batch`, `execute_kzg_bn254_ir_batch`). They share parsed VK bytes across items and produce a GLYPH proof per item from the compiled pairing trace.
- Kernel identifiers defined in `src/adapter_ir.rs` (`adapter_ir::kernel_id`): `HASH_SHA3_MERGE`, `GROTH16_BN254_VERIFY`, `KZG_BN254_VERIFY`, `IVC_VERIFY`, `IPA_VERIFY`, `STARK_VERIFY`, `BINIUS_VERIFY`, `WINTERFELL_SHA3_TRANSCRIPT`, `CIRCLE_STARK_TRANSCRIPT`.
- Adapter IR entrypoints exist for Hash, Groth16 BN254 (single and batch), KZG BN254 (single and batch), IVC, and Binius. IPA and STARK receipts use UCIR custom gates rather than Adapter IR entrypoints.
- Groth16 BN254 and KZG BN254 compile into UCIR and are proven via GLYPH-PROVER pairing trace gates.
- SNARK receipts compiled via custom gates include IPA (BN254 and BLS12-381), PLONK, Halo2 KZG, SP1, plus the BLS12-381 Groth16 and KZG receipts (`CUSTOM_GATE_IPA_VERIFY`, `CUSTOM_GATE_PLONK_VERIFY`, `CUSTOM_GATE_SP1_VERIFY`, `CUSTOM_GATE_GROTH16_BLS12381_VERIFY`, `CUSTOM_GATE_KZG_BLS12381_VERIFY`).
- IVC, STARK, and Binius compile into UCIR via custom gates (`CUSTOM_GATE_IVC_VERIFY`, `CUSTOM_GATE_STARK_VERIFY`, `CUSTOM_GATE_BINIUS_VERIFY`) and verify canonical receipts inside GLYPH-Prover.
- Canonical Groth16 BN254 and KZG BN254 vk and statement byte helpers live in `src/adapters.rs` (hash-based layouts, with optional precomputed VK bytes that embed G2 Miller loop coefficients for Groth16 beta/gamma/delta and KZG g2_s).
- On-chain vectors for Groth16 and KZG are generated by `src/e2e_proofs.rs` and stored in:
  - `scripts/tests/foundry/GLYPH_SNARK_GROTH16_Test.t.sol`
  - `scripts/tests/foundry/GLYPH_SNARK_KZG_Test.t.sol`

### 11.5.1 Adapter Compatibility Matrix (Pinned Tooling)

All adapter dependencies are pinned via `Cargo.toml` plus exact `Cargo.lock` sources.

| Adapter             | Upstream verifier or crate                     | Pinned version                                                  | Receipt or proof format                         |
|---------------------|------------------------------------------------|-----------------------------------------------------------------|-------------------------------------------------|
| Groth16 BN254       | `ark-groth16`, `ark-bn254`                     | 0.4.0                                                           | vk bytes + proof bytes + public inputs          |
| Groth16 BLS12-381   | `ark-groth16`, `ark-bls12-381`                 | 0.4.0                                                           | vk bytes + proof bytes + public inputs          |
| KZG BN254           | `gnark-bn254-verifier`                         | 1.0.2                                                           | gnark-compatible KZG proof and vk bytes         |
| PLONK BLS12-381     | `dusk-plonk`, `dusk-bls12_381`                 | 0.21.0, 0.14.2                                                  | dusk-plonk proof and vk bytes                   |
| Halo2 KZG           | `halo2_proofs`                                 | git `198e9ae30d322cd0ad003b6955f91ec095b1490d`                  | halo2 receipt bytes                             |
| SP1                 | `sp1-verifier`                                 | 5.2.4                                                           | SP1 canonical receipt                           |
| Winterfell STARK    | `winterfell`                                   | 0.13.1                                                          | canonical Winterfell receipt                    |
| Miden STARK         | `miden-verifier`                               | 0.20.2                                                          | canonical Miden receipt                         |
| Cairo STARK         | `swiftness`                                    | 1.0.0                                                           | Starknet-with-Keccak Stone v6 receipts          |
| Stwo STARK          | `stwo`                                         | git `0b8128669e91eb032b6c9f62766d6a49da4f2e64` (`vendor/stwo`)  | canonical Stwo receipt                          |
| Plonky2 STARK       | `plonky2`                                      | 0.2.2                                                           | canonical Plonky2 receipt                       |
| Plonky3 STARK       | `p3-*` crates                                  | 0.4.2                                                           | canonical Plonky3 receipt                       |
| Nova IVC            | `nova-snark`                                   | 0.43.0                                                          | canonical IVC receipt                           |
| Binius              | `binius_*`                                     | git `47675e19c86c0fb676f75437073a77af8e337938` (`vendor/binius`)| canonical Binius receipt                        |

Version sources should be verified against `Cargo.lock` for audit trails.

### 11.5.1.1 Adapter Trust Evidence Pack (Reviewer Ready)

This section consolidates adapter correctness evidence, fail-closed behavior, and reproducible checks.
It is the reviewer entry point for adapter trust. The trust boundary and assumptions are defined in
Section 11.5.2 and the Trust Matrix in Section 11.5.3.1.

#### Adapter Families and Trustless Status (Summary)
- Trustless (transparent): IVC/Folding, IPA, Binius, STARK, Hash.
- Preserves trusted setup: Groth16, KZG, PLONK/Halo2 KZG, SP1.
- See Section 11.5.3.1 for the full trust matrix and upstream assumptions.

#### Evidence Matrix (Adapters to Tests, Fuzz, Fixtures)

**Groth16, KZG (BN254, BLS12-381)**
- Fixtures or vectors: `scripts/tools/fixtures/groth16_bn254_fixture.txt`, `scripts/tools/fixtures/groth16_bls12381_receipt.txt`, `scripts/tools/fixtures/kzg_bls12381_receipt.txt`
- Tests (Rust and Foundry): `scripts/tests/rust/differential_receipt_verification.rs`, `scripts/tests/rust/ucir_compiler_equivalence.rs`, `src/adapters.rs` byte tamper tests, `scripts/tests/rust/adapter_error_semantics.rs`, `scripts/tests/rust/ir_compiler_boundary_tests.rs`
- Fuzz coverage: `decode_adapter_bytes`, `decode_adapter_ir_deep`, `diff_adapter_ir_roundtrip`, `verify_adapter_proof`

**PLONK, Halo2 KZG**
- Fixtures or vectors: `scripts/tools/fixtures/plonk_bn254_gnark_receipt.txt`, `scripts/tools/fixtures/plonk_bls12381_receipt.txt`, `scripts/tools/fixtures/halo2_bn254_kzg_receipt.txt`, `scripts/tools/fixtures/halo2_bls12381_kzg_receipt.txt`
- Tests (Rust and Foundry): `scripts/tests/rust/differential_receipt_verification.rs`, `scripts/tests/rust/ucir_compiler_equivalence.rs`, `scripts/tests/rust/adapter_error_semantics.rs`, `scripts/tests/rust/ir_compiler_boundary_tests.rs`, `scripts/tests/foundry/GLYPH_SNARK_PLONK_Test.t.sol`
- Fuzz coverage: `decode_adapter_ir_deep`, `diff_adapter_ir_roundtrip`

**IPA**
- Fixtures or vectors: `scripts/tests/foundry/GLYPH_SNARK_IPA_Test.t.sol` (generated vectors)
- Tests (Rust and Foundry): `scripts/tests/rust/adapter_error_semantics.rs`, `scripts/tests/rust/ir_compiler_boundary_tests.rs`, `src/e2e_proofs.rs` export tests
- Fuzz coverage: `decode_adapter_ir_deep`, `diff_adapter_ir_roundtrip`

**SP1 (Groth16, Plonk receipts)**
- Fixtures or vectors: `scripts/tools/fixtures/sp1_groth16_receipt.txt`, `scripts/tools/fixtures/sp1_plonk_receipt.txt`
- Tests (Rust and Foundry): `scripts/tests/rust/differential_receipt_verification.rs`, `scripts/tests/rust/ucir_compiler_equivalence.rs`, optional vectors in `scripts/tests/foundry/GLYPH_SNARK_SP1_Test.t.sol`
- Fuzz coverage: `decode_adapter_ir_deep`, `diff_adapter_ir_roundtrip`

**IVC/Folding**
- Fixtures or vectors: `scripts/tests/foundry/GLYPH_IVC_Test.t.sol` (generated vectors)
- Tests (Rust and Foundry): `src/adapters.rs` IVC byte tamper tests, `src/e2e_proofs.rs` `test_ivc_tamper_rejects`, Foundry vectors from `src/e2e_proofs.rs`, `scripts/tests/rust/ivc_supernova_tests.rs` (feature `ivc-supernova`)
- Fuzz coverage: `decode_adapter_ir_deep`, `diff_adapter_ir_roundtrip`, `verify_adapter_proof`, `decode_r1cs_receipt`, `decode_supernova_external_proof`

**STARK (Winterfell, Miden, Cairo, Stwo, Plonky2, Plonky3, Circle)**
- Fixtures or vectors: `scripts/tools/fixtures/fast_sha3_receipt.txt`, `scripts/tools/fixtures/miden_rpo_receipt.txt`, `scripts/tools/fixtures/miden_blake3_receipt.txt`, `scripts/tools/fixtures/cairo_stone6_keccak_160_lsb_example_proof.json`, `scripts/tools/fixtures/stwo_external.receipt.txt`, `scripts/tools/fixtures/fast_circle_stark_receipt.txt`
- Tests (Rust and Foundry): `scripts/tests/rust/differential_receipt_verification.rs`, `scripts/tests/rust/ucir_compiler_equivalence.rs`, `scripts/tests/rust/chaos_stark_decode_tests.rs`, `scripts/tests/foundry/GLYPH_STARK_Test.t.sol`, `scripts/tests/rust/stwo_prover_tests.rs` (default builds include `stwo-prover`)
- Fuzz coverage: `decode_stark_receipt`, `decode_stark_vk`, `decode_stark_ir`, `decode_winterfell_program`, `decode_circle_stark_program`, `decode_circle_stark_proof`, `decode_standard_stark_program`, `decode_standard_stark_proof`, `decode_stwo_profile`, `decode_stwo_program`, `synthesize_stwo_proof`

**Hash**
- Fixtures or vectors: `scripts/tests/foundry/GLYPH_HASH_Test.t.sol` (generated vectors)
- Tests (Rust and Foundry): `scripts/tests/rust/adapter_ir_property_tests.rs`, `src/e2e_proofs.rs` export tests
- Fuzz coverage: `decode_adapter_ir_deep`, `diff_adapter_ir_roundtrip`

**Binius**
- Fixtures or vectors: None (in-tree generation)
- Tests (Rust and Foundry): `src/adapters.rs` Binius vk and statement tamper tests, `src/binius_adapter.rs` `test_binius_receipt_roundtrip` (features: `binius`, `dev-tools`)
- Fuzz coverage: No dedicated fuzz target yet

#### Registry and CLI Consistency (Adapter Availability)
- Adapter availability gates now route through `src/adapter_gate.rs` at the entry points
  in `src/glyph_ir_compiler.rs` and `src/adapter_ir.rs`, with feature-gated implementations
  isolated behind those wrappers.
- Architecture intent (consolidated here):
  - `src/adapter_registry.rs` is the authoritative availability inventory for families,
    SNARK kinds, and STARK fields (including feature metadata and reasons).
  - Compile-time gating remains intentionally in `src/lib.rs` module gates and
    `Cargo.toml` `required-features` for heavy CLIs and dependencies.
  - Runtime gating, error semantics, and CLI status output route through
    `src/adapter_gate.rs`, `src/adapter_facade.rs`, and `src/cli_registry.rs`.
- Custom gate availability is centralized in `src/glyph_ir.rs` via
  `ensure_custom_gate_enabled(custom_id)` and enforced inside `custom_gate_wrefs`.
- The witness engine (`src/glyph_witness.rs`) gates custom gate evaluation through the same
  IR helper, so W1 dependency wiring and W2 evaluation fail closed with consistent errors.
- Witness custom gate evaluation is structured around per-gate verifier helpers plus a shared
  `compare_artifact_tags(...)` path to keep gating and tag comparison uniform across adapters.
- Feature-disabled fallback branches in `src/glyph_ir_compiler.rs` and `src/adapter_ir.rs`
  now route their errors through `adapter_gate`, including Stark availability via
  `ensure_any_stark_enabled()`.
- CLI registry helper outputs are validated in
  `scripts/tests/rust/cli_registry_consistency_tests.rs`.

#### Canonical Decoding and Fail-Closed Checks
- Adapter byte formats are domain-tagged and length checked, with explicit versioning where applicable. See `src/adapters.rs`,
  `src/stark_receipt.rs`, `src/binius_adapter.rs`, `src/ivc_r1cs.rs`, `src/groth16_bls12381.rs`,
  and `src/kzg_bls12381.rs`.
- Canonical decode rejects truncation and trailing data: `scripts/tests/rust/chaos_stark_decode_tests.rs`,
  `scripts/tests/rust/adapter_ir_property_tests.rs`, and tamper tests in `src/adapters.rs`.
- UCIR encode-decode stability, gate payload sizing, custom gate tag rules, and lookup witness bounds
  are property-tested in `src/glyph_ir.rs`.
- Packed calldata verification rejects malformed inputs: `scripts/tests/rust/chaos_truncated_inputs.rs` and
  on-chain tamper tests in `scripts/tests/foundry/GLYPHVerifierTest.t.sol`.
- Compiler boundary tests enforce explicit error semantics for invalid inputs:
  `scripts/tests/rust/ir_compiler_boundary_tests.rs` and `scripts/tests/rust/adapter_error_semantics.rs`.
- Symbolic fuzz coverage for the Solidity verifier is summarized in Section 14.4.1.

#### Fuzz Target Inventory (Complete)
Location: `scripts/tests/fuzz/workspace/fuzz_targets`. Corpora live under
`scripts/tests/fuzz/workspace/corpus/` (one subdirectory per target). Dictionaries are
`scripts/tests/fuzz/dicts/adapter_ir.dict` (core targets) and
`scripts/tests/fuzz/dicts/stark.dict` (STARK targets).

Core targets:
- `decode_adapter_bytes`
- `decode_adapter_ir_deep`
- `diff_adapter_ir_roundtrip`
- `verify_adapter_proof`
- `verify_packed_calldata`
- `decode_plonky2_receipt`
- `decode_ipa_receipt`
- `bn254_op_traces`

STARK targets:
- `decode_stark_receipt`
- `decode_stark_vk`
- `decode_stark_ir`
- `decode_winterfell_program`
- `decode_circle_stark_program`
- `decode_circle_stark_proof`
- `decode_standard_stark_program`
- `decode_standard_stark_proof`

#### Reproducible Short-Run Commands
Short adapter trust pass (Rust + Foundry, fuzz skipped):
```
GLYPH_SKIP_FUZZ=1 scripts/tests/run_tests.sh
```
Short fuzz pass (core targets, 30s each):
```
scripts/tests/fuzz/run_all.sh short
```
Optional STARK fuzz pass:
```
GLYPH_FUZZ_STARK=1 scripts/tests/fuzz/run_all.sh short
```
Expected outputs:
- `scripts/out/tests/run_tests.log`
- `scripts/out/tests/fuzz/`

Note: ASAN fuzz builds that compile Cairo or Starknet dependencies may hit a rustc
stack overflow. `scripts/tests/run_tests.sh` now sets `RUST_MIN_STACK=16777216`
for fuzz runs by default. When running fuzz directly, set
`RUST_MIN_STACK=16777216` explicitly.

### 11.5.1.2 Optional L2 Root Updater Contracts

GLYPH ships optional, standalone L1 contracts that bind a GLYPH proof to an L2 state root update without changing `contracts/GLYPHVerifier.sol`. These contracts are strictly optional. Users who only call `contracts/GLYPHVerifier.sol` pay no extra gas and do not depend on root updater logic.

Contracts:
- `contracts/GLYPHRootUpdaterMinimal.sol`
- `contracts/GLYPHRootUpdaterExtended.sol`

Both contracts store:
- `state_root` (bytes32)
- `batch_id` (uint64, monotonic)
- `glyph_verifier` (immutable address)

Minimal statement hash:
```
statement_hash = keccak256(
  "GLYPH_L2_STATE" ||
  chainid || address(this) ||
  old_root || new_root || da_commitment || batch_id
)
```
Extended statement hash:
```
statement_hash = keccak256(
  "GLYPH_L2_STATE" ||
  chainid || address(this) ||
  old_root || new_root || da_commitment || batch_id ||
  extra_commitment || extra_schema_id
)
```
Encoding details:
- `chainid` is encoded as a 32-byte big-endian integer (uint256).
- `address(this)` is encoded as 20 bytes.
- `batch_id` is encoded as 8 bytes (uint64 big-endian).
- roots and commitments are 32-byte values.

Artifact tag binding (both contracts):
```
commitment_tag = keccak256("GLYPH_L2_COMMIT" || statement_hash)
point_tag = keccak256("GLYPH_L2_POINT" || commitment_tag)
artifact_tag = keccak256(commitment_tag || point_tag)
```
The root updater requires `glyph_proof[0:32] == artifact_tag` before calling `contracts/GLYPHVerifier.sol`.

Events:
```
event RootUpdated(bytes32 old_root, bytes32 new_root, bytes32 da_commitment, uint64 batch_id, bytes32 extra_commitment);
```
In the minimal contract, `extra_commitment` is zero.

Off-chain helper:
- `src/l2_statement.rs` provides deterministic statement hash and tag derivation.
- `glyph_l2_statement` CLI prints statement hash, commitment tag, point tag, artifact tag, and a claim suggestion.

### 11.5.2 Security Model: Binding vs. Validity

**CRITICAL DISTINCTION:**

Binding is enforced by the packed header in `contracts/GLYPHVerifier.sol` and ties the proof to the GLYPH artifact. Binding alone does not prove the upstream proof system is valid unless the adapter verifies the upstream proof inside GLYPH-Prover.

**What binding guarantees:**
- The packed proof is cryptographically bound to `artifact_tag`, `claim128`, and `initial_claim` (and therefore to `commitment_tag` and `point_tag` via `artifact_tag`).
- Replay protection via `chainid` and `address(this)`.
- Tamper detection: any change to the bound parameters invalidates the proof.

**What binding does NOT guarantee:**
- That the upstream proof bytes represent a valid proof in the upstream system.
- That public inputs are semantically correct.
- That verification key bytes correspond to a legitimate verifier.

**Trustless validity (current adapters):**
- Groth16 SNARK and KZG SNARK: upstream verification recorded as BN254 pairing trace events, compiled to UCIR, and proven inside GLYPH-Prover. Binding then implies upstream validity.
- IVC/Folding: trustless verification is enforced by (a) verifying the BaseFold transparent PCS opening, and (b) verifying a transparent R1CS receipt for all supported IVC proof types. External proofs are verified for **Nova** (RecursiveSNARK), **HyperNova** (CompressedSNARK), and **Sangria** (CompressedSNARK), each bound to the canonical receipt. **SuperNova** external proofs are available only when the `ivc-supernova` feature is enabled (disabled by default due to an unsound dependency in the upstream `arecibo` stack). Proof fields remain deterministic functions of the receipt hash.
- IPA (Halo2 IPA): statement hash is bound into the IPA transcript using `SNARK_IPA_STATEMENT_DOMAIN`.
- STARK: canonical receipt verification inside GLYPH-Prover custom gate (Winterfell `do_work`, `fibonacci`, and `tribonacci` on F128/F64 with SHA3 or Blake3, Circle STARK M31/BabyBear/KoalaBear SHA3, Blake3, Poseidon, or Rescue, Standard FRI BabyBear SHA3, Blake3, Poseidon, or Rescue, Stwo M31 with Blake2s, Cairo STARK on Starknet Prime with Starknet-with-Keccak layout, keccak-160-lsb, Stone6 monolith only, Miden STARK on Goldilocks with Blake3-192/256, RPO256, RPX256, Poseidon2 and no precompile requests, Plonky3 BabyBear/KoalaBear/Goldilocks with Poseidon2, Poseidon, Rescue, or Blake3 and M31 with Keccak, plus Plonky2 Goldilocks SHA3).
- Hash: SHA3 merge kernel proven inside GLYPH-Prover.
- SP1: Groth16/Plonk BN254 receipts verified off-chain and bound into the artifact inside GLYPH-Prover.
- PLONK/Halo2 KZG: PLONK receipts for gnark BN254, dusk BLS12-381, and halo2 backends plus Halo2 KZG receipts on BN256 and BLS12-381 with standard, parametric, and custom circuits, verified off-chain and bound into the artifact inside GLYPH-Prover.
- Binius: canonical Binius constraint-system receipts verified inside GLYPH-Prover via the Binius custom gate.

### 11.5.2.1 Soundness Chain (Adapter → On-Chain)

This section formalizes the end-to-end trustless claim:

**Chain of implication (high level):**
1. The adapter verification checks (all adapter families) run inside GLYPH-Prover and accept only canonical, valid upstream receipts/proofs.
2. The adapter verification outputs deterministic artifact tags (`commitment_tag`, `point_tag`, `claim128`) that bind to the verified upstream statement.
3. GLYPH-Prover produces a packed sumcheck proof for the artifact-defined polynomial.
4. `contracts/GLYPHVerifier.sol` verifies the packed sumcheck and chain binding on-chain.
5. Therefore, an on-chain acceptance implies the upstream statement verified successfully under the stated assumptions.

**Adapter assumptions (explicit):**
- **Groth16 SNARK / KZG SNARK:** Pairing/KZG soundness on BN254/BLS12-381, correctness of pairing trace encoding, collision resistance of Keccak.
- **IVC/Folding:** Correctness of transparent PCS evaluation (BaseFold) and transparent relaxed R1CS verification (Nova-family formats). Proof fields are deterministic functions of `receipt_hash = keccak256(r1cs_receipt_bytes)`. External **Nova** RecursiveSNARK proofs and **HyperNova/Sangria** CompressedSNARK proofs are verified against the canonical receipt. **SuperNova** is supported only with `ivc-supernova`.
- **Binius:** Soundness of the official Binius constraint-system verifier on CanonicalTower serialization, plus collision resistance of Keccak for binding to the GLYPH artifact.
- **IPA:** IPA soundness and transcript binding via `SNARK_IPA_STATEMENT_DOMAIN`.
- **STARK:** Soundness of the upstream STARK verifier per canonical receipt format (Winterfell/Circle/Standard FRI/Stwo/Cairo Starknet-with-Keccak keccak-160-lsb Stone6 monolith only, Miden Goldilocks Blake3-192/256 RPO256 RPX256 Poseidon2 no precompile requests, Plonky2, Plonky3), and collision resistance for transcript and Merkle hashing.
- **SP1:** Soundness of SP1 Groth16/Plonk verification using the SP1 verifier keys bundled with the SP1 verifier crate, plus collision resistance for receipt hashes.
- **PLONK/Halo2 KZG:** Soundness of PLONK verification for BN254 (gnark verifier) and BLS12-381 (dusk-plonk verifier), plus Halo2 KZG verification on BN256 and BLS12-381 (standard and parametric circuits), and collision resistance for receipt hashes.
- **Hash:** Collision resistance of Keccak for the SHA3 merge kernel.

**Proof map (where to audit):**
- Adapter verification entrypoints: `src/snark_groth16_bn254_adapter.rs`, `src/snark_kzg_bn254_adapter.rs`, `src/ivc_adapter.rs`, `src/ipa_adapter.rs`, `src/binius_adapter.rs`, `src/stark_adapter.rs`, `src/adapters.rs`.
- Artifact binding: `src/glyph_gkr.rs`, `contracts/GLYPHVerifier.sol`.
- Canonical receipt formats: `src/adapters.rs` (Groth16/KZG BN254), `src/ivc_r1cs.rs`, `src/stark_receipt.rs`, `src/groth16_bls12381.rs`, `src/kzg_bls12381.rs`.
- External proof verifiers: `src/ivc_nova.rs`, `src/ivc_supernova.rs` (feature `ivc-supernova`), `src/ivc_hypernova.rs`, `src/ivc_sangria.rs`, `src/ivc_compressed.rs`.

### 11.5.3 Production Readiness (Adapters)

All supported adapters are production-ready with trustless validity. Exact receipts, tooling, and constraints are detailed in Sections 11.5.1 and 11.5.2.

#### 11.5.3.1 Trust Matrix (Upstream Assumptions)

GLYPH does not introduce or remove trusted setup assumptions. The trust model is inherited from the upstream proof system, and GLYPH always performs full verification and binding for supported receipts.

**Groth16 SNARK**
Upstream system(s): Groth16 BN254 or BLS12-381  
Upstream trust model: Trusted setup  
GLYPH behavior: Full verification and binding  
Resulting trust in GLYPH pipeline: Preserves trusted setup

**KZG SNARK**
Upstream system(s): KZG openings BN254 or BLS12-381  
Upstream trust model: Trusted setup  
GLYPH behavior: Full verification and binding  
Resulting trust in GLYPH pipeline: Preserves trusted setup

**IVC/Folding**
Upstream system(s): BaseFold PCS + Nova-family receipts  
Upstream trust model: Transparent (IPA-based)  
GLYPH behavior: Full verification and binding  
Resulting trust in GLYPH pipeline: Trustless

**IPA**
Upstream system(s): Halo2 IPA BN254  
Upstream trust model: Transparent  
GLYPH behavior: Full verification and binding  
Resulting trust in GLYPH pipeline: Trustless

**Binius**
Upstream system(s): Binius constraint-system proofs  
Upstream trust model: Transparent  
GLYPH behavior: Full verification and binding  
Resulting trust in GLYPH pipeline: Trustless

**STARK**
Upstream system(s): Winterfell, Circle, Standard FRI, Stwo, Cairo (Starknet-with-Keccak keccak-160-lsb Stone6 monolith only), Miden (Blake3-192/256, RPO256, RPX256, Poseidon2, no precompile requests), Plonky2, Plonky3  
Upstream trust model: Transparent  
GLYPH behavior: Full verification and binding  
Resulting trust in GLYPH pipeline: Trustless

**Hash**
Upstream system(s): SHA3 merge  
Upstream trust model: Transparent  
GLYPH behavior: Full proof inside GLYPH  
Resulting trust in GLYPH pipeline: Trustless

**SP1**
Upstream system(s): SP1 Groth16 or Plonk BN254  
Upstream trust model: Trusted setup  
GLYPH behavior: Full verification and binding  
Resulting trust in GLYPH pipeline: Preserves trusted setup

**PLONK/Halo2 KZG**
Upstream system(s): PLONK (gnark, dusk, halo2) and Halo2 KZG BN256 or BLS12-381  
Upstream trust model: Trusted setup  
GLYPH behavior: Full verification and binding  
Resulting trust in GLYPH pipeline: Preserves trusted setup

#### 11.5.3.2 Fail-Closed Verification Policy
The adapter pipeline is fail-closed. It never accepts format-only inputs or unverified receipts.

- All artifact derivation entrypoints call a verifier first, not just a decoder. Examples: `src/plonk_adapter.rs`, `src/halo2_receipt.rs`, `src/ipa_adapter.rs`, `src/stark_adapter.rs`, `src/sp1_adapter.rs`, and `src/adapter_ir.rs`.
- Canonical decoders reject trailing bytes, unsupported ids, or empty proof fields. Unsupported combinations are rejected explicitly by `src/stark_adapter.rs`.
- Any optional verification shortcuts are test-only. Production adapters do not call `verify_with_trusted_hints` in `src/ipa_bn254.rs`.
- Plonky2 receipts are verified natively when the STARK Goldilocks feature is enabled. Canonical Plonky2 receipts are fixed to the Goldilocks field and the SHA3 hash id, matching the verifier wiring in `src/plonky2_receipt.rs`. No alternate hash ids are accepted for Plonky2 receipts. If the STARK Goldilocks feature is disabled, Plonky2 receipts are rejected because Goldilocks is not enabled in the registry and adapter gate.

Notes:
- STARK is **generic** by design. It is trustless only when the upstream verifier
  is executed inside the folding system. The current implementation covers
  Winterfell `do_work`, `fibonacci`, and `tribonacci` (F128/F64 with SHA3 or Blake3), Circle STARK receipts
  (M31, BabyBear, KoalaBear) for SHA3, Blake3, Poseidon, or Rescue, Standard FRI BabyBear for SHA3,
  Blake3, Poseidon, or Rescue RISC Zero receipts, Plonky3 receipts (Poseidon2, Poseidon, Rescue, or Blake3 for BabyBear/KoalaBear/Goldilocks, Keccak for M31),
  Cairo STARK (Starknet Prime, Starknet-with-Keccak, keccak-160-lsb, Stone6, monolith only), and Miden STARK (Goldilocks, Blake3-192/256, RPO256, RPX256, Poseidon2, no precompile requests).
- M31, Baby Bear, and Koala Bear are supported via the Circle STARK profile in the STARK adapter.
- Plonky2 Goldilocks receipts are verified natively when the STARK Goldilocks feature is enabled. This is an explicit policy choice to keep the Plonky2 path deterministic and self-contained. The receipt format is fixed to Goldilocks plus SHA3 so that field and hash selection are not runtime variables.

### 11.5.4 STARK Coverage Matrix (Supported Combinations)

The STARK adapter accepts canonical receipts only for the combinations below. All other
field, hash, or commitment combinations are rejected by `src/stark_adapter.rs`.

| System                    | Field ID | Field            | Hash ID                    | Hash                                              | Commitment      | Receipt / Import Path                    | Feature                                |
| ------------------------- | -------- | ---------------- | -------------------------- | ------------------------------------------------- | --------------- | ---------------------------------------- | -------------------------------------- |
| Winterfell do_work        | `0x01`   | F128             | `0x02`                     | SHA3                                              | Merkle (`0x01`) | `stark_winterfell` canonical receipt     | default                                |
| Winterfell do_work        | `0x01`   | F128             | `0x01`                     | Blake3                                            | Merkle (`0x01`) | `stark_winterfell` canonical receipt     | default                                |
| Winterfell do_work        | `0x02`   | F64 (Goldilocks) | `0x02`                     | SHA3                                              | Merkle (`0x01`) | `stark_winterfell_f64` canonical receipt | default                                |
| Winterfell do_work        | `0x02`   | F64 (Goldilocks) | `0x01`                     | Blake3                                            | Merkle (`0x01`) | `stark_winterfell_f64` canonical receipt | default                                |
| Winterfell fibonacci      | `0x01`   | F128             | `0x02`                     | SHA3                                              | Merkle (`0x01`) | `stark_winterfell` canonical receipt     | default                                |
| Winterfell fibonacci      | `0x01`   | F128             | `0x01`                     | Blake3                                            | Merkle (`0x01`) | `stark_winterfell` canonical receipt     | default                                |
| Winterfell fibonacci      | `0x02`   | F64 (Goldilocks) | `0x02`                     | SHA3                                              | Merkle (`0x01`) | `stark_winterfell_f64` canonical receipt | default                                |
| Winterfell fibonacci      | `0x02`   | F64 (Goldilocks) | `0x01`                     | Blake3                                            | Merkle (`0x01`) | `stark_winterfell_f64` canonical receipt | default                                |
| Winterfell tribonacci     | `0x01`   | F128             | `0x02`                     | SHA3                                              | Merkle (`0x01`) | `stark_winterfell` canonical receipt     | default                                |
| Winterfell tribonacci     | `0x01`   | F128             | `0x01`                     | Blake3                                            | Merkle (`0x01`) | `stark_winterfell` canonical receipt     | default                                |
| Winterfell tribonacci     | `0x02`   | F64 (Goldilocks) | `0x02`                     | SHA3                                              | Merkle (`0x01`) | `stark_winterfell_f64` canonical receipt | default                                |
| Winterfell tribonacci     | `0x02`   | F64 (Goldilocks) | `0x01`                     | Blake3                                            | Merkle (`0x01`) | `stark_winterfell_f64` canonical receipt | default                                |
| Circle STARK              | `0x03`   | M31              | `0x02`                     | SHA3                                              | Merkle (`0x01`) | `glyph_import_circle_receipt`            | default                                |
| Circle STARK              | `0x04`   | Baby Bear        | `0x02`                     | SHA3                                              | Merkle (`0x01`) | `glyph_import_circle_receipt`            | default                                |
| Circle STARK              | `0x06`   | Koala Bear       | `0x02`                     | SHA3                                              | Merkle (`0x01`) | `glyph_import_circle_receipt`            | default                                |
| Circle STARK              | `0x03`   | M31              | `0x01`                     | Blake3                                            | Merkle (`0x01`) | `glyph_import_circle_receipt`            | default                                |
| Circle STARK              | `0x04`   | Baby Bear        | `0x01`                     | Blake3                                            | Merkle (`0x01`) | `glyph_import_circle_receipt`            | default                                |
| Circle STARK              | `0x06`   | Koala Bear       | `0x01`                     | Blake3                                            | Merkle (`0x01`) | `glyph_import_circle_receipt`            | default                                |
| Circle STARK              | `0x03`   | M31              | `0x04`                     | Poseidon                                          | Merkle (`0x01`) | `glyph_import_circle_receipt`            | default                                |
| Circle STARK              | `0x04`   | Baby Bear        | `0x04`                     | Poseidon                                          | Merkle (`0x01`) | `glyph_import_circle_receipt`            | default                                |
| Circle STARK              | `0x06`   | Koala Bear       | `0x04`                     | Poseidon                                          | Merkle (`0x01`) | `glyph_import_circle_receipt`            | default                                |
| Circle STARK              | `0x03`   | M31              | `0x05`                     | Rescue                                            | Merkle (`0x01`) | `glyph_import_circle_receipt`            | default                                |
| Circle STARK              | `0x04`   | Baby Bear        | `0x05`                     | Rescue                                            | Merkle (`0x01`) | `glyph_import_circle_receipt`            | default                                |
| Circle STARK              | `0x06`   | Koala Bear       | `0x05`                     | Rescue                                            | Merkle (`0x01`) | `glyph_import_circle_receipt`            | default                                |
| Plonky2                   | `0x05`   | Goldilocks       | `0x02`                     | SHA3                                              | Merkle (`0x01`) | `plonky2_receipt` canonical receipt      | default                                |
| Standard FRI (RISC Zero)  | `0x07`   | Baby Bear        | `0x02`                     | SHA3                                              | Merkle (`0x01`) | `glyph_import_risc_zero_receipt` bundle  | default                                |
| Standard FRI (RISC Zero)  | `0x07`   | Baby Bear        | `0x01`                     | Blake3                                            | Merkle (`0x01`) | `glyph_import_risc_zero_receipt` bundle  | default                                |
| Standard FRI (RISC Zero)  | `0x07`   | Baby Bear        | `0x04`                     | Poseidon                                          | Merkle (`0x01`) | `glyph_import_risc_zero_receipt` bundle  | default                                |
| Standard FRI (RISC Zero)  | `0x07`   | Baby Bear        | `0x05`                     | Rescue                                            | Merkle (`0x01`) | `glyph_import_risc_zero_receipt` bundle  | default                                |
| Stwo                      | `0x03`   | M31              | `0x03`                     | Blake2s                                           | Merkle (`0x01`) | `glyph_import_stwo_receipt` bundle       | default                                |
| Plonky3                   | `0x0b`   | BabyBear         | `0x06`                     | Poseidon2                                         | Merkle (`0x01`) | `glyph_import_plonky3_receipt`           | default                                |
| Plonky3                   | `0x0c`   | KoalaBear        | `0x06`                     | Poseidon2                                         | Merkle (`0x01`) | `glyph_import_plonky3_receipt`           | default                                |
| Plonky3                   | `0x0d`   | Goldilocks       | `0x06`                     | Poseidon2                                         | Merkle (`0x01`) | `glyph_import_plonky3_receipt`           | default                                |
| Plonky3                   | `0x0b`   | BabyBear         | `0x04`                     | Poseidon                                          | Merkle (`0x01`) | `glyph_import_plonky3_receipt`           | default                                |
| Plonky3                   | `0x0b`   | BabyBear         | `0x05`                     | Rescue                                            | Merkle (`0x01`) | `glyph_import_plonky3_receipt`           | default                                |
| Plonky3                   | `0x0b`   | BabyBear         | `0x01`                     | Blake3                                            | Merkle (`0x01`) | `glyph_import_plonky3_receipt`           | default                                |
| Plonky3                   | `0x0c`   | KoalaBear        | `0x04`                     | Poseidon                                          | Merkle (`0x01`) | `glyph_import_plonky3_receipt`           | default                                |
| Plonky3                   | `0x0c`   | KoalaBear        | `0x05`                     | Rescue                                            | Merkle (`0x01`) | `glyph_import_plonky3_receipt`           | default                                |
| Plonky3                   | `0x0c`   | KoalaBear        | `0x01`                     | Blake3                                            | Merkle (`0x01`) | `glyph_import_plonky3_receipt`           | default                                |
| Plonky3                   | `0x0d`   | Goldilocks       | `0x04`                     | Poseidon                                          | Merkle (`0x01`) | `glyph_import_plonky3_receipt`           | default                                |
| Plonky3                   | `0x0d`   | Goldilocks       | `0x05`                     | Rescue                                            | Merkle (`0x01`) | `glyph_import_plonky3_receipt`           | default                                |
| Plonky3                   | `0x0d`   | Goldilocks       | `0x01`                     | Blake3                                            | Merkle (`0x01`) | `glyph_import_plonky3_receipt`           | default                                |
| Plonky3                   | `0x0a`   | M31              | `0x02`                     | Keccak (SHA3)                                     | Merkle (`0x01`) | `glyph_import_plonky3_receipt`           | default                                |
| Cairo STARK (Stone/SHARP) | `0x09`   | Starknet Prime   | `0x01`                     | Keccak-160-LSB                                    | Merkle (`0x01`) | `glyph_import_cairo_receipt`             | default                                |
| Miden STARK               | `0x08`   | Goldilocks       | `0x10/0x11/0x12/0x13/0x14` | Blake3-192, Blake3-256, RPO256, RPX256, Poseidon2 | Merkle (`0x01`) | `glyph_import_miden_receipt`             | default (fixtures: RPO256, BLAKE3-256) |

Notes:
- Stwo receipts reuse the Circle M31 field id (`0x03`) but enforce `hash_id=0x03` (Blake2s).
- Poseidon receipts use `hash_id=0x04` for Circle and Standard FRI paths to avoid conflicts.
- Rescue receipts use `hash_id=0x05` for Circle and Standard FRI paths.
- Plonky3 Poseidon2 receipts use `hash_id=0x06` (Poseidon uses `0x04`, Rescue uses `0x05`, Blake3 uses `0x01`).
- All STARK paths require canonical receipt formats and reject non-canonical or mismatched hashes.
- Plonky2 native verification is enabled when the STARK Goldilocks feature is on. The canonical receipt is fixed to Goldilocks plus SHA3, and receipt acceptance requires Goldilocks to be enabled in the registry.

**Known gaps and popular unsupported combinations:**
- Winterfell programs beyond `do_work`, `fibonacci`, and `tribonacci` are not supported yet.
- Cairo STARK is supported only for Starknet-with-Keccak layout, Keccak-160-LSB hashing, Stone v6, and monolith verifier. Stone and SHARP are treated as this single profile.
- Miden STARK supports Goldilocks with Blake3-192/256, RPO256, RPX256, and Poseidon2. Current fixtures cover RPO256 and BLAKE3-256 only, and those are the production fixtures shipped in-repo today. Other hash ids are valid in the canonical receipt format but are not covered by fixtures and should be treated as non-production until dedicated fixtures and test vectors are added.
- Miden proofs can include precompile requests in their internal format. GLYPH rejects those receipts. This is intentional: GLYPH does not execute or validate the external precompile requests emitted by the Miden proof, so accepting them would introduce unverified assumptions and break the canonical receipt soundness story. The adapter requires fully self-contained receipts where all verification conditions are satisfied inside GLYPH-Prover with no external requests. As a result, any receipt with precompile requests is rejected at import time and during verification.
- PLONK and Halo2 KZG support is backend-agnostic with explicit backend ids and a generic backend params wrapper. Currently supported: gnark BN254, dusk BLS12-381, and generic backend kinds `halo2`, `gnark`, and `dusk`. The halo2 backend kind covers KZG receipts (standard, parametric, and custom circuits with canonical circuit params). New backends can be added by extending the backend registry in `plonk_adapter`.
- Plonky3 supports Poseidon2, Poseidon, Rescue, and Blake3 for BabyBear, KoalaBear, and Goldilocks, and Keccak for M31 only.
- Alternate hash functions beyond SHA3, Blake3, Poseidon, and Rescue for Circle or Standard FRI receipts are not supported.

### 11.5.5 Canonical VK Format for STARK (CanonicalStarkVk)

For `AdapterFamily::Stark`, the `vk_bytes` used to compute `vkHash` must follow a canonical format to ensure:
- **Uniqueness:** Different AIRs/verifiers produce different `vkHash` values.
- **Stability:** The same AIR/verifier always produces the same `vkHash`.

**Canonical VK bytes structure:**
```
CANONICAL_STARK_VK       (19 bytes, domain tag)
version                  (2 bytes, big-endian)
field_id                 (1 byte, e.g., 0x01 = F128)
hash_id                  (1 byte, e.g., 0x01 = Blake3, 0x02 = SHA3, 0x04 = Poseidon, 0x05 = Rescue)
commitment_scheme_id     (1 byte, e.g., 0x01 = Merkle)
consts_len               (4 bytes, big-endian)
consts_bytes             (variable, canonical constants blob)
program_len              (4 bytes, big-endian)
program_bytes            (variable, canonical verifier program)
program_hash             (32 bytes, keccak256(CANONICAL_STARK_VK_PROGRAM || program_bytes))
```

**Circle STARK canonical receipt (STARK, M31 or Baby Bear):**
- `vk.consts_bytes` encodes the Circle STARK profile (log_domain_size, num_queries, blowup_factor).
- `vk.program_bytes` encodes the Circle STARK program definition (field_id, hash_id, trace_width, trace_length, constraint list, air_id).
- `field_id` values: `0x03` for M31, `0x04` for Baby Bear, `0x06` for Koala Bear.
- `hash_id` values: `0x02` for SHA3, `0x01` for Blake3, `0x04` for Poseidon, `0x05` for Rescue.
- Poseidon hashing maps bytes to Starknet field elements by concatenating inputs, chunking into 31-byte big-endian limbs, and applying `poseidon_hash_many`; the digest is the 32-byte big-endian field encoding.
- Rescue hashing uses `winter-crypto` Rescue Prime 64-256 over bytes; the digest is 4 little-endian u64 limbs.
- Fixtures: `scripts/tools/fixtures/fast_circle_stark_receipt.txt` (baseline) and `scripts/tools/fixtures/fast_circle_stark_receipt_large.txt` (larger) generated by `src/bin/gen_circle_stark_fixture.rs`.
- Supported constraints: cube-plus-const, linear-mix, mul-plus-const, linear-combo, mul-add.
   - RISC Zero bundle import (Baby Bear Standard FRI):
   - Import CLI: `glyph_import_risc_zero_receipt` accepts bundle JSON and validates the receipt using the standard STARK path.
   - Field id: `0x07` (Baby Bear standard).
    - Synthetic bundle fixture:
      ```bash
       cargo run --bin gen_risc_zero_bundle_fixture -- --out scripts/tools/fixtures/risc_zero_bundle.json
       # BLAKE3 profile:
       cargo run --bin gen_risc_zero_bundle_fixture -- --hash blake3 --out scripts/tools/fixtures/risc_zero_bundle_blake3.json
       # Poseidon profile:
       cargo run --bin gen_risc_zero_bundle_fixture -- --hash poseidon --out scripts/tools/fixtures/risc_zero_bundle_poseidon.json
       # Rescue profile:
       cargo run --bin gen_risc_zero_bundle_fixture -- --hash rescue --out scripts/tools/fixtures/risc_zero_bundle_rescue.json
       ```
     - Committed fixture: `scripts/tools/fixtures/risc_zero_bundle.json`. The profile-specific outputs above are generated on demand and are not committed.
    - Verification uses the standard STARK verifier, not the Circle STARK path.

**Standard STARK canonical receipt (STARK, Baby Bear Standard FRI):**
- Implemented in `src/standard_stark.rs` and `src/standard_fri.rs`.
- Uses `FIELD_BABY_BEAR_STD_ID = 0x07`.
- `hash_id` values: `0x02` for SHA3, `0x01` for Blake3, `0x04` for Poseidon, `0x05` for Rescue.
- RISC Zero receipts import via `glyph_import_risc_zero_receipt` (use `--hash sha3`, `--hash blake3`, `--hash poseidon`, or `--hash rescue`).

**Stwo canonical receipt (STARK, M31 + Blake2s):**
- `vk.consts_bytes` encodes `STWO_PROFILE` (tag + version + log_domain_size, num_queries, blowup_factor, log_last_layer_degree_bound, pow_bits).
- `vk.program_bytes` encodes `STWO_PROGRAM` (tag + version + toolchain_id + trace_width + log_trace_length + constraint expr tree with column offsets).
- `hash_id = 0x03` (Blake2s), `commitment_scheme_id = 0x01` (Merkle).
- Constraints are expressed as expr trees over trace columns with signed row offsets (0 = row, 1 = next row, -1 = prev row).
- External receipt import: `glyph_import_stwo_receipt` assembles canonical receipts from profile and program bytes plus proof and public inputs.
- Synthetic bundle fixture: `scripts/tools/fixtures/stwo_test_bundle.json` (decode-only, not verifier-valid).
- External toolchain path:
  - Produce Stwo commitment-scheme proof JSON, program bytes, and public input bytes.
  - Convert to bundle JSON using `stwo_to_bundle`:
    ```bash
    cargo run --bin stwo_to_bundle -- --proof-json proof.json --program-file program.bin --pub-file pub.bin --log-domain-size 20 --out bundle.json
    ```
  - Synthetic E2E: `cargo +nightly test test_stwo_synthetic_receipt_e2e --lib` (requires nightly for `portable_simd`). If you disable default features, add `--features stwo-prover`.
- Vendored dependency: `vendor/stwo/` is patched in `Cargo.toml` to keep the Stwo prover buildable on current toolchains.
- External fixture generation (vendored prover):
  - Generate a verified external fixture bundle:
    ```bash
    cargo +nightly run --features stwo-prover --bin gen_stwo_external_fixture -- --out scripts/tools/fixtures/stwo_external.json
    ```
  - Verify and emit receipt hex:
    ```bash
    cargo run --bin glyph_import_stwo_receipt -- --bundle-json scripts/tools/fixtures/stwo_external.json --out scripts/tools/fixtures/stwo_external.receipt.txt
    ```

**Rust API:**
```rust
use glyph::stark_winterfell::{canonical_vk_bytes, DO_WORK_AIR_ID};

let vk = canonical_vk_bytes(DO_WORK_AIR_ID, trace_width, trace_length, &options);
let vk_hash = keccak256(&vk);
```

**Important:** The `air_id` must be a stable, version-controlled identifier for the specific AIR constraints. Changing the AIR logic requires a new `air_id`.

### 11.5.5 Adapter Alignment and Performance Roadmap

This section summarizes the current adapter alignment status and the near-term performance and hardening roadmap.

**Adapter alignment (GLYPH-Prover only):**
- Groth16 SNARK (BN254, BLS12-381): GLYPH-Prover over pairing trace events, UCIR path, precomp bytes wired.
- KZG SNARK (BN254, BLS12-381): GLYPH-Prover over pairing trace events, UCIR path.
- IVC/Folding: GLYPH-Prover custom gate for BaseFold PCS and transparent R1CS receipts for Nova, SuperNova, HyperNova, Sangria. Nova external RecursiveSNARK proofs are verified by default; SuperNova requires `ivc-supernova`. HyperNova/Sangria proofs are verified via CompressedSNARK against the canonical receipt.
- IPA (Halo2 IPA): `ipa_adapter` with statement-bound transcript.
- Binius: GLYPH-Prover custom gate `CUSTOM_GATE_BINIUS_VERIFY` with canonical Binius constraint-system receipts.
- STARK: GLYPH-Prover custom gate `CUSTOM_GATE_STARK_VERIFY` with canonical receipts (Winterfell `do_work`/`fibonacci`/`tribonacci` on F128/F64, Circle M31/BabyBear/KoalaBear, Standard FRI BabyBear, Stwo M31, Cairo Starknet Prime with Starknet-with-Keccak layout, keccak-160-lsb, Stone6 monolith only, Miden Goldilocks with Blake3-192/256, RPO256, RPX256, Poseidon2 and no precompile requests, Plonky3 M31/BabyBear/KoalaBear/Goldilocks).
- Hash: GLYPH-Prover via adapter IR SHA3 merge.
- SP1: GLYPH-Prover custom gate `CUSTOM_GATE_SP1_VERIFY` with canonical SP1 receipts.
- PLONK/Halo2 KZG: GLYPH-Prover custom gate `CUSTOM_GATE_PLONK_VERIFY` with canonical PLONK and Halo2 KZG receipts.

**CPU SIMD status:**
- BN254 field ops use fast paths and batch ops.
- Trace recorder and MSM hot paths use batch ops in fq2 arithmetic and Jacobian add/double.
- Witness engine uses BN254 batch evaluation for custom gates.
- Witness engine reuses thread-local Goldilocks buffers and arena-backed BN254 scratch slices to reduce allocation churn.

**CUDA status:**
- Default: CPU SIMD is the primary execution path. CUDA is opt-in via `GLYPH_CUDA=1`
  or `GLYPH_ACCEL_PROFILE=cpu-cuda`.
- Overhead drivers: kernel launch latency, H2D/D2H transfers, stream sync, and
  NVRTC or module load costs. These are only amortized at large batch sizes.
- Policy: CUDA benches and tests are disabled by default. Run
  `scripts/benchmarks/bench_glyph_cuda_kpi.sh` with `GLYPH_ENABLE_CUDA_BENCH=1`
  to capture local metrics (outputs are written under `scripts/out/benchmarks/`
  when run and are not committed).
- CUDA backend coverage: BN254 batch add/sub/mul, Goldilocks batch ops and reductions,
  sumcheck helpers, LogUp pairwise products, PCS column combinations, and Keccak batch
  and row hashing.
- Windows detection is enabled. `GLYPH_CUDA_PTX` can point at a precompiled module and
  `GLYPH_CUDA_DEBUG=1` logs init failures.
- `GLYPH_CUDA_PINNED_HOST=1` enables pinned host buffers for BN254 H2D transfers
  (default on in the CPU+CUDA profile).
- CUDA >= 13 emits warnings in `scripts/utils/cuda/check_cuda_toolkit.sh` because
  `cudarc` may fail to build.
- BN254 trace validation uses `BN254_TRACE_VALIDATE_CHUNK`, `BN254_TRACE_CUDA_WINDOW`,
  `BN254_TRACE_CUDA_MIN_ELEMS`, and `GLYPH_CUDA_BN254_MIN_ELEMS` for chunking and
  window selection. `BN254_TRACE_CUDA_FULL=1` enables full-batch validation.
- BN254 MSM validation can override the trace threshold with
  `BN254_MSM_TRACE_CUDA_MIN_ELEMS`.
- Sumcheck uses `cuda_sumcheck_even_odd` when available and recomputes on CPU if the
  GPU result violates the current claim. `cuda_sumcheck_next_layer` falls back to CPU
  when it returns false.

**Hardening gaps still open:**
- Pairing kernel completed (`src/glyph_pairing.rs`): precomp Miller loop, cyclotomic check, and tests.

**Gas roadmap:**
- Likely wins come from calldata layout and verifier packing, after CPU and CUDA KPIs stabilize.

### 11.6 End-to-End Flow

Putting all components together, a typical GLYPH usage looks like this:

1. **Prover (off-chain, Rust):**
   - Prepare adapter inputs (vk, statement, proof bytes) for the chosen family.
   - Run `glyph_prover` or `adapter_ir::execute_*` to obtain a `UniversalProof`.
   - Encode packed calldata with `glyph_core::encode_packed_gkr_calldata`.

2. **Adapter (off-chain):**
   - Verify the upstream proof inside GLYPH-Prover and derive the
     artifact boundary (commitment tag, point tag, claim128).
   - Bind chain id and verifier address into the packed calldata header.

3. **Verifier (on-chain, Solidity):**
   - `contracts/GLYPHVerifier.sol` receives packed calldata via `fallback()`.
   - Recomputes the artifact-defined polynomial and checks the sumcheck.
   - Returns `1` (ABI-decoded) only if all checks succeed.

4. **Tests and local Anvil checks:**
   - `GeneratedRealProofTest.t.sol`, `GLYPH_*_Test.t.sol`, and
     `GLYPHVerifierTest.t.sol` ensure real packed calldata succeeds and
     tampered inputs revert, both in Rust and on a local Anvil chain.

### 11.7 Minimal Integration Guide

This subsection sketches how an off-chain client can integrate GLYPH in
practice.

**Step 1 – Generate a GLYPH proof in Rust**

At a high level, a Rust client:

1. Encodes adapter inputs (vk/statement/proof bytes) for the chosen family.
2. Calls `adapter_ir::execute_*` or `glyph_prover` to obtain a `UniversalProof`.
3. Encodes packed calldata for `contracts/GLYPHVerifier.sol`.

Conceptually:

```rust
use glyph::adapter_ir::{execute_hash_sha3_merge_ir, AdapterIr, AdapterIrOp, kernel_id};
use glyph::glyph_core::encode_packed_gkr_calldata;

fn build_glyph_call() -> (CalldataFields) {
    // 1) Build adapter IR (example: hash merge)
    let ir = AdapterIr {
        version: 1,
        ops: vec![AdapterIrOp {
            kernel_id: kernel_id::HASH_SHA3_MERGE,
            args: Vec::new(),
        }],
    };
    let left = [0u8; 32];
    let right = [1u8; 32];
    let proof = execute_hash_sha3_merge_ir(&ir.encode(), &left, &right)?.proof;

    // 2) Encode packed calldata for GLYPHVerifier fallback
    let calldata = encode_packed_gkr_calldata(&proof);
    /* ... submit calldata ... */
}
```

Any concrete client (Rust, TypeScript, etc.) must encode the packed calldata
expected by `contracts/GLYPHVerifier.sol` (no selector). The GLYPH-Prover tooling emits
the packed bytes directly.

**Step 2 – Call the Solidity verifier**

From an off-chain client, the call has the shape:

- Contract: `GLYPHVerifier` at some address `verifier_addr`.
- Function: fallback (no selector).
- Arguments: raw packed calldata emitted by the GLYPH-Prover pipeline.

### 11.8 Example Solidity Integration

The following example shows how a Solidity contract can call the packed
fallback on `GLYPHVerifier` and handle invalid proofs and malformed calldata:

```solidity
pragma solidity ^0.8.20;

contract ExampleConsumer {
    address public verifier;

    constructor(address verifierAddr) {
        verifier = verifierAddr;
    }

    function verifyPacked(bytes calldata proof) external returns (bool) {
        (bool ok, bytes memory out) = verifier.call(proof);
        if (!ok || out.length != 32) {
            return false;
        }
        return abi.decode(out, (uint256)) == 1;
    }
}
```

This pattern makes the failure modes explicit in
on-chain application logic.

The call can be performed via:

- `eth_call` (view) for read-only checking, or
- a full transaction for stateful protocols. Gas depends on calldata size       
  (32 bytes per round) plus base transaction cost.

**Step 3 – Application-level logic**

The application typically wraps GLYPH as an **adapter**:

- Compute a statement hash or public input vector.
- Feed it into the GLYPH prover via `PublicProver` / `PublicVerifier`
  or as part of `a`.
- Only accept the transaction if the `GLYPHVerifier` fallback returns `1`
  and the application-level conditions (e.g. matching hash, account state)
  also hold.

This architecture makes the GLYPH adapter:

- **Portable:** Standard Rust API for proof generation.
- **Safe:** Strong invariants and assertions in the adapter layer.
- **Gas-accurate when measured:** Bench scripts use the deployed verifier bytecode
  and on-chain receipts; see Section 14.2.1 for published receipt evidence.

### 11.9 Sepolia Deployment and Real-World Gas Measurements

In addition to local Anvil bench runs (when executed), GLYPH has been
deployed and exercised on the public Ethereum Sepolia testnet.

**Deployed contract.**

- Network: Ethereum Sepolia
- Verifier contract: see `deployments/sepolia.json` (written by `scripts/deploy/deploy_glyph_contract.sh`)
- ABI: `contracts/GLYPHVerifier.sol` (packed fallback, no selector)
- Deployment script: `scripts/deploy/deploy_glyph_contract.sh`

The deployment script performs the following steps end-to-end:

1. Checks the balance of a dedicated Sepolia deployer address.
2. Validates the RPC chain-id and deploys `contracts/GLYPHVerifier.sol` via `forge create` (with `--broadcast`).
3. Confirms the deployed bytecode is non-empty via `cast code`.
4. Calls the `GLYPHVerifier` fallback with packed calldata emitted by the GLYPH-Prover pipeline.
   The script aborts on failure unless `ALLOW_VERIFY_FAILURE=1` is set, or the step is skipped via `VERIFY_REAL_PROOF=0`.
5. Stores deployment metadata under `deployments/sepolia.json`, including
   `chain_id`, `rpc_host`, and `verify_result`.

On Sepolia, the verification call succeeds with the same proof as used in the
local Anvil tests, confirming that the Solidity verifier and the Rust prover agree
bit-for-bit on transcript, challenges, and curve arithmetic.

**On-chain gas accounting.**

For any on-chain verify call, the total L1 gas is:

```
total_gas = base_tx_gas + calldata_gas + execution_gas
```

- `base_tx_gas` is always 21,000 for a standard transaction.
- `calldata_gas` is computed per EIP-2028: 4 gas per `0x00` byte, 16 gas per non-zero byte.
- `execution_gas` is the remaining gas once base and calldata are subtracted from the
  receipt gasUsed or from `eth_estimateGas`.

**Receipt-based evidence (testnet).** See Section 14.2.1 for the authoritative
receipt table with tx hashes and calldata breakdowns. Summary: GLYPH
artifact verification is 29,450 total tx gas (224 bytes calldata),
while Groth16 verify (3 publics) is 227,128 total tx gas (356 bytes calldata).

**Local Anvil baseline.** Run `scripts/benchmarks/bench_glyph_evm_local.sh` to capture
local baselines. Outputs are written to `scripts/out/benchmarks/bench_glyph_evm_local.json`
when the script is run and are not committed.

**Stability and comparability.**
- GasUsed is deterministic for fixed bytecode and calldata.
- GLYPH calldata depends on `chainid` and the verifier address, so bytes can differ slightly across networks.
- `eth_estimateGas` is typically higher than receipts on the same bytecode and calldata.



**GLYPH artifact-defined public polynomial (GLYPHVerifier).**

The repository's production verifier includes an artifact-defined
variant whose final check is derived on-chain from a deterministic public polynomial
parameterized by `artifact_tag` and `claim128` (where `artifact_tag = keccak256(commitment_tag || point_tag)`):

- Contract code: `contracts/GLYPHVerifier.sol` (`fallback()` packed verifier)
- Rust prover + encoder: `src/glyph_gkr.rs` (`prove_packed_artifact_poly_sumcheck`, `encode_artifact_poly_bound_packed_calldata_be`)
- CLI: `src/bin/gen_glyph_gkr_proof.rs` (`--hash-merge --chainid <u64> --verifier <addr>` or `--artifact-poly --claim <bytes32> (--commitment <bytes32> --point <bytes32> | --artifact-tag <bytes32>) --chainid <u64> --verifier <addr>`)
- On-chain tests: `scripts/tests/foundry/GLYPHVerifierTest.t.sol`
- Gas snapshot: re-run the Anvil or Sepolia benches after the packed-128 layout
  change. Calldata size now follows the packed format (32 bytes per round).

**GLYPH deployment and benchmarking (Sepolia, Anvil).**

For reproducible deployments and gas measurements of the GLYPH packed verifier:

- Sepolia deployment: `scripts/deploy/deploy_glyph_contract.sh` (writes `deployments/sepolia.json`)
- Sepolia Etherscan verification: `scripts/deploy/verify_glyph_contract.sh` (requires `ETHERSCAN_API_KEY`)
- Sepolia gas benches:
  - `scripts/benchmarks/bench_glyph_evm_sepolia.sh` (artifact-bound, estimateGas)
  - `scripts/benchmarks/bench_glyph_sepolia_artifact.sh` (artifact-bound, estimateGas)
- Hoodi gas benches:
  - `scripts/benchmarks/bench_glyph_hoodi_artifact_truncated.sh` (artifact-bound, truncated-only)
- Local Anvil tx-gas benches:
  - `scripts/benchmarks/bench_glyph_evm_local.sh` (artifact-bound)
  - `scripts/benchmarks/bench_glyph_evm_round_sweep.sh` (round sweep, artifact-bound)


## 12. Limitations and Non-Goals

This section documents what the current GLYPH implementation does
**not** aim to provide and where its boundaries lie. It is based on
the deployed Solidity verifier, the Rust prover, and the test suite –
not on any external or legacy specification.

### 12.1 Cryptographic Boundaries

- **Field choice.** The packed sumcheck verifier runs over a 128-bit
  prime field (`p = 2^128 - 159`). Security depends on field size and
  Fiat-Shamir hashing. Adapters that verify BN254 or other curves
  inherit those upstream security assumptions off-chain.
- **Fiat–Shamir heuristic.** The prover and verifier derive challenges
  using Keccak256 with 128-bit truncation. Soundness relies on
  standard random-oracle-style assumptions for Keccak and the usual
  Fiat–Shamir arguments. No alternative transcript construction is
  implemented here.
- **No post-quantum guarantees.** Like most practical ZK systems, GLYPH
  is not post-quantum secure. The design makes no attempt to mitigate
  quantum attacks.

### 12.2 Functional Scope

- **Single fixed on-chain verifier layout.** The Solidity verifier uses
  a single packed sumcheck layout that is independent of
  adapter parameter sizes. Upstream proof systems are verified off-chain,
  and only the GLYPH artifact boundary is checked on-chain.
- **Wrapper for existing proofs.** GLYPH treats external proofs as
  byte-level objects (plus optional public inputs). It does not inspect
  or reason about their internal constraint systems. Binding semantics
  ("what is being proven?") is the responsibility of the adapter code
  that constructs the vectors `a` and `b` or uses `PublicProver` /
  `PublicVerifier`.
- **Single-proof focus.** The implementation is optimized for a single
  proof per verification call. There is no multi-proof batching or
  recursive composition in this repository.

### 12.3 Deployment and Upgrade Model

- **Immutable core verifier.** `contracts/GLYPHVerifier.sol` is a plain Solidity
  contract without upgrade hooks or proxy patterns. Once deployed, a
  particular instance is immutable. Any upgrade requires deploying a
  new contract and routing application logic to the new address.
- **No IPA hints on-chain.** The production `contracts/GLYPHVerifier.sol` uses packed sumcheck and does not accept IPA-style generator hints.

### 12.4 Explicit Non-Goals

- **No general-purpose SNARK/STARK system.** GLYPH is an adapter and aggregation layer, not a full proof system. It does not replace Groth16, PLONK, STARKs, or folding schemes; it wraps their outputs into the GLYPH artifact and a packed sumcheck proof.
- **No privacy layer by itself.** GLYPH operates on commitments and
  hashes. Any privacy guarantees come from the underlying proof system
  being wrapped, not from GLYPH itself.
- **No gas-cost stability guarantees.** Reported gas figures are based
  on the current Ethereum gas schedule and precompile pricing. Future
  protocol changes (EIPs) can shift absolute costs; this repository
  does not attempt to predict or hedge against such changes.


## Appendix A: Rust Dependencies

The GLYPH crate uses the following dependencies (excerpt from `Cargo.toml`):

```toml
[dependencies]
num-bigint = { version = "0.4.4", features = ["rand"] }
num-traits = "0.2.17"
rand = "0.8.5"
lazy_static = "1.4.0"
sha2 = "0.10.8"
tiny-keccak = { version = "2.0.2", features = ["keccak"] }
num-integer = "0.1.46"

# BN254 Curve for Ethereum-compatible IPA
ark-bn254 = "0.4"
ark-ec = "0.4"
ark-ff = "0.4"
ark-serialize = "0.4"
ark-std = "0.4"

# Utilities
hex = "0.4"
rayon = "1.10"
rlp = "0.5.2"
secp256k1 = { version = "0.29", features = ["recovery"] }

[profile.test]
opt-level = 3
```

---

## Appendix B: Test Coverage (Overview)

The repository contains dedicated tests for all critical components. A
non-exhaustive overview:

| Area                     | Where                                    | Focus                                                     |
|--------------------------|------------------------------------------|-----------------------------------------------------------|
| IPA core (`ipa_bn254`)   | `ipa_bn254.rs` tests                     | Proof parity, soundness, fuzz                             |
| Parallel prover          | `parallel_prover.rs`                     | Parity vs sequential, large `n` perf                      |
| SIMD prover and ops      | `simd_prover.rs`, `glyph_field_simd.rs`  | SIMD vs scalar parity, backend detect, speedups           |
| Pippenger MSM            | `ipa_bn254.rs` (`pippenger_msm`)         | MSM parity, window heuristics, benchmarks                 |
| GLV or Shamir            | `glv.rs`                                 | 2x or 3x scalar mul parity, speedups                      |
| Public inputs            | `public_inputs.rs`                       | Binding, large-witness stress                             |
| Solidity export and E2E  | `e2e_proofs.rs`, `scripts/tests/foundry` | Calldata layout, generated Solidity, tamper cases         |

To run the full suite:

```bash
cargo test
```

For the consolidated runner:

```bash
./scripts/tests/run_tests.sh
```

`run_tests.sh` runs unit and integration tests, regenerates Solidity vectors,
runs Foundry, and can execute fuzzing when enabled.
The runner emits a `test_context` key=value block at the top of the log for quick parsing.
The runner now includes an optional full adapter test pass controlled by
`GLYPH_FULL_TESTS` and `GLYPH_TEST_FEATURES`.
Default timeouts are controlled by `STEP_TIMEOUT` and `TOTAL_TIMEOUT`. The current defaults are
9600 seconds per step and 28800 seconds total. Set `GLYPH_DISABLE_TIMEOUTS=1` to disable
per-step timeouts.
Fuzzing is disabled by default (`GLYPH_SKIP_FUZZ=1`). Enable it with
`GLYPH_SKIP_FUZZ=0`, then control the run with `FUZZ_TIME`, `FUZZ_TARGETS`, and
`GLYPH_FUZZ_SEED` (deterministic libFuzzer seed).
Default targets include `decode_adapter_bytes`, `decode_adapter_ir_deep`,
`verify_adapter_proof`, `verify_packed_calldata`, `transcript_challenges`,
and `validate_state_transition_batch`. Set `GLYPH_FUZZ_STARK=1` to add
`decode_stark_receipt` and `decode_stark_vk` to the target set.
Feature-gated fuzz targets include `decode_r1cs_receipt` (requires `ivc`),
`decode_supernova_external_proof` (requires `ivc-supernova`),
`decode_stwo_profile` and `decode_stwo_program` (require `stark-m31`), and
`synthesize_stwo_proof` (requires `stwo-prover`).
Fuzz artifacts and per-target logs are written under `scripts/out/tests/fuzz` by default
(`FUZZ_OUT_DIR` overrides).
Fuzz corpora live under `scripts/tests/fuzz/workspace/corpus/` (one subdirectory per target) and are seeded with minimal inputs.
Dictionary files live in `scripts/tests/fuzz/dicts/` and can be passed with `-dict=...`.
For structured runs, use:
- `scripts/tests/fuzz/run_all.sh` for short or deep presets (`GLYPH_FUZZ_PRESET=short|deep`)
- `scripts/tests/fuzz/run_cmin.sh` and `scripts/tests/fuzz/run_tmin.sh` for corpus minimization
Both `run_all.sh` and `run_tests.sh` accept `GLYPH_FUZZ_SEED` for deterministic runs.
Short preset runs adapter and proof fuzzers with bounded time.
Deep preset adds STARK decode targets and increases time budgets.
Differential fuzzing is covered by `diff_adapter_ir_roundtrip`, which validates encode-decode stability.
Fuzz helpers emit a `fuzz_context` key=value block at startup for quick inspection.
The block uses a stable key ordering: `mode`, `preset`, `out_dir`, `fuzz_dir`,
`dict_dir`, `toolchain`, `seed`, `time_short`, `time_stark`, `time_deep`,
`fuzz_stark`.
Context blocks are emitted in stable key order within each block to make log parsing deterministic.
To suppress known vendor warning noise in the test runner output, set
`GLYPH_SUPPRESS_VENDOR_WARNINGS=1`. You can customize the filter with
`VENDOR_WARN_FILTER` (regex applied to stderr).
Full adapter testing defaults to
`snark,ivc,hash,stark-babybear,stark-goldilocks,stark-m31,binius`. Override with
`GLYPH_TEST_FEATURES` or disable with `GLYPH_FULL_TESTS=0`.
The runner also includes feature-gated passes for SuperNova and Stwo prover tests by default.
Set `GLYPH_TEST_SUPERNOVA=0` or `GLYPH_TEST_STWO_PROVER=0` to skip those passes.
CUDA benches and tests are disabled by policy. The test runner defaults to
CPU-only settings (`NVCC=disabled`) to avoid CUDA toolchain errors in `pasta-msm`.
Cairo STARK support lives under `stark-m31`.
Default builds enable all adapter groups, but you can slim builds with
`--no-default-features` plus adapter selection.
Build presets are available via:
- `./scripts/build/glyph_build.sh --preset default|core|snark|ivc|hash|binius|stark-babybear|stark-goldilocks|stark-m31|cuda|full`
- `./scripts/build/glyph_build.sh --adapters snark,hash`
Adapter groups are: `snark`, `ivc`, `hash`, `binius`, `stark-babybear`,
`stark-goldilocks`, and `stark-m31`.
Preset `full` enables all adapters plus `cuda`.
Default builds include `stwo-prover`. Disable it with `--no-default-features` if needed.
When using `--adapters`, the script defaults to `cargo build --lib`. To build a binary,
run `cargo build --bin glyph_prover` directly (or omit `--adapters`).
To include Cairo in fuzzing, set `GLYPH_FUZZ_CAIRO=1`. On macOS with ASAN
nightly, Cairo fuzz builds can still SIGBUS due to `swiftness_air` debug info
generation. Use a Linux fuzz run if this occurs.
Foundry build artifacts are written to `scripts/out/foundry` (configured in
`scripts/tests/foundry/foundry.toml`) and cache data is centralized under
`scripts/out/foundry-cache` (configured in `scripts/tests/foundry/foundry.toml`
and reinforced via `FOUNDRY_CACHE_PATH` in `scripts/tests/run_tests.sh`).
Runner logs are written to `scripts/out/tests/run_tests.log` by default (override with
`OUT_LOG` or `OUT_DIR`).
Plonky2 receipt verification tests run in the standard suite when STARK
features are enabled (default/full builds).
Optional vector expansion for the Rust export tests:
- `GLYPH_E2E_INCLUDE_F64=1` includes Winterfell F64 SHA3 receipts.
- `GLYPH_E2E_INCLUDE_CIRCLE_LARGE=1` includes the larger Circle STARK fixture (v2).
- `GLYPH_E2E_INCLUDE_PLONKY2=1` includes Plonky2 Goldilocks receipts.

---

## Appendix C: Benchmarks (Reproducibility)

Benchmark scripts live in `scripts/benchmarks/` and write to `scripts/out/benchmarks/` by default.
The canonical registry is `scripts/benchmarks/registry.json` and the one-shot runner is
`scripts/benchmarks/run_all.sh` with presets `local`, `sepolia`, `hoodi`, and `cuda` (opt-in).
All benchmarks emit standardized JSON to `scripts/out/benchmarks/` with one `<bench>.json` file
and a matching `.meta.json` sidecar.
`run_all.sh` flags missing, empty, and invalid JSON outputs and removes empty files when a bench emits no data.
Bench logs begin with a `bench_context` key=value block that captures `bench_name`, `out_file`, and `run_id`.
Deploy and DA entrypoints emit `deploy_context`, `verify_context`, and `da_context` blocks for structured logs.

Unified JSON fields:
- `schema_version`, `bench_name`, `timestamp`, `run_id`, `git_commit`
- `toolchain` (rustc, cargo, forge, cast), `cpu`, `os`
- `rpc_host`, `chain_id`, `block_number`, `base_fee`, `gas_price`
- `case`, `bytes`, `gas`, `status`
- `data` for bench-specific metrics

EVM benches also record `calldata_gas`, `execution_gas`, and `base_tx_gas` in their case payloads.

Benchmark workflow summary (testnet receipts):
- Load keys and RPC endpoints from `docs/wallet/.env.wallet` and `scripts/deploy/.env.*`.
- Bench scripts generate packed calldata, then submit fallback calls using `scripts/benchmarks/send_raw_tx.sh`,
  which signs and broadcasts legacy raw transactions via `glyph_raw_tx` (`src/bin/glyph_raw_tx.rs`).
- Receipts provide `tx_hash` and `tx_gas` (published totals), while `execution_gas` is derived from
  `eth_estimateGas` and `calldata_gas` is computed from the raw calldata bytes per EIP-2028.

Recommended entry points:
- `scripts/benchmarks/bench_glyph_zk_kpi.sh` for fast-mode vs zk-mode proof-size deltas.
- `scripts/benchmarks/bench_glyph_adapter_kpi.sh` and `scripts/benchmarks/bench_glyph_adapter_zk_kpi.sh` for adapter KPIs.
- `scripts/benchmarks/bench_ivc_fold_kpi.sh` for IVC multilinear evaluation and folding KPIs.
- `scripts/benchmarks/bench_basefold_arity_sweep.sh` for BaseFold arity and log-inv-rate sweeps.
- `scripts/benchmarks/bench_basefold_mem_sweetspot.sh` for BaseFold host/dev memory tuning sweeps.
- `scripts/benchmarks/bench_basefold_trace_profile.sh` for BaseFold trace logs (small and large cases).
- `scripts/benchmarks/bench_bn254_batch_kpi.sh`, `scripts/benchmarks/bench_bn254_g2_kpi.sh`, `scripts/benchmarks/bench_bn254_msm_kpi.sh`, `scripts/benchmarks/bench_bn254_mul_kpi.sh`, `scripts/benchmarks/bench_bn254_trace_kpi.sh` for BN254 MSM and field operation throughput.
- `scripts/benchmarks/bench_stark_do_work_kpis.sh` for Winterfell do_work KPIs (enable SHA3 receipts with `SHA3=1` and `SEED=...`).

### Repro Pack Checklist

- Run `scripts/benchmarks/run_all.sh` with `BENCH_PRESET=sepolia` and `BENCH_PRESET=hoodi`.
- Capture `scripts/out/benchmarks/` outputs (all `.json` and `.meta.json` files).
- Record the on-chain tx hashes and include them in Section 14.2.1.
- Preserve the exact CLI parameters used to generate the proof and calldata.
- Keep the local harness outputs separate from on-chain tx gas evidence.

---

## Appendix D: Glossary

| Term  | Definition                                |
|-------|-------------------------------------------|
| BN254 | Barreto-Naehrig curve with 254-bit prime  |
| DLP   | Discrete Logarithm Problem                |
| EC    | Elliptic Curve                            |
| ECADD | Elliptic curve point addition             |
| ECMUL | Elliptic curve scalar multiplication      |
| IPA   | Inner Product Argument                    |
| MSM   | Multi-Scalar Multiplication               |
| SIMD  | Single Instruction, Multiple Data         |
| ZK    | Zero-Knowledge                            |

---

## Appendix E: Optional Developer Tooling and Quick Reference

This appendix consolidates optional interface ideas and checklists for developer tooling.

Important: the Solidity contracts in this repository include the production packed
verifier (`contracts/GLYPHVerifier.sol`), optional root updater helpers
(`contracts/GLYPHRootUpdaterMinimal.sol`, `contracts/GLYPHRootUpdaterExtended.sol`),
and the generated constants base (`contracts/GLYPHVerifierConstants.sol`). The items
below are either:

- implemented purely off-chain (SDK / tooling), or
- recommended as optional wrappers / extensions, but not present in
  `contracts/GLYPHVerifier.sol`.

### E.1 Optional Convenience Features (Zero Cost for `verify`)

The following features can be provided without changing the gas cost of the
production `verify` code path:

| Feature                | Where                   | Notes                                                   |
|------------------------|-------------------------|---------------------------------------------------------|
| View-only helpers      | off-chain or `eth_call` | Generator or challenge inspection for debugging         |
| Encoding validator     | off-chain               | Reject malformed calldata before submitting tx          |
| `estimateGas()` helper | on-chain (pure)         | Not present in `contracts/GLYPHVerifier.sol`            |

### E.5 GLYPH Prototype Tooling (Packed GKR)

This repository contains both the production packed verifier and several off-chain
prototype layouts.

Production on-chain verifier:
- `contracts/GLYPHVerifier.sol` implements the packed `fallback()` verifier (no selector).
- The on-chain calldata layout is artifact-bound only:
  - Header (64 bytes):
    - `artifact_tag: bytes32` where `artifact_tag = keccak256(commitment_tag || point_tag)`
    - `claim128 || initial_claim` as two 16-byte big-endian values packed into one word
  - Rounds:
    - Each round is 32 bytes: `c0 || c1` as two 16-byte big-endian field elements `< p`
    - `c2` is recovered from the arity-8 sumcheck constraint
  - Minimum packed size is 96 bytes (header plus one round).
- Chain binding is enforced on-chain via the initial challenge:
  - `r0 = keccak256(chainid || address(this) || artifact_tag || claim128 || initial_claim) mod p`
- Final binding check is artifact-defined:
  - `expected_final = (lin_0 + claim128 + eval_lin)^2`
- where `lin_hash = keccak256(LIN_DOMAIN || artifact_tag || claim128_be16)` and
    `LIN_DOMAIN = keccak256("GLYPH_GKR_ARTIFACT_LIN")`.

Off-chain prototype layouts:
- `src/glyph_gkr.rs` still contains unbound, statement-bound, and statement-polynomial
  prototype encoders and verifiers.
- These prototype layouts are not accepted by `contracts/GLYPHVerifier.sol` and
  should be treated as off-chain reference tooling only.

CLI modes in `src/bin/gen_glyph_gkr_proof.rs`:
- Calldata that is intended to match the on-chain verifier is produced by:
  - `--artifact-poly`
  - `--hash-merge` (implies `--artifact-poly`)
- Other modes such as `--bind` and `--stmt-poly` target prototype layouts.

**GKR Protocol Domain Tags (from `glyph_gkr.rs`):**
- `GLYPH_GKR_INIT_DOMAIN = "GLYPH_GKR_INIT"` (initial claim derivation)
- `GLYPH_GKR_COEFF_DOMAIN = "GLYPH_GKR_COEFF"` (round coefficient derivation)
- `GLYPH_GKR_ARTIFACT_LIN_DOMAIN = "GLYPH_GKR_ARTIFACT_LIN"` (artifact linear coefficients; matches the on-chain `LIN_DOMAIN`)
- Additional domains such as `GLYPH_GKR_BIND_*`, `GLYPH_GKR_STMT_POLY_*`, and
  `GLYPH_GKR_TOY_*` exist for prototype and toy flows in `src/glyph_gkr.rs`.

**Sumcheck Constraint:**
- `g(0) + ... + g(7) = current_claim` where `g(t) = c0 + c1*t + c2*t^2`
- `current_claim = 8*c0 + 28*c1 + 140*c2`, so `c2 = (current_claim - (8*c0 + 28*c1)) * inv(140)`
- No truncated recovery path: only `c0` and `c1` are sent, `c2` is recovered from the constraint.



Off-chain adapters apply profile defaults to select performance-oriented settings without
changing on-chain gas or soundness. Profiles only set environment variables if they are
not already provided, so explicit overrides always win.

Profile selectors:
- `GLYPH_GROTH16_BN254_PROFILE`, `GLYPH_KZG_BN254_PROFILE`, `GLYPH_IVC_PROFILE`, `GLYPH_IPA_PROFILE`, `GLYPH_STARK_PROFILE`, `GLYPH_HASH_PROFILE`, `GLYPH_SP1_PROFILE`, `GLYPH_PLONK_PROFILE`, `GLYPH_BINIUS_PROFILE`
- Values: `prod`, `fast`, `bench`, `single`, `auto`
- Defaults: Groth16 and KZG fall back to `prod`. IVC, IPA, STARK, Hash, SP1, PLONK, and Binius fall back to `fast`.
- Adaptive selection:
  - `GLYPH_GROTH16_BN254_PROFILE=auto` uses `GLYPH_GROTH16_BN254_CONSTRAINTS` to choose `single` (<1k), `prod` (1k to 10k), or `bench` (>10k).
  - `GLYPH_KZG_BN254_PROFILE=auto` uses `GLYPH_KZG_BN254_CONSTRAINTS` with the same thresholds.
- Profile version selector: `GLYPH_PROFILE_VERSION` (`basic` default, `cpu-aware` enables CPU-aware presets)
Adapter tuning knobs:
- IVC folding profile (prod): `chunk_size`, `recursion_limit`, and `parallel_threshold` control batch size, recursion cap, and when to parallelize.
- STARK field profiles:
  - M31 Circle: `stark_field_profile_m31_circle()`
  - Baby Bear Circle: `stark_field_profile_baby_bear_circle()`
  - Goldilocks Winterfell: `stark_field_profile_goldilocks_winterfell()`
  Each field profile specifies `fri_fold_factor` and `query_count`.
Acceleration selector:
- `GLYPH_ACCEL_PROFILE` values: `cpu` (default), `cuda`, or `cpu-cuda`. Aliases: `cpu-only`, `cpu_only`, `cpu+cuda`, `cpu_cuda`.
- `cpu`: forces CPU-only (standard profile, sets `GLYPH_CUDA=0`).
- `cuda`: enables mixed CPU + CUDA (sets `GLYPH_CUDA=1`, `GLYPH_CUDA_MIN_ELEMS=1`, `GLYPH_CUDA_BN254_MIN_ELEMS=32768`).
- CPU SIMD dispatch (AVX512, AVX2, NEON) is selected by feature detection only; no workload-size threshold is applied in `src/glyph_field_simd.rs`.

Profile CPU-aware highlights (Groth16 and KZG):
- Alternate scalar and MSM window presets tuned for modern CPU SIMD backends.
- Preserves pairing trace precompute toggles (fixed-base, IC, G2) and KZG joint MSM defaults.
Profile defaults (Groth16 and KZG, basic and cpu-aware):
- Groth16 profiles use GLV scalar mul with wNAF and enable fixed-base, IC, and G2 precomputes by default.
- KZG profiles enable KZG joint MSM by default.

BN254 profile knobs (Groth16 and KZG) map to:
- `GLYPH_BN254_SCALAR_MUL`, `GLYPH_BN254_SCALAR_WINDOW`, `GLYPH_BN254_MSM_WINDOW`, `GLYPH_BN254_MSM_GLV`, `GLYPH_BN254_MSM_SMALL_THRESHOLD`, `GLYPH_BN254_MSM_PRECOMP_THRESHOLD`, `GLYPH_BN254_MSM_SHAMIR`
- `GLYPH_BN254_FIXED_BASE_PRECOMP`, `GLYPH_BN254_IC_PRECOMP_AUTO`, `GLYPH_BN254_G2_PRECOMP_AUTO`, `GLYPH_BN254_KZG_JOINT_MSM`
- `GLYPH_BN254_WNAF_SLOW` (debug), `GLYPH_GROTH16_BN254_TRACE_STATS`, `GLYPH_KZG_BN254_TRACE_STATS`, `GLYPH_BN254_TRACE_VALIDATE_BATCH`, `GLYPH_BN254_WITNESS_BATCH`, `GLYPH_BN254_WITNESS_BATCH_MIN`

STARK verification knobs (STARK KPI and tooling):
- `GLYPH_STARK_MIN_SECURITY` (default: 90, clamped to >= 90). Only raises the minimum security threshold.

Adapter VK bytes may include precomputed data (Groth16 G2Precomp/FullPrecomp, KZG G2Precomp), but pairing-trace generation derives precomputes directly from the VK when auto precompute flags are enabled. External precomp bytes are accepted for compatibility but ignored for trace safety.

Profiles are applied in adapter entrypoints (Groth16/KZG IR, IVC direct, STARK adapter, Hash IR, SP1, PLONK)
and do not affect on-chain bindings or encodings.

KPI harnesses:
- `scripts/benchmarks/bench_bn254_mul_kpi.sh` for BN254 field add, sub, and mul throughput.
- `scripts/benchmarks/bench_bn254_batch_kpi.sh` for BN254 batch add, sub, and mul throughput (CPU or CUDA).
- `scripts/benchmarks/bench_bn254_msm_kpi.sh` for BN254 MSM tracing and validation timing.
- `scripts/benchmarks/bench_bn254_g2_kpi.sh` for BN254 G2 scalar multiplication traces.
- `scripts/benchmarks/bench_bn254_trace_kpi.sh` for BN254 pairing-trace KPI data.
- `scripts/benchmarks/bench_glyph_adapter_kpi.sh` for Groth16, KZG, IVC, STARK, and Hash compile and prove KPIs.
- `scripts/benchmarks/bench_ivc_fold_kpi.sh` for IVC multilinear evaluation and folding KPIs (`scripts/out/benchmarks/ivc_fold_kpi.json`).
- `scripts/benchmarks/bench_ivc_parallel_profile.sh` for IVC thread-sweep profiling across Rayon thread counts (`scripts/out/benchmarks/ivc_parallel_profile.jsonl`).
- Use `GLYPH_ADAPTER_KPI_PROVE_REPEAT` to repeat proves; KPI JSON includes `prove_avg_ms` and `prove_repeat`.
- `GLYPH_ADAPTER_KPI_STARK_CIRCLE=1` switches STARK to the Circle STARK receipt fixture (`scripts/tools/fixtures/fast_circle_stark_receipt.txt`).
- `GLYPH_ADAPTER_KPI_STARK_CIRCLE_LARGE=1` switches STARK to the larger Circle STARK fixture (`scripts/tools/fixtures/fast_circle_stark_receipt_large.txt`).
- `GLYPH_ADAPTER_KPI_STARK_BABY_BEAR=1` switches STARK to the Baby Bear Circle STARK fixture (`scripts/tools/fixtures/fast_circle_stark_baby_bear_receipt.txt`).
- `GLYPH_ADAPTER_KPI_STARK_F64=1` switches STARK to the Winterfell F64 SHA3 receipt fixture (`scripts/tools/fixtures/fast_sha3_receipt_f64.txt`).
- `scripts/benchmarks/bench_glyph_zk_kpi.sh` for GLYPH-PROVER fast-mode vs zk-mode proof-size deltas.
- `scripts/benchmarks/bench_glyph_adapter_zk_kpi.sh` for adapter fast vs zk proof-size KPIs (Groth16, KZG, IVC, STARK, Hash).
  - `GLYPH_ADAPTER_ZK_KPI_STARK_CIRCLE=1` switches STARK to the Circle STARK receipt fixture.
  - `GLYPH_ADAPTER_ZK_KPI_STARK_CIRCLE_LARGE=1` switches STARK to the Circle STARK larger fixture (`scripts/tools/fixtures/fast_circle_stark_receipt_large.txt`).
  - `GLYPH_ADAPTER_ZK_KPI_STARK_BABY_BEAR=1` switches STARK to the Baby Bear Circle STARK fixture.
  - `GLYPH_ADAPTER_ZK_KPI_STARK_F64=1` switches STARK to the Winterfell F64 SHA3 receipt fixture.

KPI outputs are written to `scripts/out/benchmarks/` by default, with `*.meta.json` sidecars carrying
timestamp and git commit metadata. For published numbers, rerun the KPI scripts and archive the
resulting JSON outputs under `scripts/out/benchmarks/` before generating reports.

## Appendix F: Adapter Semantics and Digest Layout

This appendix records the canonical adapter encodings and binding helpers used by
GLYPH-Prover. The production pipeline verifies upstream proofs inside GLYPH-Prover
and derives the GLYPH artifact boundary. There is no on-chain IPA wrapper.

Legacy digest-only tooling has been removed from the repository. The remaining
adapter CLIs use adapter IR and the canonical `vk_bytes` and `statement_bytes`
formats described below.

### F.1 Encoding Notation (Normative, Canonical)

This spec uses the following notation and it MUST be interpreted strictly:

- `||` denotes byte concatenation.
- `u16_be(x)`, `u32_be(x)`, `u64_be(x)` are fixed-width, big-endian encodings of unsigned integers.
- `u128_be(x)` is a fixed-width, 16-byte, big-endian encoding of an unsigned 128-bit integer.
- `u256_be(x)` is a fixed-width, 32-byte, big-endian encoding of an unsigned 256-bit integer.
- `bytes32` is exactly 32 bytes.
- `keccak256(...)` is Ethereum Keccak-256 over bytes.

### F.2 Adapter Binding and Canonical Hashes

GLYPH-Prover binds adapter inputs via canonical `vk_bytes` and `statement_bytes`
encodings. The canonical hash rules are:

```
vk_hash = keccak256( keccak256("GLYPH_VK_HASH") || family_id || sub_id || vk_bytes )
statement_hash = keccak256( keccak256("GLYPH_STATEMENT_HASH") || family_id || sub_id || statement_bytes )
```

These hashes are used during adapter compilation and for audit trails. The on-chain
verifier only binds to the artifact boundary via `artifact_tag` (hash of commitment
and point) plus `claim128`, encoded in the packed header.

### F.3 Adapter Semantic Guarantee (Trustless Validity)

To treat a successful `GLYPHVerifier` fallback call (ABI-decoded return `1`) as equivalent to “the
external proof was valid”, the adapter must satisfy the following invariants:

1. **Language definition.** For a given adapter family `F`, the proven statement
   must be:

   > There exists an external proof `π_ext` and public inputs `x` such that
   > `Verify_F(vk, x, π_ext) = 1`, and `digest = keccak256(D_adapter^F || family_id ||
   > sub_id || chain_id || verifier_addr || vk_hash || statement_hash || proof_hash || pub_hash)`.

2. **Mandatory external verification.** The adapter must execute the full
   verification algorithm for the external proof system (or be embedded in a
   protocol that enforces this). It must never produce `(a, b, P)` for an
   external proof instance that would be rejected by `Verify_F`.

3. **Replay protection and binding.** The digest must bind to the chain and the
   verifier instance (see digest layout below), so a proof cannot be replayed
   across chains, contracts, or verification keys.

Without these invariants, GLYPH still proves a valid IPA relation, but the
application-level meaning (“what computation was verified?”) may be weaker than
direct on-chain verification.

### F.4 Digest Layout (Recommended)

For strong binding and forensic traceability, the digest layout is:

- `domain_tag`: 32-byte adapter domain tag (`D_adapter^F`)
- `family_id`: 4-byte identifier of the adapter family
- `sub_id`: 1-byte sub-identifier (used for SNARK sub-kinds)
- `chain_id`: canonical encoding of the L1 chain id
- `verifier_addr`: 20-byte address of the GLYPH verifier contract
- `vk_hash`: 32-byte hash of the external verification key
- `statement_hash`: 32-byte hash of the external public statement/inputs
- `proof_hash`: 32-byte hash of the external proof bytes
- `pub_hash`: 32-byte hash of the external public inputs

These fields are concatenated in a fixed order and domain-separated inside
`keccak256`. The Solidity verifier never parses these fields; they exist to
make the off-chain adapter semantics explicit, versioned, and auditable.

### F.5 Adapter Parameterization (Off-Chain)

Adapter parameter sizes do not affect the on-chain verifier. The packed sumcheck
proof size is independent of upstream proof sizes because adapters
hash-compress-commit their canonical receipts before compiling to GLYPH-IR.

Off-chain, each adapter chooses parameters based on its receipt format:

- **IPA** uses `IPAParams::new(n)` with `n` taken from the receipt. There is
  no fixed production `n`; the verifier is purely off-chain.
- **SNARK/IVC/STARK/Hash/Binius** validate receipts (where applicable) and then bind to
  `vk_hash` and `statement_hash` without packing upstream proofs into field
  elements.

### F.6 Canonical Adapter Families (Recommended)

For practical interoperability, it is useful to define a small set of canonical
adapter families. Each family fixes:

- the canonical parsing/encoding of `proof_bytes` and `pub_bytes`
- the domain tag `D_adapter^F`
- the vector-derivation rules from the digest

The following families are a conservative taxonomy that covers most systems in
practice:

- **Hash Adapter (A_HASH).**
  - Scope: deterministic SHA3 merge receipts.
  - Strategy: hash-compress-commit.
- **SNARK Adapter (A_SNARK).**
  - Sub-kinds: Groth16 BN254, KZG BN254, PLONK, Halo2 KZG, IPA BN254, SP1.
  - Scope: pairing-based SNARKs and IPA receipts with canonical encodings.
  - Strategy: verify the receipt with the appropriate backend, then hash-compress-commit.
  - Trustless validity: GLYPH-PROVER over pairing trace or dedicated custom gates, depending on sub-kind.
  - Note: wrapping Groth16 or PLONK here does not make it transparent. It only moves
    verification off-chain and reuses GLYPH's on-chain settlement.
- **STARK Goldilocks Adapter (A_STARK_GOLDILOCKS).**
  - Scope: Winterfell F64, Plonky2 Goldilocks, Miden Goldilocks, Plonky3 Goldilocks.
  - Strategy: always hash-compress-commit.
- **STARK BabyBear Adapter (A_STARK_BABYBEAR).**
  - Scope: Circle BabyBear and KoalaBear, Plonky3 BabyBear and KoalaBear, Standard FRI BabyBear (RISC Zero).
  - Strategy: always hash-compress-commit.
- **STARK M31 Adapter (A_STARK_M31).**
  - Scope: Cairo Starknet Prime (Starknet-with-Keccak layout, Stone6 monolith only), Stwo M31, Circle M31,
    Plonky3 M31.
  - Strategy: always hash-compress-commit.
- **IVC Adapter (A_IVC).**
  - Scope: BaseFold transparent PCS receipts and Nova-family formats (Nova, SuperNova, HyperNova, Sangria).
  - Strategy: verify the BaseFold transparent PCS opening and the transparent R1CS receipt, then verify
    the external Nova-family proofs, then hash-compress-commit.
  - Trustless validity: enforced for all supported IVC proof types.
- **Binius Adapter (A_BINIUS).**
  - Scope: Binius M3 constraint-system proofs.
  - Strategy: verify the Binius receipt and hash-compress-commit.

Domain tags can be instantiated as:

```text
D_adapter^HASH             = keccak256("GLYPH_ADAPTER_HASH")
D_adapter^SNARK            = keccak256("GLYPH_ADAPTER_SNARK")
D_adapter^STARK_GOLDILOCKS = keccak256("GLYPH_ADAPTER_STARK_GOLDILOCKS")
D_adapter^STARK_BABYBEAR   = keccak256("GLYPH_ADAPTER_STARK_BABYBEAR")
D_adapter^STARK_M31        = keccak256("GLYPH_ADAPTER_STARK_M31")
D_adapter^IVC              = keccak256("GLYPH_ADAPTER_IVC")
D_adapter^BINIUS           = keccak256("GLYPH_ADAPTER_BINIUS")
```

#### F.6.1 SNARK Groth16 BN254 Canonical Byte Encodings

**Groth16 BN254 VK Bytes (Basic):**
```
domain_tag(32 bytes, keccak("GLYPH_GROTH16_BN254_VK_BYTES")) || snark_id(u8) || curve_id(u8) ||
vk_hash(32) || input_layout_hash(32) || reserved(u16 BE = 0)
Total: 100 bytes
```

**Groth16 BN254 VK Bytes (G2 Precomp):**
```
domain_tag(32 bytes, keccak("GLYPH_GROTH16_BN254_VK_BYTES_G2_PRECOMP")) || snark_id(u8) || curve_id(u8) ||
vk_hash(32) || input_layout_hash(32) ||
beta_precomp_len(u32 BE) || beta_precomp ||
gamma_precomp_len(u32 BE) || gamma_precomp ||
delta_precomp_len(u32 BE) || delta_precomp ||
reserved(u16 BE = 0)
```

**Groth16 BN254 VK Bytes (Full Precomp with IC):**
```
domain_tag(32 bytes, keccak("GLYPH_GROTH16_BN254_VK_BYTES_FULL_PRECOMP")) || snark_id(u8) || curve_id(u8) ||
vk_hash(32) || input_layout_hash(32) ||
beta_precomp_len(u32 BE) || beta_precomp ||
gamma_precomp_len(u32 BE) || gamma_precomp ||
delta_precomp_len(u32 BE) || delta_precomp ||
ic_precomp_window(u8) || ic_precomp_count(u32 BE) ||
[repeated: base_precomp_len(u32) || base_precomp || phi_precomp_len(u32) || phi_precomp] ||
reserved(u16 BE = 0)
```

**Groth16 BN254 Statement Bytes:**
```
domain_tag(32 bytes, keccak("GLYPH_GROTH16_BN254_STATEMENT_BYTES")) || input_layout_hash(32) || public_inputs_hash(32)
Total: 96 bytes
```

#### F.6.2 SNARK KZG BN254 Canonical Byte Encodings

**KZG BN254 VK Bytes (Basic):**
```
domain_tag(32 bytes, keccak("GLYPH_KZG_BN254_VK_BYTES")) || snark_id(u8) || reserved(u8 = 0) ||
curve_id(u8 = 1) || reserved2(u8 = 0) ||
kzg_params_hash(32) || vk_hash(32) || input_layout_hash(32)
Total: 132 bytes
```

**KZG BN254 VK Bytes (G2s Precomp):**
```
domain_tag(32 bytes, keccak("GLYPH_KZG_BN254_VK_BYTES_G2S_PRECOMP")) || snark_id(u8) || curve_id(u8) ||
kzg_params_hash(32) || vk_hash(32) || input_layout_hash(32) ||
g2_s_precomp_len(u32 BE) || g2_s_precomp ||
reserved(u16 BE = 0)
```

**KZG BN254 Statement Bytes:**
```
domain_tag(32 bytes, keccak("GLYPH_KZG_BN254_STATEMENT_BYTES")) || input_layout_hash(32) || public_inputs_hash(32)
Total: 96 bytes
```

#### F.6.3 IVC Canonical Byte Encodings

**IVC VK Bytes:**
```
domain_tag(32 bytes, keccak("GLYPH_IVC_VK_BYTES")) || gkr_arity(u8 = 4) ||
gkr_rounds(u8) || claim_bits(u16 BE = 128) || proof_type(u8) || reserved(u8 = 0)
Total: 38 bytes
```

**IVC Statement Bytes:**
```
domain_tag(32 bytes, keccak("GLYPH_IVC_STATEMENT_BYTES")) || proof_type(u8) || reserved(u8 = 0) ||
commitment_tag(32) || point_tag(32) || claim128(16 bytes BE)
Total: 114 bytes
```
- `proof_type` values: `0x00` BaseFoldTransparent, `0x01` Nova, `0x02` SuperNova, `0x03` HyperNova, `0x04` Sangria.

**IVC Proof Bytes (versioned wrapper):**
```
domain_tag("GLYPH_IVC_PROOF") ||
enc_version(u16 BE = 2) ||
proof_type(u8) ||
payload_len(u32 BE) ||
payload_bytes
```
- For `proof_type = BaseFoldTransparent`, `payload_bytes` is the version 1 BaseFold PCS opening encoding (below).
- For `proof_type = Nova | SuperNova | HyperNova | Sangria`, `payload_bytes` is the canonical proof encoding for that proof type (below).

**IVC Proof Bytes (BaseFold PCS opening, version 1 payload):**
```
domain_tag("GLYPH_IVC_PROOF") ||
enc_version(u16 BE = 1) ||
n_vars(u32 BE) ||
instance_digests_len(u32 BE) || [instance_digest; 32 bytes] * len ||
weights_len(u32 BE) || [weight; 16 bytes BE] * len ||
commitment_root(32) ||
commitment_depth(u32 BE) ||
commitment_n_vars(u32 BE) ||
commitment_security_bits(u16 BE) ||
commitment_security_target_bits(u16 BE) ||
commitment_log_inv_rate(u16 BE) ||
commitment_fold_arity(u16 BE) ||
eval_point_len(u32 BE) || [eval_point_i; 16 bytes BE] * len ||
claimed_eval(16 bytes BE) ||
proof_bytes_len(u32 BE) || proof_bytes
```

`proof_bytes` (BaseFold proof bundle):
```
BASEFOLD_PROOF_TAG ||
basefold_version(u16 BE) ||
proof_count(u16 BE) ||
[proof_transcript_len(u32 BE) || proof_transcript] * count
```

**IVC Proof Bytes (Nova, version 2 payload):**
```
domain_tag("GLYPH_IVC_NOVA_PROOF") ||
enc_version(u16 BE = 2) ||
u(32) || e_commitment(32) || w_commitment(32) ||
public_inputs_len(u32 BE) || [public_input; 32] * len ||
t_commitment(32) || acc_u(32) || acc_e_commitment(32) || acc_w_commitment(32) ||
snark_flag(u8) || [snark_len(u32 BE) || snark_bytes] if flag = 1 ||
r1cs_receipt_len(u32 BE) || r1cs_receipt_bytes
```
Nova external proofs (when `snark_flag = 1`) must be encoded with the
`GLYPH_IVC_NOVA_EXTERNAL` domain and versioned wrapper in `src/ivc_nova.rs`.
A deterministic fixture for the default receipt lives at
`scripts/tools/fixtures/ivc_nova_external_proof.txt`.

**IVC Proof Bytes (SuperNova, version 2 payload):**
```
domain_tag("GLYPH_IVC_SUPERNOVA_PROOF") ||
enc_version(u16 BE = 2) ||
num_circuits(u16 BE) || selector_index(u16 BE) ||
running_instance_commitments_len(u32 BE) || [commitment; 32] * len ||
step_u(32) || step_e_commitment(32) || step_w_commitment(32) || step_t_commitment(32) ||
public_inputs_len(u32 BE) || [public_input; 32] * len ||
snark_flag(u8) || [snark_len(u32 BE) || snark_bytes] if flag = 1 ||
r1cs_receipt_len(u32 BE) || r1cs_receipt_bytes
```

**IVC Proof Bytes (HyperNova, version 2 payload):**
```
domain_tag("GLYPH_IVC_HYPERNOVA_PROOF") ||
enc_version(u16 BE = 2) ||
num_vars(u32 BE) || num_constraints(u32 BE) || degree(u16 BE) ||
ccs_commitment(32) ||
sumcheck_len(u32 BE) || sumcheck_bytes ||
final_claim(32) ||
pcs_opening_len(u32 BE) || pcs_opening_bytes ||
public_inputs_len(u32 BE) || [public_input; 32] * len ||
snark_flag(u8) || [snark_len(u32 BE) || snark_bytes] if flag = 1 ||
r1cs_receipt_len(u32 BE) || r1cs_receipt_bytes
```
HyperNova external proofs (when `snark_flag = 1`) must be encoded with the
`GLYPH_IVC_HYPERNOVA_EXTERNAL` domain and versioned wrapper in `src/ivc_hypernova.rs`.
A deterministic fixture for the default receipt lives at
`scripts/tools/fixtures/ivc_hypernova_external_proof.txt`.

**IVC Proof Bytes (Sangria, version 2 payload):**
```
domain_tag("GLYPH_IVC_SANGRIA_PROOF") ||
enc_version(u16 BE = 2) ||
num_wires(u16 BE) ||
wire_commitments_len(u32 BE) || [commitment; 32] * len ||
acc_commitment(32) ||
t_commitment(32) ||
folding_challenge(32) ||
opening_proof_len(u32 BE) || opening_proof_bytes ||
public_inputs_len(u32 BE) || [public_input; 32] * len ||
snark_flag(u8) || [snark_len(u32 BE) || snark_bytes] if flag = 1 ||
r1cs_receipt_len(u32 BE) || r1cs_receipt_bytes
```
Sangria external proofs (when `snark_flag = 1`) must be encoded with the
`GLYPH_IVC_SANGRIA_EXTERNAL` domain and versioned wrapper in `src/ivc_sangria.rs`.
A deterministic fixture for the default receipt lives at
`scripts/tools/fixtures/ivc_sangria_external_proof.txt`.

**IVC Transparent R1CS receipt (version 1):**
```
domain_tag("GLYPH_IVC_R1CS") ||
enc_version(u16 BE = 1) ||
num_vars(u32 BE) ||
num_constraints(u32 BE) ||
[constraint] * num_constraints ||
witness_len(u32 BE) || [witness_i; 32] * len ||
u(32) ||
error_len(u32 BE) || [error_i; 32] * len
```
Where each `constraint` is:
```
a_terms_len(u32 BE) || (var_idx(u32 BE) || coeff(32)) * len ||
b_terms_len(u32 BE) || (var_idx(u32 BE) || coeff(32)) * len ||
c_terms_len(u32 BE) || (var_idx(u32 BE) || coeff(32)) * len
```
Receipt validation rules:
- `witness_len == num_vars`, `error_len == num_constraints`, `witness[0] == 1`.
- All coefficients and witness elements are canonical BN254 field elements.
- For each constraint: `(A·Z) * (B·Z) == u * (C·Z) + error[i]` (relaxed R1CS).

**IVC Nova-family canonical constraints (enforced in verification):**
- `public_inputs_len = 0`, optional proof blobs are empty for `sumcheck`, `pcs_opening`, and `opening_proof`.
- `snark_proof` is required for Nova, SuperNova, HyperNova, and Sangria and must verify against the canonical receipt.
- All proof fields are deterministic from the receipt hash: `receipt_hash = keccak256(r1cs_receipt_bytes)`.
  - Nova: `u`, `e_commitment`, `w_commitment`, `t_commitment`, `acc_u`, `acc_e_commitment`, `acc_w_commitment` are `keccak256(DOMAIN || receipt_hash)` with the domain tags in `src/ivc_adapter.rs`.
  - SuperNova: `num_circuits = 1`, `selector_index = 0`, `running_instance_commitments[0] = keccak256(DOMAIN || receipt_hash || 0)`, and step fields are `keccak256(DOMAIN || receipt_hash)`.
  - HyperNova: `degree = 2`, `ccs_commitment` and `final_claim` are `keccak256(DOMAIN || receipt_hash)`, `num_vars` and `num_constraints` match the receipt.
  - Sangria: `num_wires = 1`, `wire_commitments[0] = keccak256(DOMAIN || receipt_hash || 0)`, and `acc_commitment`, `t_commitment`, `folding_challenge` are `keccak256(DOMAIN || receipt_hash)`.

**BaseFold PCS proof transcript bundle (proof\_bytes):**
```
BASEFOLD_PROOF_TAG ("GLYPH_PCS_BASEFOLD") ||
basefold_version(u16 BE = 1) ||
proof_count(u16 BE) ||
[proof_transcript_len(u32 BE) || proof_transcript] * count
```
- Commitment binding uses `derive_basefold_commitment_tag` with `DOMAIN_PCS_BASEFOLD_COMMIT`.

#### F.6.4 IPA Adapter Canonical Byte Encodings

The IPA adapter defines canonical encodings for IPA proofs (e.g. Halo2-IPA receipts).

`receipt_bytes` layout (canonical):
- `domain_tag = b"GLYPH_SNARK_IPA_RECEIPT"` (23 bytes)
- `curve_id = u8`
- `backend_id = u8`
- `encoding_id = u8`
- `transcript_id = u8`
- `n = u16_be` (domain size)
- `pub_len = u16_be`
- `[public_inputs; pub_len]` (32 bytes each, Fr)
- `commitment_bytes = [u8; commitment_len]`
- `proof_len = u32_be`
- `proof_bytes = [u8; proof_len]`

`curve_id` values:
- `0x01` BN254
- `0x02` BLS12-381

`backend_id` values:
- `0x01` Halo2 IPA
- `0x02` Generic IPA

`encoding_id` values:
- `0x01` BN254 big-endian 32-byte field elements
- `0x02` BLS12-381 big-endian 48-byte field elements

`commitment_len` values:
- `64` for BN254 (x || y, 32 bytes each)
- `96` for BLS12-381 (x || y, 48 bytes each)

`transcript_id` values:
- `0x01` GLYPH IPA transcript (keccak)

Statement binding:
- `statement_hash = keccak256(SNARK_IPA_STATEMENT_DOMAIN || public_inputs_bytes)`
- Statement hash is bound into the IPA transcript before verification.

#### F.6.5 Hash Canonical Byte Encodings

**Hash VK Bytes:**
```
domain_tag(32 bytes, keccak("GLYPH_HASH_VK_BYTES")) || hash_id(u8) ||
reserved(u8 = 0) || msg_len(u32 BE)
Total: 38 bytes
```

**Hash Statement Bytes (64-byte merge):**
```
domain_tag(32 bytes, keccak("GLYPH_HASH_STATEMENT_BYTES")) || hash_id(u8) ||
reserved(u8 = 0) || msg_len(u32 BE) ||
left(32) || right(32) || digest(32)
Total: 134 bytes
```

#### F.6.6 SP1 Canonical Byte Encodings

`receipt_bytes` layout (fixed):
```
domain_tag("GLYPH_SP1_RECEIPT") ||
proof_system(u8) ||
vkey_hash_len(u16 BE) || vkey_hash_ascii_bytes ||
public_inputs_len(u32 BE) || public_inputs_bytes ||
proof_len(u32 BE) || proof_bytes
```

`proof_system` values:
- `0x01` Groth16 (BN254)
- `0x02` Plonk (BN254)

`vkey_hash` is the ASCII hex string returned by `vk.bytes32()` in the SP1 SDK (canonical lowercase with a `0x` prefix).
`public_inputs` are the raw SP1 public values bytes (e.g. `SP1ProofWithPublicValues::public_values.to_vec()`), not ABI-encoded.
The SP1 verifier hashes `public_inputs` with SHA256, masks the top 3 bits, and maps the result into BN254 field elements alongside the decoded vkey hash.

#### F.6.7 PLONK and Halo2 Canonical Byte Encodings

##### F.6.7.1 PLONK receipts

Canonical layout:
```
domain_tag("GLYPH_PLONK_RECEIPT") ||
curve_id(u8) || backend_id(u8) || encoding_id(u8) || pcs_id(u8) || protocol_id(u8) || transcript_id(u8) ||
backend_params_len(u32 BE) || backend_params_bytes ||
vk_len(u32 BE) || vk_bytes ||
public_inputs_len(u32 BE) || public_inputs_bytes ||
proof_len(u32 BE) || proof_bytes
```

`curve_id` values:
- `0x01` BN254
- `0x02` BLS12-381

`backend_id` values:
- `0x01` gnark
- `0x02` dusk
- `0x03` generic

`encoding_id` values:
- `0x01` BN254 big-endian 32-byte field elements (canonical)
- `0x02` BLS12-381 little-endian 32-byte field elements (canonical dusk scalars)
- `0x03` Halo2 instances encoding (canonical)

`pcs_id` values:
- `0x01` KZG

`protocol_id` values:
- `0x01` PLONK

`transcript_id` values:
- `0x01` native
- `0x02` Blake2b

`backend_params_bytes`:
- Empty for gnark and dusk backends.
- For generic backend:
```
tag("GLYPH_PLONK_GENERIC_PARAMS") ||
backend_kind(u8) ||
payload_len(u32 BE) || payload_bytes
```
- `backend_kind` values: `0x01` halo2, `0x02` gnark, `0x03` dusk.
- For `backend_kind = halo2`, `payload_bytes` is:
```
tag("GLYPH_PLONK_HALO2_PARAMS") ||
halo2_backend_id(u8) || circuit_id(u8) || compress_selectors(u8) ||
params_len(u32 BE) || params_bytes ||
circuit_params_len(u32 BE) || circuit_params_bytes
```

`halo2_backend_id` values:
- `0x01` KZG GWC
- `0x02` KZG SHPLONK

`circuit_id` values:
- `0x01` standard-plonk
- `0x02` parametric-plonk
- `0x03` custom-plonk

Receipt metadata and backend params hash are bound into the artifact tags.

##### F.6.7.2 Halo2 KZG receipts

Canonical layout:
```
domain_tag("GLYPH_HALO2_RECEIPT") ||
curve_id(u8) || backend_id(u8) || transcript_id(u8) || circuit_id(u8) ||
compress_selectors(u8) ||
circuit_params_len(u32 BE) || circuit_params_bytes ||
params_len(u32 BE) || params_bytes ||
vk_len(u32 BE) || vk_bytes ||
instances_len(u32 BE) || instances_bytes ||
proof_len(u32 BE) || proof_bytes
```

`curve_id` values:
- `0x01` BN256
- `0x02` BLS12-381

`backend_id` values:
- `0x01` KZG GWC
- `0x02` KZG SHPLONK

`transcript_id` values:
- `0x01` Blake2b

`circuit_id` values:
- `0x01` standard-plonk
- `0x02` parametric-plonk
- `0x03` custom-plonk

`circuit_params_bytes` for parametric-plonk:
```
tag("GLYPH_HALO2_CIRCUIT_PARAMS") ||
rows(u32 BE) ||
repeat rows times:
  q_a(u64 BE) || q_b(u64 BE) || q_c(u64 BE) || q_ab(u64 BE) || constant(u64 BE)
```

`circuit_params_bytes` for custom-plonk:
```
tag("GLYPH_HALO2_CIRCUIT_CUSTOM") ||
num_fixed(u32 BE) || num_advice(u32 BE) || num_instance(u32 BE) || num_challenges(u32 BE) ||
unblinded_len(u32 BE) || unblinded_idx[u32 BE] * ||
advice_phase_len(u32 BE) || advice_phase[u8] * ||
challenge_phase_len(u32 BE) || challenge_phase[u8] * ||
gate_len(u32 BE) || (gate_name, gate_poly) * ||
perm_len(u32 BE) || column * ||
lookup_len(u32 BE) || (lookup_name, input_exprs, table_exprs) * ||
shuffle_len(u32 BE) || (shuffle_name, input_exprs, shuffle_exprs) * ||
annotations_len(u32 BE) || (column, label) * ||
min_degree_present(u8) || [min_degree(u32 BE) if present]
```

`column` encoding:
```
col_type(u8: 0x00 instance, 0x01 advice, 0x02 fixed) || col_index(u32 BE)
```

`string` encoding:
```
len(u32 BE) || utf8_bytes
```

`gate_poly`, `input_exprs`, `table_exprs`, and `shuffle_exprs` use the canonical expression encoding:
```
expr_tag(u8) || expr_payload
```

`expr_tag` values:
- `0x00` constant (field repr bytes)
- `0x01` var
- `0x02` neg
- `0x03` sum
- `0x04` product

`var` encoding:
```
var_tag(u8) || var_payload
```

`var_tag` values:
- `0x00` query: column || rotation(i32 BE)
- `0x01` challenge: challenge_index(u32 BE) || challenge_phase(u8)

Standard-plonk requires empty `circuit_params_bytes`. Parametric-plonk and custom-plonk require non-empty `circuit_params_bytes` with the corresponding tag.

Receipt metadata and circuit params hash are bound into the artifact tags.

#### F.6.8 Binius Canonical Byte Encodings

**Binius VK bytes (fixed layout):**
```
domain_tag(32 bytes, keccak("GLYPH_BINIUS_VK_BYTES")) ||
log_inv_rate(u8) ||
security_bits(u16 BE) ||
reserved(u8 = 0) ||
cs_len(u32 BE) || cs_bytes
```

**Binius statement bytes (fixed layout):**
```
domain_tag(32 bytes, keccak("GLYPH_BINIUS_STATEMENT_BYTES")) ||
boundaries_len(u32 BE) || boundaries_bytes
```

`cs_bytes` and `boundaries_bytes` are serialized using Binius CanonicalTower mode.

**Binius proof bytes (fixed layout):**
```
proof_tag("GLYPH_BINIUS_PROOF") ||
transcript_len(u32 BE) || transcript_bytes
```

The adapter verifies the proof against the canonical constraint system and boundaries, then binds the result into the GLYPH artifact tags.

#### F.6.9 Adapter Profile System

The adapter system uses profiles to configure BN254 trace generation and acceleration:

**Bn254TraceProfile:**
- `scalar_mul`: Scalar multiplication mode ("glv" recommended)
- `scalar_window`: Window size for scalar mul (4-6)
- `msm_window`: Optional MSM window size
- `msm_glv`: Enable GLV decomposition for MSM
- `fixed_base_precomp`: Enable fixed-base precomputation
- `ic_precomp_auto`: Enable IC precomputation autogen
- `g2_precomp_auto`: Enable G2 precomputation autogen
- `kzg_joint_msm`: Enable joint MSM for KZG

**Environment Variables for Profile Control:**
- `GLYPH_GROTH16_BN254_PROFILE`: prod|fast|bench|single|auto
- `GLYPH_KZG_BN254_PROFILE`: prod|fast|bench|single|auto
- `GLYPH_IVC_PROFILE`: prod|fast|bench
- `GLYPH_STARK_PROFILE`: prod|fast|bench
- `GLYPH_HASH_PROFILE`: prod|fast|bench
- `GLYPH_ACCEL_PROFILE`: cpu|cuda|cpu-cuda (controls CUDA acceleration)
- `GLYPH_PROFILE_VERSION`: cpu-aware (enables CPU-aware presets)


### F.6 Canonical Automatic Policy (No Caller Switch)

To keep adapter usage simple and prevent caller-controlled ambiguity, an adapter
family should expose a single canonical policy:

- it chooses hash-compress-commit vs any direct packing automatically
- the caller does not provide flags or modes

For production, the policy is effectively “always hash-compress-commit” for
external proofs. The packed sumcheck verifier does not parse or verify the
external proof system on-chain.

### F.7 Field Compatibility Notes

External proofs may operate over fields unrelated to the BN254 scalar field. The
hash-compress-commit pattern avoids direct field arithmetic by operating on a
256-bit digest that is always well-defined.

If an adapter chooses to include selected public inputs directly in `pub_bytes`,
common compatibility patterns are:

- **M31 (31-bit elements):** pack multiple elements into a byte string and hash.
- **Baby Bear (31-bit elements):** pack multiple elements into a byte string and hash.
- **BLS12-381 field elements:** hash the canonical encoding (or reduce modulo
  BN254 scalar order if a reduction is explicitly part of the adapter spec).
- **Goldilocks (64-bit):** pack into bytes, then hash.

### F.8 Quantitative Rationale for Excluded On-Chain Constructions

The on-chain verifier in this repository is intentionally restricted to the
packed sumcheck circuit. Common alternatives are excluded for concrete gas
reasons:

- **Pairing-based SNARK verification on-chain.**
  - BN254 pairing precompile cost under EIP-1108 is `45,000 + 34,000·k` gas for
    `k` pairs.
  - Minimal Groth16 verification uses at least 3 pairings, implying ≳113,000 gas
    in pairings alone, before calldata, hashing, or other arithmetic.
- **On-chain point compression for large elliptic-curve payloads.**
  - Recovering `y` from an `x`-coordinate requires modular square roots.
  - Using `modexp`-style exponentiation per point is typically tens of thousands
    of gas; for large calldata payloads, the extra execution cost outweighs the
    calldata savings.
- **STARK/GKR verifiers on-chain.**
  - Proof sizes are typically tens to hundreds of kilobytes, so calldata and
    hashing dominate gas cost.

These exclusions are not claims about impossibility, but design constraints to
preserve the fixed verifier profile used throughout the codebase.

### 4. Testing and Tooling

- **Consolidated Test Suite**: The primary entry point for all tests (Rust unit tests, Solidity generation, Foundry integration tests) is the runner script:
  ```bash
  ./scripts/tests/run_tests.sh
  ```
  This script ensures that the Rust prover logic is synchronized with the Solidity test vectors before running the Foundry suite.

- **Deterministic CI**: `scripts/build/ci_deterministic_run.sh` pins toolchains via `RUSTUP_TOOLCHAIN`, validates build cache state, logs cleanups, and writes metadata under `scripts/out/ci/` (one `.meta.json` per run). The CI workflow in `.github/workflows/ci.yml` runs the preset build matrix (`default`, `snark`, `ivc`, `hash`, `binius`, `stark-babybear`, `stark-goldilocks`, `stark-m31`), a default test run, non-default preset test runs (snark, ivc, hash, binius, stark-babybear, stark-goldilocks, stark-m31) via `ci_deterministic_run.sh --cmd test`, and a short fuzz pass.
- **Feature matrix runner**: `scripts/tests/run_feature_matrix.sh --matrix ci|extended|full` runs the build preset matrix through `ci_deterministic_run.sh`, with optional default tests via `--with-tests`. Presets `core` and `full` are opt-in; `cuda` is opt-in via `GLYPH_MATRIX_CUDA=1` and can be required via `GLYPH_MATRIX_REQUIRE_CUDA=1`. The `full` preset is skipped if free disk is below `GLYPH_MATRIX_FULL_MIN_KB` unless `GLYPH_MATRIX_REQUIRE_FULL=1` is set. When `--with-tests` is used, the runner performs `cargo clean` by default to control disk usage; set `GLYPH_MATRIX_CLEAN_BEFORE_TESTS=0` to skip the cleanup.
- **Build presets**: `scripts/build/glyph_build.sh --preset` supports `default`, `core`, `snark`, `ivc`, `hash`, `binius`, `stark-babybear`, `stark-goldilocks`, `stark-m31`, `cuda`, and `full`. Use `--adapters` for explicit adapter sets.
- **Preset build scope**: non-default presets build the library target (`--lib`) by design to avoid compiling CLI binaries that require disabled adapter features. Preset `full` builds full binaries.
- **Preset matrix**:

  | Preset             | Cargo flags             | Features                        |
  |--------------------|-------------------------|---------------------------------|
  | `default`          | (default features)      | repo defaults                   |
  | `core`             | `--no-default-features` | `adapter-core`                  |
  | `snark`            | `--no-default-features` | `adapter-core,snark`            |
  | `ivc`              | `--no-default-features` | `adapter-core,ivc`              |
  | `hash`             | `--no-default-features` | `adapter-core,hash`             |
  | `binius`           | `--no-default-features` | `adapter-core,binius`           |
  | `stark-babybear`   | `--no-default-features` | `adapter-core,stark-babybear`   |
  | `stark-goldilocks` | `--no-default-features` | `adapter-core,stark-goldilocks` |
  | `stark-m31`        | `--no-default-features` | `adapter-core,stark-m31`        |
  | `cuda`             | `--no-default-features` | `adapter-core,cuda`             |
  | `full`             | `--no-default-features` | `full`                          |
  
- **CI preset coverage**: The CI build matrix uses `default`, `snark`, `ivc`, `hash`, `binius`, `stark-babybear`, `stark-goldilocks`, and `stark-m31`. The CI test matrix runs non-default presets with `--no-default-features` and `adapter-core,<preset>` features for snark, ivc, hash, binius, stark-babybear, stark-goldilocks, and stark-m31. Presets `core`, `cuda`, and `full` are manual or release-only by design.
- **Feature-matrix guardrails**: combinations outside the preset matrix are not validated by CI and must be built explicitly via `scripts/build/glyph_build.sh --preset` or the feature matrix runner.
- **Exit codes**: tool scripts return `2` for invalid input or missing tools, and `1` for runtime failures.
- **Benchmark metadata**: `bench_finalize` emits `bench_meta_v1` with `schema_version`, `bench_name`, `script`, `out_file`, `timestamp`, `run_id`, `git_commit`, and `status`.
- **JavaScript tooling**: When JS tooling is required, bun is preferred. Node, npm, and npx are supported fallbacks.
#### 4.1 Tooling Inventory (scripts/)

This is the SSOT list of non-vendor tooling under `scripts/`. Data fixtures and generated artifacts are indexed in `docs/map.md`.

##### Benchmarks

| Script                                                       | Role                                                                        |
| ------------------------------------------------------------ | --------------------------------------------------------------------------- |
| `scripts/benchmarks/common.sh`                               | Shared benchmark helpers and standardized output                            |
| `scripts/benchmarks/run_all.sh`                              | One-shot benchmark runner by preset                                         |
| `scripts/benchmarks/registry.json`                           | Canonical benchmark registry                                                |
| `scripts/benchmarks/profile_perf_config.sh`                  | Offline perf profile runner and config snapshot                             |
| `scripts/benchmarks/send_raw_tx.sh`                          | Raw calldata tx send helper (cast)                                          |
| `scripts/benchmarks/bench_glyph_evm_local.sh`                | Local Anvil gas bench for GLYPHVerifier                                     |
| `scripts/benchmarks/bench_glyph_evm_round_sweep.sh`          | Local Anvil gas bench round sweep                                           |
| `scripts/benchmarks/bench_glyph_evm_realproof.sh`            | Local Anvil gas bench using real prover path                                |
| `scripts/benchmarks/bench_glyph_evm_artifact.sh`             | Local Anvil gas bench for artifact-poly layout                              |
| `scripts/benchmarks/bench_glyph_evm_sepolia.sh`              | Sepolia gas estimate bench with optional tx send                            |
| `scripts/benchmarks/bench_glyph_sepolia_stmt.sh`             | Sepolia artifact-poly gas bench (historical `stmt` name)                    |
| `scripts/benchmarks/bench_glyph_sepolia_artifact.sh`         | Sepolia artifact-poly gas bench                                             |
| `scripts/benchmarks/bench_glyph_hoodi_artifact_truncated.sh` | Hoodi artifact-poly truncated gas bench                                     |
| `scripts/benchmarks/bench_glyph_adapter_hoodi.sh`            | Hoodi adapter gas bench using Foundry vectors re-bound to the live verifier |
| `scripts/benchmarks/bench_glyph_adapter_kpi.sh`              | Adapter KPI (Groth16, KZG, IVC, STARK, Hash)                                |
| `scripts/benchmarks/bench_glyph_adapter_zk_kpi.sh`           | Adapter KPI in ZK mode                                                      |
| `scripts/benchmarks/bench_glyph_zk_kpi.sh`                   | Proof size KPI, fast mode vs ZK mode                                        |
| `scripts/benchmarks/bench_glyph_cuda_kpi.sh`                 | CUDA KPI (disabled by policy; set `GLYPH_ENABLE_CUDA_BENCH=1` to run)       |
| `scripts/benchmarks/bench_bn254_batch_kpi.sh`                | BN254 batch KPI harness                                                     |
| `scripts/benchmarks/bench_bn254_g2_kpi.sh`                   | BN254 G2 window sweep KPI harness                                           |
| `scripts/benchmarks/bench_bn254_msm_kpi.sh`                  | BN254 MSM KPI harness                                                       |
| `scripts/benchmarks/bench_bn254_mul_kpi.sh`                  | BN254 field add, sub, mul KPI harness                                       |
| `scripts/benchmarks/bench_bn254_trace_kpi.sh`                | BN254 trace KPI harness                                                     |
| `scripts/benchmarks/bench_basefold_arity_sweep.sh`           | BaseFold arity sweep                                                        |
| `scripts/benchmarks/bench_basefold_mem_sweetspot.sh`         | BaseFold memory sweet spot sweep                                            |
| `scripts/benchmarks/bench_basefold_trace_profile.sh`         | BaseFold trace profile                                                      |
| `scripts/benchmarks/bench_ivc_fold_kpi.sh`                   | IVC fold KPI harness                                                        |
| `scripts/benchmarks/bench_ivc_parallel_profile.sh`           | IVC fold parallel profile sweep                                             |
| `scripts/benchmarks/bench_packed_gkr_layout_sweep.sh`        | Packed GKR layout sweep                                                     |
| `scripts/benchmarks/bench_stark_do_work_kpis.sh`             | STARK do_work KPI workload                                                  |
| `scripts/benchmarks/bench_state_diff_compile_prove.sh`       | State diff compile and prove KPI harness                                    |
| `scripts/benchmarks/bench_state_diff_merkle.sh`              | State diff merkle KPI harness                                               |
| `scripts/benchmarks/bench_state_diff_prover_profile.sh`      | State diff merkle vs prover profile                                         |
| `scripts/benchmarks/bench_state_transition_vm.sh`            | State transition VM execution and compile KPI                               |
| `scripts/benchmarks/bench_groth16_sepolia.sh`                | Groth16 gas estimate bench on Sepolia                                       |
| `scripts/benchmarks/bench_groth16_hoodi.sh`                  | Groth16 gas estimate bench on Hoodi                                         |
| `scripts/benchmarks/groth16_compare/build_groth16.sh`        | Groth16 compare build pipeline (circom, snarkjs)                            |
| `scripts/benchmarks/groth16_compare/calc_calldata_stats.sh`  | Groth16 calldata stats from artifacts                                       |
| `scripts/benchmarks/groth16_compare/package.json`            | Node dependencies for circom and snarkjs                                    |
| `scripts/benchmarks/groth16_compare/package-lock.json`       | Locked dependency graph                                                     |
| `scripts/benchmarks/groth16_compare/circuit.circom`          | Base circuit source                                                         |
| `scripts/benchmarks/groth16_compare/circuit_many.circom`     | Many-input circuit source                                                   |
| `scripts/benchmarks/groth16_compare/input_many.json`         | Many-input circuit example inputs                                           |

Note: Groth16 artifacts are generated under `scripts/out/benchmarks/groth16_compare/` (or `scripts/out/benchmarks/groth16_compare_many/` when using `circuit_many`).

##### Build and CI

| Script                                     | Role                                                                 |
|--------------------------------------------|----------------------------------------------------------------------|
| `scripts/build/glyph_build.sh`             | Build preset wrapper with adapter feature selection                  |
| `scripts/build/ci_deterministic_run.sh`    | Deterministic CI runner with cache validation and metadata logging   |

##### Deploy Tooling

| File                                       | Role                                                  |
|--------------------------------------------|-------------------------------------------------------|
| `scripts/deploy/deploy_glyph_contract.sh`  | Deploy GLYPHVerifier and emit deployment metadata     |
| `scripts/deploy/verify_glyph_contract.sh`  | Verify GLYPHVerifier on Etherscan                     |
| `scripts/deploy/.env.sepolia`              | Network env (contains secrets, local-only)            |
| `scripts/deploy/.env.hoodi`                | Network env (contains secrets, local-only)            |
| `scripts/deploy/.env.sepolia.example`      | Example env template                                  |
| `scripts/deploy/.env.hoodi.example`        | Example env template                                  |
| `scripts/deploy/.env.wallet.example`       | Example wallet env template                           |
| `scripts/deploy/.env.network.example`      | Example network env template                          |

##### DA Tooling

| Script                                     | Role                                                  |
|--------------------------------------------|-------------------------------------------------------|
| `scripts/da/submit_blob.sh`                | Blob submit via `cast send --blob`                    |
| `scripts/da/fetch_blob.sh`                 | Blob fetch via URL template or Beacon API             |
| `scripts/da/submit_arweave.sh`             | Arweave submit via Turbo or external command          |
| `scripts/da/fetch_arweave.sh`              | Arweave fetch via gateway                             |
| `scripts/da/submit_eigenda.sh`             | EigenDA submit via proxy or Go client                 |
| `scripts/da/poll_eigenda.sh`               | EigenDA poll to finalize pending requests             |
| `scripts/da/fetch_eigenda.sh`              | EigenDA fetch via retriever or proxy                  |
| `scripts/da/run_profile.sh`                | Single-entry DA runner with presets and env checks    |
| `scripts/da/run_all_profiles.sh`           | Run all DA profiles end to end                        |
| `scripts/da/smoke_test.sh`                 | Single profile smoke test runner                      |
| `scripts/da/arweave_local_smoke.sh`        | Local Arweave smoke test using arlocal                |
| `scripts/da/state_diff_from_snapshots.sh`  | Build state diff JSON and bytes from snapshots        |
| `scripts/da/state_diff_proof_flow.sh`      | State diff to proof bundle pipeline                   |
| `scripts/da/state_diff_onchain_verify.sh`  | Submit root update with proof calldata                |
| `scripts/da/state_transition_vm_flow.sh`   | State transition VM flow and proof bundle             |
| `scripts/da/fetch_eigenda_v2_srs.sh`       | Fetch EigenDA v2 SRS assets into the repo-local cache |

##### DA Provider Helpers

| File                                            | Role                                 |
|-------------------------------------------------|--------------------------------------|
| `scripts/da/providers/check_providers.sh`       | Provider toolchain smoke checks      |
| `scripts/da/providers/package.json`             | Provider-side Node dependencies      |
| `scripts/da/providers/package-lock.json`        | Provider-side Node lockfile          |
| `scripts/da/providers/arweave_turbo_upload.mjs` | Arweave Turbo upload helper          |
| `scripts/da/providers/eigenda_v1/main.go`       | EigenDA v1 Go client                 |
| `scripts/da/providers/eigenda_v1/go.mod`        | EigenDA v1 Go module manifest        |
| `scripts/da/providers/eigenda_v1/go.sum`        | EigenDA v1 Go module lockfile        |
| `scripts/da/providers/eigenda_v2/main.go`       | EigenDA v2 Go client                 |
| `scripts/da/providers/eigenda_v2/go.mod`        | EigenDA v2 Go module manifest        |
| `scripts/da/providers/eigenda_v2/go.sum`        | EigenDA v2 Go module lockfile        |

Note: optional generated binaries (for example `scripts/out/da/providers/eigenda_v2_client`) are not committed. After running `scripts/da/fetch_eigenda_v2_srs.sh`, the SRS assets live under `scripts/da/srs/eigenda_v2/`.

##### Test Harness Scripts

| Script                               | Role                                            |
|--------------------------------------|-------------------------------------------------|
| `scripts/tests/run_tests.sh`         | Orchestrated Rust, Foundry, and fuzz test runner|
| `scripts/tests/verifier_symbolic.sh` | Symbolic verifier harness via Foundry           |

##### Fuzz Tooling

| Script                                     | Role                                      |
|--------------------------------------------|-------------------------------------------|
| `scripts/tests/fuzz/run_all.sh`            | Fuzz runner with short and deep presets   |
| `scripts/tests/fuzz/run_cmin.sh`           | Corpus minimization wrapper (`cmin`)      |
| `scripts/tests/fuzz/run_tmin.sh`           | Testcase minimization wrapper (`tmin`)    |
| `scripts/tests/fuzz/dicts/adapter_ir.dict` | Adapter dictionary seeds                  |
| `scripts/tests/fuzz/dicts/stark.dict`      | STARK dictionary seeds                    |

##### Fuzz Targets (cargo-fuzz workspace)

Path prefix: `scripts/tests/fuzz/workspace/`.

| File                                             | Role                                                        |
|--------------------------------------------------|-------------------------------------------------------------|
| `Cargo.toml`                                     | Fuzz workspace manifest and target registration             |
| `Cargo.lock`                                     | Fuzz workspace lockfile                                     |
| `fuzz_targets/decode_adapter_bytes.rs`           | Adapter byte decoder fuzz                                   |
| `fuzz_targets/decode_adapter_ir_deep.rs`         | Adapter IR deep decode fuzz                                 |
| `fuzz_targets/decode_circle_stark_program.rs`    | Circle STARK program decode fuzz                            |
| `fuzz_targets/decode_circle_stark_proof.rs`      | Circle STARK proof decode fuzz                              |
| `fuzz_targets/decode_ipa_receipt.rs`             | IPA receipt decode fuzz                                     |
| `fuzz_targets/decode_plonky2_receipt.rs`         | Plonky2 receipt decode fuzz                                 |
| `fuzz_targets/decode_standard_stark_program.rs`  | Standard STARK program decode fuzz                          |
| `fuzz_targets/decode_standard_stark_proof.rs`    | Standard STARK proof decode fuzz                            |
| `fuzz_targets/decode_stark_ir.rs`                | STARK IR decode fuzz                                        |
| `fuzz_targets/decode_stark_receipt.rs`           | STARK receipt decode fuzz                                   |
| `fuzz_targets/decode_stark_vk.rs`                | STARK VK decode fuzz                                        |
| `fuzz_targets/decode_winterfell_program.rs`      | Winterfell program decode fuzz                              |
| `fuzz_targets/bn254_op_traces.rs`                | BN254 op trace validation fuzz                              |
| `fuzz_targets/diff_adapter_ir_roundtrip.rs`      | Adapter IR roundtrip invariant fuzz                         |
| `fuzz_targets/transcript_challenges.rs`          | Transcript challenge fuzz                                   |
| `fuzz_targets/validate_state_transition_batch.rs`| State transition batch validate and compile fuzz            |
| `fuzz_targets/verify_adapter_proof.rs`           | Adapter proof decode fuzz                                   |
| `fuzz_targets/verify_packed_calldata.rs`         | Packed calldata verifier fuzz                               |
| `corpus/`                                        | Generated fuzz corpora (data-only, one subdir per target)   |

##### Repro Tooling

| Script                        | Role                                             |
|-------------------------------|--------------------------------------------------|
| `scripts/repro/repro_pack.sh` | Deterministic repro runner with manifest output  |

##### Formal Tooling

| File                                             | Role                                     |
|--------------------------------------------------|------------------------------------------|
| `scripts/formal/sumcheck_invariants.sh`          | Sumcheck invariants runner               |
| `scripts/formal/sumcheck_invariants/Cargo.toml`  | Sumcheck invariants crate manifest       |
| `scripts/formal/sumcheck_invariants/Cargo.lock`  | Sumcheck invariants crate lockfile       |
| `scripts/formal/sumcheck_invariants/src/main.rs` | Sumcheck invariants logic (Goldilocks)   |

##### Tools - Converters

| File | Role |
| --- | --- |
| `scripts/tools/converters/stwo_to_bundle.rs` | Stwo proof and program to bundle converter |

##### Tools - Fixture Generators

Path prefix: `scripts/tools/fixture_generators/`.

| File                                   | Role                               |
|----------------------------------------|------------------------------------|
| `gnark_bn254_plonk/run.sh`             | GNARK BN254 PLONK generator runner |
| `gnark_bn254_plonk/main.go`            | GNARK BN254 PLONK generator        |
| `gnark_bn254_plonk/go.mod`             | GNARK generator dependencies       |
| `gnark_bn254_plonk/go.sum`             | GNARK generator lockfile           |
| `sp1/run.sh`                           | SP1 generator runner               |
| `sp1/src/main.rs`                      | SP1 generator logic                |
| `sp1/src/bin/build_gnark_circuits.rs`  | SP1 gnark artifact build           |
| `sp1/src/bin/build_guest.rs`           | SP1 guest build helper             |
| `sp1/guest/src/main.rs`                | SP1 guest program                  |
| `sp1/Cargo.toml`                       | SP1 generator manifest             |
| `sp1/Cargo.lock`                       | SP1 generator lockfile             |
| `sp1/guest/Cargo.toml`                 | SP1 guest manifest                 |
| `sp1/guest/Cargo.lock`                 | SP1 guest lockfile                 |

##### Tool Fixtures (data)

Path prefix: `scripts/tools/fixtures/`.

**SHA3**
- `fast_sha3_receipt.txt`: Deterministic SHA3 receipt fixture
- `fast_sha3_receipt_f64.txt`: Deterministic SHA3 F64 receipt fixture

**Circle STARK**
- `fast_circle_stark_receipt.txt`: M31 receipt fixture (UTF-16 LE)
- `fast_circle_stark_receipt.txt.candidate`: Candidate M31 receipt fixture
- `fast_circle_stark_receipt_large.txt`: Large receipt fixture
- `fast_circle_stark_receipt_large.txt.candidate`: Candidate large receipt fixture
- `fast_circle_stark_baby_bear_receipt.txt`: BabyBear receipt fixture
- `fast_circle_stark_baby_bear_receipt.txt.candidate`: Candidate BabyBear receipt fixture
- `fast_circle_stark_koala_bear_receipt.txt`: KoalaBear receipt fixture
- `fast_circle_stark_koala_bear_receipt.txt.candidate`: Candidate KoalaBear receipt fixture

**Plonky2**
- `fast_plonky2_goldilocks_receipt.txt`: Goldilocks receipt fixture
- `fast_plonky2_goldilocks_receipt.txt.candidate`: Candidate Goldilocks receipt fixture

**Groth16**
- `groth16_bn254_fixture.txt`: BN254 fixture (vk, proof, pub inputs)
- `groth16_bls12381_receipt.txt`: BLS12-381 receipt fixture
- `groth16_bls12381_receipt.txt.candidate`: Candidate BLS12-381 receipt fixture

**KZG**
- `kzg_bls12381_receipt.txt`: BLS12-381 receipt fixture
- `kzg_bls12381_receipt.txt.candidate`: Candidate BLS12-381 receipt fixture

**PLONK**
- `plonk_bn254_gnark_receipt.txt`: BN254 GNARK receipt fixture
- `plonk_bls12381_receipt.txt`: BLS12-381 receipt fixture
- `plonk_bls12381_receipt.txt.candidate`: Candidate BLS12-381 receipt fixture

**Halo2 KZG**
- `halo2_bn254_kzg_receipt.txt`: BN254 receipt fixture
- `halo2_bn254_kzg_receipt.txt.candidate`: Candidate BN254 receipt fixture
- `halo2_bls12381_kzg_receipt.txt`: BLS12-381 receipt fixture
- `halo2_bls12381_kzg_receipt.txt.candidate`: Candidate BLS12-381 receipt fixture

**Miden**
- `miden_rpo_receipt.txt`: RPO receipt fixture
- `miden_blake3_receipt.txt`: Blake3 receipt fixture

**IVC**
- `ivc_nova_external_proof.txt`: Nova external proof fixture
- `ivc_supernova_external_proof.txt`: SuperNova external proof fixture
- `ivc_hypernova_external_proof.txt`: HyperNova external proof fixture
- `ivc_sangria_external_proof.txt`: Sangria external proof fixture

**RISC Zero**
- `risc_zero_bundle.json`: Bundle fixture
- `risc_zero_external_receipt.json`: External receipt fixture

**Stwo**
- `stwo_external.json`: External bundle fixture
- `stwo_external.receipt.txt`: External receipt fixture
- `stwo_test_bundle.json`: Test bundle fixture

**SP1**
- `sp1_groth16_receipt.txt`: Groth16 BN254 receipt fixture
- `sp1_plonk_receipt.txt`: Plonk BN254 receipt fixture

**Plonky3**
- `plonky3_babybear_poseidon2_tribonacci_receipt.txt`: BabyBear Poseidon2 tribonacci receipt
- `plonky3_babybear_poseidon2_tribonacci_receipt.txt.candidate`: Candidate BabyBear Poseidon2 tribonacci receipt
- `plonky3_koalabear_poseidon2_tribonacci_receipt.txt`: KoalaBear Poseidon2 tribonacci receipt
- `plonky3_koalabear_poseidon2_tribonacci_receipt.txt.candidate`: Candidate KoalaBear Poseidon2 tribonacci receipt
- `plonky3_goldilocks_poseidon2_tribonacci_receipt.txt`: Goldilocks Poseidon2 tribonacci receipt
- `plonky3_babybear_poseidon2_receipt.txt.candidate`: Candidate BabyBear Poseidon2 receipt
- `plonky3_babybear_poseidon_receipt.txt.candidate`: Candidate BabyBear Poseidon receipt
- `plonky3_babybear_rescue_receipt.txt.candidate`: Candidate BabyBear Rescue receipt
- `plonky3_babybear_blake3_receipt.txt.candidate`: Candidate BabyBear Blake3 receipt
- `plonky3_koalabear_poseidon2_receipt.txt.candidate`: Candidate KoalaBear Poseidon2 receipt
- `plonky3_koalabear_poseidon_receipt.txt.candidate`: Candidate KoalaBear Poseidon receipt
- `plonky3_koalabear_rescue_receipt.txt.candidate`: Candidate KoalaBear Rescue receipt
- `plonky3_koalabear_blake3_receipt.txt.candidate`: Candidate KoalaBear Blake3 receipt
- `plonky3_goldilocks_poseidon2_receipt.txt.candidate`: Candidate Goldilocks Poseidon2 receipt
- `plonky3_goldilocks_poseidon_receipt.txt.candidate`: Candidate Goldilocks Poseidon receipt
- `plonky3_goldilocks_rescue_receipt.txt.candidate`: Candidate Goldilocks Rescue receipt
- `plonky3_goldilocks_blake3_receipt.txt.candidate`: Candidate Goldilocks Blake3 receipt

**Cairo**
- `cairo_stone6_keccak_160_lsb_example_proof.json`: Cairo proof example with keccak masked commitment hash

##### Utilities

| Script                                       | Role                                             |
|----------------------------------------------|--------------------------------------------------|
| `scripts/utils/cuda/check_cuda_toolkit.sh`   | CUDA toolkit detection and warnings              |
| `scripts/utils/dump_perf_config.sh`          | Perf config snapshot to JSON                     |
| `scripts/utils/perf_summary.sh`              | Perf summary formatter                           |
| `scripts/utils/ensure_state_diff_fixture.sh` | Deterministic 1 MiB state diff fixture generator |

- **Rust tests (`cargo test`)**: Cover core algebra, transcript logic, soundness, fuzzing, and end-to-end proof generation.
- **Fuzzing (`cargo fuzz`)**: Requires a nightly toolchain and uses targets in `scripts/tests/fuzz/workspace/fuzz_targets/`. Logs and artifacts default to `scripts/out/tests/fuzz` when run via `scripts/tests/run_tests.sh`.
- **Foundry outputs**: The Foundry test suite is configured to emit build outputs under
  `scripts/out/foundry` via `scripts/tests/foundry/foundry.toml` (`out` and `cache_path`).
- **Build speed tips (glyph-binius)**:
  - Use `--lib` to avoid compiling all `src/bin/` CLI binaries when you only need library tests.
  - Use `cargo test --profile release-fast ...` for faster optimized iteration (keeps `release` unchanged for KPI work).
  - Use `cargo ... --timings` to generate a compile-time breakdown under `target/cargo-timings/`.
  - Repo is configured to use `sccache` via `.cargo/config.toml` when `sccache` is installed.
- **Legacy Adapter CLI (removed)**:
  - The legacy `glyph_adapt` CLI has been removed from the repository and is
    not part of the production pipeline.
- **Circle Receipt Import CLI (`glyph_import_circle_receipt`)**:
  - `src/bin/glyph_import_circle_receipt.rs` assembles canonical Circle STARK receipts from profile and program bytes plus proof and public inputs, then verifies them before emitting `receipt_hex`.
  - Supports `--bundle-json bundle.json` for external toolchain bundles.
  - Example:
    ```bash
    cargo run --bin glyph_import_circle_receipt -- --profile-file profile.bin --program-file program.bin --proof-file proof.bin --pub-file pub.bin --out receipt.txt
    ```
  - Bundle JSON format:
    ```json
    {
      "version": 1,
      "profile_hex": "0x...",
      "program_hex": "0x...",
      "proof_hex": "0x...",
      "pub_inputs_hex": "0x..."
    }
    ```
  - Bundle example:
    ```bash
    cargo run --bin glyph_import_circle_receipt -- --bundle-json bundle.json --out receipt.txt
    ```
- **Stwo Receipt Import CLI (`glyph_import_stwo_receipt`)**:
  - `src/bin/glyph_import_stwo_receipt.rs` assembles canonical Stwo receipts from `STWO_PROFILE` and `STWO_PROGRAM` bytes plus proof and public inputs, then verifies them before emitting `receipt_hex`.
  - Supports `--bundle-json bundle.json` for external Stwo toolchain bundles.
  - Bundle generation helper: `cargo run --bin stwo_to_bundle -- --proof-json proof.json --program-file program.bin --pub-file pub.bin --log-domain-size 20 --out bundle.json`
  - Example:
    ```bash
    cargo run --bin glyph_import_stwo_receipt -- --profile-file profile.bin --program-file program.bin --proof-file proof.bin --pub-file pub.bin --out receipt.txt
    ```
  - Bundle JSON format (same layout as Circle bundles):
    ```json
    {
      "version": 1,
      "profile_hex": "0x...",
      "program_hex": "0x...",
      "proof_hex": "0x...",
      "pub_inputs_hex": "0x..."
    }
    ```
  - Bundle example:
    ```bash
    cargo run --bin glyph_import_stwo_receipt -- --bundle-json bundle.json --out receipt.txt
    ```
- **SP1 Receipt Import CLI (`glyph_import_sp1_receipt`)**:
  - `src/bin/glyph_import_sp1_receipt.rs` assembles canonical SP1 receipts for Groth16/Plonk BN254.
  - Required: `--proof-system <groth16|plonk>`, `--vkey-hash <0x...>` from `vk.bytes32()`, `--proof-hex|--proof-file`, `--pub-hex|--pub-file` (raw public values bytes).
  - Emits `receipt_hex` and verifies via `sp1-verifier`.
- **Cairo Receipt Import CLI (`glyph_import_cairo_receipt`)**:
  - `src/bin/glyph_import_cairo_receipt.rs` imports Cairo proof JSON and emits a canonical Cairo STARK receipt.
  - Supported build: `--layout starknet_with_keccak`, `--hasher keccak_160_lsb`, `--stone stone6`, `--verifier monolith`.
  - Canonical receipts store proof and public input JSON bytes; the verifier also accepts legacy bincode receipts.
- **Miden Receipt Import CLI (`glyph_import_miden_receipt`)**:
  - `src/bin/glyph_import_miden_receipt.rs` assembles canonical Miden receipts from program, proof, and stack inputs/outputs.
  - Optional `--hash <blake3-192|blake3-256|rpo|rpx|poseidon2>` to assert the proof hash function. Fixtures cover RPO256 and BLAKE3-256 only.
  - Proofs with precompile requests are rejected.
- **Plonky3 Receipt Import CLI (`glyph_import_plonky3_receipt`)**:
  - `src/bin/glyph_import_plonky3_receipt.rs` assembles canonical Plonky3 receipts for supported fields and hashes.
  - Supported fields: `m31`, `babybear`, `koalabear`, `goldilocks`. Supported hashes: `poseidon2`, `poseidon`, `rescue`, `blake3` (BabyBear, KoalaBear, Goldilocks) and `keccak` (M31).
- **PLONK Receipt Import CLI (`glyph_import_plonk_receipt`)**:
  - `src/bin/glyph_import_plonk_receipt.rs` assembles canonical PLONK receipts for gnark BN254, dusk BLS12-381, and generic backends (for `halo2` KZG on BN256 or BLS12-381, plus `gnark` or `dusk` wrappers).
  - Generic backends require `--backend generic --backend-kind halo2|gnark|dusk`. Halo2 requires `--backend-params-*` carrying encoded Halo2 backend params.
  - Required (system shortcut): `--system <bn254-gnark|bls12-381-dusk|halo2-bn256|halo2-bls12-381>`, `--vk-hex|--vk-file`, `--proof-hex|--proof-file`, `--pub-hex|--pub-file`.
  - Required for halo2 backend: `--backend-params-hex|--backend-params-file`.
  - External toolchain mapping workflow (Stwo):
    - Export `proof.json`, `program.bin`, and `pub.bin` from the Stwo prover.
    - Convert to a bundle JSON with the repo converter:
      ```bash
      cargo run --bin stwo_to_bundle -- --proof-json proof.json --program-file program.bin --pub-file pub.bin --log-domain-size 20 --out bundle.json
      ```
    - Import and verify the bundle into a canonical receipt:
      ```bash
      cargo run --bin glyph_import_stwo_receipt -- --bundle-json bundle.json --out receipt.txt
      ```
    - Use `receipt.txt` with the STARK adapter or `glyph_prover` as a standard canonical receipt input.
- **GLYPH-Prover CLI (`glyph_prover`)**:
  - `src/bin/glyph_prover.rs` compiles adapter inputs into UCIR and runs GLYPH-PROVER for all enabled adapter families.
  - SNARKs use `--family snark --snark-kind <groth16-bn254|kzg-bn254|plonk|halo2-kzg|ipa-bn254|ipa-bls12381|sp1>`.
  - Groth16 or KZG BLS12-381 receipts require `--curve bls12-381` with the matching `--snark-kind`.
  - STARKs use `--family stark-goldilocks|stark-babybear|stark-m31` plus `--receipt` and `--seed`.
  - Emits proof artifact tags and optional packed GKR calldata for on-chain verification.
  - Minimal examples:
    - Groth16:
      ```bash
      cargo run --bin glyph_prover -- --family snark --snark-kind groth16-bn254 --vk vk.bin --proof proof.bin --pub pub.bin --verifier 0x1111111111111111111111111111111111111111 --chain-id 31337 --mode fast
      ```
    - IVC:
      ```bash
      cargo run --bin glyph_prover -- --family ivc --adapter-vk vk.bin --adapter-statement statement.bin --proof proof.bin --verifier 0x1111111111111111111111111111111111111111 --chain-id 31337 --mode fast
      ```
    - STARK:
      ```bash
      cargo run --bin glyph_prover -- --family stark-goldilocks --receipt receipt.json --seed 1234 --verifier 0x1111111111111111111111111111111111111111 --chain-id 31337 --mode fast
      ```
- **Batch Adapter CLI (`glyph_adapt_batch`)**:
  - `src/bin/glyph_adapt_batch.rs` executes Groth16/KZG batch adapter IR with shared VK bytes and optional GLYPH artifact derivation.
  - Input is a newline-delimited `--items-file` containing `statement,proof,pub` file paths.
- **STARK KPI baseline (`stark_do_work_kpis`)**:
  - `src/bin/stark_do_work_kpis.rs` emits baseline Winterfell `do_work` KPIs as JSON.
  - `scripts/benchmarks/bench_stark_do_work_kpis.sh` is the reproducible harness (writes under `scripts/out/benchmarks/`).
  - `stark_do_work_kpis` also supports `--sha3`, `--f64`, `--seed`, `--receipts`, and `--glyph-artifact` (feature `glyph-binius`) for canonical SHA3 and Blake3 KPI workloads.
  - Use `bench_stark_do_work_kpis.sh` with `SHA3=1`, `F64=1`, `SEED=...`, and optional `RECEIPTS` and `GLYPH_ARTIFACT=1` to exercise SHA3 receipts (default is Blake3).
- **Foundry tests (`forge test`)**:
  - `GLYPHVerifierTest.t.sol`: Packed GLYPHVerifier calldata tests.
  - `GLYPH_SNARK_GROTH16_Test.t.sol`
  - `GLYPH_SNARK_KZG_Test.t.sol`
  - `GLYPH_IVC_Test.t.sol`
  - `GLYPH_SNARK_IPA_Test.t.sol`
  - `GLYPH_STARK_Test.t.sol`
  - `GLYPH_HASH_Test.t.sol`
  - `GLYPH_SNARK_SP1_Test.t.sol`
  - `GLYPH_SNARK_PLONK_Test.t.sol`
- **KPI Benchmarks (`bench_*`)**:
  - Bench binaries live under `src/bin/` and provide granular performance metrics for specific subsystems.
  - `bench_basefold_pcs`: BaseFold PCS commit/open/verify KPI and opening byte sizes (used by tuning sweeps).
  - `bench_bn254_batch_kpi`: Batch modular arithmetic (add, sub, mul) throughput.
  - `bench_bn254_g2_kpi`: G2 Scalar Multiplication tracing.
  - `bench_bn254_msm_kpi`: G1 MSM tracing and precomputation.
  - `bench_bn254_mul_kpi`: Individual field operation latency.
- `bench_glyph_cuda_kpi`: CUDA backend throughput and latency (requires `feature=cuda` and `nvcc`; not part of the standard benchmark suite, run manually only).
  - Output format is generally JSON for automated ingestion.
- **Fixture Generators (`gen_*`)**:
  - Fixture generator binaries live under `src/bin/` and generate strictly deterministic test vectors and reference fixtures.
  - Used by `scripts/tests/foundry` and integration scripts to ensure cross-stack compatibility.
  - `gen_stark_fixture`: Generates Winterfell do_work proof fixtures.
  - `gen_circle_stark_fixture`: Generates Circle STARK proof fixtures.
  - `gen_risc_zero_bundle_fixture`: Generates Risc Zero compatibility fixtures.

### 5. Security Architecture

GLYPH employs a **Binding + Validity** security model to ensure that low-cost on-chain verification does not compromise trust.

#### 5.1 Layer 1: Cryptographic Binding (On-Chain)
`contracts/GLYPHVerifier.sol` enforces binding via the initial Fiat-Shamir challenge:
- Binds the proof to `(artifact_tag, claim128, initial_claim)` where `artifact_tag = keccak256(commitment_tag || point_tag)`.
- Replay protection via `chainid` and `address(this)` in `r0 = keccak256(chainid || address(this) || artifact_tag || claim128 || initial_claim) mod p`.

This layer is **notarization**: it proves that the prover knows a valid GLYPH proof for the bound metadata. On-chain cost depends on calldata size and rounds.

#### 5.2 Layer 2: Validity via Folding (Off-Chain)
To guarantee that the *content* of the upstream proof (e.g., a Groth16 or STARK proof)
is valid without running its expensive verifier on-chain, GLYPH performs upstream
verification inside the off-chain adapter pipeline. For IVC-style systems, folding
schemes are the mechanism for reducing verification cost.

1.  **Folding Prover**: An off-chain entity folds the verification work into a running
    accumulator. For IVC BaseFold this is a transparent PCS opening verified inside
    GLYPH-Prover.
2.  **Validity Proof**: The final step produces a GLYPH packed sumcheck proof and
    the artifact boundary `artifact_tag` plus `claim128`.
3.  **Mathematical Guarantee**: The GLYPH proof is only constructible if the upstream
    verification succeeds for the supported adapter path. For IVC, trustless validity
    is enforced for BaseFold transparent PCS receipts and Nova-family proofs
    (Nova, SuperNova, HyperNova, Sangria) via transparent R1CS and external proof
    verification.

This shifts the computational burden of validity checks entirely off-chain while
keeping on-chain verification round-dependent and gas efficient.

---

## 14. Evidence and Implementation Summary

### Executive Summary

GLYPH provides a transparent on-chain packed verifier for heterogeneous proofs.
On Sepolia and Hoodi (receipt-backed, 2026-02-02), GLYPH artifact verification costs
≈29,450 total tx gas, while direct Groth16 verification with 3 public inputs costs
≈227,128 total tx gas. This represents an ≈7.7x on-chain gas reduction under the
same network conditions, while preserving upstream trust assumptions.
See Section 14.2.1 for receipt evidence and tx hashes.

### 14.1 Adapter Status (Implementation and Tests)

Status reflects implementation and test coverage, not a production-readiness claim. Fuzz coverage varies by adapter family; see the Evidence Matrix.

| Adapter | Proof System                                                                     | Status               |
|---------|----------------------------------------------------------------------------------|----------------------|
| Groth16 | Groth16 (BN254, BLS12-381)                                                       | Implemented, tested  |
| KZG     | KZG or Plonk (BN254, BLS12-381)                                                  | Implemented, tested  |
| IVC     | IVC or Folding (BaseFold PCS, Nova-family formats)                               | Implemented, tested  |
| IPA     | IPA (Halo2 IPA receipts)                                                         | Implemented, tested  |
| Binius  | Binius constraint-system proofs                                                  | Implemented, tested  |
| STARK   | STARK F128 or F64 (Winterfell)                                                   | Implemented, tested  |
| STARK   | Goldilocks (Plonky2)                                                             | Implemented, tested  |
| STARK   | Circle STARK (M31, BabyBear, KoalaBear)                                          | Implemented, tested  |
| STARK   | Standard FRI BabyBear (RISC Zero)                                                | Implemented, tested  |
| STARK   | Stwo (M31 + Blake2s)                                                             | Implemented, tested  |
| STARK   | Plonky3 (M31, BabyBear, KoalaBear, Goldilocks)                                   | Implemented, tested  |
| STARK   | Cairo STARK (Starknet Prime, Starknet-with-Keccak, keccak-160-lsb)               | Implemented, tested  |
| STARK   | Miden STARK (Goldilocks)                                                         | Implemented, tested  |
| Hash    | Hash Proofs (Keccak merge)                                                       | Implemented, tested  |
| SP1     | SP1 (Groth16 or Plonk BN254)                                                     | Implemented, tested  |
| PLONK   | PLONK and Halo2 KZG (gnark BN254, dusk BLS12-381, Halo2 KZG BN256 and BLS12-381) | Implemented, tested  |

Notes:
- STARK Goldilocks requires `stark-goldilocks`.
- Cairo STARK support is Stone6 monolith only.
- Miden STARK supports Blake3-192/256, RPO256, RPX256, Poseidon2; fixtures include RPO256 and BLAKE3-256; no precompile requests.
- Plonky3 supports Poseidon2, Poseidon, Rescue, Blake3 for BabyBear, KoalaBear, Goldilocks; Keccak for M31.
- PLONK and Halo2 KZG cover gnark BN254, dusk BLS12-381, Halo2 KZG BN256 and BLS12-381.

### 14.2 Gas Summary (Receipt-Backed)

| Layout                            | Gas (total tx gas) | Notes                                                      |
|-----------------------------------|--------------------|------------------------------------------------------------|
| GLYPH Packed-128 (artifact-bound) | ≈29,450            | Sepolia and Hoodi receipts, 2026-02-02; see Section 14.2.1 |
| Groth16 (3 public inputs)         | ≈227,128           | Sepolia and Hoodi receipts, 2026-02-02; see Section 14.2.1 |

### 14.2.1 Testnet Gas Breakdown (Sepolia and Hoodi, 2026-02-02)

#### Methodology

- Networks: Sepolia (11155111) and Hoodi (560048).
- GLYPH proof generation examples:
  ```bash
  target/release/gen_glyph_gkr_proof --hash-merge --rounds 5 --full --chainid <u64> --verifier <0xaddr20>
  target/release/gen_glyph_gkr_proof --hash-merge --rounds 5 --truncated --chainid <u64> --verifier <0xaddr20>
  target/release/gen_glyph_gkr_proof --artifact-poly --commitment <bytes32> --point <bytes32> --claim <bytes32> --rounds 5 --chainid <u64> --verifier <0xaddr20>
  ```
- Groth16 calldata: snarkjs Groth16 artifacts generated under `scripts/out/benchmarks/groth16_compare/`
  with 3 public inputs (`scripts/out/benchmarks/groth16_compare/artifacts/calldata.txt`).
- Bench scripts (receipts captured with `SEND_TX=1`):
  - `scripts/benchmarks/bench_glyph_sepolia_artifact.sh` (run against Sepolia and Hoodi RPCs for full and truncated cases)
  - `scripts/benchmarks/bench_glyph_hoodi_artifact_truncated.sh` (truncated-only case)
  - `scripts/benchmarks/bench_groth16_sepolia.sh`
  - `scripts/benchmarks/bench_groth16_hoodi.sh`
- Bench outputs and generated artifacts are written under `scripts/out/benchmarks/` when run
  and are tracked in this repository for reproducibility.
- Canonical JSON evidence referenced in this section:
  - `scripts/out/benchmarks/bench_glyph_sepolia_artifact.json`
  - `scripts/out/benchmarks/bench_glyph_hoodi_artifact.json`
  - `scripts/out/benchmarks/bench_glyph_hoodi_artifact_truncated.json`
  - `scripts/out/benchmarks/bench_groth16_sepolia.json`
  - `scripts/out/benchmarks/bench_groth16_hoodi.json`
- Raw calldata tx submission uses `scripts/benchmarks/send_raw_tx.sh`, which calls the
  `glyph_raw_tx` binary (`src/bin/glyph_raw_tx.rs`) to sign and broadcast legacy raw
  transactions for the fallback call.
- Env inputs:
  - `docs/wallet/.env.wallet` for `DEPLOYER_ADDRESS` and `DEPLOYER_PRIVATE_KEY`.
  - `scripts/deploy/.env.sepolia` for `SEPOLIA_RPC_URL`.
  - `scripts/deploy/.env.hoodi` for `HOODI_RPC_URL`.
- Gas sources:
  - `eth_estimateGas` for estimates.
  - On-chain tx gas measured via actual receipts.
- Calldata gas computed per EIP-2028 (4 gas per `0x00` byte, 16 gas per non-zero byte).
- Base transaction gas fixed at 21,000.

Benchmark evidence is derived from two sources and kept explicit in the JSON outputs:
- **Receipts** provide `tx_hash` and `tx_gas` (total tx gas). These values are the canonical published gas numbers.
- **estimateGas** provides `estimate_gas`, used to compute `execution_gas = estimate_gas - base_tx_gas - calldata_gas`.
- **Calldata stats** (`calldata_bytes`, `calldata_gas`) are computed from the packed calldata and EIP-2028 rules.
All benchmark JSON outputs are written under `scripts/out/benchmarks/` when run and are tracked in this repository for reproducibility.

#### Receipt Gas and Execution Estimates (Authoritative Totals)

| Network | Case                          | Tx Hash                                                            | Total Tx Gas | Base Tx Gas | Calldata Gas | Execution Gas (estimate) |
|---------|-------------------------------|--------------------------------------------------------------------|--------------|-------------|--------------|--------------------------|
| Sepolia | GLYPH artifact_full           | 0x7d37fc1722e1172d968d750db94fda10812536bd26255c40e17c5d3a498acd3b | 29,450       | 21,000      | 3,380        | 5,419                    |
| Sepolia | GLYPH artifact_truncated      | 0x076d365d2756af2c583bb96719d20008581720cbe97a40f578802f121d383052 | 29,450       | 21,000      | 3,380        | 5,419                    |
| Hoodi   | GLYPH artifact_full           | 0xf3c749f66515580cc0091416350d5dfa9525a9cb0669d84ef9d17ca78ce62352 | 29,450       | 21,000      | 3,380        | 5,419                    |
| Hoodi   | GLYPH artifact_truncated      | 0x0a7121534fcee5c515daf84432a57de020fb05d94d62296c1afaf5d91e7da37f | 29,450       | 21,000      | 3,380        | 5,419                    |
| Hoodi   | GLYPH artifact_truncated_only | 0x1e541873bf4045ea4a1ffe3377f42a41e71cc470dc6e0587dbc74b5a440d8094 | 29,450       | 21,000      | 3,380        | 5,419                    |
| Sepolia | Groth16 verify (3 publics)    | 0x522222efb008569c6a43f612ce3c1ce365138507d6ea7ab4a9b542f19b2de31f | 227,128      | 21,000      | 4,556        | 204,542                  |
| Hoodi   | Groth16 verify (3 publics)    | 0xe78fb0f464dff13704b1a608c177a1e3154317e0fefc099d6fd232a62e482931 | 227,128      | 21,000      | 4,556        | 204,542                  |

Execution gas values are derived from `eth_estimateGas` and do not come from receipts.

#### Calldata Size (Bytes)

| Case                          | Calldata Bytes |
|-------------------------------|----------------|
| GLYPH artifact_full           | 224            |
| GLYPH artifact_truncated      | 224            |
| GLYPH artifact_truncated_only | 224            |
| Groth16 verify (3 publics)    | 356            |

#### EstimateGas (Reproducibility)

Capture `eth_estimateGas` values with the bench scripts above. These estimates are
typically higher than receipts for the same bytecode and calldata and are not
committed to the repository.

#### Local Anvil Baseline

Run `scripts/benchmarks/bench_glyph_evm_local.sh` to capture a local Anvil baseline.
Outputs are written under `scripts/out/benchmarks/` when run and are not committed.

#### Comparison

- GLYPH artifact verification is ≈7.7x cheaper than Groth16 (3 publics) on Sepolia and Hoodi, based on receipts.
- The dominant cost difference is calldata size and execution gas: GLYPH uses 224 bytes and ~5.42k execution gas (estimate), while Groth16 uses 356 bytes and ~204.5k execution gas (estimate).
- `eth_estimateGas` values are typically higher than receipts for the same bytecode and calldata.

### 14.2.2 Mini Benchmark Report

This section is intentionally empty unless `scripts/out/benchmarks/` contains
fresh local outputs. Run the bench scripts listed in Section 14.2.1 (and
`scripts/benchmarks/bench_basefold_arity_sweep.sh` for PCS) to generate
local JSON outputs, then summarize them here. Section 14.2.1 remains the
authoritative receipt evidence for published gas numbers.

#### Reference Model

**Groth16 Reference Model (BN254, model only)**

This model estimate is retained for context.
Assumptions:
- Pairings: 4 (Groth16 canonical verifier)
- Pairing gas: 45,000 + 34,000 * k (EIP-1108)
- Public input MSM: 1 ECMUL + 1 ECADD per input (6,000 + 150 per input)
- Calldata: ~256 bytes proof, all non-zero, 16 gas per byte

| Item                  | Formula                                | Gas                |
|-----------------------|----------------------------------------|--------------------|
| Pairing checks        | 45,000 + 34,000 * 4                    | 181,000            |
| Public inputs (l)     | 6,150 * l                              | 6,150 * l          |
| Calldata (proof only) | 256 * 16                               | 4,096              |
| Base tx               | 21,000                                 | 21,000             |
| Total (l=2)           | 21,000 + 181,000 + 12,300 + 4,096      | 218,396 (218.396k) |
| Total (l=8)           | 21,000 + 181,000 + 49,200 + 4,096      | 255,296 (255.296k) |

These are reference estimates, not on-chain measurements.

### 14.3 Security Forensics Status

- **F1 (Transcript):** Done
- **F7 (INV2/INV6):** Verified via `test_sumcheck_constants`
- **F9 (Binding):** Done

### 14.4 Reproducibility Commands

**Run full test suite:**
```bash
cargo test
```

**Run repro pack (benchmarks and manifests):**
```bash
scripts/repro/repro_pack.sh
```
Outputs include `scripts/out/repro/manifest.json` and a perf config snapshot at
`scripts/out/perf/perf_config.json` when run.
Offline profiling can emit `scripts/out/benchmarks/perf_profile.json` via `scripts/benchmarks/profile_perf_config.sh`.
Each prover run also writes `scripts/out/perf/perf_run.json` with the effective snapshot path and runtime metadata.

---

## 14. Proof Sketches

### 14.1 Sumcheck
Let `f` be the multilinear polynomial over the evaluation table. Sumcheck proves that the claimed
sum over `{0,1}^n` is consistent with the evaluations by iteratively reducing the sum to a single
point. Each round constructs a low-degree univariate polynomial `g_i(t)` that aggregates the
current layer. The verifier checks `g_i(0) + g_i(1) = claim_i` and samples a random `r_i`. The
claim is updated to `g_i(r_i)` and the process repeats. Soundness follows from the Schwartz Zippel
bound under the transcript randomness.

### 14.1.1 Packed Arity-8 Sumcheck Explainer (Asset)

This explainer is a concise, reviewer-friendly narrative for the on-chain packed arity-8 sumcheck
used by `contracts/GLYPHVerifier.sol`. It complements the formal spec in `docs/specs/verifier_spec.md`
and the reference implementation in `src/glyph_gkr.rs`.

**Thread or video script outline (10-15 bullets):**
1) Goal: prove that a claimed sumcheck chain is consistent with the GLYPH artifact, using a tiny
   calldata footprint.
2) On-chain uses an arity-8 round. Each round encodes a quadratic `g(t) = c0 + c1*t + c2*t^2`.
3) Constraint for arity-8: `g(0) + g(1) + ... + g(7) = current_claim`.
4) Calldata is packed: only `c0` and `c1` are transmitted. `c2` is recovered from the constraint.
5) Recovery rule: `c2 = (current_claim - (8*c0 + 28*c1)) * INV140 mod p` where
   `p = 2^128 - 159`, `sum t = 28`, `sum t^2 = 140`.
6) Fiat-Shamir begins with chain binding:
   `r0 = keccak(chainid || address(this) || artifact_tag || claim128 || initial_claim) mod p`.
7) Each round mixes the coefficients into the transcript:
   `r_{i+1} = keccak(r_i || (c0 xor c1 xor c2)) mod p`.
8) Claim update is deterministic: `current_claim_{i+1} = g(r_i)`.
9) Repeat for `R = ceil(sumcheck_rounds / 3)` packed rounds. Each round costs 32 calldata bytes.
10) Final check binds to the artifact-defined polynomial:
    `expected_final = (lin_0 + claim128 + eval_lin)^2`.
11) The verifier recomputes `lin_hash = keccak(LIN_DOMAIN || artifact_tag || claim128)` and
    derives `lin_0`, `lin_step`, then `eval_lin = Σ lin_{i+1} * r_i`.
12) Accept if `current_claim == expected_final` and all field elements are canonical.

Solidity verifier constants (`MODULUS`, `INV140`, `LIN_DOMAIN`) are generated from
`src/glyph_gkr.rs` via `scripts/tools/generate_glyph_verifier_constants.py` and committed under
`contracts/GLYPHVerifierConstants.sol` and `scripts/tests/foundry/GLYPHVerifierConstants.sol`.
A Rust test asserts drift between Rust and Solidity values.

**Diagram set (ASCII with captions):**

```
[Round i: packed coefficients]
calldata: [ c0 (16B) | c1 (16B) ]
                     |
                     v
        c2 = (claim - (8*c0 + 28*c1)) * INV140
                     |
                     v
g(t) = c0 + c1*t + c2*t^2
constraint: sum_{t=0..7} g(t) = current_claim
```
Caption: Arity-8 round uses a quadratic. `c0` and `c1` are transmitted, `c2` is recovered
from the round constraint.

```
[Transcript evolution]
r0 = H(chainid || address(this) || artifact_tag || claim128 || initial_claim)
r_{i+1} = H(r_i || (c0 xor c1 xor c2))
current_claim_{i+1} = g(r_i)
```
Caption: Fiat-Shamir challenges are bound to chain id, verifier address, and artifact metadata.

```
[Final check]
lin_hash = H(LIN_DOMAIN || artifact_tag || claim128)
lin_0 = lin_hash[0..16], lin_step = lin_hash[16..32]
eval_lin = Σ lin_{i+1} * r_i
expected_final = (lin_0 + claim128 + eval_lin)^2
accept if current_claim == expected_final
```
Caption: The final check ties the sumcheck chain to the artifact-defined polynomial.

**Mini Q and A (reviewer-facing):**
- **Why arity-8?** It reduces the on-chain round count by a factor of 3 while keeping a
  simple quadratic per round.
- **Why only `c0` and `c1` on-chain?** The arity-8 constraint fixes `c2`, cutting calldata
  in half for each round.
- **Why chain id and contract address in `r0`?** It prevents replaying a valid proof on a
  different chain or verifier address.
- **Why a 128-bit field?** It keeps on-chain arithmetic cheap while providing a sufficient
  soundness margin for the packed verifier.
- **Is this the same as the off-chain sumcheck?** No. Off-chain uses Goldilocks and a
  binary sumcheck for the adapter path; on-chain uses a packed arity-8 verifier.

**Safety invariants surfaced by the explainer:**
- `c0`, `c1`, `claim128`, and `initial_claim` must be canonical `< p`.
- Calldata length must be checked before loading coefficients.
- Transcript inputs are domain-separated and chain-bound.

### 14.2 GKR Artifact Binding
The GLYPH artifact binds `(commitment_tag, point_tag, claim128)` into the packed GKR proof. The
verifier checks that the artifact tag equals `keccak256(commitment_tag || point_tag)` and that the
sumcheck chain matches `claim128`. The transcript mixes in tags and claims so a valid proof for one
tag cannot be replayed for a different statement without breaking the underlying hash or GKR
assumptions.

### 14.3 PCS Commitment Integrity
The PCS commitment binds the evaluation table to a fixed opening point derived from sumcheck
challenges. The proof checks that the opening matches the committed polynomial at the derived
point. Any inconsistency implies either a broken commitment scheme or a failed sumcheck chain.

## 14.4 Formal Proof Pack
The complete internal proof chain is available under `docs/proofs/`:
- `docs/proofs/00_overview.md`
- `docs/proofs/01_sumcheck.md`
- `docs/proofs/02_gkr_binding.md`
- `docs/proofs/03_pcs_basefold.md`
- `docs/proofs/04_ucir_correctness.md`
- `docs/proofs/05_state_diff_binding.md`
- `docs/proofs/06_end_to_end.md`
- `docs/proofs/07_mechanized_proof_plan.md`
Non-normative reference configuration for numeric bounds is described in `docs/proofs/06_end_to_end.md`.

### 14.4.1 Formal Tooling Evidence
**Sumcheck invariants (off-chain Goldilocks only).**
- Scope: cubic interpolation used in off-chain Goldilocks sumcheck rounds.
- Runner: `scripts/formal/sumcheck_invariants.sh` (Rust crate under `scripts/formal/sumcheck_invariants/`).
- Method: MT19937 seeded with 1, samples `y0..y3` over Goldilocks and checks that cubic interpolation reconstructs those values at `t in {0,1,2,3}`. Mirrors `src/glyph_core/sumcheck.rs`.
- Result: latest run completed with no failures.

**Verifier symbolic fuzz (assembly).**
- Runner: `scripts/tests/verifier_symbolic.sh` (Foundry fuzz and invariants).
- Logs: `scripts/out/formal/glyph_verifier_fuzz.log`.
- Coverage: high-volume fuzz and invariant checks, not a full formal proof.
- Gap: full symbolic execution with Halmos or Certora is not implemented.

## 14.5 Tutorials and Guides

### 14.5.1 CLI Cookbook
Prove a UCIR bundle:
```bash
glyph_prover --ucir path/to/ucir.bin --public-inputs path/to/public_inputs.hex --auto
```

Derive an L2 statement hash:
```bash
glyph_l2_statement \
  --chainid 11155111 \
  --contract 0x0000000000000000000000000000000000000000 \
  --old-root 0x... \
  --new-root 0x... \
  --da 0x... \
  --batch-id 1 \
  --extra-commitment 0x... \
  --extra-schema-id 0x... \
  --json
```

Run the state diff flow:
```bash
scripts/da/state_diff_proof_flow.sh
```

Execute and prove the state transition VM:
```bash
glyph_state_transition_execute --in path/to/ops.json --out batch.json
glyph_state_transition_prove --in batch.json --out proof.json
```

Run the reproducibility pack:
```bash
scripts/repro/repro_pack.sh
```

Run offline perf profiling:
```bash
scripts/benchmarks/profile_perf_config.sh
```

View perf summary:
```bash
scripts/utils/perf_summary.sh
```

### 14.5.2 Adapter Integration
Goal: import a canonical receipt, validate it, and derive a GLYPH artifact via the adapter pipeline.

Steps:
1. Obtain a canonical receipt for the target adapter family.
2. Import the receipt into GLYPH bytes with the matching `glyph_import_*` CLI.
3. Generate adapter IR and items, then run `glyph_adapt_batch` to validate and derive the artifact.
4. Use the artifact in downstream proofs or on-chain verification.

Example: SP1 receipt import (Groth16 or Plonk):
```bash
glyph_import_sp1_receipt \
  --proof-file proof.bin \
  --pub-file public.bin \
  --vkey-hash 0x... \
  --proof-system groth16 \
  --out sp1_receipt.glyph
```

Batch adapter validation and artifact derivation:
```bash
glyph_adapt_batch \
  --family groth16-bn254 \
  --ir-file path/to/adapter_ir.bin \
  --adapter-vk-file path/to/adapter_vk.bin \
  --raw-vk-file path/to/raw_vk.bin \
  --items-file path/to/items.txt \
  --artifact \
  --json > glyph_artifact.json
```

Validation references:
- `scripts/tests/rust/differential_receipt_verification.rs`
- `scripts/tests/rust/ucir_compiler_equivalence.rs`
- `scripts/tests/rust/adapter_error_semantics.rs`

### 14.5.3 State Diff Pipeline
Goal: produce a state diff root, bind it into a GLYPH proof, and verify it with `GLYPHRootUpdaterExtended`.

Flow:
1. Generate state diffs and compute the diff root.
2. Bind the diff root into the L2 statement hash.
3. Generate an artifact-bound proof.
4. Verify on-chain with `GLYPHRootUpdaterExtended`.

Example flow:
```bash
scripts/da/state_diff_proof_flow.sh
```

On-chain verification uses:
- `old_root`, `new_root`
- `state_diff_root` as `extra_commitment`

Reference specs:
- `docs/specs/verifier_spec.md`
- `docs/specs/state_transition_vm_spec.md`

### 14.5.4 DA Pipeline
Goal: publish proof payloads to a data availability layer while keeping the on-chain verifier unchanged.

Flow:
1. Generate the GLYPH artifact and calldata.
2. Package proof payloads for DA submission.
3. Submit to the chosen DA backend.
4. Store the DA commitment in the L2 statement binding.

Example flows:
```bash
scripts/da/state_transition_vm_flow.sh
scripts/da/state_diff_proof_flow.sh
```

Notes:
- DA submission is off-chain only.
- The on-chain verifier remains unchanged.

### 14.5.5 Rust SDK
- `src/sdk.rs` provides a minimal Rust SDK for proof and state transition flows.

## 14.6 Repository Meta and Governance
- Whitepaper source: `docs/whitepaper/glyph_paper.tex` and PDF in `docs/whitepaper/`
- Repository map and file index: `docs/map.md`
- Spec pack (canonical specs): `docs/specs/`
- Proof pack (formal notes): `docs/proofs/`
- Changelog: `docs/changelog.md`
- Master task tracking is maintained separately from this SSOT.

Vendored dependencies policy:
- Vendored subtrees are treated as upstream source and are kept for reproducible builds and pinning.
- We do not track internal TODO or FIXME comments in vendored code as GLYPH work items.
- Vendored sources are only modified when an explicit, documented change is required for this repository.

### 14.6.1 Audit Status and Evidence
- No external third-party audit has been completed.
- Internal evidence includes `docs/specs/verifier_spec.md`, `docs/specs/ucir_spec.md`, `docs/specs/state_transition_vm_spec.md`,
  the adapter evidence pack (Section 11.5.1.1), and the reproducibility pack (`scripts/repro/repro_pack.sh`).
- High-volume symbolic fuzzing is covered in Section 14.4.1. Full symbolic execution remains a gap.

### 14.6.2 Side-Channel Considerations
Findings:
- Field arithmetic and hashing are not guaranteed constant time on all platforms.
- GPU and parallel paths can introduce timing variability due to scheduling and cache effects.
- Receipt verification uses upstream libraries that are not guaranteed constant time.

Mitigations:
- Avoid exposing secret material through public logs or serialization.
- Treat witness values as sensitive and zeroize on release.
- Use deterministic inputs in reproducibility and audit workflows.

Follow ups:
- Evaluate constant time implementations for BN254 and hashing where feasible.
- Consider optional constant time feature toggles for high assurance deployments.

## 14.7 Specifications (Verbatim)

Spec pack (canonical files under `docs/specs/`):
- `docs/specs/verifier_spec.md`
- `docs/specs/ucir_spec.md`
- `docs/specs/state_transition_vm_spec.md`
- `docs/specs/adapter_ir_spec.md`
- `docs/specs/artifact_tag_spec.md`
- `docs/specs/stark_receipt_spec.md`
- `docs/specs/custom_gates_spec.md`

Canonical file: `docs/specs/verifier_spec.md`

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
| Offset | Size | Name            | Description                                                  |
|--------|------|-----------------|--------------------------------------------------------------|
| 0x00   | 32   | `artifact_tag`  | bytes32 = keccak256(commitment_tag || point_tag)             |
| 0x20   | 32   | `claim_initial` | `claim128` (hi 16 bytes) || `initial_claim` (lo 16 bytes)    |

Constraints:
- `claim128 < MODULUS`
- `initial_claim < MODULUS`

### Per-round Coefficients (32 bytes each)
For each round i:
| Offset | Size | Name | Description             |
|--------|------|------|-------------------------|
| 0x00   | 16   | `c0` | 128-bit field element   |
| 0x10   | 16   | `c1` | 128-bit field element   |

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

| Offset | Size | Value            |
|--------|------|------------------|
| 0x00   | 32   | chainid          |
| 0x20   | 32   | address(this)    |
| 0x40   | 32   | artifact_tag     |
| 0x60   | 32   | claim_initial    |

### Lin Hash Scratch (0xa0..0xef)
Used only for:
```
lin_hash = keccak256(LIN_DOMAIN || artifact_tag || claim128_be16)
```

| Offset | Size | Value                            |
|--------|------|----------------------------------|
| 0xa0   | 32   | LIN_DOMAIN                       |
| 0xc0   | 32   | artifact_tag                     |
| 0xe0   | 16   | claim128 (big endian, high half) |

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

Canonical file: `docs/specs/ucir_spec.md`
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
| Field            | Size | Encoding    |
|------------------|------|-------------|
| `version`        | 2    | u16 LE      |
| `field_id`       | 1    | u8          |
| `gate_count`     | 4    | u32 LE      |
| `lookup_count`   | 4    | u32 LE      |
| `copy_count`     | 4    | u32 LE      |
| `table_count`    | 4    | u32 LE      |
| `witness_layout` | 32   | 8 x u32 LE  |

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
Canonical file: `docs/specs/state_transition_vm_spec.md`
# GLYPH State Transition VM Specification

## Scope
This document specifies the GLYPH state transition VM used by the state diff layer. The VM is gas-neutral on-chain and provides deterministic execution, trace generation, and proof-friendly constraints. The on-chain verifier and statement binding remain unchanged.

## Design Goals
- Gas neutrality: no on-chain verifier changes and no calldata growth beyond existing bound inputs.
- Soundness: the circuit proves that a batch of state operations transforms `old_root` into `new_root`.
- Determinism: identical inputs always produce identical trace and roots.
- Performance: optimized for witness generation, SIMD, and concurrency.

## State Model
- Keys are index-encoded, little-endian `u32` in bytes `[0..4)` and zero elsewhere.
- Values are 32-byte words.
- Leaf hash: `keccak256(LEAF_DOMAIN || value)` where `LEAF_DOMAIN = keccak256("GLYPH_STATE_TRANSITION_LEAF_V1")`.
- State root: binary Keccak Merkle tree, depth in `1..=32`, padded via zero hashes.
- Zero hashes are deterministic per depth, computed from `LEAF_DOMAIN`.

## Operations
### Store
- Input: key, value
- Semantics: `new_value = value`

### Add
- Input: key, delta
- Semantics: `new_value = old_value + delta mod 2^256`

## Batch Execution
- A batch contains an `old_root` and a list of updates derived from operations.
- Each update includes key, old_value, new_value, proof, op_kind, operand.
- All updates in a batch must use the same Merkle depth.
- `proof.siblings.len == proof.path_bits.len`.
- `path_bits` length must be in `1..=32`.
- The VM enforces key-to-path binding and Merkle proof correctness for each update.

## Trace Format
Per step:
- op_kind: `store` or `add`
- key: 32-byte index key
- operand: 32-byte (value for store, delta for add)
- old_value: 32-byte value before update
- new_value: 32-byte value after update
- proof: Merkle proof (siblings, path_bits)
- old_root, new_root: roots before and after the step

## Circuit Constraints
For each update:
1. Key-to-path binding: path bits reconstruct the key index (LSB-first) and key upper bytes are zero.
2. Merkle correctness: old root equals proof path for `leaf(old_value)`; new root equals proof path for `leaf(new_value)`.
3. Operation semantics:
   - Store: `new_value = operand`
   - Add: `new_value = old_value + operand` with carry constraints per 64-bit limb.
4. Roots chain: each update consumes the previous root and produces the next root.

## Diff Commitment
- Diff bytes are `key || old_value || new_value` per update.
- Diff root is computed by the canonical state diff merkle function used by `state_diff_merkle`.
- The diff root is bound to the GLYPH artifact via the extended statement binding.

## Schema ID
- `state_transition_schema_id = keccak256("GLYPH_STATE_TRANSITION_VM_V1")`.
- This value is supplied as `extra_schema_id` alongside `extra_commitment`.

## Security and Interop
- Keccak hashing remains unchanged to preserve interoperability.
- The VM does not introduce additional on-chain data or verification steps.
- Any change to hashing or statement binding requires explicit gas-neutral approval.

## Determinism Requirements
- All hash inputs are canonical.
- Update ordering is deterministic and must be fixed by the caller.
- No nondeterministic host calls are permitted.

Canonical file: `docs/specs/adapter_ir_spec.md`
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

Canonical file: `docs/specs/artifact_tag_spec.md`
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
```
Split the 32-byte hash into two 16-byte halves and canonicalize each half as
`u128` with `x < MODULUS` (else `x - MODULUS`).

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

Canonical file: `docs/specs/stark_receipt_spec.md`
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

Canonical file: `docs/specs/custom_gates_spec.md`

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

## 14.8 Proof Pack (Canonical Files and SSOT Mirrors)

Canonical proof pack files under `docs/proofs/`:
- `docs/proofs/00_overview.md`
- `docs/proofs/01_sumcheck.md`
- `docs/proofs/02_gkr_binding.md`
- `docs/proofs/03_pcs_basefold.md`
- `docs/proofs/04_ucir_correctness.md`
- `docs/proofs/05_state_diff_binding.md`
- `docs/proofs/06_end_to_end.md`
- `docs/proofs/07_mechanized_proof_plan.md`

The following subsections mirror the proof pack content inside the SSOT and
keep explicit pointers to the canonical external files.

### 14.8.1 Overview (`docs/proofs/00_overview.md`)

# Formal Proof Pack - Overview

## Purpose
This pack provides a complete internal proof chain for GLYPH with explicit assumptions, lemmas, and a proof-to-code map. It is designed to withstand scrutiny from cryptography reviewers without relying on external audits.

## Security Model
We assume:
1. Random Oracle Model for Fiat-Shamir transforms.
2. Collision resistance of Keccak256.
3. Soundness of the GKR protocol.
4. Binding and correctness of the PCS commitment and opening scheme.
5. Correctness of adapter verification logic for each supported receipt format.

## Adversary Model
We consider a polynomial time adversary who:
- Controls all prover inputs, including transcripts and intermediate values.
- Can choose statements adaptively and submit arbitrary proofs.
- Has oracle access to the Fiat-Shamir transcript.
- Is bounded by standard cryptographic security parameters.

We target negligible soundness error in the security parameter lambda, with
explicit epsilon bounds derived in `06_end_to_end.md`.

## Formal Assumptions Registry
We reference the following assumptions in all proofs:
- A1: Fiat Shamir Random Oracle Model. Transcript outputs are indistinguishable from random.
- A2: Keccak256 collision resistance. Finding collisions is infeasible.
- A3: GKR soundness. A prover cannot convince the verifier of a false claim except with negligible probability.
- A4: PCS binding. Commitment and opening do not allow equivocation.
- A5: PCS correctness. Openings verify iff the committed polynomial evaluates to the claimed value.
- A6: Adapter upstream verifier correctness. Each receipt format verifies the intended statement.
- A7: UCIR/VM correctness. UCIR matches defined gates; VM/Merkle matches hashing and padding rules.

We explicitly do not assume any cryptographic property beyond A1..A7. All proofs must reduce to these assumptions or to standard algebraic facts about finite fields.

## Security Parameters
- Field size: |F| = 2^128 - 159 (packed verifier field).
- Sumcheck rounds: r = number of packed rounds derived from calldata length.
- Transcript security: modeled as a random oracle with domain separation tags.

All explicit bounds are computed for the above defaults and parameterized for
alternative configurations.

## Notation
- F: 128-bit prime field used by the packed verifier (p = 2^128 - 159).
- H: Keccak256.
- S: sumcheck claim.
- T: transcript state.
- C: PCS commitment.
- O: PCS opening.
- Tag: artifact tag = H(commitment_tag || point_tag).
Note: Goldilocks appears in off-chain prover and adapter receipts, but the packed
on-chain sumcheck uses the 128-bit field above.

## Dependency Graph
01_sumcheck depends on A1.
02_gkr_binding depends on A1, A2, A3.
03_pcs_basefold depends on A1, A4, A5.
04_ucir_correctness depends on A6, A7.
05_state_diff_binding depends on A1, A2, A7.
06_end_to_end depends on all A1..A7 and the composition of their bounds.

## System Statement
For any accepted proof, the on-chain verifier accepts only if the statement hash and bound artifact tags correspond to a valid execution of the intended verification logic and constraints. This is formalized in `06_end_to_end.md`.

## Artifacts
- UCIR encoding and invariants: `docs/specs/ucir_spec.md`
- Adapter IR encoding and kernel routing: `docs/specs/adapter_ir_spec.md`
- Custom gate IDs, gating, and payloads: `docs/specs/custom_gates_spec.md`
- Verifier calldata and memory spec: `docs/specs/verifier_spec.md`
- Artifact tag and chain binding: `docs/specs/artifact_tag_spec.md`
- Canonical STARK receipt and VK encoding: `docs/specs/stark_receipt_spec.md`
- State transition VM spec: `docs/specs/state_transition_vm_spec.md`

## Proof Pack Index
1. `01_sumcheck.md`
2. `02_gkr_binding.md`
3. `03_pcs_basefold.md`
4. `04_ucir_correctness.md`
5. `05_state_diff_binding.md`
6. `06_end_to_end.md`
7. `07_mechanized_proof_plan.md`

## Mechanized Proof Scope
The written proofs are complete. Mechanized proofs are planned for the core
theorems using a proof assistant; the roadmap is documented separately.

## Proof-to-Code Map
The detailed mapping is in `06_end_to_end.md` and repeated in each chapter.

### 14.8.2 Sumcheck (`docs/proofs/01_sumcheck.md`)

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

### 14.8.3 GKR Binding (`docs/proofs/02_gkr_binding.md`)

# Formal Proof Pack - GKR Binding

## Definitions
The GLYPH artifact contains `(commitment_tag, point_tag, claim128, initial_claim)`. The artifact tag is `artifact_tag = keccak256(commitment_tag || point_tag)`.

The packed proof binds the artifact tag and claim values into the transcript before the final sumcheck polynomial is produced.

Let Tag = H(commitment_tag || point_tag). Let the transcript include Tag, claim128, and
initial_claim before challenge sampling. Let Proof be the packed GKR artifact proof.

Let FS be the Fiat-Shamir transcript function that maps absorbed bytes to challenges. The transcript input stream is fixed and domain-separated.

Statement binding for L2 updates uses the extended statement hash produced by
`statement_hash_extended` in `src/l2_statement.rs`. The exact preimage is:
`L2_STATE_DOMAIN || u256_be(chainid) || contract_addr || old_root || new_root || da_commitment || batch_id_be || extra_commitment || extra_schema_id`
where `contract_addr` is 20 bytes and `batch_id_be` is a big-endian u64.
The minimal flow uses statement_hash_minimal and omits `extra_commitment` and `extra_schema_id`.

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

### 14.8.4 PCS Commitment (BaseFold) (`docs/proofs/03_pcs_basefold.md`)

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

### 14.8.5 UCIR Correctness (`docs/proofs/04_ucir_correctness.md`)

# Formal Proof Pack - UCIR Correctness

## Definitions
UCIR is the Universal Constraint IR. The UCIR decoder enforces structure, bounds, and canonical
field elements.

Let D be the UCIR decoder. Let C be the UCIR compiler for a given adapter family. Let E be the
UCIR execution engine (witness evaluation). Let V be the upstream verifier for a receipt.

Define the UCIR semantics as a relation:
UCIR_SAT(ucir, w) == all gates evaluate to zero over the witness w, with the
witness layout constraints satisfied.

Define adapter correctness as:
ADAPTER_OK(receipt) == V(receipt) == true.

Gate semantics:
- Arithmetic gate enforces: q_mul*a*b + q_l*a + q_r*b + q_o*c + q_c = 0.
- Copy gate enforces: left == right.
- Lookup gate enforces: witness value is in the specified table.
- Custom gates encode adapter specific verifier relations.

## Lemmas
1. **Decoder Safety**: `Ucir2::from_bytes` rejects malformed encodings and out-of-range values.
2. **Compiler Correctness**: Each adapter compiler produces UCIR that faithfully represents the upstream verification logic for that receipt family.
3. **Execution Soundness**: UCIR execution enforces all constraints; any mismatch between public inputs and adapter proof logic yields a non-zero constraint and cannot be satisfied.
4. **Gate Semantics Preservation**: Each gate type in UCIR implements its algebraic meaning exactly as specified in `docs/specs/ucir_spec.md`.

## Theorem 4: UCIR Adapter Equivalence
Assuming A6 and A7, if a receipt verifies under the upstream verifier V, then the UCIR produced by compiler C is satisfiable under E. If V rejects, the UCIR constraints are unsatisfiable.

## Proof (Formal Sketch)
For a given adapter family F, the compiler C_F emits UCIR constraints encoding the verifier
equations of V_F. By A6, V_F is correct, so any accepting receipt satisfies those equations.
By Lemma 4, each UCIR gate enforces the exact algebraic semantics.
Therefore there exists a witness w derived from the receipt such that UCIR_SAT(ucir, w) holds.

Conversely, if V_F rejects, then the verifier equations are unsatisfied, and any UCIR witness must
violate at least one gate, so UCIR_SAT is false. This establishes equivalence.

Adapter-specific obligations:
- Groth16 and PLONK adapters: pairing and transcript equations must be mapped to UCIR gates.
- STARK adapters: FRI and constraint evaluation equations must be mapped to UCIR gates.
- IVC and Binius adapters: recursive verification relations must be mapped to UCIR gates.
- BLS12-381 SNARK/KZG adapters: commitment and pairing checks must be mapped to UCIR gates.

## Proof Obligations Checklist
For each adapter family F:
1) Receipt parsing yields the same public inputs as upstream.
2) UCIR emission matches verifier algebraic checks.
3) Witness layout respects UCIR invariants.
4) All custom gate payloads are validated and length checked.

## Expanded Equivalence Argument
For each adapter family F, define predicate R_F where R_F(receipt, public_inputs) holds iff upstream V_F accepts.
The compiler C_F emits UCIR such that: UCIR_SAT(ucir, w) <-> R_F(receipt, public_inputs).

This equivalence is established by: 1) Parsing correctness: receipt bytes map to the same public
inputs as upstream. 2) Gate correctness: each UCIR gate enforces the same algebraic constraint.
3) Witness completeness: the witness produced by the adapter contains all intermediate values
required by the constraints. Therefore UCIR_SAT holds iff the upstream verifier relation holds.

## Assumptions
- Upstream verifier logic is correct for its receipt format. UCIR execution is faithful to the defined gate semantics.

## Proof-to-Code Map
- UCIR encoding and invariants: `docs/specs/ucir_spec.md`, `src/glyph_ir.rs`
- Adapter IR byte encoding and routing: `docs/specs/adapter_ir_spec.md`, `src/adapter_ir.rs`
- Custom gate IDs, gating, and payloads: `docs/specs/custom_gates_spec.md`, `src/glyph_ir.rs`
- Canonical STARK receipt encoding: `docs/specs/stark_receipt_spec.md`, `src/stark_receipt.rs`
- Adapter compilation: `src/glyph_ir_compiler.rs`
- UCIR execution: `src/glyph_witness.rs`
- Equivalence tests: `scripts/tests/rust/ucir_compiler_equivalence.rs`

## Implementation Invariants
- UCIR decoder rejects trailing bytes and non canonical field elements. Custom gate payload sizes are validated. Witness evaluation returns zero for all constraints on valid receipts.

### 14.8.6 State Diff Binding (`docs/proofs/05_state_diff_binding.md`)

# Formal Proof Pack - State Diff Binding

## Definitions
State diffs are serialized into bytes and committed via a Merkle root. The root
is bound into the statement hash as an extra commitment in the extended binding
flow. This extra commitment is carried as `extra_commitment` in the statement
and is included in the chain binding.

Let D be the ordered diff list. Let R = MerkleRoot(D). Let H be Keccak256. Let
S be the statement hash computed by the L2 statement logic. Let Tag be the
artifact tag derived from S.

State model: A state is a mapping from keys to values, with keys for account
nonces, balances, code hashes, and storage slots. Keys and values are encoded as 32-byte
words. A transaction batch induces a transition from old_root to new_root with
a diff set D that records all changed leaves.

Diff extraction function (VM update flow):
1) Produce a deterministic ordered list of updates during VM execution.
2) For each update, append `key || old_value || new_value` (each 32 bytes) to the byte stream.
3) Chunk the byte stream into 32-byte leaves, padding the final chunk with zeros.
4) If the byte stream is empty, use a single zero leaf.
5) Pad the leaf list with zero leaves to the next power of two.
The ordering is the VM update order and is deterministic for a fixed execution trace.

Diff extraction function (JSON state diff flow):
1) Build the diff JSON as emitted by `glyph_state_diff`, with top-level `"version": 1`
   and an `accounts` array ordered by address. Each account's `storage` array is ordered by slot.
2) Canonicalize by sorting all object keys lexicographically. Array order is preserved.
3) Serialize the canonical JSON to bytes.
4) Apply the same 32-byte chunking and padding rules as above.

Merkle root definition:
- Let L_0 be the list of leaves (padded to power of two).
- For each level k, define L_{k+1}[i] = H(L_k[2i] || L_k[2i+1]).
- The root R is the single element of the final level.

## Lemmas
1. **Diff Root Determinism**: The diff root is deterministic given the ordered byte stream and padding rules.
2. **Statement Binding**: The extended statement hash binds the diff root into the transcript.
3. **Replay Resistance**: A proof bound to one diff root cannot be reused for another.
4. **Diff Extraction Correctness**: The diff extraction function produces a unique byte stream for the transition from old_root to new_root under the chosen producer (VM updates or canonical JSON diff).

## Theorem 5: State Diff Binding
Assuming A1 and A2, if a proof verifies under the extended statement hash, then
the diff root R is the one provided to the prover, and cannot be swapped without
invalidating the proof.

## Theorem 5b: State Diff Circuit Correctness
Assuming A7, if the VM executes a batch from old_root to new_root and produces
diff list D, then the circuit output state_diff_root equals MerkleRoot(D) as
defined by `src/state_diff_merkle.rs`.

## Proof (Formal Sketch)
1. Diff extraction is deterministic by construction. VM updates use execution order, while JSON diffs are canonicalized with sorted object keys and deterministic account and storage ordering. Both are encoded into 32-byte leaves with zero padding to the next power of two.
2. The Merkle root function in the circuit matches the Rust implementation on each level, including padding and hashing rules.
3. Therefore the computed root in the circuit matches MerkleRoot(D), and the bound statement ensures the proof ties to this root.

## Expanded Correctness Argument
Let exec(old_root, txs) -> (new_root, updates) be the VM execution. The update
order is deterministic for a fixed execution trace. The byte stream is formed by
concatenating `key || old_value || new_value` for each update. The leaf encoding
is fixed-length (32-byte chunks) and deterministic. The Merkle tree construction
uses zero padding to the next power of two and Keccak hashing on each internal node.

The circuit implements the same leaf encoding and the same Merkle reduction on
the produced byte stream. By induction on tree depth, each internal node in the
circuit matches the corresponding internal node in the Rust implementation.
Therefore the final root matches MerkleRoot(D).

## Proof Sketch
The prover computes the diff root and includes it as `extra_commitment`.
The statement hash and artifact tags include this value, and the schema id
is hashed alongside to prevent cross-schema replays. For state diff flow,
`extra_schema_id = keccak256("GLYPH_STATE_DIFF_MERKLE_V1")`. Any modification
to the diff root changes the artifact tag, causing verification to fail.

## Assumptions
- Fiat-Shamir transcript behaves as a random oracle (A1).
- Keccak256 collision resistance (A2).
- Correctness of statement hash derivation.

## Proof-to-Code Map
- Diff root computation: `src/state_diff_merkle.rs`
- Statement hash derivation: `src/bin/glyph_l2_statement.rs`
- Extended binding verifier: `contracts/GLYPHRootUpdaterExtended.sol`
- State transition VM: `src/state_transition_vm.rs`

## Implementation Invariants
- Merkle root uses zero padding to power of two.
- Statement hash includes extra_commitment and schema id.
- Verifier checks artifact tag derived from the statement hash.
- Diff list ordering and leaf encoding are canonical and deterministic.

### 14.8.7 End to End Soundness (`docs/proofs/06_end_to_end.md`)
# Formal Proof Pack - End to End Soundness

## Theorem
If the prover generates a GLYPH proof accepted by `GLYPHVerifier.sol`, then the
statement encoded by `(commitment_tag, point_tag, claim128)` corresponds to a
valid execution of the intended verification logic and bound inputs, except with
negligible probability under the stated assumptions.

Formally, for any accepted proof P and statement S, under A1..A7, there exists a
witness W such that UCIR constraints hold and the bound commitments correspond
to the same statement S. The on-chain header also checks claim128 and
initial_claim are canonical field elements and binds them into the chain hash.

## Proof Outline
1. By `01_sumcheck.md`, the sumcheck chain is sound under Fiat-Shamir.
2. By `03_pcs_basefold.md`, the PCS opening binds the evaluation table to the derived point.
3. By `02_gkr_binding.md`, the artifact tag is bound into the transcript and cannot be altered.
4. By `04_ucir_correctness.md`, adapter compilers and UCIR execution correctly encode upstream verification logic.
5. By `05_state_diff_binding.md`, the state diff root is bound into the statement hash and artifact
tags. Therefore, any accepted proof implies a valid statement consistent with the bound inputs.

## Expanded Proof
Assume a proof is accepted on-chain. The verifier recomputes the artifact tag
from commitment_tag and point_tag and verifies the packed GKR proof. By Theorem
2, the tag and transcript binding are correct, so the statement hash is fixed.
By Theorem 1, the sumcheck chain is sound for the claimed evaluation.
By Theorem 3, PCS openings bind the evaluation table to the transcript-derived
point. By Theorem 4, UCIR satisfiability is equivalent to upstream verification.
By Theorem 5, the state diff root bound into the statement corresponds to the
actual VM transition. Therefore the accepted proof implies a valid statement.
Transcript domains are fixed, so all challenges and tags are domain separated.

## Assumptions Registry
- Random Oracle Model for Fiat-Shamir.
- Collision resistance of Keccak256.
- Soundness of GKR and PCS binding.
- Correctness of adapter verification logic for each supported receipt format.
- UCIR and state-diff execution correctness.

## Soundness Error
Let epsilon_sumcheck be the sumcheck soundness error. Let epsilon_gkr be the GKR
soundness error. Let epsilon_pcs be the PCS binding error. The total soundness
error is bounded by:
epsilon_total <= epsilon_sumcheck + epsilon_gkr + epsilon_pcs + epsilon_hash
where epsilon_hash is negligible under A2.

## Explicit Error Composition
Define failure events:
- E_sumcheck: sumcheck accepts with a false claim.
- E_pcs: PCS opening verifies for an incorrect evaluation.
- E_gkr: GKR artifact proof verifies for a false transcript claim.
- E_ucir: UCIR constraints accept a receipt that upstream verifier rejects.
- E_state_diff: state_diff_root is bound but does not correspond to the real transition.
- E_hash: a collision in Keccak256 breaks binding.

Then:
Pr[accepts false statement] <= Pr[E_sumcheck] + Pr[E_pcs] + Pr[E_gkr] + Pr[E_ucir] + Pr[E_state_diff] + Pr[E_hash]

Under A1..A7, each event is negligible and the sum is negligible.

## Assumption Mapping Table
| Failure event | Bound term                     | Depends on |
|---------------|--------------------------------|------------|
| E_sumcheck    | 2r/\|F\|                       | A1         |
| E_pcs         | Adv_PCS_Binding + Adv_PCS_Corr | A1, A4, A5 |
| E_gkr         | Adv_GKR + Adv_RO + Adv_Hash    | A1, A2, A3 |
| E_ucir        | Adv_Adapter                    | A6, A7     |
| E_state_diff  | Adv_Diff_Correctness           | A7         |
| E_hash        | Adv_Hash                       | A2         |

## Quantitative Bounds (Default Parameters)
Let |F| = 2^128 - 159 and r be the number of packed rounds.
- epsilon_sumcheck <= 2r / |F|
- epsilon_pcs <= Adv_PCS_Binding
- epsilon_gkr <= Adv_GKR + Adv_RO + Adv_Hash
- epsilon_ucir <= Adv_Adapter
- epsilon_state_diff <= Adv_Diff_Correctness
- epsilon_hash negligible under A2

For default configs, epsilon_sumcheck is dominated by 2r/|F| and is far below 2^-80 for typical r.
The remaining terms are cryptographic assumptions. Example numeric bounds:
- r = 32: epsilon_sumcheck <= 1.88079096131566e-37
- r = 64: epsilon_sumcheck <= 3.76158192263132e-37

## Reproducible Calculation Method
To reproduce epsilon_sumcheck: 1) Set |F| = 2^128 - 159. 2) Set r from calldata
length. 3) Compute epsilon_sumcheck = 2r / |F|.

No other terms have concrete numeric values without selecting explicit
cryptographic security parameters for A1..A7.

## Reference Configuration (Non-Normative)
To provide a concrete numeric bound without constraining the protocol, we define
one reference instance for reporting:
- r_ref = 32 (reporting baseline).
- N_ref = 8^r_ref.
- epsilon_sumcheck_ref = 2 * r_ref / |F|.

This reference is used only for reporting. The protocol remains parameterized
by N, and the formal bound stays `2 * r / |F|`.

## Default Numeric Instantiation (Reference)
To instantiate concrete epsilon values without constraining the protocol, fix
the reference configuration r_ref = 32 and assume 128-bit security for the
cryptographic terms (Keccak256, PCS binding, and GKR transcript binding). Under
A6 and A7, epsilon_ucir and epsilon_state_diff are zero.

- epsilon_sumcheck_ref = 64 / (2^128 - 159) = 1.88079096131566e-37
- epsilon_crypto_ref <= 3 * 2^-128 = 8.81620763116716e-39
- epsilon_total_ref <= 1.96895303762733e-37

For r_ref = 64, epsilon_total_ref <= 3.84974399894299e-37 under the same assumptions.

## Parameter Table (Default)
| Parameter        | Symbol | Default                          |
|------------------|--------|----------------------------------|
| Field size       | \|F\|  | 2^128 - 159                      |
| Sumcheck rounds  | r      | number of packed rounds          |
| GKR rounds       | g      | derived from sumcheck challenges |
| Transcript hash  | H      | Keccak256                        |
| Statement hash   | S      | Keccak256                        |


## Proof-to-Code Trace
The following invariants are enforced at the code level:
- Transcript absorption order in `src/glyph_transcript.rs`.
- Tag computation in `src/glyph_gkr.rs` and `contracts/GLYPHVerifier.sol`.
- Statement binding in `src/l2_statement.rs` and `contracts/GLYPHRootUpdaterExtended.sol`.

## Proof-to-Code Map
- Sumcheck: `src/glyph_core/sumcheck.rs`, `src/glyph_core.rs`, `src/glyph_gkr.rs`
- PCS: `src/glyph_pcs_basefold.rs`, `src/pcs_common.rs`
- GKR artifact: `src/glyph_gkr.rs`, `contracts/GLYPHVerifier.sol`
- UCIR: `src/glyph_ir.rs`, `src/glyph_ir_compiler.rs`, `src/glyph_witness.rs`
- State diff binding: `src/state_diff_merkle.rs`, `src/bin/glyph_l2_statement.rs`
- Spec boundaries: `docs/specs/verifier_spec.md`, `docs/specs/artifact_tag_spec.md`, `docs/specs/ucir_spec.md`, `docs/specs/adapter_ir_spec.md`, `docs/specs/custom_gates_spec.md`, `docs/specs/stark_receipt_spec.md`, `docs/specs/state_transition_vm_spec.md`

## Implementation Invariants
- Transcript order is fixed for all absorbed domains.
- Public inputs are committed prior to PCS opening.
- Artifact tags are recomputed on-chain.
### 14.8.8 Mechanized Proof Plan (`docs/proofs/07_mechanized_proof_plan.md`)
# Formal Proof Pack - Mechanized Proof Plan

## Purpose
Provide a machine-checkable proof roadmap without constraining the protocol
implementation. This plan fixes theorem statements, dependencies, and the proof
structure required by a proof assistant.

## Target Assistants
Lean4 primary, Coq fallback.

## Proof Structure
Files: `sumcheck.lean`, `pcs_basefold.lean`, `gkr_binding.lean`,
`ucir_semantics.lean`, `state_diff_correctness.lean`, `end_to_end.lean`.

## Formal Statements (Lean-style sketches)
Sumcheck:
```
theorem sumcheck_soundness (f : F^n -> F) (S : F) :
  Pr[VerifierAcceptsFalse] <= (2 * r) / |F|
```
PCS Binding:
```
theorem pcs_binding (C : Commitment) (r : Point) :
  Adv_open_two_values <= Adv_RO + Adv_Bind + Adv_Corr
```
GKR Binding:
```
theorem gkr_tag_binding (Tag : Hash) (Proof : PackedProof) :
  Adv_mismatch <= Adv_RO + Adv_Hash + Adv_GKR
```
UCIR Equivalence:
```
theorem ucir_equivalence (receipt : Receipt) (ucir : UCIR) :
  VerifierOK(receipt) <-> UCIR_SAT(ucir)
```
State Diff Correctness:
```
theorem state_diff_root_correct (old_root new_root : Hash) :
  VM_exec -> circuit_root = MerkleRoot(diff_set)
```
End-to-End Composition:
```
theorem end_to_end_soundness :
  Adv_total <= sum(Adv_sumcheck, Adv_pcs, Adv_gkr, Adv_ucir, Adv_state_diff, Adv_hash)
```

## Proof Dependencies
A1..A7 from `docs/proofs/00_overview.md`, UCIR gate semantics from
`docs/specs/ucir_spec.md`, state diff rules from
`docs/specs/state_transition_vm_spec.md`, transcript domains from
`src/glyph_transcript.rs`.

## Acceptance Criteria
- Each theorem is encoded with explicit parameters and bound terms.
- Proof assistant builds without external edits to protocol code.
- Each lemma is mapped to the corresponding proof section in `docs/proofs/`.
## 15. Data Availability Profiles and Tooling

GLYPH verification works without DA. DA is an optional, developer selectable layer
for publishing proof payloads with strong availability and retrieval guarantees.
The verifier remains unchanged.

### 15.1 Profiles (Ethereum Settlement)

1) **verifier-only**
- No DA submission.
- Envelope still records hashes for audit and reproducibility.

2) **blob-only**
- Canonical DA is Ethereum blobs.
- Envelope records blob versioned hashes and tx hash.

3) **blob-arweave**
- Blob is canonical.
- Arweave provides long-term archival storage.

4) **blob-eigenda-arweave**
- Blob is canonical.
- EigenDA used as optional high throughput availability.
- Arweave provides long-term archival storage.

### 15.2 Payload Modes

- **minimal**
  - DA payload contains the GLYPH artifact bytes.
  - Envelope includes hashes for upstream proof and vk bytes (if provided).
- **full**
  - DA payload contains the artifact bytes, upstream proof bytes, and vk bytes.
  - Full mode is opt-in for maximum transparency.

### 15.3 Envelope

Each submission writes a canonical envelope with deterministic hashing:
- `artifact_tag`, `artifact_bytes_hash`, and `payload_hash`
- Optional `upstream_proof_hash` and `vk_hash`
- Provider commitments (blob versioned hashes, Arweave tx id, EigenDA blob key)

The envelope is hashed and stored as `envelope_hash`. This is stable and reproducible.

### 15.4 CLI

```
glyph_da envelope --profile <profile> --mode <minimal|full> --artifact <path> [--proof <path>] [--vk <path>]
glyph_da submit --profile <profile> --mode <minimal|full> --artifact <path> [--proof <path>] [--vk <path>]
glyph_da fetch --provider <blob|arweave|eigenda> --envelope <path> --out <path>
glyph_da verify --envelope <path> --payload <path>
```

### 15.4.1 End-to-End Example

Minimal blob-only submit, fetch, verify:
```bash
glyph_da submit --profile blob-only --mode minimal --artifact scripts/out/glyph/artifact.bin --out-dir scripts/out/da/blob-only/demo
glyph_da fetch --provider blob --envelope scripts/out/da/blob-only/demo/envelope.json --out scripts/out/da/blob-only/demo/payload.blob.bin
glyph_da verify --envelope scripts/out/da/blob-only/demo/envelope.json --payload scripts/out/da/blob-only/demo/payload.blob.bin
```

Outputs (example from the commands above):
- `scripts/out/da/blob-only/demo/envelope.json`
- `scripts/out/da/blob-only/demo/payload.bin`
- `scripts/out/da/blob-only/demo/envelope.meta.json`
- `scripts/out/da/blob-only/demo/payload.blob.bin`

### 15.5 Scripts and Env

Scripts:
- `scripts/da/submit_blob.sh`
- `scripts/da/submit_arweave.sh`
- `scripts/da/submit_eigenda.sh`
- `scripts/da/providers/arweave_turbo_upload.mjs`
- `scripts/da/providers/eigenda_v1/`
- `scripts/da/providers/eigenda_v2/`
- `scripts/da/fetch_blob.sh`
- `scripts/da/fetch_arweave.sh`
- `scripts/da/fetch_eigenda.sh`
- `scripts/da/fetch_eigenda_v2_srs.sh`
- `scripts/da/poll_eigenda.sh`
- `scripts/da/run_profile.sh`
- `scripts/da/run_all_profiles.sh`
- `scripts/da/smoke_test.sh`
- `scripts/da/arweave_local_smoke.sh`

Env:
- `docs/wallet/.env.wallet` for `DEPLOYER_ADDRESS` and `DEPLOYER_PRIVATE_KEY`
- `BLOB_RPC_URL` and `BLOB_PRIVATE_KEY` for blob submission
- `BLOB_TO` optional recipient for blob tx (default `0x0000000000000000000000000000000000000000`)
- `BLOB_TX_TIMEOUT_SECS` and `BLOB_TX_POLL_SECS` to control blob tx receipt polling
- `BLOB_TX_NONCE` to override the pending nonce used for blob submission
- `BLOB_TX_BUMP_FACTOR` and `BLOB_TX_PRIORITY_GAS_PRICE` to retry on replacement underpriced
- `BLOB_TX_GAS_PRICE` and `BLOB_TX_BLOB_GAS_PRICE` to override base fee calculations
- `ARWEAVE_CMD` for Arweave submission (must output JSON with `tx_id`)
- `ARWEAVE_JWK_PATH` for Turbo SDK submission when `ARWEAVE_CMD` is not set
- `ARWEAVE_TURBO_SCRIPT` path to the Turbo SDK upload script (default `scripts/da/providers/arweave_turbo_upload.mjs`)
- `EIGENDA_CMD` for EigenDA submission (must output JSON with `blob_key` and `certificate_hash`)
- `EIGENDA_MODE=v1` to enable EigenDA v1 direct disperser mode
- `EIGENDA_V1_DISPERSER_ADDR` for v1 disperser gRPC host:port
- `EIGENDA_V1_ETH_RPC_URL` for v1 on-chain confirmation checks
- `EIGENDA_V1_SVC_MANAGER_ADDR` EigenDAServiceManager address
- `EIGENDA_V1_SIGNER_PRIVATE_KEY_HEX` for authenticated v1 disperser access
- `EIGENDA_V1_NO_WAIT` set to 1 to return immediately with a pending request id (default 0)
- `EIGENDA_V1_CONFIRMATION_DEPTH` confirmation depth (default 1)
- `EIGENDA_V1_CONFIRMATION_TIMEOUT_SEC` confirmation timeout
- `EIGENDA_V1_STATUS_TIMEOUT_SEC` status timeout
- `EIGENDA_V1_STATUS_RETRY_SEC` status retry interval
- `EIGENDA_V1_DISABLE_TLS` set to 1 for local insecure disperser
- `EIGENDA_V1_DISABLE_POINT_VERIFY` set to 1 to skip point verification mode
- `EIGENDA_V1_GO_BIN` override go binary for the v1 helper
- `EIGENDA_V2_DISPERSER_ADDR` v2 disperser gRPC host:port
- `EIGENDA_V2_ETH_RPC_URL` v2 Ethereum RPC
- `EIGENDA_V2_CERT_VERIFIER_ADDR` v2 EigenDACertVerifier address
- `EIGENDA_V2_RELAY_REGISTRY_ADDR` v2 EigenDARelayRegistry address
- `EIGENDA_V2_AUTH_PRIVATE_KEY_HEX` v2 disperser auth key
- `EIGENDA_V2_SRS_DIR` path to EigenDA SRS directory (`g1.point`, `g2.point`, `g2.trailing.point`)
- Use `scripts/da/fetch_eigenda_v2_srs.sh` to populate the default repo path (`scripts/da/srs/eigenda_v2/`) and verify checksums.
- `EIGENDA_V2_BLOB_VERSION` blob version (default 0)
- `EIGENDA_V2_NO_WAIT` set to 1 to return immediately with pending status (default 0)
- `EIGENDA_V2_DISPERSE_TIMEOUT_SEC` disperse timeout
- `EIGENDA_V2_BLOB_COMPLETE_TIMEOUT_SEC` completion timeout
- `EIGENDA_V2_STATUS_POLL_SEC` status poll interval
- `EIGENDA_V2_CONTRACT_TIMEOUT_SEC` contract call timeout
- `EIGENDA_V2_RELAY_TIMEOUT_SEC` relay timeout
- `EIGENDA_V2_GO_BIN` override go binary for the v2 helper
- `EIGENDA_PROXY_URL` for EigenDA proxy submission and retrieval (alternative to `EIGENDA_CMD` and `EIGENDA_RETRIEVER_URL_TEMPLATE`)
- `EIGENDA_COMMITMENT_MODE` for EigenDA proxy commitment mode (default `standard`)
- `BLOB_RETRIEVER_URL_TEMPLATE` for blob fetch
- `BLOB_BEACON_API_URL` for blob fetch via Beacon API (alternative to `BLOB_RETRIEVER_URL_TEMPLATE`)
- `ARWEAVE_GATEWAY_URL` for Arweave fetch
- `EIGENDA_RETRIEVER_URL_TEMPLATE` for EigenDA fetch
- `PROFILE` for `scripts/da/smoke_test.sh` (one of `verifier-only`, `blob-only`, `blob-arweave`, `blob-eigenda-arweave`)
- `ARTIFACT_PATH` for `scripts/da/smoke_test.sh` (artifact bytes path)
- `MODE` for `scripts/da/smoke_test.sh` (default `minimal`)
- `OUT_DIR` for `scripts/da/smoke_test.sh` (default `scripts/out/da/smoke/` with profile and timestamp subdirs)
- `RUN_SMOKE=1` to make `scripts/da/run_all_profiles.sh` run smoke tests instead of submit-only
- `V2_SMALL_PAYLOAD=0` to disable small-payload truncation for v2 runs in `scripts/da/run_profile.sh`

### 15.5.1 DA Run Profiles

Single entrypoint with presets and env checks:
```bash
scripts/da/run_profile.sh --profile full --network sepolia --artifact scripts/tools/fixtures/groth16_bn254_fixture.txt --with-v2
```

Options:
- `--network sepolia|hoodi` to load `scripts/deploy/.env.sepolia` or `scripts/deploy/.env.hoodi`
- `--env-file <path>` to load a specific env file

Profiles:
- `blob-only` for minimal blob transport
- `blob-arweave` for blob plus archival
- `blob-eigenda-arweave` or `full` for the full package
- `eigenda-v2` for Sepolia only

Notes:
- Use `--with-v2` to run v2 after the full package.
- `V2_SMALL_PAYLOAD=1` (default) truncates to 1 KiB for v2 when SRS load is limited.
- EigenDA v1 poll runs only when a pending `request_id` is present in the envelope.

Selection guide:
- Use `blob-only` if you want minimal transport with lowest ops burden.
- Use `blob-arweave` if you need archival retrieval guarantees.
- Use `blob-eigenda-arweave` if you want throughput and redundancy.
- Use `eigenda-v2` on Sepolia only. Use a small payload if the SRS load is limited.

Payload composition and size:
- The DA payload is the GLYPH payload: artifact bytes plus optional upstream proof and VK.
- Payload size depends on the upstream proof and what you include. It is not fixed.
- The 1 KiB truncation only applies to EigenDA v2 test runs when the loaded SRS is small.
- For production v2 payloads, increase SRS load or disable `V2_SMALL_PAYLOAD`.

Transaction data:
- Transaction data is not part of the default GLYPH payload.
- If you need to archive transaction data, include it as an external artifact and store it via DA, then reference it in your app logic or envelope meta.

### 15.5.2 Smoke Test Script

Run submit -> fetch -> verify in one shot:
```bash
export PROFILE=blob-eigenda-arweave
export ARTIFACT_PATH=scripts/out/glyph/artifact.bin
./scripts/da/smoke_test.sh
```

The script uses the standard DA env vars for each provider and writes outputs to
`scripts/out/da/smoke/` with profile and timestamp subdirectories.

Notes:
- `scripts/da/submit_arweave.sh` invokes `ARWEAVE_CMD` with `ARWEAVE_DATA_PATH` set to the payload path.
- `scripts/da/submit_eigenda.sh` invokes `EIGENDA_CMD` with `EIGENDA_DATA_PATH` set to the payload path.
- `scripts/da/fetch_blob.sh` accepts either raw blob bytes or JSON payloads containing a hex string under `blob.data` or `data` and decodes to raw bytes.
- EigenDA v1 direct mode uses `blob_key` format `0x<batch_header_hash>:<blob_index>`.
- EigenDA v1 no-wait returns a pending `request_id` and requires polling before fetch.

### 15.5.3 Arweave Local Smoke Test

Free local Arweave test using `arlocal`:
```bash
ARTIFACT_PATH=scripts/tools/fixtures/groth16_bn254_fixture.txt ./scripts/da/arweave_local_smoke.sh
```

Validated locally with the default test artifact and wallet JWK.

### 15.5.4 EigenDA v1 Submit and Poll

Submit without waiting for inclusion:
```bash
EIGENDA_MODE=v1 EIGENDA_V1_NO_WAIT=1 ./scripts/da/submit_eigenda.sh
```

Poll the envelope until a `blob_key` is available:
```bash
DA_ENVELOPE_PATH=scripts/out/da/blob-eigenda-arweave/<ts>/envelope.json ./scripts/da/poll_eigenda.sh
```

Validated on Sepolia with `no-wait -> poll -> fetch`, and the retrieved payload hash matched the source artifact.

### 15.5.5 EigenDA v2 Submit, Poll, and Fetch

EigenDA v2 requires a funded payment vault and the EigenDA SRS files. Configure the v2 envs and then:
Status: Sepolia only.

Submit without waiting for completion:
```bash
EIGENDA_MODE=v2 EIGENDA_V2_NO_WAIT=1 ./scripts/da/submit_eigenda.sh
```

Poll until complete:
```bash
EIGENDA_MODE=v2 DA_ENVELOPE_PATH=scripts/out/da/blob-eigenda-arweave/<ts>/envelope.json ./scripts/da/poll_eigenda.sh
```

Fetch via relays:
```bash
EIGENDA_MODE=v2 DA_ENVELOPE_PATH=scripts/out/da/blob-eigenda-arweave/<ts>/envelope.json ./scripts/da/fetch_eigenda.sh
```

Validated on Sepolia using `CERT_VERIFIER_LEGACY_V2` from the EigenDA Directory and a small payload to fit the default SRS load. Fetch returned a payload hash match.
Latest v2 run output:
- `scripts/out/da/eigenda-v2/sepolia-20260120T012205Z/`
Note: The v2 helper currently loads a limited SRS size. Use a small payload (for example 1 KiB) or adjust the SRS load if you need larger payloads.

### 15.5.6 Live Integration Tests

`scripts/tests/rust/da_integration_tests.rs` runs live submit -> fetch -> verify loops when
`GLYPH_DA_LIVE=1` and the provider envs are set. If any env var is missing, the
test is skipped without mocks.

Required envs:
- blob-only: `BLOB_RPC_URL`, `BLOB_PRIVATE_KEY`, and one of `BLOB_RETRIEVER_URL_TEMPLATE` or `BLOB_BEACON_API_URL`
- blob-arweave: blob-only + (`ARWEAVE_CMD` or `ARWEAVE_JWK_PATH`) + `ARWEAVE_GATEWAY_URL`
- blob-eigenda-arweave: blob-arweave + (`EIGENDA_CMD` or `EIGENDA_PROXY_URL`) + (`EIGENDA_RETRIEVER_URL_TEMPLATE` or `EIGENDA_PROXY_URL`)

Optional:
- `GLYPH_DA_BIN` can override the `glyph_da` binary path if `CARGO_BIN_EXE_glyph_da` is not set.

Env templates:
- `scripts/deploy/.env.sepolia.example`
- `scripts/deploy/.env.hoodi.example`

Live blob submissions were validated on Sepolia and Hoodi. Detailed run logs and
transaction ids are stored in `docs/context.md`.

Full package validation (blob + eigenda v1 + arweave):
- Sepolia: `scripts/out/da/blob-eigenda-arweave/sepolia-20260119T215152Z/`
- Hoodi: `scripts/out/da/blob-eigenda-arweave/20260120T011221Z/`

### 15.5.7 Devnet Requirements

Blob submission uses `cast send --blob`, so the RPC must support EIP-4844 blob
transactions. For a devnet run, point `BLOB_RPC_URL` to a blob-capable devnet RPC.
If the RPC does not support blobs, the submit step fails as expected.
Beacon fetch uses `BLOB_BEACON_API_URL` to resolve blob sidecars by slot. This is an
alternative to the retriever template and still requires `BLOB_RPC_URL` for block data.

Arweave Turbo SDK submission uses an Arweave JWK wallet to sign a data item and upload
via Turbo. Install the SDK and point `ARWEAVE_JWK_PATH` to the wallet file. The upload
returns a transaction id that can be fetched from the gateway you provide via `ARWEAVE_GATEWAY_URL`.
Install Turbo SDK (one-time):
`npm install @ardrive/turbo-sdk` (or `bun add @ardrive/turbo-sdk`).

EigenDA proxy mode uses a REST proxy that exposes `/put` and `/get` endpoints over the
EigenDA disperser and retriever. Set `EIGENDA_PROXY_URL` to that proxy and use
`EIGENDA_COMMITMENT_MODE=standard` unless you need a different commitment mode.

### 15.5.8 DA Release Readiness Checklist
- No provider-specific RPC URLs or API keys in public docs. Benchmark tx hashes are listed only in Section 14.2.1.
- Env files are placeholders only; examples live under `scripts/deploy/.env.sepolia.example`, `scripts/deploy/.env.hoodi.example`, `scripts/deploy/.env.network.example`, and `scripts/deploy/.env.wallet.example`.
- DA scripts are POSIX shell only, fail fast when required envs are missing.
- v2 is Sepolia-only.
- Optional live validation runs are documented and reproducible.
- DA payload encode/decode and envelope hash logic are covered by unit and property tests.

### 15.5.9 DA Final Validation Plan (Optional)
Minimal final validation runs if you want fresh proofs before release:
- Blob DA: Sepolia and Hoodi submit -> fetch -> verify.
- EigenDA v1: Sepolia and Hoodi no-wait submit -> poll -> fetch.
- EigenDA v2: Sepolia only, submit -> poll -> fetch.
- Arweave: local smoke test via arlocal.

### 15.5.10 DA Feature Gates and Flow

Feature gates are simple profile selectors. The verifier stays the same.
The DA interface is provider-neutral. The current release supports Ethereum blobs,
EigenDA v1/v2, and Arweave through the same envelope format and submit or fetch
flow. Additional DA providers can be integrated by implementing the same
envelope schema and provider hooks.

| Profile              | Providers                   | Networks       | Notes                             |
|----------------------|-----------------------------|----------------|-----------------------------------|
| verifier-only        | none                        | all            | No DA, proof verification only.   |
| blob-only            | blob                        | Sepolia, Hoodi | Canonical DA.                     |
| blob-arweave         | blob + arweave              | Sepolia, Hoodi | Adds archival storage.            |
| blob-eigenda-arweave | blob + eigenda v1 + arweave | Sepolia, Hoodi | Throughput option via EigenDA v1. |
| eigenda-v2           | eigenda v2                  | Sepolia only   | Sepolia only.                     |

DA flow (full package):
```
artifact -> glyph_da submit -> envelope.json
  -> eigenda v1 poll (if pending)
  -> glyph_da fetch (per provider)
  -> glyph_da verify (per provider)
```

Single entrypoint:
```
scripts/da/run_profile.sh --profile blob-eigenda-arweave --network sepolia --artifact /path/to/payload.bin
```

### 15.6 Security Model

- Canonical DA is Ethereum blobs.
- Arweave is archival, not canonical DA.
- EigenDA is optional high throughput availability, not canonical DA.
- Envelope hashing binds payload content to commitments.

### 15.7 Feature Matrix (GLYPH vs Starknet-Style State Layer)

| Capability                 | GLYPH        | Starknet-Style State Layer |
|----------------------------|--------------|----------------------------|
| Proof verification         | Yes          | Yes                        |
| Universal adapters         | Yes          | No (app-specific)          |
| DA pipeline                | Optional     | Required                   |
| State diff generation      | Implemented  | Yes                        |
| State diff verification    | In progress  | Yes                        |
| Sequencer commitments      | In progress  | Yes                        |
| L2 state machine execution | Implemented  | Core                       |

Notes:
- GLYPH is a universal verifier and proof transport layer, not a state transition system.
- State diffs can be built on top of GLYPH, but they are a separate workstream.
- "Implemented" refers to the state diff toolkit and GLYPH VM outputs.
- "In progress" refers to the VM circuit path and sequencer binding work.

### 15.8 State Diff Toolkit

GLYPH provides a state diff toolkit and a dedicated state transition VM. The toolkit provides:
- Canonical JSON encoding for diffs
- Deterministic diff hashes
- Optional emission of canonical bytes for DA transport
- Property tests for canonicalization, tamper detection, and large diff stability

State snapshot input format (chain-agnostic):
```json
{
  "accounts": {
    "0xabc...": {
      "nonce": "0x1",
      "balance": "0x0",
      "code_hash": "0x0",
      "storage": {
        "0x00": "0x0",
        "0x01": "0x02"
      }
    }
  }
}
```

State diff output format:
```json
{
  "version": 1,
  "accounts": [
    {
      "address": "0xabc...",
      "created": true,
      "nonce": {"from": "0x0", "to": "0x1"},
      "balance": {"from": "0x0", "to": "0x0"},
      "code_hash": {"from": "0x0", "to": "0x0"},
      "storage": [
        {"slot": "0x01", "from": "0x0", "to": "0x02"}
      ]
    }
  ]
}
```

Build a diff from two snapshots:
```bash
glyph_state_diff build --pre /path/to/pre.json --post /path/to/post.json --out /tmp/state_diff.json --emit-bytes /tmp/state_diff.bytes --json
```

Convenience wrapper:
```bash
scripts/da/state_diff_from_snapshots.sh --pre /path/to/pre.json --post /path/to/post.json --out /tmp/state_diff.json --emit-bytes /tmp/state_diff.bytes
```

Proof binding flow (statement tags + proof calldata):
```bash
scripts/da/state_diff_proof_flow.sh \
  --pre /path/to/pre.json --post /path/to/post.json \
  --chainid 11155111 \
  --verifier 0x<glyph_verifier_addr> \
  --contract 0x<root_updater_addr> \
  --old-root 0x<old_root> --new-root 0x<new_root> --batch-id 0
```

Outputs:
- `bundle.json` includes the state diff hash, statement tags, and proof calldata.
- Use the proof calldata with the root updater contract.
- Use `state_diff.bytes` as the DA payload if you want to store the diff off-chain.

On-chain verify via root updater:
```bash
scripts/da/state_diff_onchain_verify.sh \
  --rpc https://<your-rpc> \
  --private-key 0x<key> \
  --root-updater 0x<root_updater_addr> \
  --new-root 0x<new_root> \
  --da-commitment 0x<state_diff_hash> \
  --proof-json /path/to/proof.json
```

### 15.9 State Transition VM

The GLYPH state transition VM provides a deterministic execution engine, Merkle-based state model, and circuit-friendly trace that binds `old_root`, `new_root`, and `state_diff_root` into the GLYPH artifact.

Spec:
- `docs/specs/state_transition_vm_spec.md`

Key properties:
- Gas-neutral on-chain. No verifier changes and no calldata growth beyond the artifact-bound header inputs.
- Keccak-based state root with deterministic zero hashes.
- Deterministic op semantics (`store`, `add`) with range-safe u256 add constraints.
- Canonical diff bytes: `key || old_value || new_value`, padded via `state_diff_merkle`.

VM execution and proof tooling:
```bash
glyph_state_transition_execute --in /path/to/ops.json --out /tmp/batch.json
glyph_state_transition_prove --in /tmp/batch.json --chainid 11155111 --verifier 0x<glyph_verifier> --json --out /tmp/vm_proof.json
```

Flow wrapper:
```bash
scripts/da/state_transition_vm_flow.sh --ops /path/to/ops.json --chainid 11155111 --verifier 0x<glyph_verifier>
```

Ops input format:
```json
{
  "depth": 4,
  "ops": [
    {"op": "store", "key": "0x..32 bytes..", "value": "0x..32 bytes.."},
    {"op": "add", "key": "0x..32 bytes..", "delta": "0x..32 bytes.."}
  ]
}
```

Batch output format includes per-update proofs and is compatible with `glyph_state_transition_prove`.

Hash a state diff and emit canonical bytes:
```bash
glyph_state_diff hash --in /path/to/state_diff.json --emit-bytes /tmp/state_diff.bytes
```

Verify a state diff hash:
```bash
glyph_state_diff verify --in /path/to/state_diff.json --hash 0x...
```

State diff prover benchmarks (local):
- Environment: Apple M1, macOS 24.6.0, rustc 1.92.0-nightly. Inputs are 1 MiB and 10 MiB synthetic bytes (repeated from `/tmp/state_diff.bytes`).
- Fast mode avg prove: 1 MiB 108.54 ms, 10 MiB 1780.65 ms. Merkle share about 7.7 percent.
- ZK mode avg prove: 1 MiB 198.15 ms, 10 MiB 3120.49 ms. Merkle share about 4.2 percent.
- Compile vs prove (fast): 1 MiB 9.24 ms plus 85.99 ms. 10 MiB 152.59 ms plus 1476.01 ms.
- Raw outputs: `scripts/out/benchmarks/state_diff_prover_summary.json`.

Summary table (ms):

| Mode | Size   | Prover avg | Merkle share | Compile | Prove   |
|------|--------|------------|--------------|---------|---------|
| fast | 1 MiB  | 108.54     | 7.7%         | 9.24    | 85.99   |
| fast | 10 MiB | 1780.65    | 7.7%         | 152.59  | 1476.01 |
| zk   | 1 MiB  | 198.15     | 4.2%         | -       | -       |
| zk   | 10 MiB | 3120.49    | 4.4%         | -       | -       |

DA integration:
- Use the emitted `state_diff.bytes` as the artifact input for `glyph_da` or `run_profile.sh`.
- This stores the diff on DA and binds it to the envelope hash.

**Foundry tests (Solidity verifier):**
```bash
cd scripts/tests/foundry
forge test -vv
```

**GLYPH Sepolia deployment:**
```bash
NETWORK=sepolia ./scripts/deploy/deploy_glyph_contract.sh
```

**Local Anvil gas benchmark:**
```bash
./scripts/benchmarks/bench_glyph_evm_local.sh
```

**STARK baseline KPIs:**
```bash
./scripts/benchmarks/bench_stark_do_work_kpis.sh
```

For detailed deployment instructions, see Appendix L or `docs/QUICKSTART.md`.


### Script Utilities and Foundry Integration (`scripts/`)

The `scripts/` directory contains essential tooling for benchmarking and deployment.

#### 1. Benchmark Suites (`scripts/benchmarks/`)
- **Bench scripts**: A collection of Bash scripts for running various performance tests under `scripts/benchmarks/`.
    - **KPI Benchmarks**: `scripts/benchmarks/bench_bn254_batch_kpi.sh`, `scripts/benchmarks/bench_bn254_g2_kpi.sh`, `scripts/benchmarks/bench_bn254_msm_kpi.sh`, `scripts/benchmarks/bench_bn254_mul_kpi.sh`, `scripts/benchmarks/bench_bn254_trace_kpi.sh`, `scripts/benchmarks/bench_glyph_zk_kpi.sh` (measure field ops, MSM, proof sizes).
    - **Network Benchmarks**: `scripts/benchmarks/bench_glyph_evm_local.sh`, `scripts/benchmarks/bench_glyph_evm_round_sweep.sh`, `scripts/benchmarks/bench_glyph_evm_sepolia.sh`, `scripts/benchmarks/bench_glyph_evm_artifact.sh`, `scripts/benchmarks/bench_glyph_sepolia_artifact.sh`, `scripts/benchmarks/bench_glyph_hoodi_artifact_truncated.sh`, `scripts/benchmarks/bench_glyph_adapter_hoodi.sh`, `scripts/benchmarks/bench_glyph_sepolia_stmt.sh` (deploy verifiers and measure gas costs on local or testnet chains; `scripts/benchmarks/bench_glyph_sepolia_stmt.sh` uses the artifact-bound layout).
    - **Artifact-only calldata**: GLYPHVerifier accepts artifact-bound layouts only. Bench scripts generate calldata via `--hash-merge` to derive `commitment_tag` and `point_tag`.
    - **Features**: Automatic timeout handling, environment variable configuration, eth_call prechecks for EVM benches, receipt status validation, and JSON output generation.
    - **Outputs**: Default output is `scripts/out/benchmarks/` (override with `OUT_DIR` or `OUT_FILE`). Cross-network summaries are written to `scripts/out/benchmarks/bench_glyph_compare.json` and `scripts/out/benchmarks/bench_glyph_compare.md`.

#### 2. Deployment & Verification (`scripts/deploy/`, `contracts/`)
- **`contracts/GLYPHVerifier.sol`**: The core on-chain verifier contract (copied into `scripts/tests/foundry/GLYPHVerifier.sol` for testing).
    - **Optimized Assembly**: Uses raw `assembly` blocks for maximum gas efficiency.
    - **Packed Calldata**: Expects tightly packed arguments (no ABI selector) for lower call costs.
    - **Protocol**: Implements a Fiat-Shamir transformed GKR protocol with sumcheck and linear combination evaluations.
- **`scripts/deploy/deploy_glyph_contract.sh`**: Robust deployment script using `forge create`. Supports multiple networks (Sepolia, Hoodi), environment variable checks (`.env` files), and balance verification.
- **`scripts/tests/run_tests.sh`**: Comprehensive test runner that executes Rust unit tests, updates Solidity test vectors (by running Rust generators), and then runs Foundry tests.
- **Auto-Generated Tests**: Solidity test files like `GLYPH_SNARK_GROTH16_Test.t.sol` are automatically generated from Rust to ensure the on-chain verifier matches the off-chain prover logic perfectly.

---

---

## 16. Testnet Deployment Requirements (Normative)

The final repository state MUST include reproducible deployments for:

- Hoodi (required testnet)

Note: Sepolia is optional. 

For each network, the repo MUST provide:

- a reproducible deployment script that writes a deployment JSON under `deployments/` (for example `deployments/sepolia.json`) containing:
  - chain id
  - contract addresses
  - bytecode hash (or `cast code` output hash)
- a post-deploy verification step that asserts bytecode is non-empty at the address
- Etherscan verification where supported

## 17. Test Suite Requirements (Normative)

The final repository state MUST include:

### 17.1 Rust tests
- unit tests for canonical encodings and parsing rejection (receipt, VK, program, IR)
- kernel roundtrip and tamper tests for:
  - transcript challenges
  - Merkle multiproofs
  - Fp128 arithmetic
  - FRI fold checks
  - AIR evaluation checks

### 17.2 End-to-end trustless validity tamper test (non-negotiable)

There MUST exist an integration test that:
- produces a valid upstream STARK receipt and a valid GLYPH proof, and verifies it on-chain, then
- tampers the upstream proof bytes (or public input bytes or VK/program bytes) while keeping any digest metadata consistent, and
- proves that the pipeline cannot produce an on-chain accepted GLYPH proof for the tampered receipt.

### 17.3 Foundry tests
- deterministic vector-based tests for all on-chain verifiers
- tamper rejection tests for packed calldata
- gas KPI tests that record execution gas and detect regressions

## 18. Performance Requirements (Normative)

The final system MUST aggressively optimize for:

- on-chain gas (primary)
- off-chain prover throughput (secondary)

At minimum, the repository MUST include:

- an ARM SIMD profiling report (M1/M2) for the prover hot path
- an audit of `contracts/GLYPHVerifier.sol` memory layout and calldata decoding for gas regressions
- evaluation of Shamir-style multi-scalar optimizations where applicable to the final check

---

## Appendix G: Canonical STARK Encodings (SSOT)

This appendix defines the **normative canonical encoding** for STARK inputs, specifically for Winterfell, Circle STARK, and Stwo profiles. These layouts are non-negotiable for the GLYPH canonical adapter.

### G.1 Canonical Domains

The STARK adapter MUST use the following canonical domains:

- `CANONICAL_STARK_RECEIPT_DOMAIN = b"CANONICAL_STARK_RECEIPT"`
- `CANONICAL_STARK_VK_DOMAIN = b"CANONICAL_STARK_VK"`
- `CANONICAL_STARK_VK_PROGRAM_DOMAIN = b"CANONICAL_STARK_VK_PROGRAM"`

### G.2 CanonicalStarkReceipt Encoding

Receipt encoding MUST be domain-separated, length-prefixed, and strictly parsed:

- `CANONICAL_STARK_RECEIPT_DOMAIN`
- `proof_len_be_u32 || proof_bytes`
- `pub_inputs_len_be_u32 || pub_inputs_bytes`
- `vk_len_be_u32 || vk_bytes` (must decode as `CanonicalStarkVk`)

**Receipt digest:**
- `receipt_digest := keccak256(encode_for_hash(receipt))`

### G.3 CanonicalStarkVk Encoding

VK encoding MUST be domain-separated, length-prefixed, and strictly parsed:

- `CANONICAL_STARK_VK_DOMAIN`
- `vk_version_u16_be` (initially `0x0001`)
- `field_id_u8`
- `hash_id_u8`
- `commitment_scheme_id_u8`
- `consts_len_be_u32 || consts_bytes` (canonical, system-defined constants blob)
- `program_len_be_u32 || program_bytes`
- `program_hash_bytes32`

**Program hash binding:**
- `program_hash := keccak256(CANONICAL_STARK_VK_PROGRAM_DOMAIN || program_bytes)`
- `program_hash_bytes32` MUST equal `program_hash`.

### G.4 Winterfell Consts Schema (Canonical)

For the canonical Winterfell profile, `consts_bytes` MUST be the canonical VK-params encoding:

- `CANONICAL_VK_STARK_PREFIX = b"GLYPH-STARK-VK\x00"`
- `WINTERFELL_IMPL_ID = b"winterfell-0.13\x00"` (16 bytes)
- `FIELD_F128_ID = 0x01`
- `FIELD_F64_ID = 0x02`
- `VC_MERKLE_ID = 0x01`
- `HASH_BLAKE3_ID = 0x01`
- `HASH_SHA3_ID = 0x02`

**Encoding (strict):**
- `CANONICAL_VK_STARK_PREFIX`
- `impl_id[16]` (must equal `WINTERFELL_IMPL_ID`)
- `field_id_u8` (must equal `FIELD_F128_ID` or `FIELD_F64_ID`)
- `hash_id_u8` (must be one of the defined hash ids)
- `commitment_scheme_id_u8` (must equal `VC_MERKLE_ID`)
- `field_extension_u8` (must equal `0x01` for FieldExtension::None or `0x02` for FieldExtension::Quadratic)
- `air_id_len_u16_be || air_id_bytes`
- `trace_width_u16_be`
- `trace_length_u32_be`
- `num_queries_u32_be`
- `blowup_factor_u32_be`
- `grinding_factor_u32_be`

### G.5 Winterfell Stark Program (Canonical)

For the canonical Winterfell profile, `program_bytes` MUST be encoded as:

- `WINTERFELL_STARK_PROGRAM_TAG = b"WINTERFELL_STARK_PROGRAM"`
- `version_u16_be = 0x0001`
- `impl_id[16]`
- `field_id_u8`, `hash_id_u8`, `commitment_scheme_id_u8`
- `air_id_len_u16_be || air_id_bytes`
- `ir_len_be_u32 || ir_bytes` (canonical verifier IR container)

**Canonical Identifiers:**
- `DO_WORK_AIR_ID = b"do_work:x^3+42"`
- `FIB_AIR_ID = b"fibonacci:a+b"`
- `TRIB_AIR_ID = b"tribonacci:a+b+c"`

**Winterfell public input layouts (canonical):**
- `do_work` (F128): `pub_inputs_bytes = start_u128_be || result_u128_be` (32 bytes total), `trace_width = 1`.
- `do_work` (F64): `pub_inputs_bytes = start_u64_be || result_u64_be` (16 bytes total), `trace_width = 1`.
- `fibonacci` (F128): `pub_inputs_bytes = start_a_u128_be || start_b_u128_be || result_u128_be` (48 bytes total), `trace_width = 2`.
- `fibonacci` (F64): `pub_inputs_bytes = start_a_u64_be || start_b_u64_be || result_u64_be` (24 bytes total), `trace_width = 2`.
- `tribonacci` (F128): `pub_inputs_bytes = start_a_u128_be || start_b_u128_be || start_c_u128_be || result_u128_be` (64 bytes total), `trace_width = 3`.
- `tribonacci` (F64): `pub_inputs_bytes = start_a_u64_be || start_b_u64_be || start_c_u64_be || result_u64_be` (32 bytes total), `trace_width = 3`.

### G.6 Verifier IR Container & Kernel Registry

The verifier IR container MUST be:

- `STARK_VERIFIER_IR_TAG = b"STARK_VERIFIER_IR"`
- `version_u16_be = 0x0001`
- `op_count_u16_be`
- repeated `op_count` times:
  - `kernel_id_u16_be`
  - `args_len_be_u32 || args_bytes`

**Canonical Kernel IDs:**

| kernel_id | Name                                     |
|-----------|------------------------------------------|
| 0x0001    | `WINTERFELL_SHA3_TRANSCRIPT`             |
| 0x0002    | `WINTERFELL_SHA3_TRACE_OPENINGS`         |
| 0x0003    | `WINTERFELL_SHA3_CONSTRAINT_OPENINGS`    |
| 0x0004    | `WINTERFELL_SHA3_FRI_OPENINGS`           |
| 0x0005    | `WINTERFELL_SHA3_FRI_REMAINDER`          |
| 0x0006    | `WINTERFELL_FRI_VERIFY`                  |
| 0x0007    | `WINTERFELL_AIR_VERIFY`                  |
| 0x0008    | `WINTERFELL_DEEP_COMPOSITION`            |

**BLAKE3 Kernel IDs:**

| kernel_id | Name                                     |
|-----------|------------------------------------------|
| 0x0101    | `WINTERFELL_BLAKE3_TRANSCRIPT`           |
| 0x0102    | `WINTERFELL_BLAKE3_TRACE_OPENINGS`       |
| 0x0103    | `WINTERFELL_BLAKE3_CONSTRAINT_OPENINGS`  |
| 0x0104    | `WINTERFELL_BLAKE3_FRI_OPENINGS`         |
| 0x0105    | `WINTERFELL_BLAKE3_FRI_REMAINDER`        |
| 0x0106    | `WINTERFELL_BLAKE3_FRI_VERIFY`           |
| 0x0107    | `WINTERFELL_BLAKE3_AIR_VERIFY`           |
| 0x0108    | `WINTERFELL_BLAKE3_DEEP_COMPOSITION`     |

The canonical `do_work` SHA3 IR program uses these kernels in exactly this order: 1, 2, 3, 4, 5, 8, 6, 7.
The canonical `do_work` Blake3 IR program uses these kernels in exactly this order: 0x0101, 0x0102, 0x0103, 0x0104, 0x0105, 0x0108, 0x0106, 0x0107.

### G.7 Circle STARK Profile (M31, BabyBear, KoalaBear)

For Circle STARK receipts (field_ids 0x03, 0x04, 0x06), `consts_bytes` MUST use `CIRCLE_STARK_PROFILE_TAG`.
Program bytes MUST use `CIRCLE_STARK_SIMPLE_PROGRAM_TAG` (simple constraints) or `CIRCLE_STARK_EXPR_PROGRAM_TAG` (expression DAG).
`hash_id` MUST be one of:
- `0x02` (SHA3-256 transcript + Merkle hashing)
- `0x01` (BLAKE3 transcript + Merkle hashing)
- `0x04` (Poseidon transcript + Merkle hashing)
- `0x05` (Rescue transcript + Merkle hashing)

**Constraints (simple program):**
- `CUBE_PLUS_CONST (0x01)`: `a^3 + c`
- `LINEAR_MIX (0x02)`: `a + b + c`
- `MUL_PLUS_CONST (0x03)`: `a*b + c`

**Constraints (expression DAG program):**
- `LINEAR_COMBO (0x04)`: `constant + sum(coeff_i * term_i)`
- `MUL_ADD (0x05)`: `constant + a*b + sum(coeff_i * term_i)`

### G.8 Stwo Profile (M31 + Blake2s)

For Stwo receipts (M31 + Blake2s), `consts_bytes` MUST use `STWO_PROFILE_TAG`.
Program bytes MUST use `STWO_PROGRAM_TAG` and toolchain id `0x5354`.

### G.9 Standard FRI Profile (BabyBear)

For Standard FRI receipts (BabyBear), `consts_bytes` MUST use `STANDARD_STARK_PROFILE_TAG`.
Program bytes MUST use `STANDARD_STARK_PROGRAM_TAG`.
`hash_id` MUST be one of:
- `0x02` (SHA3-256 transcript + Merkle hashing)
- `0x01` (BLAKE3 transcript + Merkle hashing)
- `0x04` (Poseidon transcript + Merkle hashing)
- `0x05` (Rescue transcript + Merkle hashing)

---

## Appendix H: STARK Validity and Kernels (SSOT)

This appendix defines the **normative validity relation** that the STARK adapter MUST prove in-circuit.

### H.1 Validity Statement

Given a `CanonicalStarkReceipt`, the GLYPH proof MUST prove:
1. The receipt digest is computed canonically.
2. The verifier program in `vk.program_bytes` is executed on the receipt.
3. All checks succeed (transcript, Merkle, OOD, DEEP, FRI, AIR).
4. The final folder claim is exported through the GLYPH artifact boundary.

### H.2 SHA3-256 Transcript Kernel Rules

The transcript kernel MUST prove the canonical Winterfell SHA3 derivation:
- **Hasher**: `winter_crypto::hashers::Sha3_256` (rate 136, padding 0x06...0x80).
- **Draw**: `digest[0..ELEMENT_BYTES]` as little-endian integer, accepted if `< p` (16 bytes for F128, 8 bytes for F64).
- **Max Retries**: 1000 (strict bound).
- **Seed Mixing**: `H.merge_with_int(seed, ctr)` for 40-byte messages.

### H.3 BLAKE3 Transcript Kernel Rules

The transcript kernel MUST prove the canonical Winterfell BLAKE3 derivation:
- **Hasher**: BLAKE3 in default mode, output truncated to 32 bytes.
- **Draw**: `digest[0..ELEMENT_BYTES]` as little-endian integer, accepted if `< p` (16 bytes for F128, 8 bytes for F64).
- **Max Retries**: 1000 (strict bound).
- **Seed Mixing**: `H.merge_with_int(seed, ctr)` with 40-byte messages, identical to SHA3 ordering.

---

## Appendix I: BaseFold PCS Notes (SSOT)

GLYPH uses BaseFold over binary tower fields for PCS commitments and openings.
The SSOT for proofs and transcript logic is the code in `src/pcs_basefold.rs`,
`src/glyph_pcs_basefold.rs`, and `src/pcs_ring_switch.rs`.

### I.1 Canonical Domains

- `DOMAIN_PCS_BASEFOLD_COMMIT`
- `DOMAIN_PCS_BASEFOLD_OPEN`
- `DOMAIN_PCS_RING_SWITCH`
- `DOMAIN_PCS_ZK_MASK`
- `PCS_COMMIT_DOMAIN = b"GLYPH_PCS_COMMIT"`
- `PCS_POINT_TAG_DOMAIN = b"GLYPH_PCS_POINT_TAG"`
- `PCS_SALT_DOMAIN = b"GLYPH_PCS_SALT"`

### I.2 Commitment Tag Binding

- `base_tag = derive_basefold_commitment_tag(basefold_commitment)`
- `commitment_tag = keccak256(PCS_COMMIT_DOMAIN || base_tag || [salt_commitment] || [mask_commitment])`

### I.3 Point Tag Derivation

- `point_tag = keccak256(PCS_POINT_TAG_DOMAIN || commitment_tag || eval_point_bytes)`
- `eval_point_bytes` uses `u128_be` per coordinate, where the upper 64 bits are zero and the lower 64 bits are the Goldilocks value in big-endian.

### I.4 ZK Mask Commitment

- `mask_commitment = keccak256(DOMAIN_PCS_ZK_MASK || mask_rows_u64_be || cols_u64_be || mask_row_values)`
- `mask_row_values` are Goldilocks field elements encoded as little-endian `u64`.

### I.5 BaseFold PCS Defaults and Tuning Notes

- Default BaseFold parameters (code defaults in `BaseFoldConfig`):
  - `security_bits = 128`
  - `security_target_bits = 128`
  - `security_repeat = 1`
  - `log_inv_rate = 1`
  - `fold_arity = 8`
- Memory floors are enforced by `basefold_min_mem_for_len` in `src/glyph_pcs_basefold.rs` and cap at 1 GiB.
- For `security_target_bits > security_bits`, the prover sets `security_repeat` and generates multiple BaseFold proofs per opening.
- When `security_bits >= 128`, the prover auto-searches `log_inv_rate` and `fold_arity` to find feasible FRI parameters without changing on-chain behavior.
- `fold_arity = 0` in the commitment encoding means "optimal arity selection" during verification.

---

## Appendix J: GLYPH Artifact Boundary Specification (SSOT)

The GLYPH artifact boundary MUST be:
- `commitment_tag: bytes32`
- `point_tag: bytes32`
- `claim128: uint128`

**Point Tag Derivation:**
- `point_tag := keccak256(PCS_POINT_TAG_DOMAIN || commitment_tag || eval_point_bytes)`
- `eval_point_bytes := concat( u128_be(x_i) )`

---

## Appendix K: Tooling Index (scripts/)

All tooling lives under `scripts/`. Outputs live under `scripts/out/`. Rust build artifacts are centralized under the target directory when built.

Conventions:
- `scripts/tools/` holds bundled external tools and fixture generators. Example: the foundry bundle lives under `scripts/tools/foundry/`.
- `scripts/tests/foundry/` is the Foundry test harness and contracts used for on-chain verification tests.
- `scripts/benchmarks/groth16_compare/` uses local Node dependencies. Install them locally and keep `node_modules` untracked.

### Benchmarks
- `scripts/benchmarks/common.sh`: shared bench helpers and `bench_v1` JSON rewrap. If raw output is not valid JSON, `status` is set to `parse_error` or `invalid_json`.
- `scripts/benchmarks/run_all.sh`: orchestrate benchmark presets from `scripts/benchmarks/registry.json`.
- `scripts/benchmarks/registry.json`: preset registry for benchmark runs.
- `scripts/benchmarks/profile_perf_config.sh`: perf profile runner and config snapshot bundle.
- `scripts/benchmarks/bench_glyph_evm_local.sh`: local gas bench for GLYPH verifier (Anvil).
- `scripts/benchmarks/bench_glyph_evm_round_sweep.sh`: round-count sweep for packed GKR layout (Anvil).
- `scripts/benchmarks/bench_glyph_evm_realproof.sh`: real prover path bench for hash or STARK families.
- `scripts/benchmarks/bench_glyph_evm_artifact.sh`: artifact-poly calldata bench (Anvil).
- `scripts/benchmarks/bench_glyph_evm_sepolia.sh`: gas estimates and optional tx on Sepolia.
- `scripts/benchmarks/bench_glyph_sepolia_stmt.sh`: artifact-poly layout bench on Sepolia (historical `stmt` name).
- `scripts/benchmarks/bench_glyph_sepolia_artifact.sh`: artifact-poly layout bench on Sepolia.
- `scripts/benchmarks/bench_glyph_hoodi_artifact_truncated.sh`: truncated artifact-poly bench on Hoodi.
- `scripts/benchmarks/bench_glyph_adapter_hoodi.sh`: adapter calldata bench on Hoodi with truncated layout.
- `scripts/benchmarks/bench_glyph_adapter_kpi.sh`: adapter KPI bench on canonical fixtures.
- `scripts/benchmarks/bench_glyph_adapter_zk_kpi.sh`: ZK KPI bench for adapters.
- `scripts/benchmarks/bench_glyph_zk_kpi.sh`: ZK proof size KPI bench.
- `scripts/benchmarks/bench_glyph_cuda_kpi.sh`: CUDA KPI bench for packed GKR (disabled by policy; set `GLYPH_ENABLE_CUDA_BENCH=1` to run).
- `scripts/benchmarks/bench_basefold_arity_sweep.sh`: BaseFold arity sweep.
- `scripts/benchmarks/bench_basefold_mem_sweetspot.sh`: BaseFold memory sweep.
- `scripts/benchmarks/bench_basefold_trace_profile.sh`: BaseFold trace profiles.
- `scripts/benchmarks/bench_bn254_batch_kpi.sh`: BN254 batch KPI bench.
- `scripts/benchmarks/bench_bn254_g2_kpi.sh`: BN254 G2 KPI bench.
- `scripts/benchmarks/bench_bn254_msm_kpi.sh`: BN254 MSM KPI bench.
- `scripts/benchmarks/bench_bn254_mul_kpi.sh`: BN254 add/sub/mul KPI bench.
- `scripts/benchmarks/bench_bn254_trace_kpi.sh`: BN254 trace KPI bench.
- `scripts/benchmarks/bench_ivc_fold_kpi.sh`: IVC fold KPI bench.
- `scripts/benchmarks/bench_ivc_parallel_profile.sh`: IVC fold parallel profiling.
- `scripts/benchmarks/bench_packed_gkr_layout_sweep.sh`: packed GKR layout sweep.
- `scripts/benchmarks/bench_stark_do_work_kpis.sh`: STARK do_work KPI bench.
- `scripts/benchmarks/bench_state_diff_compile_prove.sh`: state-diff compile/prove bench.
- `scripts/benchmarks/bench_state_diff_merkle.sh`: state-diff merkle bench.
- `scripts/benchmarks/bench_state_diff_prover_profile.sh`: state-diff prover vs merkle share profile.
- `scripts/benchmarks/bench_state_transition_vm.sh`: state transition VM bench.
- `scripts/benchmarks/bench_groth16_sepolia.sh`: Groth16 verifier gas estimates on Sepolia.
- `scripts/benchmarks/bench_groth16_hoodi.sh`: Groth16 verifier gas estimates on Hoodi.
- `scripts/benchmarks/send_raw_tx.sh`: raw calldata tx sender for benchmarks.

### Groth16 Compare
- `scripts/benchmarks/groth16_compare/build_groth16.sh`: build Groth16 artifacts (circom/snarkjs).
- `scripts/benchmarks/groth16_compare/calc_calldata_stats.sh`: calldata size and gas calculator.
- `scripts/benchmarks/groth16_compare/package.json`: Groth16 compare Node dependencies.
- `scripts/benchmarks/groth16_compare/package-lock.json`: Groth16 compare lockfile.
- `scripts/utils/ensure_groth16_compare_deps.sh`: install Groth16 compare Node dependencies locally (bun or npm).

### Build and Deploy
- `scripts/build/ci_deterministic_run.sh`: deterministic CI wrapper for build and test presets.
- `scripts/build/glyph_build.sh`: feature-aware build runner.
- `scripts/deploy/deploy_glyph_contract.sh`: deploy GLYPHVerifier to a network.
- `scripts/deploy/verify_glyph_contract.sh`: verify GLYPHVerifier on Etherscan.

### DA Tooling
- `scripts/da/submit_blob.sh`: submit blob payloads and emit commitment JSON.
- `scripts/da/fetch_blob.sh`: fetch blob payloads from retrievers or Beacon API.
- `scripts/da/submit_eigenda.sh`: submit payloads to EigenDA v1/v2.
- `scripts/da/poll_eigenda.sh`: poll EigenDA status and update envelopes.
- `scripts/da/fetch_eigenda.sh`: fetch EigenDA payloads via proxy or retriever.
- `scripts/da/submit_arweave.sh`: submit payloads to Arweave.
- `scripts/da/fetch_arweave.sh`: fetch payloads from Arweave gateway.
- `scripts/da/arweave_local_smoke.sh`: local Arweave smoke test (arlocal).
- `scripts/da/run_profile.sh`: end-to-end DA profile runner.
- `scripts/da/run_all_profiles.sh`: run submit for all DA profiles.
- `scripts/da/smoke_test.sh`: submit/fetch/verify for a single profile.
- `scripts/da/state_diff_from_snapshots.sh`: build state diff JSON from snapshots.
- `scripts/da/state_diff_onchain_verify.sh`: call or send root update verification.
- `scripts/da/state_diff_proof_flow.sh`: full state diff proof pipeline.
- `scripts/da/state_transition_vm_flow.sh`: state transition VM proof pipeline.
- `scripts/da/fetch_eigenda_v2_srs.sh`: fetch EigenDA v2 SRS assets.

### DA Providers
- `scripts/da/providers/arweave_turbo_upload.mjs`: Arweave Turbo upload helper.
- `scripts/da/providers/eigenda_v1/main.go`: EigenDA v1 client wrapper.
- `scripts/da/providers/eigenda_v2/main.go`: EigenDA v2 client wrapper.
- `scripts/out/da/providers/eigenda_v2_client`: compiled client binary (Linux build artifact, not committed).
Note: EigenDA v1/v2 helpers require Go in PATH. Arweave Turbo uploads require the Turbo SDK
(`bun add @ardrive/turbo-sdk` or `npm install @ardrive/turbo-sdk`).

### Tests and Fuzzing
- `scripts/tests/run_tests.sh`: test orchestrator (Rust, Foundry, fuzz).
- `scripts/tests/verifier_symbolic.sh`: symbolic fuzz for GLYPHVerifier.
- `scripts/tests/fuzz/run_all.sh`: fuzz harness runner.
- `scripts/tests/fuzz/run_cmin.sh`: corpus minimization helper.
- `scripts/tests/fuzz/run_tmin.sh`: test-case minimization helper.
- `scripts/tests/fuzz/workspace/fuzz_targets/decode_adapter_bytes.rs`: fuzz adapter byte decoding.
- `scripts/tests/fuzz/workspace/fuzz_targets/decode_adapter_ir_deep.rs`: fuzz deep IR decoding.
- `scripts/tests/fuzz/workspace/fuzz_targets/decode_circle_stark_program.rs`: fuzz Circle STARK program decode.
- `scripts/tests/fuzz/workspace/fuzz_targets/decode_circle_stark_proof.rs`: fuzz Circle STARK proof decode.
- `scripts/tests/fuzz/workspace/fuzz_targets/decode_ipa_receipt.rs`: fuzz IPA receipt decode.
- `scripts/tests/fuzz/workspace/fuzz_targets/decode_plonky2_receipt.rs`: fuzz Plonky2 receipt decode.
- `scripts/tests/fuzz/workspace/fuzz_targets/decode_standard_stark_program.rs`: fuzz standard STARK program decode.
- `scripts/tests/fuzz/workspace/fuzz_targets/decode_standard_stark_proof.rs`: fuzz standard STARK proof decode.
- `scripts/tests/fuzz/workspace/fuzz_targets/decode_stark_ir.rs`: fuzz STARK IR decode.
- `scripts/tests/fuzz/workspace/fuzz_targets/decode_stark_receipt.rs`: fuzz STARK receipt decode.
- `scripts/tests/fuzz/workspace/fuzz_targets/decode_stark_vk.rs`: fuzz STARK VK decode.
- `scripts/tests/fuzz/workspace/fuzz_targets/decode_winterfell_program.rs`: fuzz Winterfell program decode.
- `scripts/tests/fuzz/workspace/fuzz_targets/diff_adapter_ir_roundtrip.rs`: fuzz IR roundtrip diffs.
- `scripts/tests/fuzz/workspace/fuzz_targets/transcript_challenges.rs`: fuzz transcript challenge derivation.
- `scripts/tests/fuzz/workspace/fuzz_targets/validate_state_transition_batch.rs`: fuzz VM batch validation.
- `scripts/tests/fuzz/workspace/fuzz_targets/verify_adapter_proof.rs`: fuzz adapter proof verification.
- `scripts/tests/fuzz/workspace/fuzz_targets/verify_packed_calldata.rs`: fuzz packed calldata verification.

### Repro and Utils
- `scripts/repro/repro_pack.sh`: deterministic repro pack builder.
- `scripts/utils/cuda/check_cuda_toolkit.sh`: CUDA toolkit availability check.
- `scripts/utils/dump_perf_config.sh`: perf env snapshot to JSON.
- `scripts/utils/ensure_state_diff_fixture.sh`: deterministic state diff fixture generator.
- `scripts/utils/perf_summary.sh`: summary of perf run outputs.

### Formal and Examples
- `scripts/formal/sumcheck_invariants.sh`: sumcheck invariant runner.
- `scripts/formal/sumcheck_invariants/Cargo.toml`: sumcheck crate manifest.
- `scripts/formal/sumcheck_invariants/src/main.rs`: sumcheck invariants implementation.

### Tools and Generators
- `scripts/tools/converters/stwo_to_bundle.rs`: Stwo bundle converter.
- `scripts/tools/fixture_generators/gnark_bn254_plonk/run.sh`: GNARK fixture runner.
- `scripts/tools/fixture_generators/gnark_bn254_plonk/main.go`: GNARK fixture generator.
- `scripts/tools/fixture_generators/gnark_bn254_plonk/go.mod`: GNARK generator deps.
- `scripts/tools/fixture_generators/gnark_bn254_plonk/go.sum`: GNARK generator lockfile.
- `scripts/tools/fixture_generators/sp1/run.sh`: SP1 fixture runner.
- `scripts/tools/fixture_generators/sp1/Cargo.toml`: SP1 generator manifest.
- `scripts/tools/fixture_generators/sp1/Cargo.lock`: SP1 generator lockfile.
- `scripts/tools/fixture_generators/sp1/src/main.rs`: SP1 fixture generator.
- `scripts/tools/fixture_generators/sp1/src/bin/build_gnark_circuits.rs`: build SP1 gnark circuits.
- `scripts/tools/fixture_generators/sp1/src/bin/build_guest.rs`: build SP1 guest ELF.
- `scripts/tools/fixture_generators/sp1/guest/Cargo.toml`: SP1 guest manifest.
- `scripts/tools/fixture_generators/sp1/guest/Cargo.lock`: SP1 guest lockfile.
- `scripts/tools/fixture_generators/sp1/guest/src/main.rs`: SP1 guest program.

Fixture generator notes:
- **GNARK BN254 PLONK**: Generates a deterministic BN254 PLONK fixture for the `gnark-bn254-verifier` backend used by the A8 PLONK adapter and normalizes the verifying key trailer. Outputs `scripts/tools/fixtures/plonk_bn254_gnark_receipt.txt` (`vk_hex`, `proof_hex`, `pub_inputs_hex`). Requires Go in PATH. Run `scripts/tools/fixture_generators/gnark_bn254_plonk/run.sh`.
- **SP1**: Generates deterministic SP1 Groth16 and Plonk receipts for the A7 adapter and emits canonical GLYPH receipt bytes compatible with `src/sp1_adapter.rs`. Outputs `scripts/tools/fixtures/sp1_groth16_receipt.txt` and `scripts/tools/fixtures/sp1_plonk_receipt.txt`. Requires Rust and Go in PATH and an SP1 guest ELF. Optional: `cargo-prove` (recommended for building the guest ELF without Docker). Usage: `scripts/tools/fixture_generators/sp1/run.sh --elf /path/to/guest.elf --stdin-hex 0x`. Notes: empty stdin is allowed; use the same ELF and stdin for Groth16 and Plonk; if no ELF is provided the scripts try `cargo prove build` and fall back to `build_guest`; native gnark bindings are used so Docker is not required when `cargo-prove` is available.

### Tool Fixtures (data)
- `scripts/tools/fixtures/fast_circle_stark_baby_bear_receipt.txt`: Circle STARK BabyBear receipt.
- `scripts/tools/fixtures/fast_circle_stark_baby_bear_receipt.txt.candidate`: Circle STARK BabyBear candidate.
- `scripts/tools/fixtures/fast_circle_stark_koala_bear_receipt.txt`: Circle STARK KoalaBear receipt.
- `scripts/tools/fixtures/fast_circle_stark_koala_bear_receipt.txt.candidate`: Circle STARK KoalaBear candidate.
- `scripts/tools/fixtures/fast_circle_stark_receipt.txt`: Circle STARK receipt (UTF-16 LE).
- `scripts/tools/fixtures/fast_circle_stark_receipt.txt.candidate`: Circle STARK candidate.
- `scripts/tools/fixtures/fast_circle_stark_receipt_large.txt`: Circle STARK large receipt.
- `scripts/tools/fixtures/fast_circle_stark_receipt_large.txt.candidate`: Circle STARK large candidate.
- `scripts/tools/fixtures/fast_plonky2_goldilocks_receipt.txt`: Plonky2 Goldilocks receipt.
- `scripts/tools/fixtures/fast_plonky2_goldilocks_receipt.txt.candidate`: Plonky2 Goldilocks candidate.
- `scripts/tools/fixtures/fast_sha3_receipt.txt`: SHA3 receipt.
- `scripts/tools/fixtures/fast_sha3_receipt_f64.txt`: SHA3 receipt (f64).
- `scripts/tools/fixtures/groth16_bls12381_receipt.txt`: Groth16 BLS12-381 receipt.
- `scripts/tools/fixtures/groth16_bls12381_receipt.txt.candidate`: Groth16 BLS12-381 candidate.
- `scripts/tools/fixtures/groth16_bn254_fixture.txt`: Groth16 BN254 fixture (vk/proof/pub inputs).
- `scripts/tools/fixtures/halo2_bls12381_kzg_receipt.txt`: Halo2 BLS12-381 receipt.
- `scripts/tools/fixtures/halo2_bls12381_kzg_receipt.txt.candidate`: Halo2 BLS12-381 candidate.
- `scripts/tools/fixtures/halo2_bn254_kzg_receipt.txt`: Halo2 BN254 receipt.
- `scripts/tools/fixtures/halo2_bn254_kzg_receipt.txt.candidate`: Halo2 BN254 candidate.
- `scripts/tools/fixtures/ivc_hypernova_external_proof.txt`: HyperNova external proof.
- `scripts/tools/fixtures/ivc_nova_external_proof.txt`: Nova external proof.
- `scripts/tools/fixtures/ivc_sangria_external_proof.txt`: Sangria external proof.
- `scripts/tools/fixtures/ivc_supernova_external_proof.txt`: SuperNova external proof.
- `scripts/tools/fixtures/kzg_bls12381_receipt.txt`: KZG BLS12-381 receipt.
- `scripts/tools/fixtures/kzg_bls12381_receipt.txt.candidate`: KZG BLS12-381 candidate.
- `scripts/tools/fixtures/miden_blake3_receipt.txt`: Miden Blake3 receipt.
- `scripts/tools/fixtures/miden_rpo_receipt.txt`: Miden RPO receipt.
- `scripts/tools/fixtures/plonk_bls12381_receipt.txt`: PLONK BLS12-381 receipt.
- `scripts/tools/fixtures/plonk_bls12381_receipt.txt.candidate`: PLONK BLS12-381 candidate.
- `scripts/tools/fixtures/plonk_bn254_gnark_receipt.txt`: GNARK BN254 PLONK fixture.
- `scripts/tools/fixtures/plonky3_babybear_blake3_receipt.txt.candidate`: Plonky3 BabyBear Blake3 candidate.
- `scripts/tools/fixtures/plonky3_babybear_poseidon2_receipt.txt.candidate`: Plonky3 BabyBear Poseidon2 candidate.
- `scripts/tools/fixtures/plonky3_babybear_poseidon2_tribonacci_receipt.txt`: Plonky3 BabyBear Poseidon2 Tribonacci receipt.
- `scripts/tools/fixtures/plonky3_babybear_poseidon2_tribonacci_receipt.txt.candidate`: Plonky3 BabyBear Poseidon2 Tribonacci candidate.
- `scripts/tools/fixtures/plonky3_babybear_poseidon_receipt.txt.candidate`: Plonky3 BabyBear Poseidon candidate.
- `scripts/tools/fixtures/plonky3_babybear_rescue_receipt.txt.candidate`: Plonky3 BabyBear Rescue candidate.
- `scripts/tools/fixtures/plonky3_goldilocks_blake3_receipt.txt.candidate`: Plonky3 Goldilocks Blake3 candidate.
- `scripts/tools/fixtures/plonky3_goldilocks_poseidon2_receipt.txt.candidate`: Plonky3 Goldilocks Poseidon2 candidate.
- `scripts/tools/fixtures/plonky3_goldilocks_poseidon2_tribonacci_receipt.txt`: Plonky3 Goldilocks Poseidon2 Tribonacci receipt.
- `scripts/tools/fixtures/plonky3_goldilocks_poseidon_receipt.txt.candidate`: Plonky3 Goldilocks Poseidon candidate.
- `scripts/tools/fixtures/plonky3_goldilocks_rescue_receipt.txt.candidate`: Plonky3 Goldilocks Rescue candidate.
- `scripts/tools/fixtures/plonky3_koalabear_blake3_receipt.txt.candidate`: Plonky3 KoalaBear Blake3 candidate.
- `scripts/tools/fixtures/plonky3_koalabear_poseidon2_receipt.txt.candidate`: Plonky3 KoalaBear Poseidon2 candidate.
- `scripts/tools/fixtures/plonky3_koalabear_poseidon2_tribonacci_receipt.txt`: Plonky3 KoalaBear Poseidon2 Tribonacci receipt.
- `scripts/tools/fixtures/plonky3_koalabear_poseidon2_tribonacci_receipt.txt.candidate`: Plonky3 KoalaBear Poseidon2 Tribonacci candidate.
- `scripts/tools/fixtures/plonky3_koalabear_poseidon_receipt.txt.candidate`: Plonky3 KoalaBear Poseidon candidate.
- `scripts/tools/fixtures/plonky3_koalabear_rescue_receipt.txt.candidate`: Plonky3 KoalaBear Rescue candidate.
- `scripts/tools/fixtures/risc_zero_bundle.json`: Risc0 bundle fixture.
- `scripts/tools/fixtures/risc_zero_external_receipt.json`: Risc0 external receipt fixture.
- `scripts/tools/fixtures/sp1_groth16_receipt.txt`: SP1 Groth16 receipt.
- `scripts/tools/fixtures/sp1_plonk_receipt.txt`: SP1 Plonk receipt.
- `scripts/tools/fixtures/stwo_external.json`: Stwo external proof fixture.
- `scripts/tools/fixtures/stwo_external.receipt.txt`: Stwo external receipt fixture.
- `scripts/tools/fixtures/stwo_test_bundle.json`: Stwo test bundle fixture.
- `scripts/tools/fixtures/cairo_stone6_keccak_160_lsb_example_proof.json`: Cairo proof example.

## Appendix L: Quickstart & Deployment Guide

Canonical file: `docs/QUICKSTART.md`

# GLYPH Quickstart & Deployment Guide
End-to-end instructions to build GLYPH locally, prove receipts, and deploy `GLYPHVerifier.sol` on testnets.

## 1. Supported Proof Systems
- Groth16 (SNARK adapter)
- KZG/Plonk (SNARK adapter)
- IVC/Folding (IVC adapter)
- STARK (Winterfell F128/F64 Goldilocks, Circle M31/BabyBear/KoalaBear, Standard FRI BabyBear, Stwo M31, Cairo, Miden, Plonky2, Plonky3)
- Hash proofs (Hash adapter)

## 2. Prerequisites
0. **Windows**: WSL2 is recommended for the Bash tooling and SP1. Native Windows builds require MSVC Build Tools.
1. **Foundry** installed (`forge`, `cast`).
2. **Rust toolchain** (stable `rustup`, `cargo`; nightly required for `stark-*` or `full` builds due to `plonky2_field`). This repo pins `nightly-2025-09-15` via `rust-toolchain.toml`.
3. **Wallet credentials** stored locally (e.g., `docs/wallet/.env.wallet`):
   ```
   DEPLOYER_ADDRESS=0x...
   DEPLOYER_PRIVATE_KEY=0x...
   ```
4. **RPC URL** per target network (environment variable or `.env.<network>` file).
5. **JavaScript runtime** (only if using JS tooling): bun preferred, node/npm/npx supported.
   - Required for Groth16 compare (circom/snarkjs).
   - Required for DA provider tooling (Arweave Turbo).
   - Not required for any GLYPH prover or verifier path.
   - Optional Arweave Turbo SDK install: `bun add @ardrive/turbo-sdk` or `npm install @ardrive/turbo-sdk`.
6. **Go toolchain** (only if using EigenDA v1/v2 helpers):
   ```bash
   # macOS
   brew install go

   # Ubuntu or Debian
   sudo apt-get install golang-go

   # Windows (PowerShell)
   winget install GoLang.Go
   ```
7. **EigenDA v2 SRS assets** (only if using EigenDA v2): fetch into `scripts/da/srs/eigenda_v2/`:
   ```bash
   scripts/da/fetch_eigenda_v2_srs.sh
   ```

---

### Windows (native)
- Native Windows builds require MSVC (Visual Studio Build Tools, C++ workload + Windows SDK).
- Ensure `cl.exe` is on PATH (Developer Command Prompt or VS Build Tools environment).
- If MSYS2 or MinGW is on PATH (for example `C:\\msys64\\mingw64\\bin\\gcc.exe`), set `CC=cl.exe` or remove MSYS2 from PATH to avoid gcc being picked for `x86_64-pc-windows-msvc`.
- Recommended: use WSL2 for scripts, Foundry, and SP1.

### WSL2 path tip
For large builds, clone into the Linux filesystem (for example `~/glyph-zk`) instead of `/mnt/c/...` for better performance and fewer toolchain timeouts.

### ZIP download note (Windows)
If you downloaded a ZIP instead of cloning with git, the execute bits for `scripts/**/*.sh` may be missing. In WSL run:
```bash
chmod +x scripts/**/*.sh
```

### Groth16 Compare Dependencies (Optional)
The Groth16 compare benchmarks use local Node dependencies under `scripts/benchmarks/groth16_compare/`.
Install them locally and keep `node_modules` untracked:
```bash
scripts/utils/ensure_groth16_compare_deps.sh
```

Manual install (alternative):
```bash
cd scripts/benchmarks/groth16_compare
bun install --frozen-lockfile
# or
npm ci
```

## 3. Local Setup & Build

### Install Dependencies
Install the Rust toolchain and Foundry CLI tools:
```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install Foundry
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

### Build Project
```bash
cargo build --release
```

### Run Tests
```bash
cargo test
```

Full suite with vector export and Foundry integration:
```bash
./scripts/tests/run_tests.sh
```

CI-like preset coverage (build matrix plus default tests):
```bash
./scripts/tests/run_feature_matrix.sh --matrix ci --with-tests
```

### Basic Usage
```bash
GLYPH_ACCEL_PROFILE=cpu cargo run --bin glyph_prover -- ...
```

### Profiles
- cpu: Pure CPU, works everywhere
- cuda: opt-in CUDA acceleration for large batches. Requires `--features cuda` and a working CUDA toolkit. CPU SIMD is faster for typical workloads, so CUDA stays off by default.

### Feature Flags (IVC)
- `ivc` is enabled by default in standard builds.
- `ivc-supernova` is **opt-in** and only enables SuperNova external proofs.

Build with SuperNova enabled:
```bash
cargo build --features ivc-supernova
```

Test SuperNova explicitly:
```bash
cargo test --no-default-features --features "adapter-core,ivc,ivc-supernova,dev-tools" --test ivc_supernova_tests
```

---

## 4. Testnet Funding

Use any reputable faucet for the target testnet and fund the deployer address.
Keep funding links and choices out of the repo to avoid provider lock-in.

---

## 5. Configure RPC URL

Create `.env.sepolia` or `.env.hoodi` in the repo root:

```bash
# Sepolia
SEPOLIA_RPC_URL="https://<your-sepolia-rpc>"

# Hoodi
HOODI_RPC_URL="https://<your-hoodi-rpc>"
```

Or set directly via environment:
```bash
export RPC_URL="https://..."
```

---

## 6. Deploy GLYPHVerifier

### Single Verifier (GLYPHVerifier)

```bash
# Deploy (Default: Sepolia)
NETWORK=sepolia ./scripts/deploy/deploy_glyph_contract.sh

# Deploy to Hoodi
NETWORK=hoodi ./scripts/deploy/deploy_glyph_contract.sh
```

Output: `deployments/<network>.json`

---

## 7. Verify Deployment

Generate packed calldata and call the verifier:

```bash
CONTRACT="0x..."  # from deployment output
CHAIN_ID="11155111"  # or 560048 for Hoodi

cargo run --bin gen_glyph_gkr_proof --release -- \
  --hash-merge --rounds 5 \
  --chainid $CHAIN_ID --verifier $CONTRACT \
  --json > /tmp/glyph_calldata.json

CALLDATA=$(python3 -c 'import json; print(json.load(open("/tmp/glyph_calldata.json"))["calldata"])')

cast call $CONTRACT --data "$CALLDATA" --rpc-url $RPC_URL
```

Expected output: `0x01` (success)

---

## 8. Measure Gas Usage

```bash
cast estimate $CONTRACT --data "$CALLDATA" --rpc-url $RPC_URL
```

Expected (packed artifact-bound layout):
- Execution gas: ~5,070-5,230
- Total tx gas: ~29,450-29,720 (base tx + calldata + execution)

---

## 9. Etherscan Verification (Optional)

```bash
NETWORK=sepolia ETHERSCAN_API_KEY=... ./scripts/deploy/verify_glyph_contract.sh
```

For Hoodi, use `--chain hoodi` if supported, otherwise manual verification.

---

## 10. Environment Variables
| Variable               | Description                                         |
|------------------------|-----------------------------------------------------|
| `NETWORK`              | Target network (`sepolia`, `hoodi`)                 |
| `RPC_URL`              | RPC endpoint URL (overrides `.env.<network>`)       |
| `WALLET_ENV_FILE`      | Path to wallet credentials                          |
| `OUT_FILE_BASE`        | Deployment JSON output path                         |
| `TIMEOUT`              | Deploy script timeout in seconds (default 300)      |
| `CHAIN_ID_EXPECTED`    | Override chain ID validation                        |
| `EXPLORER_BASE_URL`    | Override explorer URL for verification hints        |
| `NETWORK_ENV_FILE`     | Override `.env.<network>` path                      |
| `PACKED_CALLDATA`      | Optional calldata to include in deployment metadata |
| `ALLOW_VERIFY_FAILURE` | Allow verification to fail without aborting         |
| `GLYPH_ACCEL_PROFILE`  | Acceleration profile (`cpu`, `cuda`, `cpu-cuda`)    |

---

## 11. Troubleshooting
| Issue                                   | Solution                                                                                                                          |
|-----------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------|
| "No ETH in wallet"                      | Get testnet ETH from faucets above                                                                                                |
| "RPC_URL not set"                       | Export `RPC_URL` or create `.env.<network>`                                                                                       |
| "chain-id mismatch"                     | Check `CHAIN_ID_EXPECTED` or RPC URL                                                                                              |
| "empty bytecode"                        | Deployment failed, inspect `forge` output                                                                                         |
| "Build failed"                          | Confirm Rust toolchain and dependencies                                                                                           |
| "Windows build fails"                   | Install MSVC Build Tools and ensure `cl.exe` is on PATH. If MSYS2 or MinGW is on PATH, set `CC=cl.exe` or remove MinGW from PATH. |
| "scripts/*.sh Permission denied"        | If using a ZIP download, run `chmod +x scripts/**/*.sh` in WSL.                                                                   |
| Vendor warnings (e.g., `vendor/binius`) | Suppressed by default via `.cargo/config.toml` rustflags. Remove those flags to see vendor warnings.                              |
| "Nightly required"                      | Use Nightly when building `stark-*` or `full` presets                                                                             |
| "Tests or fuzz toggles unclear"         | See the "Test Runner Flags" section below and the full matrix in `docs/documentation.md` Appendix B.                              |

---

## 12. Performance Tips
### GPU Acceleration
Requires `--features cuda` and a working CUDA toolkit. Default remains CPU.
```bash
GLYPH_ACCEL_PROFILE=cuda cargo run --bin glyph_prover -- ...
```

### Batch Processing
- Choose `cpu` vs `cuda` based on constraint count. CUDA is opt-in and best for large batches. CPU SIMD is faster for typical workloads.
- Track memory usage when running multiple proves.
- Use automation scripts for repeated benchmark runs.

---

## 13. Fuzzing (cargo-fuzz)

GLYPH includes a `cargo-fuzz` workspace under `scripts/tests/fuzz/workspace/`.

```bash
cargo install cargo-fuzz
cd scripts/tests/fuzz/workspace
cargo fuzz list
```

Common targets:
- `decode_stark_receipt`, `decode_stark_vk`, `decode_plonky2_receipt`
- `decode_adapter_bytes`, `verify_adapter_proof`, `decode_adapter_ir_deep`
- `verify_packed_calldata`
- `decode_stark_ir`, `decode_winterfell_program`, `decode_circle_stark_program`, `decode_circle_stark_proof`, `decode_standard_stark_program`, `decode_standard_stark_proof`

### Fuzzing notes
- Some nightly toolchains may SIGSEGV during ASAN fuzz builds (for example `decode_stark_vk` / `swiftness_air`).
- Workarounds:
  - Try a newer nightly (for example `nightly-2026-01-13`).
  - Set `RUST_MIN_STACK=16777216`.
  - Disable STARK fuzz via `GLYPH_FUZZ_STARK=0`.
  - Run fuzz targets individually.

Run one target:
```bash
cd scripts/tests/fuzz/workspace
cargo fuzz run decode_stark_receipt
```

Or use the wrappers:
```bash
scripts/tests/fuzz/run_all.sh short
scripts/tests/fuzz/run_cmin.sh decode_stark_receipt scripts/tests/fuzz/workspace/corpus/decode_stark_receipt /tmp/glyph_corpus_min
scripts/tests/fuzz/run_tmin.sh decode_stark_receipt /tmp/crash-001 /tmp/crash-min
```

### Test Runner Flags (scripts/tests/run_tests.sh)

Key toggles:

| Flag                     | Default        | Purpose                                                                 |
|--------------------------|----------------|-------------------------------------------------------------------------|
| `GLYPH_SKIP_FUZZ`        | `1`            | Set to `0` to enable fuzzing during `run_tests.sh`                      |
| `GLYPH_FUZZ_STARK`       | `0`            | Set to `1` to include STARK fuzz targets                                |
| `GLYPH_FUZZ_CAIRO`       | `0`            | Set to `1` to include Cairo fuzz targets on Linux                       |
| `GLYPH_FUZZ_SOFT_FAIL`   | `0`            | Soft-fail on toolchain crashes (SIGSEGV/stack overflow) in fuzz targets |
| `GLYPH_FULL_TESTS`       | `1`            | Run full adapter test pass                                              |  
| `GLYPH_TEST_SUPERNOVA`   | `1`            | Enable SuperNova tests                                                  |
| `GLYPH_TEST_STWO_PROVER` | `1`            | Enable Stwo Prover tests                                                |  
| `GLYPH_TEST_PROFILE`     | `release-fast` | Build profile for tests                                                 |    
| `GLYPH_TEST_FEATURES`    | default set    | Feature set for the full adapter pass                                   |

For the complete list and detailed behavior, see `docs/documentation.md` in Appendix B.

---%

*Last updated: January 2026*
