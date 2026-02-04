# GLYPH Repository Map

This document indexes the core files and describes the data flow for the GLYPH trustless validity pipeline.

**Product naming:**
- **GLYPH-PROVER**: Universal off-chain prover core
- **GLYPH-VERIFIER**: On-chain verifier (`contracts/GLYPHVerifier.sol`)

---

## Top-Level Layout
- `Cargo.toml`, `Cargo.lock`: Rust workspace manifest and lockfile.
- `src/`: core prover, adapters, PCS, and IR compilers.
- `contracts/`: Solidity verifiers and root updater contracts.
- `scripts/tests/rust/`: Rust integration tests.
- `scripts/`: all tooling, benchmarks, DA flows, tests, utils, and generators.
- `docs/`: SSOT documentation and specs.
- `deployments/`: deployment artifacts and metadata.
- `vendor/`: vendored dependencies.

## Source Layout Conventions
- `src/bin/`: Rust binaries (benchmarks and generators), e.g. `bench_*` and `gen_*`.
- `scripts/`: orchestration and automation that call Rust binaries or shell tooling.
- `src/glyph_core.rs` is the module root, with submodules in `src/glyph_core/` (sumcheck, types, tests).
- `scripts/tools/`: bundled external tools and fixture generators (for example, foundry bundles).
- `scripts/tests/foundry/`: Foundry test harness and contracts for on-chain verification tests.
- `scripts/out/`: generated outputs from scripts (local only, not committed).

## Repository Structure (ASCII)

Snapshot date: 2026-02-04.

```text
glyph-zk/
|-- contracts/
|  |-- GLYPHRootUpdaterExtended.sol
|  |-- GLYPHRootUpdaterMinimal.sol
|  |-- GLYPHVerifier.sol
|  \-- GLYPHVerifierConstants.sol
|-- deployments/
|  |-- hoodi.json
|  |-- hoodi_groth16_3publics.json
|  |-- hoodi_groth16_many.json
|  |-- sepolia.json
|  |-- sepolia_groth16_3publics.json
|  \-- sepolia_groth16_many.json
|-- docs/
|  |-- proofs/
|  |  |-- 00_overview.md
|  |  |-- 01_sumcheck.md
|  |  |-- 02_gkr_binding.md
|  |  |-- 03_pcs_basefold.md
|  |  |-- 04_ucir_correctness.md
|  |  |-- 05_state_diff_binding.md
|  |  |-- 06_end_to_end.md
|  |  \-- 07_mechanized_proof_plan.md
|  |-- specs/
|  |  |-- adapter_ir_spec.md
|  |  |-- artifact_tag_spec.md
|  |  |-- custom_gates_spec.md
|  |  |-- stark_receipt_spec.md
|  |  |-- state_transition_vm_spec.md
|  |  |-- ucir_spec.md
|  |  \-- verifier_spec.md
|  |-- whitepaper/
|  |  |-- build/
|  |  |-- build_proof_appendix.sh
|  |  |-- build_whitepaper.sh
|  |  |-- glyph-proof-appendix.pdf
|  |  |-- glyph-whitepaper.pdf
|  |  |-- glyph_paper.tex
|  |  |-- glyph_proof_appendix.tex
|  |  \-- latexmkrc
|  |-- QUICKSTART.md
|  |-- documentation.md
|  \-- map.md
|-- scripts/
|  |-- benchmarks/
|  |  |-- groth16_compare/
|  |  |  |-- build_groth16.sh
|  |  |  |-- calc_calldata_stats.sh
|  |  |  |-- circuit.circom
|  |  |  |-- circuit_many.circom
|  |  |  |-- input_many.json
|  |  |  |-- package-lock.json
|  |  |  \-- package.json
|  |  |-- bench_basefold_arity_sweep.sh
|  |  |-- bench_basefold_mem_sweetspot.sh
|  |  |-- bench_basefold_trace_profile.sh
|  |  |-- bench_bn254_batch_kpi.sh
|  |  |-- bench_bn254_g2_kpi.sh
|  |  |-- bench_bn254_msm_kpi.sh
|  |  |-- bench_bn254_mul_kpi.sh
|  |  |-- bench_bn254_trace_kpi.sh
|  |  |-- bench_glyph_adapter_hoodi.sh
|  |  |-- bench_glyph_adapter_kpi.sh
|  |  |-- bench_glyph_adapter_zk_kpi.sh
|  |  |-- bench_glyph_cuda_kpi.sh
|  |  |-- bench_glyph_evm_artifact.sh
|  |  |-- bench_glyph_evm_local.sh
|  |  |-- bench_glyph_evm_realproof.sh
|  |  |-- bench_glyph_evm_round_sweep.sh
|  |  |-- bench_glyph_evm_sepolia.sh
|  |  |-- bench_glyph_hoodi_artifact_truncated.sh
|  |  |-- bench_glyph_sepolia_artifact.sh
|  |  |-- bench_glyph_sepolia_stmt.sh
|  |  |-- bench_glyph_zk_kpi.sh
|  |  |-- bench_groth16_hoodi.sh
|  |  |-- bench_groth16_sepolia.sh
|  |  |-- bench_ivc_fold_kpi.sh
|  |  |-- bench_ivc_parallel_profile.sh
|  |  |-- bench_packed_gkr_layout_sweep.sh
|  |  |-- bench_stark_do_work_kpis.sh
|  |  |-- bench_state_diff_compile_prove.sh
|  |  |-- bench_state_diff_merkle.sh
|  |  |-- bench_state_diff_prover_profile.sh
|  |  |-- bench_state_transition_vm.sh
|  |  |-- common.sh
|  |  |-- profile_perf_config.sh
|  |  |-- registry.json
|  |  |-- run_all.sh
|  |  \-- send_raw_tx.sh
|  |-- build/
|  |  |-- ci_deterministic_run.sh
|  |  \-- glyph_build.sh
|  |-- da/
|  |  |-- providers/
|  |  |  |-- eigenda_v1/
|  |  |  |  |-- go.mod
|  |  |  |  |-- go.sum
|  |  |  |  \-- main.go
|  |  |  |-- eigenda_v2/
|  |  |  |  |-- go.mod
|  |  |  |  |-- go.sum
|  |  |  |  \-- main.go
|  |  |  |-- arweave_turbo_upload.mjs
|  |  |  |-- check_providers.sh
|  |  |  |-- package-lock.json
|  |  |  \-- package.json
|  |  |-- arweave_local_smoke.sh
|  |  |-- fetch_arweave.sh
|  |  |-- fetch_blob.sh
|  |  |-- fetch_eigenda.sh
|  |  |-- fetch_eigenda_v2_srs.sh
|  |  |-- poll_eigenda.sh
|  |  |-- run_all_profiles.sh
|  |  |-- run_profile.sh
|  |  |-- smoke_test.sh
|  |  |-- state_diff_from_snapshots.sh
|  |  |-- state_diff_onchain_verify.sh
|  |  |-- state_diff_proof_flow.sh
|  |  |-- state_transition_vm_flow.sh
|  |  |-- submit_arweave.sh
|  |  |-- submit_blob.sh
|  |  \-- submit_eigenda.sh
|  |-- deploy/
|  |  |-- deploy_glyph_contract.sh
|  |  \-- verify_glyph_contract.sh
|  |-- formal/
|  |  |-- sumcheck_invariants/
|  |  |  |-- src/
|  |  |  |  \-- main.rs
|  |  |  |-- Cargo.lock
|  |  |  \-- Cargo.toml
|  |  \-- sumcheck_invariants.sh
|  |-- repro/
|  |  \-- repro_pack.sh
|  |-- tests/
|  |  |-- foundry/
|  |  |  |-- lib/
|  |  |  |  \-- forge-std/
|  |  |  |     |-- scripts/
|  |  |  |     |  \-- vm.py
|  |  |  |     |-- src/
|  |  |  |     |  |-- interfaces/
|  |  |  |     |  |  |-- IERC1155.sol
|  |  |  |     |  |  |-- IERC165.sol
|  |  |  |     |  |  |-- IERC20.sol
|  |  |  |     |  |  |-- IERC4626.sol
|  |  |  |     |  |  |-- IERC6909.sol
|  |  |  |     |  |  |-- IERC721.sol
|  |  |  |     |  |  |-- IERC7540.sol
|  |  |  |     |  |  |-- IERC7575.sol
|  |  |  |     |  |  \-- IMulticall3.sol
|  |  |  |     |  |-- Base.sol
|  |  |  |     |  |-- Config.sol
|  |  |  |     |  |-- LibVariable.sol
|  |  |  |     |  |-- Script.sol
|  |  |  |     |  |-- StdAssertions.sol
|  |  |  |     |  |-- StdChains.sol
|  |  |  |     |  |-- StdCheats.sol
|  |  |  |     |  |-- StdConfig.sol
|  |  |  |     |  |-- StdConstants.sol
|  |  |  |     |  |-- StdError.sol
|  |  |  |     |  |-- StdInvariant.sol
|  |  |  |     |  |-- StdJson.sol
|  |  |  |     |  |-- StdMath.sol
|  |  |  |     |  |-- StdStorage.sol
|  |  |  |     |  |-- StdStyle.sol
|  |  |  |     |  |-- StdToml.sol
|  |  |  |     |  |-- StdUtils.sol
|  |  |  |     |  |-- Test.sol
|  |  |  |     |  |-- Vm.sol
|  |  |  |     |  |-- console.sol
|  |  |  |     |  |-- console2.sol
|  |  |  |     |  \-- safeconsole.sol
|  |  |  |     |-- test/
|  |  |  |     |  |-- compilation/
|  |  |  |     |  |  |-- CompilationScript.sol
|  |  |  |     |  |  |-- CompilationScriptBase.sol
|  |  |  |     |  |  |-- CompilationTest.sol
|  |  |  |     |  |  \-- CompilationTestBase.sol
|  |  |  |     |  |-- fixtures/
|  |  |  |     |  |  |-- broadcast.log.json
|  |  |  |     |  |  |-- config.toml
|  |  |  |     |  |  |-- test.json
|  |  |  |     |  |  \-- test.toml
|  |  |  |     |  |-- CommonBase.t.sol
|  |  |  |     |  |-- Config.t.sol
|  |  |  |     |  |-- LibVariable.t.sol
|  |  |  |     |  |-- StdAssertions.t.sol
|  |  |  |     |  |-- StdChains.t.sol
|  |  |  |     |  |-- StdCheats.t.sol
|  |  |  |     |  |-- StdConstants.t.sol
|  |  |  |     |  |-- StdError.t.sol
|  |  |  |     |  |-- StdJson.t.sol
|  |  |  |     |  |-- StdMath.t.sol
|  |  |  |     |  |-- StdStorage.t.sol
|  |  |  |     |  |-- StdStyle.t.sol
|  |  |  |     |  |-- StdToml.t.sol
|  |  |  |     |  |-- StdUtils.t.sol
|  |  |  |     |  \-- Vm.t.sol
|  |  |  |     |-- CONTRIBUTING.md
|  |  |  |     |-- LICENSE-APACHE
|  |  |  |     |-- LICENSE-MIT
|  |  |  |     |-- README.md
|  |  |  |     |-- RELEASE_CHECKLIST.md
|  |  |  |     |-- foundry.toml
|  |  |  |     \-- package.json
|  |  |  |-- GLYPHRootUpdaterExtended.sol
|  |  |  |-- GLYPHRootUpdaterExtended.t.sol
|  |  |  |-- GLYPHRootUpdaterMinimal.sol
|  |  |  |-- GLYPHRootUpdaterMinimal.t.sol
|  |  |  |-- GLYPHVerifier.sol
|  |  |  |-- GLYPHVerifierConstants.sol
|  |  |  |-- GLYPHVerifierTest.t.sol
|  |  |  |-- GLYPH_HASH_Test.t.sol
|  |  |  |-- GLYPH_IVC_Test.t.sol
|  |  |  |-- GLYPH_SNARK_GROTH16_Test.t.sol
|  |  |  |-- GLYPH_SNARK_IPA_Test.t.sol
|  |  |  |-- GLYPH_SNARK_KZG_Test.t.sol
|  |  |  |-- GLYPH_SNARK_PLONK_Test.t.sol
|  |  |  |-- GLYPH_SNARK_SP1_Test.t.sol
|  |  |  |-- GLYPH_STARK_Test.t.sol
|  |  |  |-- GeneratedRealProofTest.t.sol
|  |  |  |-- Groth16Verifier.sol
|  |  |  |-- Groth16VerifierMany.sol
|  |  |  \-- foundry.toml
|  |  |-- fuzz/
|  |  |  |-- dicts/
|  |  |  |  |-- adapter_ir.dict
|  |  |  |  \-- stark.dict
|  |  |  |-- workspace/
|  |  |  |  |-- fuzz_targets/
|  |  |  |  |  |-- bn254_op_traces.rs
|  |  |  |  |  |-- decode_adapter_bytes.rs
|  |  |  |  |  |-- decode_adapter_ir_deep.rs
|  |  |  |  |  |-- decode_circle_stark_program.rs
|  |  |  |  |  |-- decode_circle_stark_proof.rs
|  |  |  |  |  |-- decode_ipa_receipt.rs
|  |  |  |  |  |-- decode_plonky2_receipt.rs
|  |  |  |  |  |-- decode_r1cs_receipt.rs
|  |  |  |  |  |-- decode_supernova_external_proof.rs
|  |  |  |  |  |-- decode_stwo_profile.rs
|  |  |  |  |  |-- decode_stwo_program.rs
|  |  |  |  |  |-- decode_standard_stark_program.rs
|  |  |  |  |  |-- decode_standard_stark_proof.rs
|  |  |  |  |  |-- decode_stark_ir.rs
|  |  |  |  |  |-- decode_stark_receipt.rs
|  |  |  |  |  |-- decode_stark_vk.rs
|  |  |  |  |  |-- decode_winterfell_program.rs
|  |  |  |  |  |-- diff_adapter_ir_roundtrip.rs
|  |  |  |  |  |-- synthesize_stwo_proof.rs
|  |  |  |  |  |-- transcript_challenges.rs
|  |  |  |  |  |-- validate_state_transition_batch.rs
|  |  |  |  |  |-- verify_adapter_proof.rs
|  |  |  |  |  \-- verify_packed_calldata.rs
|  |  |  |  |-- Cargo.lock
|  |  |  |  \-- Cargo.toml
|  |  |  |-- run_all.sh
|  |  |  |-- run_cmin.sh
|  |  |  \-- run_tmin.sh
|  |  |-- rust/
|  |  |  |-- adapter_error_semantics.rs
|  |  |  |-- adapter_ir_property_tests.rs
|  |  |  |-- bn254_emulation_property_tests.rs
|  |  |  |-- chaos_stark_decode_tests.rs
|  |  |  |-- chaos_truncated_inputs.rs
|  |  |  |-- cli_registry_consistency_tests.rs
|  |  |  |-- crypto_parameter_integrity.rs
|  |  |  |-- da_envelope_tests.rs
|  |  |  |-- da_integration_tests.rs
|  |  |  |-- differential_receipt_verification.rs
|  |  |  |-- ir_compiler_boundary_tests.rs
|  |  |  |-- ivc_supernova_tests.rs
|  |  |  |-- prop_test_suite.rs
|  |  |  |-- risc_zero_fixture_checks.rs
|  |  |  |-- stwo_prover_tests.rs
|  |  |  |-- transcript_property_tests.rs
|  |  |  \-- ucir_compiler_equivalence.rs
|  |  |-- run_tests.sh
|  |  |-- run_feature_matrix.sh
|  |  \-- verifier_symbolic.sh
|  |-- tools/
|  |  |-- converters/
|  |  |  \-- stwo_to_bundle.rs
|  |  |-- fixture_generators/
|  |  |  |-- gnark_bn254_plonk/
|  |  |  |  |-- README.md
|  |  |  |  |-- go.mod
|  |  |  |  |-- go.sum
|  |  |  |  |-- main.go
|  |  |  |  \-- run.sh
|  |  |  \-- sp1/
|  |  |     |-- guest/
|  |  |     |  |-- src/
|  |  |     |  |  \-- main.rs
|  |  |     |  |-- Cargo.lock
|  |  |     |  \-- Cargo.toml
|  |  |     |-- src/
|  |  |     |  |-- bin/
|  |  |     |  |  |-- build_gnark_circuits.rs
|  |  |     |  |  \-- build_guest.rs
|  |  |     |  \-- main.rs
|  |  |     |-- Cargo.lock
|  |  |     |-- Cargo.toml
|  |  |     |-- README.md
|  |  |     \-- run.sh
|  |  |-- fixtures/
|  |  |  |-- cairo_stone6_keccak_160_lsb_example_proof.json
|  |  |  |-- fast_circle_stark_baby_bear_receipt.txt
|  |  |  |-- fast_circle_stark_baby_bear_receipt.txt.candidate
|  |  |  |-- fast_circle_stark_koala_bear_receipt.txt
|  |  |  |-- fast_circle_stark_koala_bear_receipt.txt.candidate
|  |  |  |-- fast_circle_stark_receipt.txt
|  |  |  |-- fast_circle_stark_receipt.txt.candidate
|  |  |  |-- fast_circle_stark_receipt_large.txt
|  |  |  |-- fast_circle_stark_receipt_large.txt.candidate
|  |  |  |-- fast_plonky2_goldilocks_receipt.txt
|  |  |  |-- fast_plonky2_goldilocks_receipt.txt.candidate
|  |  |  |-- fast_sha3_receipt.txt
|  |  |  |-- fast_sha3_receipt_f64.txt
|  |  |  |-- groth16_bls12381_receipt.txt
|  |  |  |-- groth16_bls12381_receipt.txt.candidate
|  |  |  |-- groth16_bn254_fixture.txt
|  |  |  |-- halo2_bls12381_kzg_receipt.txt
|  |  |  |-- halo2_bls12381_kzg_receipt.txt.candidate
|  |  |  |-- halo2_bn254_kzg_receipt.txt
|  |  |  |-- halo2_bn254_kzg_receipt.txt.candidate
|  |  |  |-- ivc_hypernova_external_proof.txt
|  |  |  |-- ivc_nova_external_proof.txt
|  |  |  |-- ivc_sangria_external_proof.txt
|  |  |  |-- ivc_supernova_external_proof.txt
|  |  |  |-- kzg_bls12381_receipt.txt
|  |  |  |-- kzg_bls12381_receipt.txt.candidate
|  |  |  |-- miden_blake3_receipt.txt
|  |  |  |-- miden_rpo_receipt.txt
|  |  |  |-- plonk_bls12381_receipt.txt
|  |  |  |-- plonk_bls12381_receipt.txt.candidate
|  |  |  |-- plonk_bn254_gnark_receipt.txt
|  |  |  |-- plonky3_babybear_blake3_receipt.txt.candidate
|  |  |  |-- plonky3_babybear_poseidon2_receipt.txt.candidate
|  |  |  |-- plonky3_babybear_poseidon2_tribonacci_receipt.txt
|  |  |  |-- plonky3_babybear_poseidon2_tribonacci_receipt.txt.candidate
|  |  |  |-- plonky3_babybear_poseidon_receipt.txt.candidate
|  |  |  |-- plonky3_babybear_rescue_receipt.txt.candidate
|  |  |  |-- plonky3_goldilocks_blake3_receipt.txt.candidate
|  |  |  |-- plonky3_goldilocks_poseidon2_receipt.txt.candidate
|  |  |  |-- plonky3_goldilocks_poseidon2_tribonacci_receipt.txt
|  |  |  |-- plonky3_goldilocks_poseidon_receipt.txt.candidate
|  |  |  |-- plonky3_goldilocks_rescue_receipt.txt.candidate
|  |  |  |-- plonky3_koalabear_blake3_receipt.txt.candidate
|  |  |  |-- plonky3_koalabear_poseidon2_receipt.txt.candidate
|  |  |  |-- plonky3_koalabear_poseidon2_tribonacci_receipt.txt
|  |  |  |-- plonky3_koalabear_poseidon2_tribonacci_receipt.txt.candidate
|  |  |  |-- plonky3_koalabear_poseidon_receipt.txt.candidate
|  |  |  |-- plonky3_koalabear_rescue_receipt.txt.candidate
|  |  |  |-- risc_zero_bundle.json
|  |  |  |-- risc_zero_external_receipt.json
|  |  |  |-- sp1_groth16_receipt.txt
|  |  |  |-- sp1_plonk_receipt.txt
|  |  |  |-- stwo_external.json
|  |  |  |-- stwo_external.receipt.txt
|  |  |  \-- stwo_test_bundle.json
|  \-- utils/
|     |-- cuda/
|     |  \-- check_cuda_toolkit.sh
|     |-- dump_perf_config.sh
|     |-- ensure_groth16_compare_deps.sh
|     |-- ensure_state_diff_fixture.sh
|     \-- perf_summary.sh
|-- src/
|  |-- bin/
|  |  |-- bench_basefold_pcs.rs
|  |  |-- bench_bn254_batch_kpi.rs
|  |  |-- bench_bn254_g2_kpi.rs
|  |  |-- bench_bn254_msm_kpi.rs
|  |  |-- bench_bn254_mul_kpi.rs
|  |  |-- bench_bn254_trace_kpi.rs
|  |  |-- bench_glyph_adapter_kpi.rs
|  |  |-- bench_glyph_adapter_zk_kpi.rs
|  |  |-- bench_glyph_cuda_kpi.rs
|  |  |-- bench_glyph_packed_gkr_layout.rs
|  |  |-- bench_glyph_zk_kpi.rs
|  |  |-- bench_ivc_fold_kpi.rs
|  |  |-- bench_state_diff_compile_prove.rs
|  |  |-- bench_state_diff_merkle.rs
|  |  |-- bench_state_transition_vm.rs
|  |  |-- gen_circle_stark_fixture.rs
|  |  |-- gen_fast_sha3_fixture.rs
|  |  |-- gen_glyph_gkr_proof.rs
|  |  |-- gen_risc_zero_bundle_fixture.rs
|  |  |-- gen_stark_fixture.rs
|  |  |-- gen_stark_fixture_f64.rs
|  |  |-- gen_stwo_external_fixture.rs
|  |  |-- glyph_adapt_batch.rs
|  |  |-- glyph_da.rs
|  |  |-- glyph_emit_cuda_kernels.rs
|  |  |-- glyph_import_cairo_receipt.rs
|  |  |-- glyph_import_circle_receipt.rs
|  |  |-- glyph_import_halo2_receipt.rs
|  |  |-- glyph_import_miden_receipt.rs
|  |  |-- glyph_import_plonk_receipt.rs
|  |  |-- glyph_import_plonky3_receipt.rs
|  |  |-- glyph_import_risc_zero_receipt.rs
|  |  |-- glyph_import_sp1_receipt.rs
|  |  |-- glyph_import_stwo_receipt.rs
|  |  |-- glyph_l2_statement.rs
|  |  |-- glyph_prover.rs
|  |  |-- glyph_raw_tx.rs
|  |  |-- glyph_state_diff.rs
|  |  |-- glyph_state_diff_prove.rs
|  |  |-- glyph_state_transition_execute.rs
|  |  |-- glyph_state_transition_prove.rs
|  |  \-- stark_do_work_kpis.rs
|  |-- glyph_core/
|  |  |-- sumcheck.rs
|  |  |-- tests.rs
|  |  \-- types.rs
|  |-- adapter_error.rs
|  |-- adapter_facade.rs
|  |-- adapter_gate.rs
|  |-- adapter_ir.rs
|  |-- adapter_registry.rs
|  |-- adapters.rs
|  |-- arena.rs
|  |-- baby_bear_field.rs
|  |-- binius_adapter.rs
|  |-- bn254_curve.rs
|  |-- bn254_field.rs
|  |-- bn254_groth16.rs
|  |-- bn254_ops.rs
|  |-- bn254_pairing.rs
|  |-- bn254_pairing_trace.rs
|  |-- cairo_stark.rs
|  |-- circle_fri.rs
|  |-- circle_merkle.rs
|  |-- circle_stark.rs
|  |-- circle_stark_bundle.rs
|  |-- cli_registry.rs
|  |-- da.rs
|  |-- e2e_proofs.rs
|  |-- f128_field.rs
|  |-- f64_field.rs
|  |-- glv.rs
|  |-- glyph_basefold.rs
|  |-- glyph_bn254_field.rs
|  |-- glyph_core.rs
|  |-- glyph_field_simd.rs
|  |-- glyph_gkr.rs
|  |-- glyph_ir.rs
|  |-- glyph_ir_compiler.rs
|  |-- glyph_logup.rs
|  |-- glyph_pairing.rs
|  |-- glyph_pcs_basefold.rs
|  |-- glyph_proof.rs
|  |-- glyph_prover.rs
|  |-- glyph_transcript.rs
|  |-- glyph_verifier.rs
|  |-- glyph_witness.rs
|  |-- groth16_bls12381.rs
|  |-- halo2_receipt.rs
|  |-- ipa_adapter.rs
|  |-- ipa_bls12381.rs
|  |-- ipa_bn254.rs
|  |-- ivc_adapter.rs
|  |-- ivc_compressed.rs
|  |-- ivc_hypernova.rs
|  |-- ivc_nova.rs
|  |-- ivc_r1cs.rs
|  |-- ivc_sangria.rs
|  |-- ivc_supernova.rs
|  |-- koala_bear_field.rs
|  |-- kzg_bls12381.rs
|  |-- l2_statement.rs
|  |-- lib.rs
|  |-- m31_field.rs
|  |-- miden_stark.rs
|  |-- parallel_prover.rs
|  |-- pcs_basefold.rs
|  |-- pcs_binary_field.rs
|  |-- pcs_common.rs
|  |-- pcs_encoding.rs
|  |-- pcs_ring_switch.rs
|  |-- perf_config.rs
|  |-- plonk_adapter.rs
|  |-- plonk_halo2_adapter.rs
|  |-- plonky2_receipt.rs
|  |-- plonky3_stark.rs
|  |-- precomputed.rs
|  |-- public_inputs.rs
|  |-- risc_zero_bundle.rs
|  |-- sdk.rs
|  |-- simd_prover.rs
|  |-- snark_groth16_bn254_adapter.rs
|  |-- snark_kzg_bn254_adapter.rs
|  |-- sp1_adapter.rs
|  |-- standard_fri.rs
|  |-- standard_stark.rs
|  |-- stark_adapter.rs
|  |-- stark_hash.rs
|  |-- stark_ir.rs
|  |-- stark_program.rs
|  |-- stark_receipt.rs
|  |-- stark_transcript.rs
|  |-- stark_winterfell.rs
|  |-- stark_winterfell_f64.rs
|  |-- state_diff_merkle.rs
|  |-- state_transition_vm.rs
|  |-- stwo_bundle.rs
|  |-- stwo_fri.rs
|  |-- stwo_types.rs
|  \-- stwo_verifier.rs
|-- vendor/
|  |-- binius/
|  |-- feldera-size-of/
|  |-- msgpacker/
|  |-- stackalloc/
|  \-- stwo/
|-- Cargo.lock
|-- Cargo.toml
\-- rust-toolchain.toml
```

## Tooling Inventory (scripts/)

All tooling lives under `scripts/`. Outputs live under `scripts/out/`.

### Benchmarks
- `scripts/benchmarks/common.sh`: shared bench helpers and `bench_v1` JSON rewrap.
- `scripts/benchmarks/run_all.sh`: orchestrate benchmark presets from `registry.json`.
- `scripts/benchmarks/registry.json`: preset registry for benchmark runs.
- `scripts/benchmarks/profile_perf_config.sh`: perf profile runner and config snapshot bundle.
- `scripts/benchmarks/bench_glyph_evm_local.sh`: local gas bench for GLYPH verifier (Anvil).
- `scripts/benchmarks/bench_glyph_evm_round_sweep.sh`: round-count sweep for packed GKR layout (Anvil).
- `scripts/benchmarks/bench_glyph_evm_realproof.sh`: real prover path bench for hash or STARK families.
- `scripts/benchmarks/bench_glyph_evm_artifact.sh`: artifact-poly calldata bench (Anvil).
- `scripts/benchmarks/bench_glyph_evm_sepolia.sh`: gas estimates and optional tx on Sepolia.
- `scripts/benchmarks/bench_glyph_sepolia_stmt.sh`: artifact-bound layout bench on Sepolia (historical `stmt` name).
- `scripts/benchmarks/bench_glyph_sepolia_artifact.sh`: artifact-poly layout bench on Sepolia.
- `scripts/benchmarks/bench_glyph_hoodi_artifact_truncated.sh`: truncated artifact-poly bench on Hoodi.
- `scripts/benchmarks/bench_glyph_adapter_hoodi.sh`: adapter calldata bench on Hoodi with truncated layout.
- `scripts/benchmarks/bench_glyph_adapter_kpi.sh`: adapter KPI bench on canonical fixtures.
- `scripts/benchmarks/bench_glyph_adapter_zk_kpi.sh`: ZK KPI bench for adapters.
- `scripts/benchmarks/bench_glyph_zk_kpi.sh`: ZK proof size KPI bench.
- `scripts/benchmarks/bench_glyph_cuda_kpi.sh`: CUDA KPI bench for packed GKR (preset `cuda`, requires `GLYPH_ENABLE_CUDA_BENCH=1`).
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
- `scripts/da/fetch_eigenda_v2_srs.sh`: fetch EigenDA v2 SRS assets into the local SRS cache.
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

### DA Providers
- `scripts/da/providers/arweave_turbo_upload.mjs`: Arweave Turbo upload helper.
- `scripts/da/providers/eigenda_v1/main.go`: EigenDA v1 client wrapper.
- `scripts/da/providers/eigenda_v2/main.go`: EigenDA v2 client wrapper.
- `scripts/da/providers/check_providers.sh`: provider toolchain smoke checks.
- `scripts/da/providers/package.json`: provider helper dependencies.
- `scripts/da/providers/package-lock.json`: provider dependency lockfile.

### Tests and Fuzzing
- `scripts/tests/run_tests.sh`: test orchestrator (Rust, Foundry, fuzz).
- `scripts/tests/run_feature_matrix.sh`: build preset matrix runner with optional default tests.
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
- `scripts/tests/fuzz/workspace/fuzz_targets/bn254_op_traces.rs`: fuzz BN254 op trace validation.
- `scripts/tests/fuzz/workspace/fuzz_targets/diff_adapter_ir_roundtrip.rs`: fuzz IR roundtrip diffs.
- `scripts/tests/fuzz/workspace/fuzz_targets/transcript_challenges.rs`: fuzz transcript challenge derivation.
- `scripts/tests/fuzz/workspace/fuzz_targets/validate_state_transition_batch.rs`: fuzz VM batch validation.
- `scripts/tests/fuzz/workspace/fuzz_targets/verify_adapter_proof.rs`: fuzz adapter proof verification.
- `scripts/tests/fuzz/workspace/fuzz_targets/verify_packed_calldata.rs`: fuzz packed calldata verification.

### Repro and Utils
- `scripts/repro/repro_pack.sh`: deterministic repro pack builder.
- `scripts/utils/ensure_groth16_compare_deps.sh`: Groth16 compare deps installer (bun or npm).
- `scripts/utils/cuda/check_cuda_toolkit.sh`: CUDA toolkit availability check.
- `scripts/utils/dump_perf_config.sh`: perf env snapshot to JSON.
- `scripts/utils/ensure_state_diff_fixture.sh`: deterministic state diff fixture generator.
- `scripts/utils/perf_summary.sh`: summary of perf run outputs.

### Formal and Examples
- `scripts/formal/sumcheck_invariants.sh`: sumcheck invariant runner.
- `scripts/formal/sumcheck_invariants/Cargo.toml`: sumcheck crate manifest.
- `scripts/formal/sumcheck_invariants/Cargo.lock`: sumcheck crate lockfile.
- `scripts/formal/sumcheck_invariants/src/main.rs`: sumcheck invariants implementation.

### Tools and Generators
- `scripts/tools/converters/stwo_to_bundle.rs`: Stwo bundle converter.
- `scripts/tools/generate_glyph_verifier_constants.py`: Generate GLYPHVerifier constants from `src/glyph_gkr.rs`.
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
- `scripts/tools/fixtures/cairo_stone6_keccak_160_lsb_example_proof.json`: Cairo proof example fixture.

## VM Spec

- `docs/specs/state_transition_vm_spec.md`: GLYPH state transition VM specification, trace format, and constraints.
- `src/bin/glyph_state_transition_execute.rs`: VM op execution CLI that emits batch updates with proofs.
- `src/bin/glyph_state_transition_prove.rs`: VM batch proof CLI that emits GLYPH artifact calldata.
- `scripts/da/state_transition_vm_flow.sh`: VM execution and proof flow wrapper.
- `src/state_diff_merkle.rs`: MerkleHasher interface with CPU fallback for diff roots.

## Security Model (Binding vs. Validity)

- `docs/specs/verifier_spec.md`: Byte-accurate calldata and memory layout for `GLYPHVerifier.sol`.
- **Binding (on-chain)**: `contracts/GLYPHVerifier.sol` enforces chain binding via `r0 = keccak256(chainid || address(this) || artifact_tag || claim128 || initial_claim) mod p`, and `artifact_tag = keccak256(commitment_tag || point_tag)` is provided in the header.
- **Validity (off-chain)**: implemented for Winterfell SHA3 `do_work`, Circle STARK (M31, BabyBear, KoalaBear), Standard FRI BabyBear, Stwo, Cairo (Starknet-with-Keccak), and Miden receipts via canonical receipts, verified inside GLYPH-Prover with the STARK custom gate (`CUSTOM_GATE_STARK_VERIFY`), and bound to the GLYPH artifact (`src/stark_adapter.rs`, `src/glyph_ir_compiler.rs`). SP1, PLONK plus Halo2 KZG, and Binius receipts are verified via dedicated custom gates. See `docs/documentation.md`.
- **PCS (off-chain commitment)**: BaseFold PCS over binary towers via `src/glyph_pcs_basefold.rs` and `src/pcs_basefold.rs`. Legacy Brakedown PCS is archived and not used in the build.
- **Optional L2 root update (on-chain)**: `contracts/GLYPHRootUpdaterMinimal.sol` and `contracts/GLYPHRootUpdaterExtended.sol` bind GLYPH proofs to state root updates without changing `GLYPHVerifier.sol`.
- **Optional DA layer (off-chain)**: `glyph_da` CLI and `scripts/da/*` submit proof payloads to Ethereum blobs and optional archival layers. The verifier remains unchanged.
- **Adapter error semantics**: standardized in `src/adapter_error.rs` and used by adapter entrypoints.
- **Adapter registry and gate**: availability inventory in `src/adapter_registry.rs` with runtime checks in `src/adapter_gate.rs`.
- **Adapter facades and CLI registry helpers**: `src/adapter_facade.rs` wraps feature-gated compilers, and `src/cli_registry.rs` formats registry-aware CLI help.
- **Centralized adapter gating at entrypoints**: `src/glyph_ir_compiler.rs` and `src/adapter_ir.rs` gate through `adapter_gate` and route to feature-gated implementations.
- **Centralized fallback errors**: feature-disabled branches in `src/glyph_ir_compiler.rs` and
  `src/adapter_ir.rs` route errors through `adapter_gate`, including
  `ensure_any_stark_enabled()`.
- **Centralized custom gate gating**: `src/glyph_ir.rs` gates custom gates via
  `ensure_custom_gate_enabled(custom_id)` inside `custom_gate_wrefs`, and the witness engine
  (`src/glyph_witness.rs`) uses the same gate check during evaluation.
- **Uniform witness gate verification**: `src/glyph_witness.rs` routes adapter custom gates through
  per-gate verifier helpers and a shared `compare_artifact_tags(...)` path.

## Repro Pack

- `scripts/repro/repro_pack.sh`: deterministic reproduction runner with manifest output under `scripts/out/repro/`.
- `scripts/utils/dump_perf_config.sh`: emits a JSON snapshot of performance-related env vars.
- `scripts/benchmarks/profile_perf_config.sh`: offline profiling runner that emits `scripts/out/benchmarks/perf_profile.json`.
- `scripts/utils/ensure_state_diff_fixture.sh`: deterministic state diff fixture generator.
- `scripts/utils/perf_summary.sh`: CLI summary for perf snapshots.
- `src/perf_config.rs`: in-process perf config schema, validation, and snapshots to `scripts/out/perf/perf_config.json` and `scripts/out/perf/perf_run.json`.
- `docs/map.md`: repository structure, wiring overview, and tooling index.
- `scripts/tests/verifier_symbolic.sh`: verifier symbolic fuzz harness.
- `scripts/tests/rust/cli_registry_consistency_tests.rs`: registry helper consistency checks for CLI feature status.
- Formal tooling evidence is summarized in `docs/documentation.md` (Section 14.4.1).

## Guides

- `docs/QUICKSTART.md`: entry quickstart for setup and deployment.
- `docs/documentation.md`: SSOT, includes CLI cookbook, adapter integration, state diff and DA tutorials, and audit status.
- `docs/proofs/`: formal proof pack notes and proof-to-code mapping.
- `src/sdk.rs`: minimal Rust SDK for proof and state transition flows.
- Adapter registry architecture notes are consolidated in `docs/documentation.md`
  under "Registry and CLI Consistency (Adapter Availability)".

## Formal Proof Pack

- `docs/proofs/00_overview.md`: security model and assumptions.
- `docs/proofs/01_sumcheck.md`: sumcheck proof and binding.
- `docs/proofs/02_gkr_binding.md`: artifact tag and GKR binding.
- `docs/proofs/03_pcs_basefold.md`: PCS commitment correctness.
- `docs/proofs/04_ucir_correctness.md`: UCIR semantics and adapter correctness.
- `docs/proofs/05_state_diff_binding.md`: state diff binding and replay resistance.
- `docs/proofs/06_end_to_end.md`: end-to-end soundness theorem.

## UCIR Spec

- `docs/specs/ucir_spec.md`: UCIR encoding, semantics, and invariants for adapter transpilation.

## Formal Proof Pack

- `docs/proofs/07_mechanized_proof_plan.md`: machine-checkable proof roadmap and theorem list.

## Roadmap (Trustless Upstream Validity)

Target direction (GLYPH-first):

- **Phase 1 (Transpiler)**: upstream verifier logic compiles into GLYPH UCIR and canonical adapter bytes.
- **Phase 2 (Internal folding)**: aggregate instances into a single succinct claim using Keccak-derived folding weights.
- **Phase 3 (GKR bridge)**: map the final claim into the BN254 field and expose it via the stable GLYPH artifact `(commitment_tag, point_tag, claim128)`.
- **Phase 4 (On-chain)**: `contracts/GLYPHVerifier.sol` verifies the packed arity-8 sumcheck proof bound to the GLYPH artifact.

Current state: canonical receipt validation and GLYPH artifact derivation are implemented, and Winterfell `do_work`, Circle STARK, Standard FRI, Stwo, Cairo, and Miden receipts are verified inside GLYPH-PROVER via the STARK custom gate. SP1, PLONK plus Halo2 KZG, and Binius adapters are implemented via custom gates.

---

## Part 1: Data Flow (Wiring)

### STARK Adapter Flow (Winterfell SHA3)

```
Upstream Receipt -> Canonical Receipt -> UCIR + STARK Gate -> GLYPH-PROVER -> GLYPHVerifier
```

1. **Upstream receipt bytes**
   - Sources: `scripts/tools/fixtures/fast_sha3_receipt.txt`, `scripts/tools/fixtures/fast_sha3_receipt_f64.txt`
   - Parsed into `StarkUpstreamReceipt` in `src/stark_adapter.rs`
2. **Canonical receipt**
   - Canonical receipt derivation in `src/stark_winterfell.rs`
   - Produces a canonical receipt with verifier program bytes
3. **UCIR compile + STARK custom gate**
   - `glyph_ir_compiler::compile_stark`
   - Encodes receipt bytes into `CUSTOM_GATE_STARK_VERIFY`
4. **Packed GLYPH proof**
   - `glyph_core::prove_universal` proves the custom gate
   - Packed by `origami_gkr::prove_packed_artifact_poly_sumcheck`
5. **On-chain verification**
   - `contracts/GLYPHVerifier.sol`
   - Foundry vectors: `scripts/tests/foundry/GLYPH_STARK_Test.t.sol`

### STARK Adapter Flow (Circle STARK M31/BabyBear/KoalaBear)

1. **Canonical receipt bytes**
   - Canonical receipt with Circle STARK profile bytes
   - Fixtures: `scripts/tools/fixtures/fast_circle_stark_receipt.txt`, `scripts/tools/fixtures/fast_circle_stark_receipt_large.txt`
   - Import: `src/bin/glyph_import_circle_receipt.rs`
2. **Circle STARK verification**
   - `circle_stark::verify_circle_stark_receipt`
   - Field profiles: M31 (0x03), BabyBear (0x04), KoalaBear (0x06)
3. **UCIR compile + STARK custom gate**
   - Same as Winterfell flow
4. **Packed GLYPH proof** -> **On-chain verification**

### STARK Adapter Flow (Standard FRI BabyBear - RISC Zero)

1. **Bundle import**
   - `glyph_import_risc_zero_receipt` converts RISC Zero bundle JSON to canonical receipt (field_id 0x05)
2. **Standard STARK verification**
   - `standard_stark::verify_standard_stark_receipt`
3. **UCIR compile + STARK custom gate** -> **Packed GLYPH proof** -> **On-chain verification**

### STARK Adapter Flow (Stwo M31)

1. **Canonical receipt bytes**
   - Import via `src/bin/glyph_import_stwo_receipt.rs`
2. **Stwo receipt verification**
   - `stwo_verifier::verify_stwo_receipt` (Blake2s Merkle PCS)
3. **UCIR compile + STARK custom gate** -> **Packed GLYPH proof** -> **On-chain verification**

### STARK Adapter Flow (Cairo Starknet Prime)

1. **Canonical receipt bytes**
   - Import via `src/bin/glyph_import_cairo_receipt.rs`
2. **Cairo receipt verification**
   - `cairo_stark::verify_cairo_receipt` (Swiftness verifier, Starknet-with-Keccak layout)
3. **UCIR compile + STARK custom gate** -> **Packed GLYPH proof** -> **On-chain verification**

### STARK Adapter Flow (Miden Goldilocks)

1. **Canonical receipt bytes**
   - Import via `src/bin/glyph_import_miden_receipt.rs`
2. **Miden receipt verification**
   - `miden_stark::verify_miden_receipt` (Miden verifier, no precompile requests)
3. **UCIR compile + STARK custom gate** -> **Packed GLYPH proof** -> **On-chain verification**

### Groth16 SNARK Adapter Flow (BN254)

1. **Inputs**: Groth16 VK, proof, public input bytes
2. **Groth16 SNARK adapter**
   - `snark_groth16_bn254_adapter::derive_glyph_artifact_from_groth16_bn254`
   - Records BN254 pairing trace events, compiles to UCIR
3. **GLYPH artifact boundary**
   - `(commitment_tag, point_tag, claim128)` derived from adapter IR
4. **Packed GLYPH proof** -> **On-chain verification**
   - Foundry: `scripts/tests/foundry/GLYPH_SNARK_GROTH16_Test.t.sol`

### KZG SNARK Adapter Flow (BN254)

1. **Inputs**: KZG VK, proof, public input bytes
2. **KZG SNARK adapter**
   - `snark_kzg_bn254_adapter::derive_glyph_artifact_from_kzg_bn254`
   - Records BN254 pairing trace events, compiles to UCIR
3. **GLYPH artifact boundary** -> **Packed GLYPH proof** -> **On-chain verification**
   - Foundry: `scripts/tests/foundry/GLYPH_SNARK_KZG_Test.t.sol`

### IVC/Folding Adapter Flow (BaseFold PCS)

1. **Inputs**: BaseFold PCS opening proof bytes
2. **UCIR compile + IVC custom gate**
   - `glyph_ir_compiler::compile_ivc`
   - Encodes proof bytes into `CUSTOM_GATE_IVC_VERIFY`
3. **Packed GLYPH proof** -> **On-chain verification**
   - Foundry: `scripts/tests/foundry/GLYPH_IVC_Test.t.sol`

### IPA Adapter Flow (Halo2 IPA)

1. **Inputs**: IPA receipt bytes plus public inputs
2. **IPA adapter**
   - `ipa_adapter::derive_glyph_artifact_from_ipa_receipt` with statement-bound transcript
3. **GLYPH artifact boundary** -> **Packed GLYPH proof** -> **On-chain verification**
   - Foundry: `scripts/tests/foundry/GLYPH_SNARK_IPA_Test.t.sol`

### Binius Adapter Flow (Constraint-System Proofs)

1. **Inputs**: Binius VK bytes, boundaries bytes, proof transcript bytes
2. **Binius adapter**
   - `binius_adapter::derive_glyph_artifact_from_binius_receipt`
   - Verifies canonical Binius constraint-system proof
3. **UCIR compile + Binius custom gate** -> **Packed GLYPH proof** -> **On-chain verification**

### Hash Adapter Flow (Keccak-256 merge)

1. **Inputs**: Two 32-byte digests
2. **Hash proof**
   - `adapter_ir::execute_hash_sha3_merge_ir` validates `digest = keccak256(left || right)`
3. **GLYPH artifact boundary** -> **Packed GLYPH proof** -> **On-chain verification**
   - Foundry: `scripts/tests/foundry/GLYPH_HASH_Test.t.sol`

### SP1 Adapter Flow (Groth16/Plonk BN254)

1. **Canonical receipt bytes**
   - Import via `src/bin/glyph_import_sp1_receipt.rs`
2. **SP1 receipt verification**
   - `sp1_adapter::verify_sp1_receipt` (SP1 verifier keys)
3. **UCIR compile + SP1 custom gate** -> **Packed GLYPH proof** -> **On-chain verification**

### PLONK and Halo2 Adapter Flow (gnark BN254, dusk BLS12-381, Halo2 KZG BN256 and BLS12-381)

1. **Canonical receipt bytes**
   - Import via `src/bin/glyph_import_plonk_receipt.rs` or `src/bin/glyph_import_halo2_receipt.rs`
2. **Receipt verification**
   - PLONK via `plonk_adapter::verify_plonk_receipt`
   - Halo2 KZG via `halo2_receipt` verification
3. **UCIR compile + PLONK custom gate** -> **Packed GLYPH proof** -> **On-chain verification**

---

## Optional DA Pipeline (Profiles)

```
GLYPH Artifact Bytes -> DA Payload -> Provider Commitments -> DA Envelope -> Archive
```

1. **DA payload assembly**
   - `glyph_da` encodes a deterministic payload and hashes it
2. **Provider submission**
   - Blob submit: `scripts/da/submit_blob.sh` (EIP-4844, canonical)
   - Arweave submit: `scripts/da/submit_arweave.sh` (archive)
   - EigenDA submit: `scripts/da/submit_eigenda.sh` (optional throughput)
3. **DA envelope**
   - `glyph_da` writes the canonical envelope and `envelope_hash`
4. **Retrieval**
   - `scripts/da/fetch_blob.sh`, `scripts/da/fetch_arweave.sh`, and `scripts/da/fetch_eigenda.sh` fetch payloads by commitment ids

---

## Part 2: File Index

### Core Rust Modules

| File | Role |
|------|------|
| `src/stark_adapter.rs` | Universal STARK adapter, receipt validation, STARK proof helper |
| `src/standard_stark.rs` | Standard FRI STARK receipt verification (BabyBear) |
| `src/standard_fri.rs` | Standard FRI proof encoding and verification |
| `src/stark_winterfell.rs` | Winterfell `do_work` AIR, receipt helpers |
| `src/circle_stark.rs` | Circle STARK receipt verification (M31, BabyBear, KoalaBear) |
| `src/circle_fri.rs` | Circle FRI proof encoding and verification |
| `src/circle_merkle.rs` | Circle STARK Merkle hashing utilities |
| `src/baby_bear_field.rs` | Baby Bear field arithmetic |
| `src/koala_bear_field.rs` | Koala Bear field arithmetic |
| `src/stwo_verifier.rs` | Stwo receipt verifier (Blake2s Merkle PCS) |
| `src/stwo_types.rs` | Stwo-compatible field types and decode helpers |
| `src/ivc_adapter.rs` | IVC adapter, BaseFold PCS binding |
| `src/ipa_adapter.rs` | IPA adapter with statement-bound transcript |
| `src/binius_adapter.rs` | Binius adapter (constraint-system receipts) |
| `src/sp1_adapter.rs` | SP1 adapter (Groth16/Plonk BN254) |
| `src/plonk_adapter.rs` | PLONK adapter (v1 legacy and v2 generic receipts) |
| `src/halo2_receipt.rs` | Halo2 KZG receipt verification (standard and parametric circuits) |
| `src/plonky2_receipt.rs` | Plonky2 Goldilocks receipt decoder |
| `src/cairo_stark.rs` | Cairo/Stone/SHARP verification via Swiftness |
| `src/miden_stark.rs` | Miden receipt verification (Goldilocks) |
| `src/adapter_ir.rs` | Canonical adapter IR encoding (version=1) for Groth16, KZG, IVC, and Hash |
| `src/glyph_ir.rs` | UCIR encoding and custom gate formats |
| `src/glyph_witness.rs` | UCIR witness engine and gate evaluation |
| `src/glyph_ir_compiler.rs` | Adapter-to-UCIR compilers (IVC, STARK, IPA, SP1, PLONK, Binius custom gates) |
| `src/glyph_core.rs` | GLYPH prover pipeline and artifact derivation |
| `src/glyph_core/types.rs` | GLYPH prover types, configs, and error definitions |
| `src/glyph_core/sumcheck.rs` | Sumcheck helpers and paging utilities |
| `src/state_transition_vm.rs` | GLYPH state transition VM (deterministic execution + circuit compile) |
| `src/glyph_pcs_basefold.rs` | BaseFold PCS integration (binary tower) |
| `src/pcs_common.rs` | Shared PCS domains and tag helpers |
| `src/pcs_basefold.rs` | BaseFold PCS wrapper using binius ring-switch and FRI |
| `src/pcs_ring_switch.rs` | Ring-switch proof wrapper for BaseFold PCS |
| `src/pcs_binary_field.rs` | Goldilocks to BinaryField128b encoding helpers |
| `src/pcs_encoding.rs` | BinaryField128b vector encoding helpers |
| `src/glyph_field_simd.rs` | Goldilocks field ops, SIMD and CUDA kernels |
| `src/bn254_field.rs` | BN254 Fq parsing and arithmetic |
| `src/bn254_curve.rs` | BN254 G1/G2 parsing and serialization |
| `src/bn254_ops.rs` | BN254 op event types for pairing trace |
| `src/e2e_proofs.rs` | Solidity vector generation for GLYPH artifact tests |

### Bundle Decoders

| File | Role |
|------|------|
| `src/circle_stark_bundle.rs` | Circle STARK bundle decoder |
| `src/risc_zero_bundle.rs` | RISC Zero bundle decoder (BabyBear standard) |
| `src/stwo_bundle.rs` | Stwo receipt bundle decoder |

### CLI Tools

| File | Role |
|------|------|
| `src/bin/glyph_prover.rs` | GLYPH-PROVER CLI (compiles adapter inputs, emits proof artifacts) |
| `src/bin/glyph_adapt_batch.rs` | Batch adapter CLI for Groth16/KZG IR batch execution |
| `src/bin/glyph_da.rs` | DA CLI for envelope, submit, fetch, and verify |
| `src/bin/glyph_state_diff.rs` | State diff canonicalization and hashing CLI |
| `src/bin/glyph_state_diff_prove.rs` | State diff proof generator and artifact output |
| `src/bin/glyph_state_transition_prove.rs` | State transition VM proof generator |
| `src/bin/glyph_import_circle_receipt.rs` | Imports Circle STARK receipts |
| `src/bin/glyph_import_risc_zero_receipt.rs` | Imports RISC Zero bundle JSON |
| `src/bin/glyph_import_stwo_receipt.rs` | Imports Stwo receipts |
| `src/bin/glyph_import_sp1_receipt.rs` | Imports SP1 Groth16/Plonk receipts |
| `src/bin/glyph_import_cairo_receipt.rs` | Imports Cairo proof JSON receipts |
| `src/bin/glyph_import_miden_receipt.rs` | Imports Miden receipts |
| `src/bin/glyph_import_plonk_receipt.rs` | Imports PLONK receipts (backend + curve tagged) |
| `src/bin/glyph_import_halo2_receipt.rs` | Imports Halo2 KZG receipts (standard or parametric circuits) |

### Fixtures

| File | Role |
|------|------|
| `scripts/tools/fixtures/fast_sha3_receipt.txt` | Deterministic SHA3 receipt fixture |
| `scripts/tools/fixtures/fast_sha3_receipt_f64.txt` | Deterministic SHA3 F64 receipt fixture |
| `scripts/tools/fixtures/fast_circle_stark_receipt.txt` | Circle STARK M31 receipt fixture (UTF-16 LE) |
| `scripts/tools/fixtures/fast_circle_stark_receipt.txt.candidate` | Candidate Circle STARK M31 receipt fixture |
| `scripts/tools/fixtures/fast_circle_stark_receipt_large.txt` | Circle STARK large receipt fixture |
| `scripts/tools/fixtures/fast_circle_stark_receipt_large.txt.candidate` | Candidate Circle STARK large receipt fixture |
| `scripts/tools/fixtures/fast_circle_stark_baby_bear_receipt.txt` | Circle STARK BabyBear receipt fixture |
| `scripts/tools/fixtures/fast_circle_stark_baby_bear_receipt.txt.candidate` | Candidate Circle STARK BabyBear receipt fixture |
| `scripts/tools/fixtures/fast_circle_stark_koala_bear_receipt.txt` | Circle STARK KoalaBear receipt fixture |
| `scripts/tools/fixtures/fast_circle_stark_koala_bear_receipt.txt.candidate` | Candidate Circle STARK KoalaBear receipt fixture |
| `scripts/tools/fixtures/fast_plonky2_goldilocks_receipt.txt` | Plonky2 Goldilocks receipt fixture |
| `scripts/tools/fixtures/fast_plonky2_goldilocks_receipt.txt.candidate` | Candidate Plonky2 Goldilocks receipt fixture |
| `scripts/tools/fixtures/groth16_bn254_fixture.txt` | Groth16 BN254 fixture (vk, proof, pub inputs) |
| `scripts/tools/fixtures/groth16_bls12381_receipt.txt` | Groth16 BLS12-381 receipt fixture |
| `scripts/tools/fixtures/groth16_bls12381_receipt.txt.candidate` | Candidate Groth16 BLS12-381 receipt fixture |
| `scripts/tools/fixtures/kzg_bls12381_receipt.txt` | KZG BLS12-381 receipt fixture |
| `scripts/tools/fixtures/kzg_bls12381_receipt.txt.candidate` | Candidate KZG BLS12-381 receipt fixture |
| `scripts/tools/fixtures/plonk_bn254_gnark_receipt.txt` | PLONK BN254 GNARK receipt fixture |
| `scripts/tools/fixtures/plonk_bls12381_receipt.txt` | PLONK BLS12-381 receipt fixture |
| `scripts/tools/fixtures/plonk_bls12381_receipt.txt.candidate` | Candidate PLONK BLS12-381 receipt fixture |
| `scripts/tools/fixtures/halo2_bn254_kzg_receipt.txt` | Halo2 KZG BN254 receipt fixture |
| `scripts/tools/fixtures/halo2_bn254_kzg_receipt.txt.candidate` | Candidate Halo2 KZG BN254 receipt fixture |
| `scripts/tools/fixtures/halo2_bls12381_kzg_receipt.txt` | Halo2 KZG BLS12-381 receipt fixture |
| `scripts/tools/fixtures/halo2_bls12381_kzg_receipt.txt.candidate` | Candidate Halo2 KZG BLS12-381 receipt fixture |
| `scripts/tools/fixtures/miden_rpo_receipt.txt` | Miden RPO receipt fixture |
| `scripts/tools/fixtures/miden_blake3_receipt.txt` | Miden Blake3 receipt fixture |
| `scripts/tools/fixtures/ivc_nova_external_proof.txt` | Nova external proof fixture |
| `scripts/tools/fixtures/ivc_supernova_external_proof.txt` | SuperNova external proof fixture |
| `scripts/tools/fixtures/ivc_hypernova_external_proof.txt` | HyperNova external proof fixture |
| `scripts/tools/fixtures/ivc_sangria_external_proof.txt` | Sangria external proof fixture |
| `scripts/tools/fixtures/risc_zero_bundle.json` | RISC Zero bundle fixture |
| `scripts/tools/fixtures/risc_zero_external_receipt.json` | RISC Zero external receipt fixture |
| `scripts/tools/fixtures/stwo_external.json` | Stwo external bundle fixture |
| `scripts/tools/fixtures/stwo_external.receipt.txt` | Stwo external receipt fixture |
| `scripts/tools/fixtures/stwo_test_bundle.json` | Stwo test bundle fixture |
| `scripts/tools/fixtures/sp1_groth16_receipt.txt` | SP1 Groth16 BN254 receipt fixture |
| `scripts/tools/fixtures/sp1_plonk_receipt.txt` | SP1 Plonk BN254 receipt fixture |
| `scripts/tools/fixtures/plonky3_babybear_poseidon2_tribonacci_receipt.txt` | Plonky3 BabyBear Poseidon2 tribonacci receipt |
| `scripts/tools/fixtures/plonky3_babybear_poseidon2_tribonacci_receipt.txt.candidate` | Candidate Plonky3 BabyBear Poseidon2 tribonacci receipt |
| `scripts/tools/fixtures/plonky3_koalabear_poseidon2_tribonacci_receipt.txt` | Plonky3 KoalaBear Poseidon2 tribonacci receipt |
| `scripts/tools/fixtures/plonky3_koalabear_poseidon2_tribonacci_receipt.txt.candidate` | Candidate Plonky3 KoalaBear Poseidon2 tribonacci receipt |
| `scripts/tools/fixtures/plonky3_goldilocks_poseidon2_tribonacci_receipt.txt` | Plonky3 Goldilocks Poseidon2 tribonacci receipt |
| `scripts/tools/fixtures/plonky3_babybear_poseidon2_receipt.txt.candidate` | Candidate Plonky3 BabyBear Poseidon2 receipt |
| `scripts/tools/fixtures/plonky3_babybear_poseidon_receipt.txt.candidate` | Candidate Plonky3 BabyBear Poseidon receipt |
| `scripts/tools/fixtures/plonky3_babybear_rescue_receipt.txt.candidate` | Candidate Plonky3 BabyBear Rescue receipt |
| `scripts/tools/fixtures/plonky3_babybear_blake3_receipt.txt.candidate` | Candidate Plonky3 BabyBear Blake3 receipt |
| `scripts/tools/fixtures/plonky3_koalabear_poseidon2_receipt.txt.candidate` | Candidate Plonky3 KoalaBear Poseidon2 receipt |
| `scripts/tools/fixtures/plonky3_koalabear_poseidon_receipt.txt.candidate` | Candidate Plonky3 KoalaBear Poseidon receipt |
| `scripts/tools/fixtures/plonky3_koalabear_rescue_receipt.txt.candidate` | Candidate Plonky3 KoalaBear Rescue receipt |
| `scripts/tools/fixtures/plonky3_koalabear_blake3_receipt.txt.candidate` | Candidate Plonky3 KoalaBear Blake3 receipt |
| `scripts/tools/fixtures/plonky3_goldilocks_poseidon2_receipt.txt.candidate` | Candidate Plonky3 Goldilocks Poseidon2 receipt |
| `scripts/tools/fixtures/plonky3_goldilocks_poseidon_receipt.txt.candidate` | Candidate Plonky3 Goldilocks Poseidon receipt |
| `scripts/tools/fixtures/plonky3_goldilocks_rescue_receipt.txt.candidate` | Candidate Plonky3 Goldilocks Rescue receipt |
| `scripts/tools/fixtures/plonky3_goldilocks_blake3_receipt.txt.candidate` | Candidate Plonky3 Goldilocks Blake3 receipt |
| `scripts/tools/fixtures/cairo_stone6_keccak_160_lsb_example_proof.json` | Cairo proof example with keccak masked commitment hash |

### Benchmark Harnesses

| Script | Role |
|--------|------|
| `scripts/benchmarks/common.sh` | Shared benchmark helpers and standardized output |
| `scripts/benchmarks/run_all.sh` | One-shot benchmark runner by preset |
| `scripts/benchmarks/registry.json` | Canonical benchmark registry |
| `scripts/benchmarks/profile_perf_config.sh` | Offline perf profile runner and config snapshot |
| `scripts/benchmarks/send_raw_tx.sh` | Raw calldata tx send helper (cast) |
| `scripts/benchmarks/bench_glyph_evm_local.sh` | Local Anvil gas bench for GLYPHVerifier |
| `scripts/benchmarks/bench_glyph_evm_round_sweep.sh` | Local Anvil gas bench round sweep |
| `scripts/benchmarks/bench_glyph_evm_realproof.sh` | Local Anvil gas bench using real prover path |
| `scripts/benchmarks/bench_glyph_evm_artifact.sh` | Local Anvil gas bench for artifact-poly layout |
| `scripts/benchmarks/bench_glyph_evm_sepolia.sh` | Sepolia gas estimate bench with optional tx send |
| `scripts/benchmarks/bench_glyph_sepolia_stmt.sh` | Sepolia artifact-bound gas bench (historical `stmt` name) |
| `scripts/benchmarks/bench_glyph_sepolia_artifact.sh` | Sepolia artifact-poly gas bench |
| `scripts/benchmarks/bench_glyph_hoodi_artifact_truncated.sh` | Hoodi artifact-poly truncated gas bench |
| `scripts/benchmarks/bench_glyph_adapter_hoodi.sh` | Hoodi adapter gas bench using Foundry vectors re-bound to the live verifier |
| `scripts/benchmarks/bench_glyph_adapter_kpi.sh` | Adapter KPI (Groth16, KZG, IVC, STARK, Hash) |
| `scripts/benchmarks/bench_glyph_adapter_zk_kpi.sh` | Adapter KPI in ZK mode |
| `scripts/benchmarks/bench_glyph_zk_kpi.sh` | Proof size KPI, fast mode vs ZK mode |
| `scripts/benchmarks/bench_glyph_cuda_kpi.sh` | CUDA KPI (preset `cuda`; requires `GLYPH_ENABLE_CUDA_BENCH=1`) |
| `scripts/benchmarks/bench_bn254_batch_kpi.sh` | BN254 batch KPI harness |
| `scripts/benchmarks/bench_bn254_g2_kpi.sh` | BN254 G2 window sweep KPI harness |
| `scripts/benchmarks/bench_bn254_msm_kpi.sh` | BN254 MSM KPI harness |
| `scripts/benchmarks/bench_bn254_mul_kpi.sh` | BN254 field add, sub, mul KPI harness |
| `scripts/benchmarks/bench_bn254_trace_kpi.sh` | BN254 trace KPI harness |
| `scripts/benchmarks/bench_basefold_arity_sweep.sh` | BaseFold arity sweep |
| `scripts/benchmarks/bench_basefold_mem_sweetspot.sh` | BaseFold memory sweet spot sweep |
| `scripts/benchmarks/bench_basefold_trace_profile.sh` | BaseFold trace profile |
| `scripts/benchmarks/bench_ivc_fold_kpi.sh` | IVC fold KPI harness |
| `scripts/benchmarks/bench_ivc_parallel_profile.sh` | IVC fold parallel profile sweep |
| `scripts/benchmarks/bench_packed_gkr_layout_sweep.sh` | Packed GKR layout sweep |
| `scripts/benchmarks/bench_stark_do_work_kpis.sh` | STARK do_work KPI workload |
| `scripts/benchmarks/bench_state_diff_compile_prove.sh` | State diff compile and prove KPI harness |
| `scripts/benchmarks/bench_state_diff_merkle.sh` | State diff merkle KPI harness |
| `scripts/benchmarks/bench_state_diff_prover_profile.sh` | State diff merkle vs prover profile |
| `scripts/benchmarks/bench_state_transition_vm.sh` | State transition VM execution and compile KPI |
| `scripts/benchmarks/bench_groth16_sepolia.sh` | Groth16 gas estimate bench on Sepolia |
| `scripts/benchmarks/bench_groth16_hoodi.sh` | Groth16 gas estimate bench on Hoodi |
| `scripts/benchmarks/groth16_compare/build_groth16.sh` | Groth16 compare build pipeline (circom, snarkjs) |
| `scripts/benchmarks/groth16_compare/calc_calldata_stats.sh` | Groth16 calldata stats from artifacts |

### Groth16 Compare Inputs and Sources

| File | Role |
|------|------|
| `scripts/benchmarks/groth16_compare/package.json` | Node dependencies for circom and snarkjs |
| `scripts/benchmarks/groth16_compare/package-lock.json` | Locked dependency graph |
| `scripts/benchmarks/groth16_compare/circuit.circom` | Base circuit source |
| `scripts/benchmarks/groth16_compare/circuit_many.circom` | Many-input circuit source |
| `scripts/benchmarks/groth16_compare/input_many.json` | Many-input circuit example inputs |

### Build and CI

| Script | Role |
|--------|------|
| `scripts/build/glyph_build.sh` | Build preset wrapper with adapter feature selection |
| `scripts/build/ci_deterministic_run.sh` | Deterministic CI runner with cache validation and metadata logging |

### Deploy Tooling

| File | Role |
|------|------|
| `scripts/deploy/deploy_glyph_contract.sh` | Deploy GLYPHVerifier and emit deployment metadata |
| `scripts/deploy/verify_glyph_contract.sh` | Verify GLYPHVerifier on Etherscan |
| `scripts/deploy/.env.sepolia` | Network env (contains secrets, local-only) |
| `scripts/deploy/.env.hoodi` | Network env (contains secrets, local-only) |
| `scripts/deploy/.env.sepolia.example` | Example env template |
| `scripts/deploy/.env.hoodi.example` | Example env template |
| `scripts/deploy/.env.wallet.example` | Example wallet env template |
| `scripts/deploy/.env.network.example` | Example network env template |

### Repro Tooling

| Script | Role |
|--------|------|
| `scripts/repro/repro_pack.sh` | Deterministic repro runner with manifest output |

### Formal Tooling

| File | Role |
|------|------|
| `scripts/formal/sumcheck_invariants.sh` | Sumcheck invariants runner |
| `scripts/formal/sumcheck_invariants/Cargo.toml` | Sumcheck invariants crate manifest |
| `scripts/formal/sumcheck_invariants/src/main.rs` | Sumcheck invariants logic (Goldilocks) |

### Examples

| File | Role |
|------|------|

### Tools - Converters

| File | Role |
|------|------|
| `scripts/tools/converters/stwo_to_bundle.rs` | Stwo proof and program to bundle converter |
| `scripts/tools/generate_glyph_verifier_constants.py` | Generate GLYPHVerifier constants from `src/glyph_gkr.rs` |

### Tools - Fixture Generators

| File | Role |
|------|------|
| `scripts/tools/fixture_generators/gnark_bn254_plonk/run.sh` | GNARK BN254 PLONK fixture generator runner |
| `scripts/tools/fixture_generators/gnark_bn254_plonk/main.go` | GNARK BN254 PLONK fixture generator |
| `scripts/tools/fixture_generators/gnark_bn254_plonk/go.mod` | GNARK generator dependencies |
| `scripts/tools/fixture_generators/gnark_bn254_plonk/go.sum` | GNARK generator lockfile |
| `scripts/tools/fixture_generators/sp1/run.sh` | SP1 fixture generator runner |
| `scripts/tools/fixture_generators/sp1/src/main.rs` | SP1 fixture generator logic |
| `scripts/tools/fixture_generators/sp1/src/bin/build_gnark_circuits.rs` | SP1 gnark artifact build |
| `scripts/tools/fixture_generators/sp1/src/bin/build_guest.rs` | SP1 guest build helper |
| `scripts/tools/fixture_generators/sp1/guest/src/main.rs` | SP1 guest program |
| `scripts/tools/fixture_generators/sp1/Cargo.toml` | SP1 generator manifest |
| `scripts/tools/fixture_generators/sp1/Cargo.lock` | SP1 generator lockfile |
| `scripts/tools/fixture_generators/sp1/guest/Cargo.toml` | SP1 guest manifest |
| `scripts/tools/fixture_generators/sp1/guest/Cargo.lock` | SP1 guest lockfile |

### Utilities

| Script | Role |
|--------|------|
| `scripts/utils/cuda/check_cuda_toolkit.sh` | CUDA toolkit detection and warnings |
| `scripts/utils/dump_perf_config.sh` | Perf config snapshot to JSON |
| `scripts/utils/ensure_groth16_compare_deps.sh` | Groth16 compare deps installer (bun or npm) |
| `scripts/utils/perf_summary.sh` | Perf summary formatter |
| `scripts/utils/ensure_state_diff_fixture.sh` | Deterministic 1 MiB state diff fixture generator |

### Fuzz Tooling

| Script | Role |
|--------|------|
| `scripts/tests/fuzz/run_all.sh` | Fuzz runner with short and deep presets |
| `scripts/tests/fuzz/run_cmin.sh` | Corpus minimization wrapper (`cmin`) |
| `scripts/tests/fuzz/run_tmin.sh` | Testcase minimization wrapper (`tmin`) |
| `scripts/tests/fuzz/dicts/adapter_ir.dict` | Adapter dictionary seeds |
| `scripts/tests/fuzz/dicts/stark.dict` | STARK dictionary seeds |

### Fuzz Targets (cargo-fuzz workspace)

| File | Role |
|------|------|
| `scripts/tests/fuzz/workspace/Cargo.toml` | Fuzz workspace manifest and target registration |
| `scripts/tests/fuzz/workspace/Cargo.lock` | Fuzz workspace lockfile |
| `scripts/tests/fuzz/workspace/fuzz_targets/decode_adapter_bytes.rs` | Adapter byte decoder fuzz |
| `scripts/tests/fuzz/workspace/fuzz_targets/decode_adapter_ir_deep.rs` | Adapter IR deep decode fuzz |
| `scripts/tests/fuzz/workspace/fuzz_targets/decode_circle_stark_program.rs` | Circle STARK program decode fuzz |
| `scripts/tests/fuzz/workspace/fuzz_targets/decode_circle_stark_proof.rs` | Circle STARK proof decode fuzz |
| `scripts/tests/fuzz/workspace/fuzz_targets/decode_ipa_receipt.rs` | IPA receipt decode fuzz |
| `scripts/tests/fuzz/workspace/fuzz_targets/decode_plonky2_receipt.rs` | Plonky2 receipt decode fuzz |
| `scripts/tests/fuzz/workspace/fuzz_targets/decode_r1cs_receipt.rs` | R1CS receipt decode fuzz |
| `scripts/tests/fuzz/workspace/fuzz_targets/decode_supernova_external_proof.rs` | SuperNova external proof decode fuzz |
| `scripts/tests/fuzz/workspace/fuzz_targets/decode_stwo_profile.rs` | Stwo profile decode fuzz |
| `scripts/tests/fuzz/workspace/fuzz_targets/decode_stwo_program.rs` | Stwo program decode fuzz |
| `scripts/tests/fuzz/workspace/fuzz_targets/decode_standard_stark_program.rs` | Standard STARK program decode fuzz |
| `scripts/tests/fuzz/workspace/fuzz_targets/decode_standard_stark_proof.rs` | Standard STARK proof decode fuzz |
| `scripts/tests/fuzz/workspace/fuzz_targets/decode_stark_ir.rs` | STARK IR decode fuzz |
| `scripts/tests/fuzz/workspace/fuzz_targets/decode_stark_receipt.rs` | STARK receipt decode fuzz |
| `scripts/tests/fuzz/workspace/fuzz_targets/decode_stark_vk.rs` | STARK VK decode fuzz |
| `scripts/tests/fuzz/workspace/fuzz_targets/decode_winterfell_program.rs` | Winterfell program decode fuzz |
| `scripts/tests/fuzz/workspace/fuzz_targets/bn254_op_traces.rs` | BN254 op trace validation fuzz |
| `scripts/tests/fuzz/workspace/fuzz_targets/diff_adapter_ir_roundtrip.rs` | Adapter IR roundtrip invariant fuzz |
| `scripts/tests/fuzz/workspace/fuzz_targets/synthesize_stwo_proof.rs` | Stwo prover synthesis fuzz |
| `scripts/tests/fuzz/workspace/fuzz_targets/transcript_challenges.rs` | Transcript challenge fuzz |
| `scripts/tests/fuzz/workspace/fuzz_targets/validate_state_transition_batch.rs` | State transition batch validate/compile fuzz |
| `scripts/tests/fuzz/workspace/fuzz_targets/verify_adapter_proof.rs` | Adapter proof decode fuzz |
| `scripts/tests/fuzz/workspace/fuzz_targets/verify_packed_calldata.rs` | Packed calldata verifier fuzz |
| `scripts/tests/fuzz/workspace/corpus/**` | Generated fuzz corpora (data-only) |

### DA Tooling

| Script | Role |
|--------|------|
| `scripts/da/submit_blob.sh` | Blob submit via `cast send --blob` |
| `scripts/da/fetch_blob.sh` | Blob fetch via URL template or Beacon API |
| `scripts/da/submit_arweave.sh` | Arweave submit via Turbo or external command |
| `scripts/da/fetch_arweave.sh` | Arweave fetch via gateway |
| `scripts/da/submit_eigenda.sh` | EigenDA submit via proxy or Go client |
| `scripts/da/poll_eigenda.sh` | EigenDA poll to finalize pending requests |
| `scripts/da/fetch_eigenda.sh` | EigenDA fetch via retriever or proxy |
| `scripts/da/fetch_eigenda_v2_srs.sh` | Download EigenDA v2 SRS files and verify checksums |
| `scripts/da/run_profile.sh` | Single-entry DA runner with presets and env checks |
| `scripts/da/run_all_profiles.sh` | Run all DA profiles end to end |
| `scripts/da/smoke_test.sh` | Single profile smoke test runner |
| `scripts/da/arweave_local_smoke.sh` | Local Arweave smoke test using arlocal |
| `scripts/da/state_diff_from_snapshots.sh` | Build state diff JSON and bytes from snapshots |
| `scripts/da/state_diff_proof_flow.sh` | State diff to proof bundle pipeline |
| `scripts/da/state_diff_onchain_verify.sh` | Submit root update with proof calldata |
| `scripts/da/state_transition_vm_flow.sh` | State transition VM flow and proof bundle |

### DA Provider Helpers

| File | Role |
|------|------|
| `scripts/da/providers/check_providers.sh` | Provider toolchain smoke checks |
| `scripts/da/providers/package.json` | Provider-side Node dependencies |
| `scripts/da/providers/package-lock.json` | Provider-side Node lockfile |
| `scripts/da/providers/arweave_turbo_upload.mjs` | Arweave Turbo upload helper |
| `scripts/da/providers/eigenda_v1/main.go` | EigenDA v1 Go client |
| `scripts/da/providers/eigenda_v1/go.mod` | EigenDA v1 Go module manifest |
| `scripts/da/providers/eigenda_v1/go.sum` | EigenDA v1 Go module lockfile |
| `scripts/da/providers/eigenda_v2/main.go` | EigenDA v2 Go client |
| `scripts/da/providers/eigenda_v2/go.mod` | EigenDA v2 Go module manifest |
| `scripts/da/providers/eigenda_v2/go.sum` | EigenDA v2 Go module lockfile |

### Test Harness Scripts

| Script | Role |
|--------|------|
| `scripts/tests/run_tests.sh` | Orchestrated Rust, Foundry, and fuzz test runner |
| `scripts/tests/run_feature_matrix.sh` | Deterministic build preset matrix runner with optional default tests |
| `scripts/tests/verifier_symbolic.sh` | Symbolic verifier harness via Foundry |

Notes:
- EVM gas benches now validate proofs via `eth_call`, enforce receipt status checks, and emit JSON plus `.meta.json` outputs for publication.

### Tests

| File | Role |
|------|------|
| `scripts/tests/rust/da_envelope_tests.rs` | DA payload encoding and envelope hash stability |
| `scripts/tests/rust/da_integration_tests.rs` | Live DA submit and fetch verification (env-gated) |
| `scripts/tests/rust/bn254_emulation_property_tests.rs` | BN254 limb emulation property tests |
| `scripts/tests/rust/ivc_supernova_tests.rs` | SuperNova external proof roundtrip and verify (feature-gated) |
| `scripts/tests/rust/stwo_prover_tests.rs` | Stwo prover synthetic receipt E2E (feature-gated) |

### Solidity Contracts

| File | Role |
|------|------|
| `contracts/GLYPHVerifier.sol` | **Single active on-chain verifier** (GLYPH-VERIFIER) |
| `contracts/GLYPHVerifierConstants.sol` | Verifier constants generated from `src/glyph_gkr.rs` |

### Foundry Test Vectors

| File | Role |
|------|------|
| `scripts/tests/foundry/foundry.toml` | Foundry config for GLYPH test suite |
| `scripts/tests/foundry/GLYPHVerifierTest.t.sol` | Packed calldata tests |
| `scripts/tests/foundry/GLYPHVerifier.sol` | Test-time verifier wrapper |
| `scripts/tests/foundry/GLYPHVerifierConstants.sol` | Verifier constants mirror for Foundry tests |
| `scripts/tests/foundry/GLYPHRootUpdaterMinimal.sol` | Minimal root updater contract |
| `scripts/tests/foundry/GLYPHRootUpdaterMinimal.t.sol` | Root updater minimal tests |
| `scripts/tests/foundry/GLYPHRootUpdaterExtended.sol` | Extended root updater contract |
| `scripts/tests/foundry/GLYPHRootUpdaterExtended.t.sol` | Root updater extended tests |
| `scripts/tests/foundry/GLYPH_SNARK_GROTH16_Test.t.sol` | Groth16 vectors |
| `scripts/tests/foundry/GLYPH_SNARK_KZG_Test.t.sol` | KZG vectors |
| `scripts/tests/foundry/GLYPH_IVC_Test.t.sol` | IVC vectors |
| `scripts/tests/foundry/GLYPH_SNARK_IPA_Test.t.sol` | IPA vectors |
| `scripts/tests/foundry/GLYPH_STARK_Test.t.sol` | STARK vectors |
| `scripts/tests/foundry/GLYPH_HASH_Test.t.sol` | Hash vectors |
| `scripts/tests/foundry/GLYPH_SNARK_SP1_Test.t.sol` | SP1 vectors |
| `scripts/tests/foundry/GLYPH_SNARK_PLONK_Test.t.sol` | PLONK vectors |
| `scripts/tests/foundry/Groth16Verifier.sol` | Groth16 verifier contract under test |
| `scripts/tests/foundry/Groth16VerifierMany.sol` | Groth16 verifier contract for batch-sized vectors |
| `scripts/tests/foundry/GeneratedRealProofTest.t.sol` | Real proof execution harness |

### Documentation

| File | Role |
|------|------|
| `docs/documentation.md` | Canonical technical documentation (SSOT) |
| `docs/QUICKSTART.md` | Quickstart and deployment guide |
| `docs/whitepaper/glyph_paper.tex` | GLYPH whitepaper source |
| `docs/whitepaper/glyph_proof_appendix.tex` | Whitepaper proof appendix |
| `docs/map.md` | Repository structure, wiring overview, and tooling index |
| `docs/specs/verifier_spec.md` | Byte-accurate calldata and verifier spec |
| `docs/specs/ucir_spec.md` | UCIR encoding and invariants |
| `docs/specs/state_transition_vm_spec.md` | State transition VM specification |
| `docs/specs/adapter_ir_spec.md` | Adapter IR byte encoding, kernel IDs, fail-closed decoding |
| `docs/specs/artifact_tag_spec.md` | Artifact tag derivation and chain binding rules |
| `docs/specs/stark_receipt_spec.md` | Canonical STARK receipt and VK encoding rules |
| `docs/specs/custom_gates_spec.md` | Custom gate IDs, gating semantics, and payload encoding |
