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

### Windows (native)
- Native Windows builds require MSVC (Visual Studio Build Tools, C++ workload + Windows SDK).
- Ensure `cl.exe` is on PATH (Developer Command Prompt or VS Build Tools environment).
- If MSYS2 or MinGW is on PATH (for example `C:\msys64\mingw64\bin\gcc.exe`), set `CC=cl.exe` or remove MSYS2 from PATH to avoid gcc being picked for `x86_64-pc-windows-msvc`.
- Recommended: use WSL2 for scripts, Foundry, and SP1.

### WSL2 path tip
For large builds, clone into the Linux filesystem (for example `~/glyph-zk`) instead of `/mnt/c/...` for better performance and fewer toolchain timeouts.

### ZIP download note (Windows)
If you downloaded a ZIP instead of cloning with git, the execute bits for `scripts/**/*.sh` may be missing. In WSL run:
```bash
chmod +x scripts/**/*.sh
```

---

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
