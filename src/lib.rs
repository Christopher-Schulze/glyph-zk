#![recursion_limit = "256"]


pub mod ipa_bn254;
#[cfg(feature = "snark")]
pub mod ipa_bls12381;
#[cfg(feature = "snark")]
pub mod ipa_adapter;
pub mod adapter_error;
pub mod adapter_registry;
pub mod adapter_gate;
pub mod adapter_facade;
pub mod cli_registry;
pub mod perf_config;
pub mod sdk;
pub mod adapters;
pub mod adapter_ir;
#[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
pub mod stark_winterfell;
#[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
pub mod stark_winterfell_f64;
#[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
pub mod f128_field;
#[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
pub mod f64_field;
#[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
pub mod m31_field;
#[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
pub mod baby_bear_field;
#[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
pub mod koala_bear_field;
#[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
pub mod plonky2_receipt;
#[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
pub mod plonky3_stark;
#[cfg(feature = "snark")]
pub mod plonk_adapter;
#[cfg(feature = "snark")]
pub mod halo2_receipt;
#[cfg(feature = "snark")]
pub mod plonk_halo2_adapter;
#[cfg(feature = "binius")]
pub mod binius_adapter;
#[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
pub mod circle_merkle;
#[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
pub mod stark_hash;
#[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
pub mod stark_transcript;
#[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
pub mod circle_fri;
#[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
pub mod circle_stark;
#[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
pub mod cairo_stark;
#[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
pub mod miden_stark;
#[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
pub mod standard_fri;
#[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
pub mod standard_stark;
#[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
pub mod circle_stark_bundle;
#[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
pub mod risc_zero_bundle;
#[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
pub mod stwo_types;
#[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
pub mod stwo_verifier;
#[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
pub mod stwo_bundle;
pub mod bn254_field;
pub mod bn254_curve;
pub mod bn254_pairing;
pub mod bn254_groth16;
pub mod groth16_bls12381;
pub mod kzg_bls12381;
pub mod bn254_ops;
pub mod bn254_pairing_trace;
#[cfg(feature = "snark")]
pub mod snark_groth16_bn254_adapter;
#[cfg(feature = "snark")]
pub mod snark_kzg_bn254_adapter;
#[cfg(feature = "ivc")]
pub mod ivc_adapter;
#[cfg(feature = "ivc")]
pub mod ivc_compressed;
#[cfg(feature = "ivc")]
pub mod ivc_hypernova;
#[cfg(feature = "ivc")]
pub mod ivc_nova;
#[cfg(feature = "ivc")]
#[cfg(feature = "ivc-supernova")]
pub mod ivc_supernova;
#[cfg(feature = "ivc")]
pub mod ivc_sangria;
#[cfg(feature = "ivc")]
pub mod ivc_r1cs;
#[cfg(feature = "snark")]
pub mod sp1_adapter;
#[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
pub mod stark_receipt;
#[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
pub mod stark_ir;
#[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
pub mod stark_program;
#[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
pub mod stark_adapter;
pub mod glyph_proof;
pub mod glyph_prover;
pub mod glyph_verifier;
// solidity_export archived - see archive/solidity_export.rs
pub mod public_inputs;
pub mod parallel_prover;
pub mod glv;
pub mod precomputed;
pub mod glyph_field_simd;
pub mod arena;
pub mod simd_prover;
pub mod glyph_gkr;
pub mod glyph_transcript;
pub mod glyph_ir;
pub mod glyph_ir_compiler;
pub mod state_diff_merkle;
pub mod state_transition_vm;
pub mod pcs_common;
pub mod glyph_pcs_basefold;
pub mod pcs_binary_field;
pub mod pcs_encoding;
pub mod pcs_basefold;
pub mod pcs_ring_switch;
pub mod glyph_logup;
pub mod glyph_witness;
pub mod glyph_core;
pub mod glyph_pairing;
pub mod glyph_bn254_field;
pub mod glyph_basefold;
pub mod l2_statement;
pub mod da;

#[cfg(all(
    test,
    feature = "snark",
    feature = "ivc",
    feature = "hash",
    feature = "stark-babybear",
    feature = "stark-goldilocks",
    feature = "stark-m31",
    feature = "binius"
))]
pub mod e2e_proofs;       // Real end-to-end proof tests

#[cfg(test)]
pub mod test_utils {
    use std::sync::{Mutex, OnceLock};
    use std::time::Duration;

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[allow(dead_code)]
    pub struct EnvLockGuard(std::sync::MutexGuard<'static, ()>);

    pub fn lock_env() -> EnvLockGuard {
        let guard = env_lock()
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        EnvLockGuard(guard)
    }

    pub struct EnvVarGuard {
        key: &'static str,
        prev: Option<String>,
    }

    impl EnvVarGuard {
        pub fn set(key: &'static str, value: &str) -> Self {
            let prev = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, prev }
        }

        pub fn remove(key: &'static str) -> Self {
            let prev = std::env::var(key).ok();
            std::env::remove_var(key);
            Self { key, prev }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }

    pub fn run_with_timeout<F>(name: &str, timeout: Duration, test_fn: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let _ = name;
        let _ = timeout;
        test_fn();
    }
}
