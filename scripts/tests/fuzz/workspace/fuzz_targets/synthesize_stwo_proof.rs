#![no_main]

use libfuzzer_sys::fuzz_target;

#[cfg(feature = "stwo-prover")]
use glyph::stwo_verifier::{
    synthesize_stwo_proof_bytes, StwoConstraint, StwoExpr, StwoProfile, StwoProgram, STWO_TOOLCHAIN_ID,
};

#[cfg(feature = "stwo-prover")]
fn run(data: &[u8]) {
    let log_domain_size = data.get(0).cloned().unwrap_or(1) % 3 + 1;
    let num_queries = data.get(1).cloned().unwrap_or(1) % 2 + 1;
    let blowup_factor = data.get(2).cloned().unwrap_or(1) % 2 + 1;
    let profile = StwoProfile {
        log_domain_size,
        num_queries,
        blowup_factor,
        log_last_layer_degree_bound: 1,
        pow_bits: 0,
    };
    let program = StwoProgram {
        toolchain_id: STWO_TOOLCHAIN_ID,
        trace_width: 1,
        log_trace_length: log_domain_size as u32,
        constraints: vec![StwoConstraint {
            expr: StwoExpr::Add(
                Box::new(StwoExpr::Col { col: 0, offset: 0 }),
                Box::new(StwoExpr::Neg(Box::new(StwoExpr::Col { col: 0, offset: 0 }))),
            ),
        }],
    };
    let _ = synthesize_stwo_proof_bytes(&program, &profile, &[]);
}

#[cfg(not(feature = "stwo-prover"))]
fn run(_data: &[u8]) {}

fuzz_target!(|data: &[u8]| {
    run(data);
});
