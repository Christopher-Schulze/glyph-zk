use glyph::stark_winterfell::{
    build_do_work_trace, default_proof_options, DoWorkProverSha3, DoWorkPublicInputs,
    StarkUpstreamReceipt,
};
use winterfell::Prover;
use winterfell::math::fields::f128::BaseElement;

fn die(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1);
}

fn main() {
    let trace_length = 16usize;
    let start = 3u128;

    let options = default_proof_options();

    let start_elem = BaseElement::new(start);
    let trace = build_do_work_trace(start_elem, trace_length);
    let result = trace.get(0, trace_length - 1);

    let prover = DoWorkProverSha3::new(options.clone());
    let proof = match prover.prove(trace) {
        Ok(proof) => proof,
        Err(err) => die(&format!("winterfell prove failed: {err}")),
    };
    let pub_inputs = DoWorkPublicInputs { start: start_elem, result };

    let receipt = StarkUpstreamReceipt::from_do_work_sha3_canonical(&proof, &pub_inputs, trace_length);

    println!("trace_length={trace_length}");
    println!("proof_hex={}", hex::encode(&receipt.proof_bytes));
    println!("pub_inputs_hex={}", hex::encode(&receipt.pub_inputs_bytes));
    println!("vk_params_hex={}", hex::encode(&receipt.vk_params_bytes));
}
