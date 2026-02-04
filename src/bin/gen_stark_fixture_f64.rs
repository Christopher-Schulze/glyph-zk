use glyph::stark_winterfell::StarkUpstreamReceipt;
use glyph::stark_winterfell_f64::{
    build_do_work_trace, default_proof_options, DoWorkProverBlake3F64, DoWorkProverSha3F64,
    DoWorkPublicInputsF64, public_inputs_bytes, vk_params_bytes_canonical,
    vk_params_bytes_sha3_canonical,
};
use winterfell::Prover;
use winterfell::math::fields::f64::BaseElement;

fn die(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let use_blake3 = args.iter().any(|a| a == "--blake3");

    let trace_length = 8usize;
    let start = 3u64;

    let options = default_proof_options();

    let start_elem = BaseElement::new(start);
    let trace = build_do_work_trace(start_elem, trace_length);
    let result = trace.get(0, trace_length - 1);

    let proof = if use_blake3 {
        let prover = DoWorkProverBlake3F64::new(options.clone());
        match prover.prove(trace) {
            Ok(proof) => proof,
            Err(err) => die(&format!("winterfell prove failed: {err}")),
        }
    } else {
        let prover = DoWorkProverSha3F64::new(options.clone());
        match prover.prove(trace) {
            Ok(proof) => proof,
            Err(err) => die(&format!("winterfell prove failed: {err}")),
        }
    };
    let pub_inputs = DoWorkPublicInputsF64 { start: start_elem, result };

    let trace_width = 1;
    let receipt = StarkUpstreamReceipt {
        proof_bytes: proof.to_bytes(),
        pub_inputs_bytes: public_inputs_bytes(&pub_inputs),
        vk_params_bytes: if use_blake3 {
            vk_params_bytes_canonical(trace_width, trace_length, proof.options())
        } else {
            vk_params_bytes_sha3_canonical(trace_width, trace_length, proof.options())
        },
    };

    println!("trace_length={trace_length}");
    println!("proof_hex={}", hex::encode(&receipt.proof_bytes));
    println!("pub_inputs_hex={}", hex::encode(&receipt.pub_inputs_bytes));
    println!("vk_params_hex={}", hex::encode(&receipt.vk_params_bytes));
}
