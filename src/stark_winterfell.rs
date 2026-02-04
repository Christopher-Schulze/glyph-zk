#![allow(clippy::items_after_test_module)]

use winterfell::{
    crypto::{
        hashers::{Blake3_256, Sha3_256},
        DefaultRandomCoin, Digest, MerkleTree, RandomCoin,
    },
    math::{fields::f128::BaseElement, FieldElement, StarkField, ToElements},
    matrix::ColMatrix,
    Air, AirContext, Assertion, AuxRandElements, BatchingMethod, CompositionPoly,
    CompositionPolyTrace, ConstraintCompositionCoefficients, DefaultConstraintCommitment,
    DefaultConstraintEvaluator, DefaultTraceLde, EvaluationFrame, FieldExtension,
    PartitionOptions, Proof, ProofOptions, Prover, StarkDomain, Trace, TraceInfo,
    TracePolyTable, TraceTable, TransitionConstraintDegree,
};
use rayon::prelude::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DoWorkPublicInputs {
    pub start: BaseElement,
    pub result: BaseElement,
}

impl ToElements<BaseElement> for DoWorkPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        vec![self.start, self.result]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FibonacciPublicInputs {
    pub start_a: BaseElement,
    pub start_b: BaseElement,
    pub result: BaseElement,
}

impl ToElements<BaseElement> for FibonacciPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        vec![self.start_a, self.start_b, self.result]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TribonacciPublicInputs {
    pub start_a: BaseElement,
    pub start_b: BaseElement,
    pub start_c: BaseElement,
    pub result: BaseElement,
}

impl ToElements<BaseElement> for TribonacciPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        vec![self.start_a, self.start_b, self.start_c, self.result]
    }
}

pub struct DoWorkAir {
    context: AirContext<BaseElement>,
    start: BaseElement,
    result: BaseElement,
}

impl Air for DoWorkAir {
    type BaseField = BaseElement;
    type PublicInputs = DoWorkPublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: DoWorkPublicInputs, options: ProofOptions) -> Self {
        assert_eq!(1, trace_info.width());

        let degrees = vec![TransitionConstraintDegree::new(3)];
        let num_assertions = 2;

        Self {
            context: AirContext::new(trace_info, degrees, num_assertions, options),
            start: pub_inputs.start,
            result: pub_inputs.result,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current_state = frame.current()[0];
        let next_state = current_state.exp(3u32.into()) + E::from(42u32);
        result[0] = frame.next()[0] - next_state;
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let last_step = self.trace_length() - 1;
        vec![
            Assertion::single(0, 0, self.start),
            Assertion::single(0, last_step, self.result),
        ]
    }
}

pub struct FibonacciAir {
    context: AirContext<BaseElement>,
    start_a: BaseElement,
    start_b: BaseElement,
    result: BaseElement,
}

impl Air for FibonacciAir {
    type BaseField = BaseElement;
    type PublicInputs = FibonacciPublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: FibonacciPublicInputs, options: ProofOptions) -> Self {
        assert_eq!(2, trace_info.width());

        let degrees = vec![
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
        ];
        let num_assertions = 3;

        Self {
            context: AirContext::new(trace_info, degrees, num_assertions, options),
            start_a: pub_inputs.start_a,
            start_b: pub_inputs.start_b,
            result: pub_inputs.result,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current_a = frame.current()[0];
        let current_b = frame.current()[1];
        let next_a = frame.next()[0];
        let next_b = frame.next()[1];
        result[0] = next_a - current_b;
        result[1] = next_b - (current_a + current_b);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let last_step = self.trace_length() - 1;
        vec![
            Assertion::single(0, 0, self.start_a),
            Assertion::single(1, 0, self.start_b),
            Assertion::single(1, last_step, self.result),
        ]
    }
}

pub struct TribonacciAir {
    context: AirContext<BaseElement>,
    start_a: BaseElement,
    start_b: BaseElement,
    start_c: BaseElement,
    result: BaseElement,
}

impl Air for TribonacciAir {
    type BaseField = BaseElement;
    type PublicInputs = TribonacciPublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: TribonacciPublicInputs, options: ProofOptions) -> Self {
        assert_eq!(3, trace_info.width());

        let degrees = vec![
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
        ];
        let num_assertions = 4;

        Self {
            context: AirContext::new(trace_info, degrees, num_assertions, options),
            start_a: pub_inputs.start_a,
            start_b: pub_inputs.start_b,
            start_c: pub_inputs.start_c,
            result: pub_inputs.result,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current_a = frame.current()[0];
        let current_b = frame.current()[1];
        let current_c = frame.current()[2];
        let next_a = frame.next()[0];
        let next_b = frame.next()[1];
        let next_c = frame.next()[2];
        result[0] = next_a - current_b;
        result[1] = next_b - current_c;
        result[2] = next_c - (current_a + current_b + current_c);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let last_step = self.trace_length() - 1;
        vec![
            Assertion::single(0, 0, self.start_a),
            Assertion::single(1, 0, self.start_b),
            Assertion::single(2, 0, self.start_c),
            Assertion::single(2, last_step, self.result),
        ]
    }
}

pub struct DoWorkProver {
    options: ProofOptions,
}

impl DoWorkProver {
    pub fn new(options: ProofOptions) -> Self {
        Self { options }
    }
}

impl Prover for DoWorkProver {
    type BaseField = BaseElement;
    type Air = DoWorkAir;
    type Trace = TraceTable<Self::BaseField>;

    type HashFn = Blake3_256<Self::BaseField>;
    type VC = MerkleTree<Self::HashFn>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;

    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;

    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;

    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> DoWorkPublicInputs {
        let last_step = trace.length() - 1;
        DoWorkPublicInputs {
            start: trace.get(0, 0),
            result: trace.get(0, last_step),
        }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

pub struct FibonacciProver {
    options: ProofOptions,
}

impl FibonacciProver {
    pub fn new(options: ProofOptions) -> Self {
        Self { options }
    }
}

impl Prover for FibonacciProver {
    type BaseField = BaseElement;
    type Air = FibonacciAir;
    type Trace = TraceTable<Self::BaseField>;

    type HashFn = Blake3_256<Self::BaseField>;
    type VC = MerkleTree<Self::HashFn>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;

    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;

    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;

    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> FibonacciPublicInputs {
        let last_step = trace.length() - 1;
        FibonacciPublicInputs {
            start_a: trace.get(0, 0),
            start_b: trace.get(1, 0),
            result: trace.get(1, last_step),
        }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

pub struct TribonacciProver {
    options: ProofOptions,
}

impl TribonacciProver {
    pub fn new(options: ProofOptions) -> Self {
        Self { options }
    }
}

impl Prover for TribonacciProver {
    type BaseField = BaseElement;
    type Air = TribonacciAir;
    type Trace = TraceTable<Self::BaseField>;

    type HashFn = Blake3_256<Self::BaseField>;
    type VC = MerkleTree<Self::HashFn>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;

    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;

    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;

    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> TribonacciPublicInputs {
        let last_step = trace.length() - 1;
        TribonacciPublicInputs {
            start_a: trace.get(0, 0),
            start_b: trace.get(1, 0),
            start_c: trace.get(2, 0),
            result: trace.get(2, last_step),
        }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

pub fn build_do_work_trace(start: BaseElement, n: usize) -> TraceTable<BaseElement> {
    let trace_width = 1;
    let mut trace = TraceTable::new(trace_width, n);

    trace.fill(
        |state| {
            state[0] = start;
        },
        |_, state| {
            state[0] = state[0].exp(3u32.into()) + BaseElement::new(42);
        },
    );

    trace
}

pub fn build_fibonacci_trace(
    start_a: BaseElement,
    start_b: BaseElement,
    n: usize,
) -> TraceTable<BaseElement> {
    let trace_width = 2;
    let mut trace = TraceTable::new(trace_width, n);

    trace.fill(
        |state| {
            state[0] = start_a;
            state[1] = start_b;
        },
        |_, state| {
            let next = state[0] + state[1];
            state[0] = state[1];
            state[1] = next;
        },
    );

    trace
}

pub fn build_tribonacci_trace(
    start_a: BaseElement,
    start_b: BaseElement,
    start_c: BaseElement,
    n: usize,
) -> TraceTable<BaseElement> {
    let trace_width = 3;
    let mut trace = TraceTable::new(trace_width, n);

    trace.fill(
        |state| {
            state[0] = start_a;
            state[1] = start_b;
            state[2] = start_c;
        },
        |_, state| {
            let next = state[0] + state[1] + state[2];
            state[0] = state[1];
            state[1] = state[2];
            state[2] = next;
        },
    );

    trace
}

pub fn default_proof_options() -> ProofOptions {
    ProofOptions::new(
        32,
        8,
        0,
        FieldExtension::None,
        8,
        31,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

fn min_conjectured_security() -> u32 {
    let base = 90u32;
    let override_val = std::env::var("GLYPH_STARK_MIN_SECURITY")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(base);
    override_val.max(base)
}

pub fn prove_do_work(start: u128, n: usize) -> Result<(Proof, DoWorkPublicInputs), String> {
    let start = BaseElement::new(start);
    let trace = build_do_work_trace(start, n);
    let result = trace.get(0, n - 1);

    let options = default_proof_options();
    let prover = DoWorkProver::new(options);
    let proof = prover
        .prove(trace)
        .map_err(|e| format!("winterfell prove failed: {e:?}"))?;

    Ok((proof, DoWorkPublicInputs { start, result }))
}

pub fn prove_fibonacci(
    start_a: u128,
    start_b: u128,
    n: usize,
) -> Result<(Proof, FibonacciPublicInputs), String> {
    let start_a = BaseElement::new(start_a);
    let start_b = BaseElement::new(start_b);
    let trace = build_fibonacci_trace(start_a, start_b, n);
    let result = trace.get(1, n - 1);

    let options = default_proof_options();
    let prover = FibonacciProver::new(options);
    let proof = prover
        .prove(trace)
        .map_err(|e| format!("winterfell prove failed: {e:?}"))?;

    Ok((
        proof,
        FibonacciPublicInputs {
            start_a,
            start_b,
            result,
        },
    ))
}

pub fn prove_tribonacci(
    start_a: u128,
    start_b: u128,
    start_c: u128,
    n: usize,
) -> Result<(Proof, TribonacciPublicInputs), String> {
    let start_a = BaseElement::new(start_a);
    let start_b = BaseElement::new(start_b);
    let start_c = BaseElement::new(start_c);
    let trace = build_tribonacci_trace(start_a, start_b, start_c, n);
    let result = trace.get(2, n - 1);

    let options = default_proof_options();
    let prover = TribonacciProver::new(options);
    let proof = prover
        .prove(trace)
        .map_err(|e| format!("winterfell prove failed: {e:?}"))?;

    Ok((
        proof,
        TribonacciPublicInputs {
            start_a,
            start_b,
            start_c,
            result,
        },
    ))
}

pub fn verify_do_work(proof: Proof, pub_inputs: DoWorkPublicInputs) -> Result<(), winterfell::VerifierError> {
    let min_opts = winterfell::AcceptableOptions::MinConjecturedSecurity(min_conjectured_security());

    winterfell::verify::<
        DoWorkAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
        MerkleTree<Blake3_256<BaseElement>>,
    >(proof, pub_inputs, &min_opts)
}

pub fn verify_fibonacci(
    proof: Proof,
    pub_inputs: FibonacciPublicInputs,
) -> Result<(), winterfell::VerifierError> {
    let min_opts = winterfell::AcceptableOptions::MinConjecturedSecurity(min_conjectured_security());

    winterfell::verify::<
        FibonacciAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
        MerkleTree<Blake3_256<BaseElement>>,
    >(proof, pub_inputs, &min_opts)
}

pub fn verify_tribonacci(
    proof: Proof,
    pub_inputs: TribonacciPublicInputs,
) -> Result<(), winterfell::VerifierError> {
    let min_opts = winterfell::AcceptableOptions::MinConjecturedSecurity(min_conjectured_security());

    winterfell::verify::<
        TribonacciAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
        MerkleTree<Blake3_256<BaseElement>>,
    >(proof, pub_inputs, &min_opts)
}

pub fn public_inputs_bytes(pub_inputs: &DoWorkPublicInputs) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(&pub_inputs.start.as_int().to_be_bytes());
    out.extend_from_slice(&pub_inputs.result.as_int().to_be_bytes());
    out
}

pub fn fibonacci_public_inputs_bytes(pub_inputs: &FibonacciPublicInputs) -> Vec<u8> {
    let mut out = Vec::with_capacity(48);
    out.extend_from_slice(&pub_inputs.start_a.as_int().to_be_bytes());
    out.extend_from_slice(&pub_inputs.start_b.as_int().to_be_bytes());
    out.extend_from_slice(&pub_inputs.result.as_int().to_be_bytes());
    out
}

pub fn tribonacci_public_inputs_bytes(pub_inputs: &TribonacciPublicInputs) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&pub_inputs.start_a.as_int().to_be_bytes());
    out.extend_from_slice(&pub_inputs.start_b.as_int().to_be_bytes());
    out.extend_from_slice(&pub_inputs.start_c.as_int().to_be_bytes());
    out.extend_from_slice(&pub_inputs.result.as_int().to_be_bytes());
    out
}

pub fn do_work_public_inputs_from_bytes(pub_bytes: &[u8]) -> Option<DoWorkPublicInputs> {
    if pub_bytes.len() != 32 {
        return None;
    }
    let mut start_be = [0u8; 16];
    start_be.copy_from_slice(&pub_bytes[0..16]);
    let mut result_be = [0u8; 16];
    result_be.copy_from_slice(&pub_bytes[16..32]);
    Some(DoWorkPublicInputs {
        start: BaseElement::new(u128::from_be_bytes(start_be)),
        result: BaseElement::new(u128::from_be_bytes(result_be)),
    })
}

pub fn fibonacci_public_inputs_from_bytes(pub_bytes: &[u8]) -> Option<FibonacciPublicInputs> {
    if pub_bytes.len() != 48 {
        return None;
    }
    let mut start_a_be = [0u8; 16];
    start_a_be.copy_from_slice(&pub_bytes[0..16]);
    let mut start_b_be = [0u8; 16];
    start_b_be.copy_from_slice(&pub_bytes[16..32]);
    let mut result_be = [0u8; 16];
    result_be.copy_from_slice(&pub_bytes[32..48]);
    Some(FibonacciPublicInputs {
        start_a: BaseElement::new(u128::from_be_bytes(start_a_be)),
        start_b: BaseElement::new(u128::from_be_bytes(start_b_be)),
        result: BaseElement::new(u128::from_be_bytes(result_be)),
    })
}

pub fn tribonacci_public_inputs_from_bytes(pub_bytes: &[u8]) -> Option<TribonacciPublicInputs> {
    if pub_bytes.len() != 64 {
        return None;
    }
    let mut start_a_be = [0u8; 16];
    start_a_be.copy_from_slice(&pub_bytes[0..16]);
    let mut start_b_be = [0u8; 16];
    start_b_be.copy_from_slice(&pub_bytes[16..32]);
    let mut start_c_be = [0u8; 16];
    start_c_be.copy_from_slice(&pub_bytes[32..48]);
    let mut result_be = [0u8; 16];
    result_be.copy_from_slice(&pub_bytes[48..64]);
    Some(TribonacciPublicInputs {
        start_a: BaseElement::new(u128::from_be_bytes(start_a_be)),
        start_b: BaseElement::new(u128::from_be_bytes(start_b_be)),
        start_c: BaseElement::new(u128::from_be_bytes(start_c_be)),
        result: BaseElement::new(u128::from_be_bytes(result_be)),
    })
}

pub fn proof_to_bytes(proof: &Proof) -> Vec<u8> {
    proof.to_bytes()
}

pub fn verify_do_work_from_bytes(
    proof_bytes: &[u8],
    pub_bytes: &[u8],
) -> Result<(), String> {
    let proof = Proof::from_bytes(proof_bytes).map_err(|e| format!("proof deserialization failed: {e:?}"))?;

    let trace_info = proof.trace_info();
    if trace_info.main_trace_width() != 1 {
        return Err(format!(
            "unexpected main_trace_width={} (expected 1)",
            trace_info.main_trace_width()
        ));
    }
    if trace_info.is_multi_segment() {
        return Err("unexpected multi-segment trace (aux segment)".to_string());
    }
    if trace_info.get_aux_segment_width() != 0 {
        return Err(format!(
            "unexpected aux_segment_width={} (expected 0)",
            trace_info.get_aux_segment_width()
        ));
    }

    let pub_inputs =
        do_work_public_inputs_from_bytes(pub_bytes).ok_or_else(|| "public inputs must be 32 bytes (start||result)".to_string())?;
    verify_do_work(proof, pub_inputs).map_err(|e| format!("winterfell verify failed: {e:?}"))
}

pub fn verify_fibonacci_from_bytes(
    proof_bytes: &[u8],
    pub_bytes: &[u8],
) -> Result<(), String> {
    let proof =
        Proof::from_bytes(proof_bytes).map_err(|e| format!("proof deserialization failed: {e:?}"))?;

    let trace_info = proof.trace_info();
    if trace_info.main_trace_width() != 2 {
        return Err(format!(
            "unexpected main_trace_width={} (expected 2)",
            trace_info.main_trace_width()
        ));
    }
    if trace_info.is_multi_segment() {
        return Err("unexpected multi-segment trace (aux segment)".to_string());
    }
    if trace_info.get_aux_segment_width() != 0 {
        return Err(format!(
            "unexpected aux_segment_width={} (expected 0)",
            trace_info.get_aux_segment_width()
        ));
    }

    let pub_inputs =
        fibonacci_public_inputs_from_bytes(pub_bytes).ok_or_else(|| "public inputs must be 48 bytes (a||b||result)".to_string())?;
    verify_fibonacci(proof, pub_inputs).map_err(|e| format!("winterfell verify failed: {e:?}"))
}

pub fn verify_tribonacci_from_bytes(
    proof_bytes: &[u8],
    pub_bytes: &[u8],
) -> Result<(), String> {
    let proof =
        Proof::from_bytes(proof_bytes).map_err(|e| format!("proof deserialization failed: {e:?}"))?;

    let trace_info = proof.trace_info();
    if trace_info.main_trace_width() != 3 {
        return Err(format!(
            "unexpected main_trace_width={} (expected 3)",
            trace_info.main_trace_width()
        ));
    }
    if trace_info.is_multi_segment() {
        return Err("unexpected multi-segment trace (aux segment)".to_string());
    }
    if trace_info.get_aux_segment_width() != 0 {
        return Err(format!(
            "unexpected aux_segment_width={} (expected 0)",
            trace_info.get_aux_segment_width()
        ));
    }

    let pub_inputs =
        tribonacci_public_inputs_from_bytes(pub_bytes).ok_or_else(|| "public inputs must be 64 bytes (a||b||c||result)".to_string())?;
    verify_tribonacci(proof, pub_inputs).map_err(|e| format!("winterfell verify failed: {e:?}"))
}

pub fn verify_do_work_sha3_from_bytes(
    proof_bytes: &[u8],
    pub_bytes: &[u8],
) -> Result<(), String> {
    let proof = Proof::from_bytes(proof_bytes).map_err(|e| format!("proof deserialization failed: {e:?}"))?;

    let trace_info = proof.trace_info();
    if trace_info.main_trace_width() != 1 {
        return Err(format!(
            "unexpected main_trace_width={} (expected 1)",
            trace_info.main_trace_width()
        ));
    }
    if trace_info.is_multi_segment() {
        return Err("unexpected multi-segment trace (aux segment)".to_string());
    }
    if trace_info.get_aux_segment_width() != 0 {
        return Err(format!(
            "unexpected aux_segment_width={} (expected 0)",
            trace_info.get_aux_segment_width()
        ));
    }

    let pub_inputs =
        do_work_public_inputs_from_bytes(pub_bytes).ok_or_else(|| "public inputs must be 32 bytes (start||result)".to_string())?;
    verify_do_work_sha3(proof, pub_inputs).map_err(|e| format!("winterfell verify failed: {e:?}"))
}

pub fn verify_fibonacci_sha3_from_bytes(
    proof_bytes: &[u8],
    pub_bytes: &[u8],
) -> Result<(), String> {
    let proof =
        Proof::from_bytes(proof_bytes).map_err(|e| format!("proof deserialization failed: {e:?}"))?;

    let trace_info = proof.trace_info();
    if trace_info.main_trace_width() != 2 {
        return Err(format!(
            "unexpected main_trace_width={} (expected 2)",
            trace_info.main_trace_width()
        ));
    }
    if trace_info.is_multi_segment() {
        return Err("unexpected multi-segment trace (aux segment)".to_string());
    }
    if trace_info.get_aux_segment_width() != 0 {
        return Err(format!(
            "unexpected aux_segment_width={} (expected 0)",
            trace_info.get_aux_segment_width()
        ));
    }

    let pub_inputs =
        fibonacci_public_inputs_from_bytes(pub_bytes).ok_or_else(|| "public inputs must be 48 bytes (a||b||result)".to_string())?;
    verify_fibonacci_sha3(proof, pub_inputs).map_err(|e| format!("winterfell verify failed: {e:?}"))
}

pub fn verify_tribonacci_sha3_from_bytes(
    proof_bytes: &[u8],
    pub_bytes: &[u8],
) -> Result<(), String> {
    let proof =
        Proof::from_bytes(proof_bytes).map_err(|e| format!("proof deserialization failed: {e:?}"))?;

    let trace_info = proof.trace_info();
    if trace_info.main_trace_width() != 3 {
        return Err(format!(
            "unexpected main_trace_width={} (expected 3)",
            trace_info.main_trace_width()
        ));
    }
    if trace_info.is_multi_segment() {
        return Err("unexpected multi-segment trace (aux segment)".to_string());
    }
    if trace_info.get_aux_segment_width() != 0 {
        return Err(format!(
            "unexpected aux_segment_width={} (expected 0)",
            trace_info.get_aux_segment_width()
        ));
    }

    let pub_inputs =
        tribonacci_public_inputs_from_bytes(pub_bytes).ok_or_else(|| "public inputs must be 64 bytes (a||b||c||result)".to_string())?;
    verify_tribonacci_sha3(proof, pub_inputs).map_err(|e| format!("winterfell verify failed: {e:?}"))
}

pub const CANONICAL_VK_STARK_PREFIX: &[u8] = b"GLYPH-STARK-VK\x00";

pub fn infer_winterfell_hash_id_from_vk_bytes(vk_bytes: &[u8]) -> Option<u8> {
    if !vk_bytes.starts_with(CANONICAL_VK_STARK_PREFIX) {
        return None;
    }
    let mut off = CANONICAL_VK_STARK_PREFIX.len();
    off = off.checked_add(WINTERFELL_IMPL_ID.len())?;
    off = off.checked_add(1)?;
    vk_bytes.get(off).copied()
}

pub const WINTERFELL_IMPL_ID: &[u8; 16] = b"winterfell-0.13\0";
pub const FIELD_F128_ID: u8 = 0x01;
pub const HASH_BLAKE3_ID: u8 = 0x01;
pub const HASH_SHA3_ID: u8 = 0x02;
pub const VC_MERKLE_ID: u8 = 0x01;

pub const GLYPH_STARK_DOWORK_SEED_DOMAIN: &[u8] = b"GLYPH_STARK_DOWORK_SEED";
pub const GLYPH_STARK_FIB_SEED_DOMAIN: &[u8] = b"GLYPH_STARK_FIB_SEED";
pub const GLYPH_STARK_TRIB_SEED_DOMAIN: &[u8] = b"GLYPH_STARK_TRIB_SEED";

pub fn canonical_vk_bytes_with_hash_id(
    air_id: &[u8],
    hash_id: u8,
    trace_width: usize,
    trace_length: usize,
    options: &ProofOptions,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(b"GLYPH-STARK-VK\x00");
    out.extend_from_slice(WINTERFELL_IMPL_ID);
    out.push(FIELD_F128_ID);
    out.push(hash_id);
    out.push(VC_MERKLE_ID);
    out.push(options.field_extension() as u8);
    out.extend_from_slice(&(air_id.len() as u16).to_be_bytes());
    out.extend_from_slice(air_id);
    out.extend_from_slice(&(trace_width as u16).to_be_bytes());
    out.extend_from_slice(&(trace_length as u32).to_be_bytes());
    out.extend_from_slice(&(options.num_queries() as u32).to_be_bytes());
    out.extend_from_slice(&(options.blowup_factor() as u32).to_be_bytes());
    out.extend_from_slice(&options.grinding_factor().to_be_bytes());
    out
}

pub fn canonical_vk_bytes(
    air_id: &[u8],
    trace_width: usize,
    trace_length: usize,
    options: &ProofOptions,
) -> Vec<u8> {
    canonical_vk_bytes_with_hash_id(air_id, HASH_BLAKE3_ID, trace_width, trace_length, options)
}

pub const DO_WORK_AIR_ID: &[u8] = b"do_work:x^3+42";
pub const FIB_AIR_ID: &[u8] = b"fibonacci:a+b";
pub const TRIB_AIR_ID: &[u8] = b"tribonacci:a+b+c";

pub fn derive_do_work_start_from_seed(seed: &[u8], idx: u32) -> u128 {
    let mut input = Vec::with_capacity(GLYPH_STARK_DOWORK_SEED_DOMAIN.len() + seed.len() + 4);
    input.extend_from_slice(GLYPH_STARK_DOWORK_SEED_DOMAIN);
    input.extend_from_slice(seed);
    input.extend_from_slice(&idx.to_be_bytes());
    let h = crate::adapters::keccak256(&input);
    let mut be = [0u8; 16];
    be.copy_from_slice(&h[16..32]);
    u128::from_be_bytes(be)
}

pub fn derive_fibonacci_starts_from_seed(seed: &[u8], idx: u32) -> (u128, u128) {
    let mut input = Vec::with_capacity(GLYPH_STARK_FIB_SEED_DOMAIN.len() + seed.len() + 5);
    input.extend_from_slice(GLYPH_STARK_FIB_SEED_DOMAIN);
    input.extend_from_slice(seed);
    input.extend_from_slice(&idx.to_be_bytes());
    input.push(0);
    let h0 = crate::adapters::keccak256(&input);
    let mut be0 = [0u8; 16];
    be0.copy_from_slice(&h0[16..32]);

    if let Some(last) = input.last_mut() {
        *last = 1;
    } else {
        debug_assert!(false, "domain suffix missing");
        return (0, 0);
    }
    let h1 = crate::adapters::keccak256(&input);
    let mut be1 = [0u8; 16];
    be1.copy_from_slice(&h1[16..32]);
    (u128::from_be_bytes(be0), u128::from_be_bytes(be1))
}

pub fn derive_tribonacci_starts_from_seed(seed: &[u8], idx: u32) -> (u128, u128, u128) {
    let mut input = Vec::with_capacity(GLYPH_STARK_TRIB_SEED_DOMAIN.len() + seed.len() + 5);
    input.extend_from_slice(GLYPH_STARK_TRIB_SEED_DOMAIN);
    input.extend_from_slice(seed);
    input.extend_from_slice(&idx.to_be_bytes());
    input.push(0);
    let h0 = crate::adapters::keccak256(&input);
    let mut be0 = [0u8; 16];
    be0.copy_from_slice(&h0[16..32]);

    if let Some(last) = input.last_mut() {
        *last = 1;
    } else {
        debug_assert!(false, "domain suffix missing");
        return (0, 0, 0);
    }
    let h1 = crate::adapters::keccak256(&input);
    let mut be1 = [0u8; 16];
    be1.copy_from_slice(&h1[16..32]);

    if let Some(last) = input.last_mut() {
        *last = 2;
    } else {
        debug_assert!(false, "domain suffix missing");
        return (0, 0, 0);
    }
    let h2 = crate::adapters::keccak256(&input);
    let mut be2 = [0u8; 16];
    be2.copy_from_slice(&h2[16..32]);

    (
        u128::from_be_bytes(be0),
        u128::from_be_bytes(be1),
        u128::from_be_bytes(be2),
    )
}

pub fn seeded_do_work_receipts(
    seed: &[u8],
    trace_length: usize,
    n_receipts: usize,
) -> Result<Vec<StarkUpstreamReceipt>, String> {
    if n_receipts == 0 {
        return Err("need at least one receipt".to_string());
    }
    if n_receipts > 64 {
        return Err("max 64 receipts for folding".to_string());
    }

    (0..n_receipts)
        .map(|i| {
            let idx = i as u32;
            let start = derive_do_work_start_from_seed(seed, idx);
            let (proof, pub_inputs) = prove_do_work(start, trace_length)?;
            Ok(StarkUpstreamReceipt::from_do_work_canonical(
                &proof,
                &pub_inputs,
                trace_length,
            ))
        })
        .collect()
}

pub fn seeded_fibonacci_receipts(
    seed: &[u8],
    trace_length: usize,
    n_receipts: usize,
) -> Result<Vec<StarkUpstreamReceipt>, String> {
    if n_receipts == 0 {
        return Err("need at least one receipt".to_string());
    }
    if n_receipts > 64 {
        return Err("max 64 receipts for folding".to_string());
    }

    (0..n_receipts)
        .map(|i| {
            let idx = i as u32;
            let (start_a, start_b) = derive_fibonacci_starts_from_seed(seed, idx);
            let (proof, pub_inputs) = prove_fibonacci(start_a, start_b, trace_length)?;
            Ok(StarkUpstreamReceipt::from_fibonacci_canonical(
                &proof,
                &pub_inputs,
                trace_length,
            ))
        })
        .collect()
}

pub fn seeded_tribonacci_receipts(
    seed: &[u8],
    trace_length: usize,
    n_receipts: usize,
) -> Result<Vec<StarkUpstreamReceipt>, String> {
    if n_receipts == 0 {
        return Err("need at least one receipt".to_string());
    }
    if n_receipts > 64 {
        return Err("max 64 receipts for folding".to_string());
    }

    (0..n_receipts)
        .map(|i| {
            let idx = i as u32;
            let (start_a, start_b, start_c) = derive_tribonacci_starts_from_seed(seed, idx);
            let (proof, pub_inputs) =
                prove_tribonacci(start_a, start_b, start_c, trace_length)?;
            Ok(StarkUpstreamReceipt::from_tribonacci_canonical(
                &proof,
                &pub_inputs,
                trace_length,
            ))
        })
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sha3MainTraceOpening {
    pub domain_size: usize,
    pub position: usize,
    pub root: [u8; 32],
    pub leaf: [u8; 32],
    pub path: Vec<[u8; 32]>,
}

fn hash_row<H, E>(row: &[E], partition_size: usize) -> H::Digest
where
    E: FieldElement,
    H: winterfell::crypto::ElementHasher<BaseField = E::BaseField>,
{
    if partition_size == row.len() {
        H::hash_elements(row)
    } else {
        let num_partitions = row.len().div_ceil(partition_size);
        let mut buffer = vec![H::Digest::default(); num_partitions];

        row.chunks(partition_size)
            .zip(buffer.iter_mut())
            .for_each(|(chunk, buf)| *buf = H::hash_elements(chunk));

        <H as winterfell::crypto::Hasher>::merge_many(&buffer)
    }
}

fn derive_sha3_query_positions_for_proof(
    proof: &Proof,
    pub_inputs: DoWorkPublicInputs,
) -> Result<Vec<usize>, String> {
    let (_, positions) = derive_sha3_raw_and_unique_query_positions_for_proof(proof, pub_inputs)?;
    Ok(positions)
}

fn derive_sha3_raw_and_unique_query_positions_for_proof(
    proof: &Proof,
    pub_inputs: DoWorkPublicInputs,
) -> Result<(Vec<usize>, Vec<usize>), String> {
    let air = DoWorkAir::new(proof.trace_info().clone(), pub_inputs, proof.options().clone());

    let lde_domain_size = air.lde_domain_size();
    let fri_options = air.options().to_fri_options();
    let num_fri_layers_expected = fri_options.num_fri_layers(lde_domain_size);
    let num_fri_layers_in_proof = proof.fri_proof.num_layers();
    if num_fri_layers_expected != num_fri_layers_in_proof {
        return Err(format!(
            "FRI layer mismatch: options.num_fri_layers={} but proof.fri_proof.num_layers={}",
            num_fri_layers_expected, num_fri_layers_in_proof
        ));
    }

    let (trace_commitments, constraint_commitment, fri_commitments) = proof
        .commitments
        .clone()
        .parse::<Sha3_256<BaseElement>>(air.trace_info().num_segments(), num_fri_layers_expected)
        .map_err(|e| format!("commitments.parse failed: {e:?}"))?;

    let mut public_coin_seed = proof.context.to_elements();
    public_coin_seed.append(&mut pub_inputs.to_elements());
    let mut public_coin = DefaultRandomCoin::<Sha3_256<BaseElement>>::new(&public_coin_seed);

    public_coin.reseed(trace_commitments[0]);
    let _constraint_coeffs = air
        .get_constraint_composition_coefficients::<BaseElement, _>(&mut public_coin)
        .map_err(|_| "failed to draw constraint composition coefficients".to_string())?;

    public_coin.reseed(constraint_commitment);
    let z: BaseElement = public_coin
        .draw()
        .map_err(|_| "failed to draw out-of-domain point z".to_string())?;
    let _ = z;

    let constraint_frame_width = air.context().num_constraint_composition_columns();
    let (ood_trace_frame, ood_constraint_frame) = proof
        .ood_frame
        .clone()
        .parse::<BaseElement>(
            air.trace_info().main_trace_width(),
            air.trace_info().aux_segment_width(),
            constraint_frame_width,
        )
        .map_err(|e| format!("ood_frame.parse failed: {e:?}"))?;

    let mut current_row = ood_trace_frame.current_row().to_vec();
    current_row.extend_from_slice(ood_constraint_frame.current_row());
    let mut next_row = ood_trace_frame.next_row().to_vec();
    next_row.extend_from_slice(ood_constraint_frame.next_row());
    let mut ood_evals = current_row;
    ood_evals.extend_from_slice(&next_row);

    let ood_digest = <Sha3_256<BaseElement> as winterfell::crypto::ElementHasher>::hash_elements(
        &ood_evals,
    );
    public_coin.reseed(ood_digest);

    let _deep_coefficients = air
        .get_deep_composition_coefficients::<BaseElement, _>(&mut public_coin)
        .map_err(|_| "failed to draw DEEP coefficients".to_string())?;

    let mut max_degree_plus_1 = air.trace_poly_degree() + 1;
    for (depth, commitment) in fri_commitments.iter().enumerate() {
        public_coin.reseed(*commitment);
        let _alpha: BaseElement = public_coin
            .draw()
            .map_err(|_| format!("failed to draw FRI alpha at depth {depth}"))?;

        if depth != fri_commitments.len().saturating_sub(1) {
            max_degree_plus_1 /= fri_options.folding_factor();
        }
    }
    let _ = max_degree_plus_1;

    let raw_query_positions = public_coin
        .draw_integers(air.options().num_queries(), air.lde_domain_size(), proof.pow_nonce)
        .map_err(|_| "failed to draw query positions".to_string())?;
    let mut unique_positions = raw_query_positions.clone();
    unique_positions.sort_unstable();
    unique_positions.dedup();
    Ok((raw_query_positions, unique_positions))
}

pub fn extract_sha3_main_trace_opening(
    proof: &Proof,
    pub_inputs: DoWorkPublicInputs,
) -> Result<Sha3MainTraceOpening, String> {
    let air = DoWorkAir::new(proof.trace_info().clone(), pub_inputs, proof.options().clone());
    let domain_size = air.lde_domain_size();

    let positions = derive_sha3_query_positions_for_proof(proof, pub_inputs)?;
    if positions.len() != proof.num_unique_queries as usize {
        return Err(format!(
            "num_unique_queries mismatch: proof says {} but derived {}",
            proof.num_unique_queries,
            positions.len()
        ));
    }

    let fri_options = air.options().to_fri_options();
    let num_fri_layers = fri_options.num_fri_layers(domain_size);
    let (trace_commitments, _constraint_commitment, _fri_commitments) = proof
        .commitments
        .clone()
        .parse::<Sha3_256<BaseElement>>(air.trace_info().num_segments(), num_fri_layers)
        .map_err(|e| format!("commitments.parse failed: {e:?}"))?;
    let root = trace_commitments[0].as_bytes();

    let main_trace_width = air.trace_info().main_trace_width();
    let (multiproof, queried_states) = proof
        .trace_queries
        .first()
        .ok_or_else(|| "proof.trace_queries empty".to_string())?
        .clone()
        .parse::<BaseElement, Sha3_256<BaseElement>, MerkleTree<Sha3_256<BaseElement>>>(
            domain_size,
            positions.len(),
            main_trace_width,
        )
        .map_err(|e| format!("trace_queries.parse failed: {e:?}"))?;

    let partition_size_main = air
        .options()
        .partition_options()
        .partition_size::<BaseElement>(main_trace_width);
    let items = queried_states
        .rows()
        .map(|row| hash_row::<Sha3_256<BaseElement>, BaseElement>(row, partition_size_main))
        .collect::<Vec<_>>();

    let openings = multiproof
        .into_openings(&items, &positions)
        .map_err(|e| format!("multiproof.into_openings failed: {e:?}"))?;

    if openings.is_empty() {
        return Err("no openings".to_string());
    }

    let position = positions[0];
    let opening = &openings[0];

    Ok(Sha3MainTraceOpening {
        domain_size,
        position,
        root,
        leaf: opening.0.as_bytes(),
        path: opening.1.iter().map(|d| d.as_bytes()).collect(),
    })
}

pub fn extract_sha3_main_trace_opening_with_leaf_value(
    proof: &Proof,
    pub_inputs: DoWorkPublicInputs,
) -> Result<(Sha3MainTraceOpening, [u8; 16]), String> {
    let air = DoWorkAir::new(proof.trace_info().clone(), pub_inputs, proof.options().clone());
    let domain_size = air.lde_domain_size();

    let positions = derive_sha3_query_positions_for_proof(proof, pub_inputs)?;
    if positions.len() != proof.num_unique_queries as usize {
        return Err(format!(
            "num_unique_queries mismatch: proof says {} but derived {}",
            proof.num_unique_queries,
            positions.len()
        ));
    }

    let fri_options = air.options().to_fri_options();
    let num_fri_layers = fri_options.num_fri_layers(domain_size);
    let (trace_commitments, _constraint_commitment, _fri_commitments) = proof
        .commitments
        .clone()
        .parse::<Sha3_256<BaseElement>>(air.trace_info().num_segments(), num_fri_layers)
        .map_err(|e| format!("commitments.parse failed: {e:?}"))?;
    let root = trace_commitments[0].as_bytes();

    let main_trace_width = air.trace_info().main_trace_width();
    let (multiproof, queried_states) = proof
        .trace_queries
        .first()
        .ok_or_else(|| "proof.trace_queries empty".to_string())?
        .clone()
        .parse::<BaseElement, Sha3_256<BaseElement>, MerkleTree<Sha3_256<BaseElement>>>(
            domain_size,
            positions.len(),
            main_trace_width,
        )
        .map_err(|e| format!("trace_queries.parse failed: {e:?}"))?;

    if main_trace_width != 1 {
        return Err(format!("unexpected main_trace_width={main_trace_width} (expected 1)"));
    }
    let first_row = queried_states
        .rows()
        .next()
        .ok_or_else(|| "queried_states empty".to_string())?;
    let first_value = first_row
        .first()
        .ok_or_else(|| "queried_states first row empty".to_string())?;
    let leaf_value_le = first_value.as_int().to_le_bytes();

    let partition_size_main = air
        .options()
        .partition_options()
        .partition_size::<BaseElement>(main_trace_width);
    let items = queried_states
        .rows()
        .map(|row| hash_row::<Sha3_256<BaseElement>, BaseElement>(row, partition_size_main))
        .collect::<Vec<_>>();

    let openings = multiproof
        .into_openings(&items, &positions)
        .map_err(|e| format!("multiproof.into_openings failed: {e:?}"))?;

    if openings.is_empty() {
        return Err("no openings".to_string());
    }

    let position = positions[0];
    let opening = &openings[0];

    Ok((
        Sha3MainTraceOpening {
            domain_size,
            position,
            root,
            leaf: opening.0.as_bytes(),
            path: opening.1.iter().map(|d| d.as_bytes()).collect(),
        },
        leaf_value_le,
    ))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sha3MainTraceOpeningWithValue {
    pub opening: Sha3MainTraceOpening,
    pub leaf_value_le: [u8; 16],
}

pub fn extract_sha3_main_trace_openings_with_leaf_values(
    proof: &Proof,
    pub_inputs: DoWorkPublicInputs,
) -> Result<Vec<Sha3MainTraceOpeningWithValue>, String> {
    let air = DoWorkAir::new(proof.trace_info().clone(), pub_inputs, proof.options().clone());
    let domain_size = air.lde_domain_size();

    let positions = derive_sha3_query_positions_for_proof(proof, pub_inputs)?;
    if positions.len() != proof.num_unique_queries as usize {
        return Err(format!(
            "num_unique_queries mismatch: proof says {} but derived {}",
            proof.num_unique_queries,
            positions.len()
        ));
    }

    let fri_options = air.options().to_fri_options();
    let num_fri_layers = fri_options.num_fri_layers(domain_size);
    let (trace_commitments, _constraint_commitment, _fri_commitments) = proof
        .commitments
        .clone()
        .parse::<Sha3_256<BaseElement>>(air.trace_info().num_segments(), num_fri_layers)
        .map_err(|e| format!("commitments.parse failed: {e:?}"))?;
    let root = trace_commitments[0].as_bytes();

    let main_trace_width = air.trace_info().main_trace_width();
    let (multiproof, queried_states) = proof
        .trace_queries
        .first()
        .ok_or_else(|| "proof.trace_queries empty".to_string())?
        .clone()
        .parse::<BaseElement, Sha3_256<BaseElement>, MerkleTree<Sha3_256<BaseElement>>>(
            domain_size,
            positions.len(),
            main_trace_width,
        )
        .map_err(|e| format!("trace_queries.parse failed: {e:?}"))?;

    if main_trace_width != 1 {
        return Err(format!("unexpected main_trace_width={main_trace_width} (expected 1)"));
    }

    let leaf_values_le: Vec<[u8; 16]> = queried_states
        .rows()
        .map(|row| {
            row.first()
                .ok_or_else(|| "queried_states row empty".to_string())
                .map(|v| v.as_int().to_le_bytes())
        })
        .collect::<Result<Vec<_>, _>>()?;

    let partition_size_main = air
        .options()
        .partition_options()
        .partition_size::<BaseElement>(main_trace_width);
    let items = queried_states
        .rows()
        .map(|row| hash_row::<Sha3_256<BaseElement>, BaseElement>(row, partition_size_main))
        .collect::<Vec<_>>();

    let openings = multiproof
        .into_openings(&items, &positions)
        .map_err(|e| format!("multiproof.into_openings failed: {e:?}"))?;

    if openings.len() != positions.len() || openings.len() != leaf_values_le.len() {
        return Err(format!(
            "opening count mismatch: positions={} openings={} leaf_values={}",
            positions.len(),
            openings.len(),
            leaf_values_le.len()
        ));
    }

    let out = if openings.len() >= 128 && rayon::current_num_threads() > 1 {
        (0..openings.len())
            .into_par_iter()
            .map(|i| {
                let position = positions[i];
                let opening = &openings[i];
                Sha3MainTraceOpeningWithValue {
                    opening: Sha3MainTraceOpening {
                        domain_size,
                        position,
                        root,
                        leaf: opening.0.as_bytes(),
                        path: opening.1.iter().map(|d| d.as_bytes()).collect(),
                    },
                    leaf_value_le: leaf_values_le[i],
                }
            })
            .collect()
    } else {
        let mut out = Vec::with_capacity(openings.len());
        for i in 0..openings.len() {
            let position = positions[i];
            let opening = &openings[i];
            out.push(Sha3MainTraceOpeningWithValue {
                opening: Sha3MainTraceOpening {
                    domain_size,
                    position,
                    root,
                    leaf: opening.0.as_bytes(),
                    path: opening.1.iter().map(|d| d.as_bytes()).collect(),
                },
                leaf_value_le: leaf_values_le[i],
            });
        }
        out
    };

    Ok(out)
}

pub fn vk_params_bytes_canonical_for_air(
    air_id: &[u8],
    trace_width: usize,
    trace_length: usize,
    options: &ProofOptions,
) -> Vec<u8> {
    canonical_vk_bytes(air_id, trace_width, trace_length, options)
}

pub fn vk_params_bytes_sha3_canonical_for_air(
    air_id: &[u8],
    trace_width: usize,
    trace_length: usize,
    options: &ProofOptions,
) -> Vec<u8> {
    canonical_vk_bytes_with_hash_id(air_id, HASH_SHA3_ID, trace_width, trace_length, options)
}

pub fn vk_params_bytes_canonical(trace_width: usize, trace_length: usize, options: &ProofOptions) -> Vec<u8> {
    vk_params_bytes_canonical_for_air(DO_WORK_AIR_ID, trace_width, trace_length, options)
}

pub fn vk_params_bytes_sha3_canonical(trace_width: usize, trace_length: usize, options: &ProofOptions) -> Vec<u8> {
    vk_params_bytes_sha3_canonical_for_air(DO_WORK_AIR_ID, trace_width, trace_length, options)
}

#[deprecated(note = "use vk_params_bytes_canonical with full canonical format")]
pub fn vk_params_bytes(options: &ProofOptions) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    out.extend_from_slice(&(options.num_queries() as u32).to_be_bytes());
    out.extend_from_slice(&(options.blowup_factor() as u32).to_be_bytes());
    out.extend_from_slice(&options.grinding_factor().to_be_bytes());
    out
}

#[derive(Clone, Debug)]
pub struct StarkUpstreamReceipt {
    pub proof_bytes: Vec<u8>,
    pub pub_inputs_bytes: Vec<u8>,
    pub vk_params_bytes: Vec<u8>,
}

impl StarkUpstreamReceipt {
    #[allow(deprecated)]
    pub fn from_do_work(proof: &Proof, pub_inputs: &DoWorkPublicInputs) -> Self {
        Self {
            proof_bytes: proof_to_bytes(proof),
            pub_inputs_bytes: public_inputs_bytes(pub_inputs),
            vk_params_bytes: vk_params_bytes(proof.options()),
        }
    }

    pub fn from_do_work_canonical(proof: &Proof, pub_inputs: &DoWorkPublicInputs, trace_length: usize) -> Self {
        let trace_width = 1;
        Self {
            proof_bytes: proof_to_bytes(proof),
            pub_inputs_bytes: public_inputs_bytes(pub_inputs),
            vk_params_bytes: vk_params_bytes_canonical_for_air(
                DO_WORK_AIR_ID,
                trace_width,
                trace_length,
                proof.options(),
            ),
        }
    }

    pub fn from_do_work_sha3_canonical(proof: &Proof, pub_inputs: &DoWorkPublicInputs, trace_length: usize) -> Self {
        let trace_width = 1;
        Self {
            proof_bytes: proof_to_bytes(proof),
            pub_inputs_bytes: public_inputs_bytes(pub_inputs),
            vk_params_bytes: vk_params_bytes_sha3_canonical_for_air(
                DO_WORK_AIR_ID,
                trace_width,
                trace_length,
                proof.options(),
            ),
        }
    }

    pub fn from_fibonacci_canonical(
        proof: &Proof,
        pub_inputs: &FibonacciPublicInputs,
        trace_length: usize,
    ) -> Self {
        let trace_width = 2;
        Self {
            proof_bytes: proof_to_bytes(proof),
            pub_inputs_bytes: fibonacci_public_inputs_bytes(pub_inputs),
            vk_params_bytes: vk_params_bytes_canonical_for_air(
                FIB_AIR_ID,
                trace_width,
                trace_length,
                proof.options(),
            ),
        }
    }

    pub fn from_fibonacci_sha3_canonical(
        proof: &Proof,
        pub_inputs: &FibonacciPublicInputs,
        trace_length: usize,
    ) -> Self {
        let trace_width = 2;
        Self {
            proof_bytes: proof_to_bytes(proof),
            pub_inputs_bytes: fibonacci_public_inputs_bytes(pub_inputs),
            vk_params_bytes: vk_params_bytes_sha3_canonical_for_air(
                FIB_AIR_ID,
                trace_width,
                trace_length,
                proof.options(),
            ),
        }
    }

    pub fn from_tribonacci_canonical(
        proof: &Proof,
        pub_inputs: &TribonacciPublicInputs,
        trace_length: usize,
    ) -> Self {
        let trace_width = 3;
        Self {
            proof_bytes: proof_to_bytes(proof),
            pub_inputs_bytes: tribonacci_public_inputs_bytes(pub_inputs),
            vk_params_bytes: vk_params_bytes_canonical_for_air(
                TRIB_AIR_ID,
                trace_width,
                trace_length,
                proof.options(),
            ),
        }
    }

    pub fn from_tribonacci_sha3_canonical(
        proof: &Proof,
        pub_inputs: &TribonacciPublicInputs,
        trace_length: usize,
    ) -> Self {
        let trace_width = 3;
        Self {
            proof_bytes: proof_to_bytes(proof),
            pub_inputs_bytes: tribonacci_public_inputs_bytes(pub_inputs),
            vk_params_bytes: vk_params_bytes_sha3_canonical_for_air(
                TRIB_AIR_ID,
                trace_width,
                trace_length,
                proof.options(),
            ),
        }
    }
}

pub use crate::stark_program::WINTERFELL_STARK_PROGRAM_TAG;

pub fn winterfell_stark_program_bytes(air_id: &[u8], hash_id: u8) -> Vec<u8> {
    let ops = if hash_id == HASH_SHA3_ID {
        vec![
            crate::stark_ir::IrOp {
                kernel_id: crate::stark_ir::kernel_id::WINTERFELL_SHA3_TRANSCRIPT,
                args: vec![],
            },
            crate::stark_ir::IrOp {
                kernel_id: crate::stark_ir::kernel_id::WINTERFELL_SHA3_TRACE_OPENINGS,
                args: vec![],
            },
            crate::stark_ir::IrOp {
                kernel_id: crate::stark_ir::kernel_id::WINTERFELL_SHA3_CONSTRAINT_OPENINGS,
                args: vec![],
            },
            crate::stark_ir::IrOp {
                kernel_id: crate::stark_ir::kernel_id::WINTERFELL_SHA3_FRI_OPENINGS,
                args: vec![],
            },
            crate::stark_ir::IrOp {
                kernel_id: crate::stark_ir::kernel_id::WINTERFELL_SHA3_FRI_REMAINDER,
                args: vec![],
            },
            crate::stark_ir::IrOp {
                kernel_id: crate::stark_ir::kernel_id::WINTERFELL_DEEP_COMPOSITION,
                args: vec![],
            },
            crate::stark_ir::IrOp {
                kernel_id: crate::stark_ir::kernel_id::WINTERFELL_FRI_VERIFY,
                args: vec![],
            },
            crate::stark_ir::IrOp {
                kernel_id: crate::stark_ir::kernel_id::WINTERFELL_AIR_VERIFY,
                args: vec![],
            },
        ]
    } else if hash_id == HASH_BLAKE3_ID {
        vec![
            crate::stark_ir::IrOp {
                kernel_id: crate::stark_ir::kernel_id::WINTERFELL_BLAKE3_TRANSCRIPT,
                args: vec![],
            },
            crate::stark_ir::IrOp {
                kernel_id: crate::stark_ir::kernel_id::WINTERFELL_BLAKE3_TRACE_OPENINGS,
                args: vec![],
            },
            crate::stark_ir::IrOp {
                kernel_id: crate::stark_ir::kernel_id::WINTERFELL_BLAKE3_CONSTRAINT_OPENINGS,
                args: vec![],
            },
            crate::stark_ir::IrOp {
                kernel_id: crate::stark_ir::kernel_id::WINTERFELL_BLAKE3_FRI_OPENINGS,
                args: vec![],
            },
            crate::stark_ir::IrOp {
                kernel_id: crate::stark_ir::kernel_id::WINTERFELL_BLAKE3_FRI_REMAINDER,
                args: vec![],
            },
            crate::stark_ir::IrOp {
                kernel_id: crate::stark_ir::kernel_id::WINTERFELL_BLAKE3_DEEP_COMPOSITION,
                args: vec![],
            },
            crate::stark_ir::IrOp {
                kernel_id: crate::stark_ir::kernel_id::WINTERFELL_BLAKE3_FRI_VERIFY,
                args: vec![],
            },
            crate::stark_ir::IrOp {
                kernel_id: crate::stark_ir::kernel_id::WINTERFELL_BLAKE3_AIR_VERIFY,
                args: vec![],
            },
        ]
    } else {
        vec![crate::stark_ir::IrOp {
            kernel_id: crate::stark_ir::kernel_id::WINTERFELL_SHA3_TRANSCRIPT,
            args: vec![],
        }]
    };
    let ir = crate::stark_ir::StarkVerifierIr {
        version: crate::stark_ir::STARK_VERIFIER_IR_VERSION,
        ops,
    };
    crate::stark_program::WinterfellStarkProgram {
        version: crate::stark_program::WINTERFELL_STARK_PROGRAM_VERSION,
        impl_id: *WINTERFELL_IMPL_ID,
        field_id: FIELD_F128_ID,
        hash_id,
        commitment_scheme_id: VC_MERKLE_ID,
        air_id: air_id.to_vec(),
        ir_bytes: ir.encode(),
    }
    .encode()
}

pub fn canonical_stark_receipt_from_upstream_do_work(
    receipt: &StarkUpstreamReceipt,
) -> Result<crate::stark_receipt::CanonicalStarkReceipt, String> {
    use crate::stark_receipt::{CanonicalStarkReceipt, CanonicalStarkVk};

    let hash_id = infer_winterfell_hash_id_from_vk_bytes(&receipt.vk_params_bytes)
        .ok_or_else(|| "vk_params_bytes must be canonical (missing hash_id)".to_string())?;

    let vk = CanonicalStarkVk {
        version: 1,
        field_id: FIELD_F128_ID,
        hash_id,
        commitment_scheme_id: VC_MERKLE_ID,
        consts_bytes: receipt.vk_params_bytes.clone(),
        program_bytes: winterfell_stark_program_bytes(DO_WORK_AIR_ID, hash_id),
    };

    Ok(CanonicalStarkReceipt {
        proof_bytes: receipt.proof_bytes.clone(),
        pub_inputs_bytes: receipt.pub_inputs_bytes.clone(),
        vk_bytes: vk.encode(),
    })
}

pub fn canonical_stark_receipt_from_upstream_fibonacci(
    receipt: &StarkUpstreamReceipt,
) -> Result<crate::stark_receipt::CanonicalStarkReceipt, String> {
    use crate::stark_receipt::{CanonicalStarkReceipt, CanonicalStarkVk};

    let hash_id = infer_winterfell_hash_id_from_vk_bytes(&receipt.vk_params_bytes)
        .ok_or_else(|| "vk_params_bytes must be canonical (missing hash_id)".to_string())?;

    let vk = CanonicalStarkVk {
        version: 1,
        field_id: FIELD_F128_ID,
        hash_id,
        commitment_scheme_id: VC_MERKLE_ID,
        consts_bytes: receipt.vk_params_bytes.clone(),
        program_bytes: winterfell_stark_program_bytes(FIB_AIR_ID, hash_id),
    };

    Ok(CanonicalStarkReceipt {
        proof_bytes: receipt.proof_bytes.clone(),
        pub_inputs_bytes: receipt.pub_inputs_bytes.clone(),
        vk_bytes: vk.encode(),
    })
}

pub fn canonical_stark_receipt_from_upstream_tribonacci(
    receipt: &StarkUpstreamReceipt,
) -> Result<crate::stark_receipt::CanonicalStarkReceipt, String> {
    use crate::stark_receipt::{CanonicalStarkReceipt, CanonicalStarkVk};

    let hash_id = infer_winterfell_hash_id_from_vk_bytes(&receipt.vk_params_bytes)
        .ok_or_else(|| "vk_params_bytes must be canonical (missing hash_id)".to_string())?;

    let vk = CanonicalStarkVk {
        version: 1,
        field_id: FIELD_F128_ID,
        hash_id,
        commitment_scheme_id: VC_MERKLE_ID,
        consts_bytes: receipt.vk_params_bytes.clone(),
        program_bytes: winterfell_stark_program_bytes(TRIB_AIR_ID, hash_id),
    };

    Ok(CanonicalStarkReceipt {
        proof_bytes: receipt.proof_bytes.clone(),
        pub_inputs_bytes: receipt.pub_inputs_bytes.clone(),
        vk_bytes: vk.encode(),
    })
}

pub struct DoWorkProverSha3 {
    options: ProofOptions,
}

impl DoWorkProverSha3 {
    pub fn new(options: ProofOptions) -> Self {
        Self { options }
    }
}

impl Prover for DoWorkProverSha3 {
    type BaseField = BaseElement;
    type Air = DoWorkAir;
    type Trace = TraceTable<Self::BaseField>;

    type HashFn = Sha3_256<Self::BaseField>;
    type VC = MerkleTree<Self::HashFn>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;

    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;

    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;

    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> DoWorkPublicInputs {
        let last_step = trace.length() - 1;
        DoWorkPublicInputs {
            start: trace.get(0, 0),
            result: trace.get(0, last_step),
        }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

pub struct FibonacciProverSha3 {
    options: ProofOptions,
}

impl FibonacciProverSha3 {
    pub fn new(options: ProofOptions) -> Self {
        Self { options }
    }
}

impl Prover for FibonacciProverSha3 {
    type BaseField = BaseElement;
    type Air = FibonacciAir;
    type Trace = TraceTable<Self::BaseField>;

    type HashFn = Sha3_256<Self::BaseField>;
    type VC = MerkleTree<Self::HashFn>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;

    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;

    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;

    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> FibonacciPublicInputs {
        let last_step = trace.length() - 1;
        FibonacciPublicInputs {
            start_a: trace.get(0, 0),
            start_b: trace.get(1, 0),
            result: trace.get(1, last_step),
        }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

pub struct TribonacciProverSha3 {
    options: ProofOptions,
}

impl TribonacciProverSha3 {
    pub fn new(options: ProofOptions) -> Self {
        Self { options }
    }
}

impl Prover for TribonacciProverSha3 {
    type BaseField = BaseElement;
    type Air = TribonacciAir;
    type Trace = TraceTable<Self::BaseField>;

    type HashFn = Sha3_256<Self::BaseField>;
    type VC = MerkleTree<Self::HashFn>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;

    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;

    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;

    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> TribonacciPublicInputs {
        let last_step = trace.length() - 1;
        TribonacciPublicInputs {
            start_a: trace.get(0, 0),
            start_b: trace.get(1, 0),
            start_c: trace.get(2, 0),
            result: trace.get(2, last_step),
        }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

pub fn prove_do_work_sha3(start: u128, n: usize) -> Result<(Proof, DoWorkPublicInputs), String> {
    let start = BaseElement::new(start);
    let trace = build_do_work_trace(start, n);
    let result = trace.get(0, n - 1);

    let options = default_proof_options();
    let prover = DoWorkProverSha3::new(options);
    let proof = prover
        .prove(trace)
        .map_err(|e| format!("winterfell prove failed: {e:?}"))?;

    Ok((proof, DoWorkPublicInputs { start, result }))
}

pub fn prove_fibonacci_sha3(
    start_a: u128,
    start_b: u128,
    n: usize,
) -> Result<(Proof, FibonacciPublicInputs), String> {
    let start_a = BaseElement::new(start_a);
    let start_b = BaseElement::new(start_b);
    let trace = build_fibonacci_trace(start_a, start_b, n);
    let result = trace.get(1, n - 1);

    let options = default_proof_options();
    let prover = FibonacciProverSha3::new(options);
    let proof = prover
        .prove(trace)
        .map_err(|e| format!("winterfell prove failed: {e:?}"))?;

    Ok((
        proof,
        FibonacciPublicInputs {
            start_a,
            start_b,
            result,
        },
    ))
}

pub fn prove_tribonacci_sha3(
    start_a: u128,
    start_b: u128,
    start_c: u128,
    n: usize,
) -> Result<(Proof, TribonacciPublicInputs), String> {
    let start_a = BaseElement::new(start_a);
    let start_b = BaseElement::new(start_b);
    let start_c = BaseElement::new(start_c);
    let trace = build_tribonacci_trace(start_a, start_b, start_c, n);
    let result = trace.get(2, n - 1);

    let options = default_proof_options();
    let prover = TribonacciProverSha3::new(options);
    let proof = prover
        .prove(trace)
        .map_err(|e| format!("winterfell prove failed: {e:?}"))?;

    Ok((
        proof,
        TribonacciPublicInputs {
            start_a,
            start_b,
            start_c,
            result,
        },
    ))
}

pub fn verify_do_work_sha3(proof: Proof, pub_inputs: DoWorkPublicInputs) -> Result<(), winterfell::VerifierError> {
    let min_opts = winterfell::AcceptableOptions::MinConjecturedSecurity(min_conjectured_security());

    winterfell::verify::<
        DoWorkAir,
        Sha3_256<BaseElement>,
        DefaultRandomCoin<Sha3_256<BaseElement>>,
        MerkleTree<Sha3_256<BaseElement>>,
    >(proof, pub_inputs, &min_opts)
}

pub fn verify_fibonacci_sha3(
    proof: Proof,
    pub_inputs: FibonacciPublicInputs,
) -> Result<(), winterfell::VerifierError> {
    let min_opts = winterfell::AcceptableOptions::MinConjecturedSecurity(min_conjectured_security());

    winterfell::verify::<
        FibonacciAir,
        Sha3_256<BaseElement>,
        DefaultRandomCoin<Sha3_256<BaseElement>>,
        MerkleTree<Sha3_256<BaseElement>>,
    >(proof, pub_inputs, &min_opts)
}

pub fn verify_tribonacci_sha3(
    proof: Proof,
    pub_inputs: TribonacciPublicInputs,
) -> Result<(), winterfell::VerifierError> {
    let min_opts = winterfell::AcceptableOptions::MinConjecturedSecurity(min_conjectured_security());

    winterfell::verify::<
        TribonacciAir,
        Sha3_256<BaseElement>,
        DefaultRandomCoin<Sha3_256<BaseElement>>,
        MerkleTree<Sha3_256<BaseElement>>,
    >(proof, pub_inputs, &min_opts)
}

pub fn seeded_do_work_receipts_sha3(
    seed: &[u8],
    trace_length: usize,
    n_receipts: usize,
) -> Result<Vec<StarkUpstreamReceipt>, String> {
    if n_receipts == 0 {
        return Err("need at least one receipt".to_string());
    }
    if n_receipts > 64 {
        return Err("max 64 receipts for folding".to_string());
    }

    (0..n_receipts)
        .map(|i| {
            let idx = i as u32;
            let start = derive_do_work_start_from_seed(seed, idx);
            let (proof, pub_inputs) = prove_do_work_sha3(start, trace_length)?;
            Ok(StarkUpstreamReceipt::from_do_work_sha3_canonical(
                &proof,
                &pub_inputs,
                trace_length,
            ))
        })
        .collect()
}

pub fn seeded_fibonacci_receipts_sha3(
    seed: &[u8],
    trace_length: usize,
    n_receipts: usize,
) -> Result<Vec<StarkUpstreamReceipt>, String> {
    if n_receipts == 0 {
        return Err("need at least one receipt".to_string());
    }
    if n_receipts > 64 {
        return Err("max 64 receipts for folding".to_string());
    }

    (0..n_receipts)
        .map(|i| {
            let idx = i as u32;
            let (start_a, start_b) = derive_fibonacci_starts_from_seed(seed, idx);
            let (proof, pub_inputs) = prove_fibonacci_sha3(start_a, start_b, trace_length)?;
            Ok(StarkUpstreamReceipt::from_fibonacci_sha3_canonical(
                &proof,
                &pub_inputs,
                trace_length,
            ))
        })
        .collect()
}

pub fn seeded_tribonacci_receipts_sha3(
    seed: &[u8],
    trace_length: usize,
    n_receipts: usize,
) -> Result<Vec<StarkUpstreamReceipt>, String> {
    if n_receipts == 0 {
        return Err("need at least one receipt".to_string());
    }
    if n_receipts > 64 {
        return Err("max 64 receipts for folding".to_string());
    }

    (0..n_receipts)
        .map(|i| {
            let idx = i as u32;
            let (start_a, start_b, start_c) = derive_tribonacci_starts_from_seed(seed, idx);
            let (proof, pub_inputs) =
                prove_tribonacci_sha3(start_a, start_b, start_c, trace_length)?;
            Ok(StarkUpstreamReceipt::from_tribonacci_sha3_canonical(
                &proof,
                &pub_inputs,
                trace_length,
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_trace_length(default_len: usize) -> usize {
        std::env::var("GLYPH_TEST_TRACE_LEN")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|&v| v > 0)
            .unwrap_or(default_len)
    }

    #[test]
    fn test_winterfell_do_work_proof_roundtrip() -> Result<(), String> {
        let (proof, pub_inputs) = prove_do_work(3, 1024)?;
        assert!(verify_do_work(proof, pub_inputs).is_ok());
        Ok(())
    }

    #[test]
    fn test_winterfell_do_work_proof_roundtrip_sha3() -> Result<(), String> {
        let (proof, pub_inputs) = prove_do_work_sha3(3, 1024)?;
        assert!(verify_do_work_sha3(proof, pub_inputs).is_ok());
        Ok(())
    }

    #[test]
    fn test_winterfell_fibonacci_proof_roundtrip() -> Result<(), String> {
        let (proof, pub_inputs) = prove_fibonacci(1, 1, 128)?;
        assert!(verify_fibonacci(proof, pub_inputs).is_ok());
        Ok(())
    }

    #[test]
    fn test_winterfell_fibonacci_proof_roundtrip_sha3() -> Result<(), String> {
        let (proof, pub_inputs) = prove_fibonacci_sha3(1, 1, 128)?;
        assert!(verify_fibonacci_sha3(proof, pub_inputs).is_ok());
        Ok(())
    }

    #[test]
    fn test_winterfell_tribonacci_proof_roundtrip() -> Result<(), String> {
        let (proof, pub_inputs) = prove_tribonacci(1, 1, 2, 128)?;
        assert!(verify_tribonacci(proof, pub_inputs).is_ok());
        Ok(())
    }

    #[test]
    fn test_winterfell_tribonacci_proof_roundtrip_sha3() -> Result<(), String> {
        let (proof, pub_inputs) = prove_tribonacci_sha3(1, 1, 2, 128)?;
        assert!(verify_tribonacci_sha3(proof, pub_inputs).is_ok());
        Ok(())
    }

    #[test]
    fn test_canonical_receipt_program_bytes_decodes_and_matches_vk() -> Result<(), String> {
        let trace_length = test_trace_length(64);
        let receipts = seeded_do_work_receipts_sha3(b"canonical-program-bytes", trace_length, 1)?;
        let cr = canonical_stark_receipt_from_upstream_do_work(&receipts[0])?;
        let vk = crate::stark_receipt::CanonicalStarkReceipt::decode_and_validate_vk(&cr)
            .map_err(|err| format!("vk: {err}"))?;

        let program = crate::stark_program::WinterfellStarkProgram::decode(&vk.program_bytes)
            .map_err(|err| format!("program bytes must decode: {err}"))?;
        assert_eq!(program.version, crate::stark_program::WINTERFELL_STARK_PROGRAM_VERSION);
        assert_eq!(program.impl_id, *WINTERFELL_IMPL_ID);
        assert_eq!(program.field_id, vk.field_id);
        assert_eq!(program.hash_id, vk.hash_id);
        assert_eq!(program.commitment_scheme_id, vk.commitment_scheme_id);
        assert_eq!(program.air_id.as_slice(), DO_WORK_AIR_ID);
        Ok(())
    }

    #[test]
    fn test_canonical_receipt_program_bytes_decodes_fibonacci() -> Result<(), String> {
        let trace_length = test_trace_length(64);
        let receipts = seeded_fibonacci_receipts_sha3(b"canonical-fib-program", trace_length, 1)?;
        let cr = canonical_stark_receipt_from_upstream_fibonacci(&receipts[0])?;
        let vk = crate::stark_receipt::CanonicalStarkReceipt::decode_and_validate_vk(&cr)
            .map_err(|err| format!("vk: {err}"))?;

        let program = crate::stark_program::WinterfellStarkProgram::decode(&vk.program_bytes)
            .map_err(|err| format!("program bytes must decode: {err}"))?;
        assert_eq!(program.version, crate::stark_program::WINTERFELL_STARK_PROGRAM_VERSION);
        assert_eq!(program.impl_id, *WINTERFELL_IMPL_ID);
        assert_eq!(program.field_id, vk.field_id);
        assert_eq!(program.hash_id, vk.hash_id);
        assert_eq!(program.commitment_scheme_id, vk.commitment_scheme_id);
        assert_eq!(program.air_id.as_slice(), FIB_AIR_ID);
        Ok(())
    }

    #[test]
    fn test_canonical_receipt_program_bytes_decodes_tribonacci() -> Result<(), String> {
        let trace_length = test_trace_length(64);
        let receipts =
            seeded_tribonacci_receipts_sha3(b"canonical-trib-program", trace_length, 1)?;
        let cr = canonical_stark_receipt_from_upstream_tribonacci(&receipts[0])?;
        let vk = crate::stark_receipt::CanonicalStarkReceipt::decode_and_validate_vk(&cr)
            .map_err(|err| format!("vk: {err}"))?;

        let program = crate::stark_program::WinterfellStarkProgram::decode(&vk.program_bytes)
            .map_err(|err| format!("program bytes must decode: {err}"))?;
        assert_eq!(program.version, crate::stark_program::WINTERFELL_STARK_PROGRAM_VERSION);
        assert_eq!(program.impl_id, *WINTERFELL_IMPL_ID);
        assert_eq!(program.field_id, vk.field_id);
        assert_eq!(program.hash_id, vk.hash_id);
        assert_eq!(program.commitment_scheme_id, vk.commitment_scheme_id);
        assert_eq!(program.air_id.as_slice(), TRIB_AIR_ID);
        Ok(())
    }

    #[test]
    fn test_extract_sha3_main_trace_opening_roundtrip() -> Result<(), String> {
        use winterfell::crypto::Hasher;

        let (proof, pub_inputs) = prove_do_work_sha3(3, 1024)?;
        let opening = extract_sha3_main_trace_opening(&proof, pub_inputs)
            .map_err(|err| format!("extract: {err}"))?;

        let mut idx = opening.position;
        let mut acc = <<Sha3_256<BaseElement> as Hasher>::Digest>::new(opening.leaf);
        for sib in &opening.path {
            let sib = <<Sha3_256<BaseElement> as Hasher>::Digest>::new(*sib);
            acc = if idx & 1 == 0 {
                Sha3_256::<BaseElement>::merge(&[acc, sib])
            } else {
                Sha3_256::<BaseElement>::merge(&[sib, acc])
            };
            idx >>= 1;
        }

        assert_eq!(acc.as_bytes(), opening.root);
        Ok(())
    }

    #[test]
    fn test_winterfell_do_work_proof_rejects_wrong_public_inputs() -> Result<(), String> {
        let (proof, mut pub_inputs) = prove_do_work(3, 1024)?;
        pub_inputs.result = BaseElement::new(pub_inputs.result.as_int().wrapping_add(1));
        assert!(verify_do_work(proof, pub_inputs).is_err());
        Ok(())
    }

    #[test]
    fn test_winterfell_do_work_proof_rejects_wrong_public_inputs_sha3() -> Result<(), String> {
        let (proof, mut pub_inputs) = prove_do_work_sha3(3, 1024)?;
        pub_inputs.result = BaseElement::new(pub_inputs.result.as_int().wrapping_add(1));
        assert!(verify_do_work_sha3(proof, pub_inputs).is_err());
        Ok(())
    }

    #[test]
    fn test_do_work_public_inputs_from_bytes_roundtrip() -> Result<(), String> {
        let (_proof, pub_inputs) = prove_do_work(3, 1024)?;
        let bytes = public_inputs_bytes(&pub_inputs);
        let parsed = match do_work_public_inputs_from_bytes(&bytes) {
            Some(value) => value,
            None => return Err("parse must succeed".to_string()),
        };
        assert_eq!(parsed.start.as_int(), pub_inputs.start.as_int());
        assert_eq!(parsed.result.as_int(), pub_inputs.result.as_int());
        Ok(())
    }

    #[test]
    fn test_fibonacci_public_inputs_from_bytes_roundtrip() -> Result<(), String> {
        let (_proof, pub_inputs) = prove_fibonacci(1, 1, 128)?;
        let bytes = fibonacci_public_inputs_bytes(&pub_inputs);
        let parsed = match fibonacci_public_inputs_from_bytes(&bytes) {
            Some(value) => value,
            None => return Err("parse must succeed".to_string()),
        };
        assert_eq!(parsed.start_a.as_int(), pub_inputs.start_a.as_int());
        assert_eq!(parsed.start_b.as_int(), pub_inputs.start_b.as_int());
        assert_eq!(parsed.result.as_int(), pub_inputs.result.as_int());
        Ok(())
    }

    #[test]
    fn test_tribonacci_public_inputs_from_bytes_roundtrip() -> Result<(), String> {
        let (_proof, pub_inputs) = prove_tribonacci(1, 1, 2, 128)?;
        let bytes = tribonacci_public_inputs_bytes(&pub_inputs);
        let parsed = match tribonacci_public_inputs_from_bytes(&bytes) {
            Some(value) => value,
            None => return Err("parse must succeed".to_string()),
        };
        assert_eq!(parsed.start_a.as_int(), pub_inputs.start_a.as_int());
        assert_eq!(parsed.start_b.as_int(), pub_inputs.start_b.as_int());
        assert_eq!(parsed.start_c.as_int(), pub_inputs.start_c.as_int());
        assert_eq!(parsed.result.as_int(), pub_inputs.result.as_int());
        Ok(())
    }

    #[test]
    fn test_verify_do_work_from_bytes_roundtrip() -> Result<(), String> {
        let (proof, pub_inputs) = prove_do_work(3, 1024)?;
        let proof_bytes = proof_to_bytes(&proof);
        let pub_bytes = public_inputs_bytes(&pub_inputs);
        assert!(verify_do_work_from_bytes(&proof_bytes, &pub_bytes).is_ok());
        Ok(())
    }

    #[test]
    fn test_verify_fibonacci_from_bytes_roundtrip() -> Result<(), String> {
        let (proof, pub_inputs) = prove_fibonacci(1, 1, 128)?;
        let proof_bytes = proof_to_bytes(&proof);
        let pub_bytes = fibonacci_public_inputs_bytes(&pub_inputs);
        assert!(verify_fibonacci_from_bytes(&proof_bytes, &pub_bytes).is_ok());
        Ok(())
    }

    #[test]
    fn test_verify_do_work_sha3_from_bytes_roundtrip() -> Result<(), String> {
        let (proof, pub_inputs) = prove_do_work_sha3(3, 1024)?;
        let proof_bytes = proof_to_bytes(&proof);
        let pub_bytes = public_inputs_bytes(&pub_inputs);
        assert!(verify_do_work_sha3_from_bytes(&proof_bytes, &pub_bytes).is_ok());
        Ok(())
    }

    #[test]
    fn test_verify_fibonacci_sha3_from_bytes_roundtrip() -> Result<(), String> {
        let (proof, pub_inputs) = prove_fibonacci_sha3(1, 1, 128)?;
        let proof_bytes = proof_to_bytes(&proof);
        let pub_bytes = fibonacci_public_inputs_bytes(&pub_inputs);
        assert!(verify_fibonacci_sha3_from_bytes(&proof_bytes, &pub_bytes).is_ok());
        Ok(())
    }

    #[test]
    fn test_verify_tribonacci_from_bytes_roundtrip() -> Result<(), String> {
        let (proof, pub_inputs) = prove_tribonacci(1, 1, 2, 128)?;
        let proof_bytes = proof_to_bytes(&proof);
        let pub_bytes = tribonacci_public_inputs_bytes(&pub_inputs);
        assert!(verify_tribonacci_from_bytes(&proof_bytes, &pub_bytes).is_ok());
        Ok(())
    }

    #[test]
    fn test_verify_tribonacci_sha3_from_bytes_roundtrip() -> Result<(), String> {
        let (proof, pub_inputs) = prove_tribonacci_sha3(1, 1, 2, 128)?;
        let proof_bytes = proof_to_bytes(&proof);
        let pub_bytes = tribonacci_public_inputs_bytes(&pub_inputs);
        assert!(verify_tribonacci_sha3_from_bytes(&proof_bytes, &pub_bytes).is_ok());
        Ok(())
    }

    #[test]
    fn test_verify_do_work_from_bytes_rejects_tampered_public_inputs() -> Result<(), String> {
        let (proof, pub_inputs) = prove_do_work(3, 1024)?;
        let proof_bytes = proof_to_bytes(&proof);
        let mut pub_bytes = public_inputs_bytes(&pub_inputs);
        pub_bytes[31] ^= 1;
        assert!(verify_do_work_from_bytes(&proof_bytes, &pub_bytes).is_err());
        Ok(())
    }

    #[test]
    fn test_stark_upstream_receipt_serialization() -> Result<(), String> {
        let (proof, pub_inputs) = prove_do_work(3, 1024)?;
        let receipt = StarkUpstreamReceipt::from_do_work(&proof, &pub_inputs);

        assert!(!receipt.proof_bytes.is_empty());
        assert_eq!(receipt.pub_inputs_bytes.len(), 32);
        assert_eq!(receipt.vk_params_bytes.len(), 12);
        Ok(())
    }

    #[test]
    fn test_canonical_vk_bytes_structure() {
        let options = default_proof_options();
        let vk = vk_params_bytes_canonical(1, 1024, &options);

        assert!(vk.starts_with(b"GLYPH-STARK-VK\x00"));
        assert!(vk.len() > 50);

        let expected_len = CANONICAL_VK_STARK_PREFIX.len()
            + 16
            + 4
            + 2
            + DO_WORK_AIR_ID.len()
            + 2
            + 4
            + 4
            + 4
            + 4;
        assert_eq!(vk.len(), expected_len);
    }

    #[test]
    fn test_canonical_vk_bytes_uniqueness_different_air() {
        let options = default_proof_options();

        let vk1 = canonical_vk_bytes(b"air", 1, 1024, &options);
        let vk2 = canonical_vk_bytes(b"air_alt", 1, 1024, &options);

        assert_ne!(vk1, vk2);
    }

    #[test]
    fn test_canonical_vk_bytes_uniqueness_different_trace() {
        let options = default_proof_options();

        let vk1 = canonical_vk_bytes(DO_WORK_AIR_ID, 1, 1024, &options);
        let vk2 = canonical_vk_bytes(DO_WORK_AIR_ID, 1, 2048, &options);
        let vk3 = canonical_vk_bytes(DO_WORK_AIR_ID, 2, 1024, &options);

        assert_ne!(vk1, vk2);
        assert_ne!(vk1, vk3);
        assert_ne!(vk2, vk3);
    }

    #[test]
    fn test_canonical_vk_bytes_stability() {
        let options = default_proof_options();

        let vk1 = canonical_vk_bytes(DO_WORK_AIR_ID, 1, 1024, &options);
        let vk2 = canonical_vk_bytes(DO_WORK_AIR_ID, 1, 1024, &options);

        assert_eq!(vk1, vk2);
    }

    #[test]
    fn test_canonical_vk_bytes_uniqueness_different_options() {
        let opts1 = ProofOptions::new(
            32, 8, 0, FieldExtension::None, 8, 31,
            BatchingMethod::Linear, BatchingMethod::Linear,
        );
        let opts2 = ProofOptions::new(
            64, 8, 0, FieldExtension::None, 8, 31,
            BatchingMethod::Linear, BatchingMethod::Linear,
        );
        let opts3 = ProofOptions::new(
            32, 16, 0, FieldExtension::None, 8, 31,
            BatchingMethod::Linear, BatchingMethod::Linear,
        );

        let vk1 = canonical_vk_bytes(DO_WORK_AIR_ID, 1, 1024, &opts1);
        let vk2 = canonical_vk_bytes(DO_WORK_AIR_ID, 1, 1024, &opts2);
        let vk3 = canonical_vk_bytes(DO_WORK_AIR_ID, 1, 1024, &opts3);

        assert_ne!(vk1, vk2);
        assert_ne!(vk1, vk3);
    }

    #[test]
    fn test_receipt_uses_canonical_vk() -> Result<(), String> {
        let (proof, pub_inputs) = prove_do_work(3, 1024)?;
        let receipt = StarkUpstreamReceipt::from_do_work_canonical(&proof, &pub_inputs, 1024);

        assert!(receipt.vk_params_bytes.starts_with(b"GLYPH-STARK-VK\x00"));
        assert!(receipt.vk_params_bytes.len() > 50);
        Ok(())
    }

    #[test]
    fn test_extract_stark_commitments() -> Result<(), String> {
        let (proof, pub_inputs) = prove_do_work(3, 1024)?;
        let receipt = StarkUpstreamReceipt::from_do_work_canonical(&proof, &pub_inputs, 1024);

        let commitments = super::extract_stark_commitments(&receipt);
        assert_eq!(commitments.len(), 4);
        for c in &commitments {
            assert_ne!(*c, [0u8; 32]);
        }
        // Determinism check
        let commitments2 = super::extract_stark_commitments(&receipt);
        assert_eq!(commitments, commitments2);
        Ok(())
    }

    #[test]
    fn test_stark_receipt_digest() -> Result<(), String> {
        let (proof, pub_inputs) = prove_do_work(3, 1024)?;
        let receipt = StarkUpstreamReceipt::from_do_work_canonical(&proof, &pub_inputs, 1024);

        let digest = super::stark_receipt_digest(&receipt);
        assert_ne!(digest, [0u8; 32]);
        // Determinism check
        let digest2 = super::stark_receipt_digest(&receipt);
        assert_eq!(digest, digest2);
        Ok(())
    }

    #[test]
    fn test_seeded_do_work_receipts_determinism_same_seed() -> Result<(), String> {
        let seed = b"glyph-stark-seed-test";
        let trace_length = 256;

        let receipts1 = seeded_do_work_receipts(seed, trace_length, 2)?;
        let receipts2 = seeded_do_work_receipts(seed, trace_length, 2)?;

        assert_eq!(receipts1.len(), receipts2.len());
        for (a, b) in receipts1.iter().zip(receipts2.iter()) {
            assert_eq!(stark_receipt_digest(a), stark_receipt_digest(b));
        }
        Ok(())
    }

    #[test]
    fn test_seeded_do_work_receipts_change_with_seed() -> Result<(), String> {
        let trace_length = 256;

        let receipts1 = seeded_do_work_receipts(b"seed-a", trace_length, 2)?;
        let receipts2 = seeded_do_work_receipts(b"seed-b", trace_length, 2)?;

        assert_eq!(receipts1.len(), receipts2.len());
        let d1: Vec<[u8; 32]> = receipts1.iter().map(stark_receipt_digest).collect();
        let d2: Vec<[u8; 32]> = receipts2.iter().map(stark_receipt_digest).collect();
        assert_ne!(d1, d2);
        Ok(())
    }

	}

pub fn extract_stark_commitments(receipt: &StarkUpstreamReceipt) -> Vec<[u8; 32]> {
    use tiny_keccak::{Hasher, Keccak};

    fn keccak256(data: &[u8]) -> [u8; 32] {
        let mut hasher = Keccak::v256();
        hasher.update(data);
        let mut out = [0u8; 32];
        hasher.finalize(&mut out);
        out
    }

    let mut commitments = Vec::with_capacity(4);

    let mut buf = Vec::with_capacity(256 + 32);
    buf.extend_from_slice(b"STARK_TRACE_COMMITMENT");
    buf.extend_from_slice(&receipt.proof_bytes[..receipt.proof_bytes.len().min(256)]);
    commitments.push(keccak256(&buf));

    buf.clear();
    buf.extend_from_slice(b"STARK_CONSTRAINT_COMMITMENT");
    buf.extend_from_slice(&receipt.proof_bytes);
    commitments.push(keccak256(&buf));

    buf.clear();
    buf.extend_from_slice(b"STARK_FRI_COMMITMENT");
    buf.extend_from_slice(&receipt.vk_params_bytes);
    buf.extend_from_slice(&receipt.proof_bytes);
    commitments.push(keccak256(&buf));

    buf.clear();
    buf.extend_from_slice(b"STARK_PUBLIC_INPUTS");
    buf.extend_from_slice(&receipt.pub_inputs_bytes);
    commitments.push(keccak256(&buf));

    commitments
}

pub fn stark_receipt_digest(receipt: &StarkUpstreamReceipt) -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak};

    let mut hasher = Keccak::v256();
    hasher.update(b"STARK_RECEIPT_DIGEST");
    hasher.update(&(receipt.proof_bytes.len() as u32).to_be_bytes());
    hasher.update(&receipt.proof_bytes);
    hasher.update(&(receipt.pub_inputs_bytes.len() as u32).to_be_bytes());
    hasher.update(&receipt.pub_inputs_bytes);
    hasher.update(&(receipt.vk_params_bytes.len() as u32).to_be_bytes());
    hasher.update(&receipt.vk_params_bytes);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

pub fn verify_stark_upstream_receipt_do_work(receipt: &StarkUpstreamReceipt) -> Result<(), String> {
    match infer_winterfell_hash_id_from_vk_bytes(&receipt.vk_params_bytes) {
        Some(HASH_BLAKE3_ID) => verify_do_work_from_bytes(&receipt.proof_bytes, &receipt.pub_inputs_bytes),
        Some(HASH_SHA3_ID) => verify_do_work_sha3_from_bytes(&receipt.proof_bytes, &receipt.pub_inputs_bytes),
        Some(other) => Err(format!("unsupported winterfell hash_id=0x{other:02x} in receipt vk bytes")),
        None => {
            // Fallback for legacy / non-canonical VK bytes.
            verify_do_work_from_bytes(&receipt.proof_bytes, &receipt.pub_inputs_bytes).or_else(|e1| {
                verify_do_work_sha3_from_bytes(&receipt.proof_bytes, &receipt.pub_inputs_bytes).map_err(|e2| {
                    format!("receipt verify failed (blake3_err={e1}; sha3_err={e2})")
                })
            })
        }
    }
}

pub fn verify_stark_upstream_receipt_fibonacci(receipt: &StarkUpstreamReceipt) -> Result<(), String> {
    match infer_winterfell_hash_id_from_vk_bytes(&receipt.vk_params_bytes) {
        Some(HASH_BLAKE3_ID) => verify_fibonacci_from_bytes(&receipt.proof_bytes, &receipt.pub_inputs_bytes),
        Some(HASH_SHA3_ID) => verify_fibonacci_sha3_from_bytes(&receipt.proof_bytes, &receipt.pub_inputs_bytes),
        Some(other) => Err(format!("unsupported winterfell hash_id=0x{other:02x} in receipt vk bytes")),
        None => {
            verify_fibonacci_from_bytes(&receipt.proof_bytes, &receipt.pub_inputs_bytes).or_else(|e1| {
                verify_fibonacci_sha3_from_bytes(&receipt.proof_bytes, &receipt.pub_inputs_bytes)
                    .map_err(|e2| format!("receipt verify failed (blake3_err={e1}; sha3_err={e2})"))
            })
        }
    }
}

pub fn verify_stark_upstream_receipt_tribonacci(receipt: &StarkUpstreamReceipt) -> Result<(), String> {
    match infer_winterfell_hash_id_from_vk_bytes(&receipt.vk_params_bytes) {
        Some(HASH_BLAKE3_ID) => verify_tribonacci_from_bytes(&receipt.proof_bytes, &receipt.pub_inputs_bytes),
        Some(HASH_SHA3_ID) => verify_tribonacci_sha3_from_bytes(&receipt.proof_bytes, &receipt.pub_inputs_bytes),
        Some(other) => Err(format!("unsupported winterfell hash_id=0x{other:02x} in receipt vk bytes")),
        None => {
            verify_tribonacci_from_bytes(&receipt.proof_bytes, &receipt.pub_inputs_bytes).or_else(|e1| {
                verify_tribonacci_sha3_from_bytes(&receipt.proof_bytes, &receipt.pub_inputs_bytes)
                    .map_err(|e2| format!("receipt verify failed (blake3_err={e1}; sha3_err={e2})"))
            })
        }
    }
}
