// Copyright 2024-2025 Irreducible Inc.

use std::{borrow::Cow, env, marker::PhantomData, sync::Arc};

use super::{
	CsInstance, ProveFlags, ProverTranscript, ZerocheckProverConstructor,
	augment_flush_po2_step_down, convert_witnesses_to_fast_ext, emit_max_rss,
	get_cached_cs_instance, get_cached_fri_params, greedy_evalcheck, gkr_exp, gkr_gpa,
	make_flush_oracles, make_masked_flush_witnesses, prepare_constraint_system,
	reduce_flush_evalcheck_claims, ring_switch, standard_switchover_heuristic, sumcheck,
	populate_flush_po2_step_down_witnesses, prove_cache_enabled,
};
use super::super::r7x_piop;
use crate::{
	constraint_system::{
		Exp,
		ConstraintSystem,
		Proof,
		ProvePrecomputed,
		channel::Boundary,
		common::{FDomain, FEncode, FExt, FFastExt},
	},
	constraint_system::exp,
	fiat_shamir::{CanSample, Challenger},
	merkle_tree::BinaryMerkleTreeProver,
	oracle::OracleId,
	piop,
	protocols::{
		fri::CommitOutput,
		greedy_evalcheck::GreedyEvalcheckProveOutput,
		gkr_gpa::{GrandProductBatchProveOutput, GrandProductWitness},
	},
	witness::MultilinearExtensionIndex,
};
use binius_compute::{ComputeData, ComputeLayer, alloc::ComputeAllocator, cpu::CpuMemory};
use binius_field::{
	BinaryField, PackedField, PackedFieldIndexable, RepackedExtension,
	as_packed_field::PackedType,
	linear_transformation::PackedTransformationFactory,
	tower::{PackedTop, ProverTowerFamily, ProverTowerUnderlier},
};
use binius_hal::ComputationBackend;
use binius_hash::{PseudoCompressionFunction, multi_digest::ParallelDigest};
use binius_math::{
	DefaultEvaluationDomainFactory, EvaluationOrder, IsomorphicEvaluationDomainFactory,
};
use binius_maybe_rayon::prelude::*;
use binius_utils::bail;
use binius_ntt::SingleThreadedNTT;
use digest::{FixedOutputReset, Output, core_api::BlockSizeUser};
use itertools::chain;

/// R7X core proof pipeline entrypoint.
///
/// This is a dedicated entrypoint intended for BN254 op-trace workloads that
/// keeps the transcript ordering identical to the standard prover while
/// allowing a future specialized constraint-eval, commit, and FRI engine to
/// be swapped in without touching adapter wiring.
#[allow(clippy::too_many_arguments)]
pub fn prove_r7x_core<
	Hal,
	U,
	Tower,
	Hash,
	Compress,
	Challenger_,
	Backend,
	HostAllocatorType,
	DeviceAllocatorType,
>(
	compute_data: &mut ComputeData<Tower::B128, Hal, HostAllocatorType, DeviceAllocatorType>,
	constraint_system: &ConstraintSystem<FExt<Tower>>,
	log_inv_rate: usize,
	security_bits: usize,
	constraint_system_digest: &Output<Hash::Digest>,
	boundaries: &[Boundary<FExt<Tower>>],
	table_sizes: &[usize],
	witness: crate::witness::MultilinearExtensionIndex<
		PackedType<U, FExt<Tower>>,
	>,
	backend: &Backend,
	codeword_scratch: Option<&mut Vec<PackedType<U, FExt<Tower>>>>,
) -> Result<Proof, super::Error>
where
	Hal: ComputeLayer<Tower::B128> + Default,
	U: ProverTowerUnderlier<Tower>,
	Tower: ProverTowerFamily,
	Tower::B128: binius_math::TowerTop
		+ binius_math::PackedTop
		+ PackedTop<Tower>
		+ From<FFastExt<Tower>>,
	Hash: ParallelDigest,
	Hash::Digest: BlockSizeUser + FixedOutputReset + Send + Sync + Clone + 'static,
	Compress: PseudoCompressionFunction<Output<Hash::Digest>, 2> + Default + Sync + 'static,
	Challenger_: Challenger + Default,
	Backend: ComputationBackend,
	PackedType<U, Tower::B128>: PackedTop<Tower>
		+ PackedFieldIndexable
		+ RepackedExtension<PackedType<U, Tower::B1>>
		+ RepackedExtension<PackedType<U, Tower::B8>>
		+ RepackedExtension<PackedType<U, Tower::B16>>
		+ RepackedExtension<PackedType<U, Tower::B32>>
		+ RepackedExtension<PackedType<U, Tower::B64>>
		+ RepackedExtension<PackedType<U, Tower::B128>>
		+ PackedTransformationFactory<PackedType<U, Tower::FastB128>>
		+ binius_math::PackedTop,
	PackedType<U, Tower::FastB128>:
		PackedTransformationFactory<PackedType<U, Tower::B128>>,
	HostAllocatorType: ComputeAllocator<Tower::B128, CpuMemory>,
	DeviceAllocatorType: ComputeAllocator<Tower::B128, Hal::DevMem>,
{
	constraint_system.check_table_sizes(table_sizes)?;
	let instance = if prove_cache_enabled() {
		get_cached_cs_instance(constraint_system, constraint_system_digest.as_ref(), table_sizes)?
	} else {
		Arc::new(prepare_constraint_system(constraint_system, table_sizes)?)
	};
	let flags = ProveFlags {
		has_exponents: !instance.exponents.is_empty(),
		has_non_zero: !instance.non_zero_oracle_ids.is_empty(),
		has_flushes: !instance.flushes.is_empty(),
	};
	prove_r7x_core_with_instance::<
		Hal,
		U,
		Tower,
		Hash,
		Compress,
		Challenger_,
		Backend,
		HostAllocatorType,
		DeviceAllocatorType,
	>(
		compute_data,
		constraint_system_digest,
		log_inv_rate,
		security_bits,
		boundaries,
		table_sizes,
		witness,
		backend,
		&instance,
		flags,
		None,
		codeword_scratch,
	)
}

/// R7X core proof pipeline using precomputed constraint-system state.
#[allow(clippy::too_many_arguments)]
pub fn prove_r7x_core_with_precomputed<
	Hal,
	U,
	Tower,
	Hash,
	Compress,
	Challenger_,
	Backend,
	HostAllocatorType,
	DeviceAllocatorType,
>(
	compute_data: &mut ComputeData<Tower::B128, Hal, HostAllocatorType, DeviceAllocatorType>,
	precomputed: &ProvePrecomputed<Tower>,
	constraint_system_digest: &Output<Hash::Digest>,
	boundaries: &[Boundary<FExt<Tower>>],
	table_sizes: &[usize],
	witness: crate::witness::MultilinearExtensionIndex<
		PackedType<U, FExt<Tower>>,
	>,
	backend: &Backend,
	codeword_scratch: Option<&mut Vec<PackedType<U, FExt<Tower>>>>,
) -> Result<Proof, super::Error>
where
	Hal: ComputeLayer<Tower::B128> + Default,
	U: ProverTowerUnderlier<Tower>,
	Tower: ProverTowerFamily,
	Tower::B128: binius_math::TowerTop
		+ binius_math::PackedTop
		+ PackedTop<Tower>
		+ From<FFastExt<Tower>>,
	Hash: ParallelDigest,
	Hash::Digest: BlockSizeUser + FixedOutputReset + Send + Sync + Clone + 'static,
	Compress: PseudoCompressionFunction<Output<Hash::Digest>, 2> + Default + Sync + 'static,
	Challenger_: Challenger + Default,
	Backend: ComputationBackend,
	PackedType<U, Tower::B128>: PackedTop<Tower>
		+ PackedFieldIndexable
		+ RepackedExtension<PackedType<U, Tower::B1>>
		+ RepackedExtension<PackedType<U, Tower::B8>>
		+ RepackedExtension<PackedType<U, Tower::B16>>
		+ RepackedExtension<PackedType<U, Tower::B32>>
		+ RepackedExtension<PackedType<U, Tower::B64>>
		+ RepackedExtension<PackedType<U, Tower::B128>>
		+ PackedTransformationFactory<PackedType<U, Tower::FastB128>>
		+ binius_math::PackedTop,
	PackedType<U, Tower::FastB128>:
		PackedTransformationFactory<PackedType<U, Tower::B128>>,
	HostAllocatorType: ComputeAllocator<Tower::B128, CpuMemory>,
	DeviceAllocatorType: ComputeAllocator<Tower::B128, Hal::DevMem>,
{
	let instance = &precomputed.instance;
	let flags = precomputed.flags;
	prove_r7x_core_with_instance::<
		Hal,
		U,
		Tower,
		Hash,
		Compress,
		Challenger_,
		Backend,
		HostAllocatorType,
		DeviceAllocatorType,
	>(
		compute_data,
		constraint_system_digest,
		precomputed.log_inv_rate,
		precomputed.security_bits,
		boundaries,
		table_sizes,
		witness,
		backend,
		instance,
		flags,
		Some(precomputed),
		codeword_scratch,
	)
}

#[allow(clippy::too_many_arguments)]
fn prove_r7x_core_with_instance<
	Hal,
	U,
	Tower,
	Hash,
	Compress,
	Challenger_,
	Backend,
	HostAllocatorType,
	DeviceAllocatorType,
>(
	compute_data: &mut ComputeData<Tower::B128, Hal, HostAllocatorType, DeviceAllocatorType>,
	constraint_system_digest: &Output<Hash::Digest>,
	log_inv_rate: usize,
	security_bits: usize,
	boundaries: &[Boundary<FExt<Tower>>],
	table_sizes: &[usize],
	mut witness: MultilinearExtensionIndex<PackedType<U, FExt<Tower>>>,
	backend: &Backend,
	instance: &CsInstance<FExt<Tower>>,
	flags: ProveFlags,
	precomputed: Option<&ProvePrecomputed<Tower>>,
	mut codeword_scratch: Option<&mut Vec<PackedType<U, FExt<Tower>>>>,
) -> Result<Proof, super::Error>
where
	Hal: ComputeLayer<Tower::B128> + Default,
	U: ProverTowerUnderlier<Tower>,
	Tower: ProverTowerFamily,
	Tower::B128: binius_math::TowerTop
		+ binius_math::PackedTop
		+ PackedTop<Tower>
		+ From<FFastExt<Tower>>,
	Hash: ParallelDigest,
	Hash::Digest: BlockSizeUser + FixedOutputReset + Send + Sync + Clone + 'static,
	Compress: PseudoCompressionFunction<Output<Hash::Digest>, 2> + Default + Sync + 'static,
	Challenger_: Challenger + Default,
	Backend: ComputationBackend,
	PackedType<U, Tower::B128>: PackedTop<Tower>
		+ PackedFieldIndexable
		+ RepackedExtension<PackedType<U, Tower::B1>>
		+ RepackedExtension<PackedType<U, Tower::B8>>
		+ RepackedExtension<PackedType<U, Tower::B16>>
		+ RepackedExtension<PackedType<U, Tower::B32>>
		+ RepackedExtension<PackedType<U, Tower::B64>>
		+ RepackedExtension<PackedType<U, Tower::B128>>
		+ PackedTransformationFactory<PackedType<U, Tower::FastB128>>
		+ binius_math::PackedTop,
	PackedType<U, Tower::FastB128>:
		PackedTransformationFactory<PackedType<U, Tower::B128>>,
	HostAllocatorType: ComputeAllocator<Tower::B128, CpuMemory>,
	DeviceAllocatorType: ComputeAllocator<Tower::B128, Hal::DevMem>,
{
	tracing::debug!(
		arch = env::consts::ARCH,
		rayon_threads = binius_maybe_rayon::current_num_threads(),
		"using computation backend: {backend:?}"
	);

	let (domain_factory, fast_domain_factory) = if let Some(precomputed) = precomputed {
		(
			precomputed.domain_factory.clone(),
			precomputed.fast_domain_factory.clone(),
		)
	} else {
		(
			DefaultEvaluationDomainFactory::<FDomain<Tower>>::default(),
			IsomorphicEvaluationDomainFactory::<FFastExt<Tower>>::default(),
		)
	};

	let mut oracles = if flags.has_flushes {
		Cow::Owned(instance.oracles.clone())
	} else {
		Cow::Borrowed(&instance.oracles)
	};
	let table_constraints = instance.table_constraints.as_slice();
	let table_constraints_len = table_constraints.len();
	let _zerocheck_claims = instance.zerocheck_claims.as_slice();
	let zerocheck_oracle_metas = instance.zerocheck_oracle_metas.as_slice();
	let constraint_set_base_tower_levels = instance.constraint_set_base_tower_levels.as_slice();
	let zerocheck_max_n_vars = instance.zerocheck_max_n_vars;
	let zerocheck_min_log_degree = instance.zerocheck_min_log_degree;
	let mut flushes = if flags.has_flushes {
		instance.flushes.clone()
	} else {
		Vec::new()
	};
	let flushes_sorted = instance.flushes_sorted;
	let exponents: &[Exp<FExt<Tower>>] = if flags.has_exponents {
		instance.exponents.as_slice()
	} else {
		&[]
	};
	let non_zero_oracle_ids: &[OracleId] = if flags.has_non_zero {
		instance.non_zero_oracle_ids.as_slice()
	} else {
		&[]
	};
	let channel_count = instance.channel_count;
	let challenge_count = instance.challenge_count;
	let table_size_specs = instance.table_size_specs.as_slice();

	let mut transcript = ProverTranscript::<Challenger_>::new();
	transcript.observe().write_slice(constraint_system_digest.as_ref());
	transcript.observe().write_slice(boundaries);
	let mut writer = transcript.message();
	writer.write_slice(table_sizes);
	super::trace_transcript_checkpoint(&transcript, "table_sizes");

	let witness_span = tracing::info_span!(
		"[phase] Witness Finalization",
		phase = "witness",
		perfetto_category = "phase.main"
	)
	.entered();

	let exp_compute_layer_span = tracing::info_span!(
		"[step] Compute Exponentiation Layers",
		phase = "witness",
		perfetto_category = "phase.sub"
	)
	.entered();
	let has_exponents = flags.has_exponents;
	let exp_witnesses = if has_exponents {
		exp::make_exp_witnesses::<U, Tower>(&mut witness, oracles.as_ref(), exponents)?
	} else {
		Vec::new()
	};
	drop(exp_compute_layer_span);
	drop(witness_span);

	let merkle_prover = BinaryMerkleTreeProver::<_, Hash, _>::new(Compress::default());
	let merkle_scheme = merkle_prover.scheme();

	let commit_meta = &instance.commit_meta;
	let oracle_to_commit_index = &instance.oracle_to_commit_index;
	let committed_multilins = instance
		.commit_oracle_ids
		.par_iter()
		.map(|oracle_id| witness.get_multilin_poly(*oracle_id))
		.collect::<Result<Vec<_>, _>>()?;
	let packed_committed_multilins = r7x_piop::pack_committed_multilins::<
		FExt<Tower>,
		PackedType<U, FExt<Tower>>,
		_,
	>(&committed_multilins)?;

	let (fri_params, ntt) = if let Some(precomputed) = precomputed {
		(precomputed.fri_params.clone(), precomputed.ntt.clone())
	} else if prove_cache_enabled() {
		let (fri_params, ntt) = get_cached_fri_params::<Tower, _>(
			commit_meta,
			merkle_scheme,
			security_bits,
			log_inv_rate,
			&instance.fri_cache,
		)?;
		(fri_params, ntt)
	} else {
		let fri_params = piop::make_commit_params_with_optimal_arity::<_, FEncode<Tower>, _>(
			commit_meta,
			merkle_scheme,
			security_bits,
			log_inv_rate,
		)?;
		let ntt = SingleThreadedNTT::with_subspace(fri_params.rs_code().subspace())?
			.precompute_twiddles()
			.multithreaded();
		(Arc::new(fri_params), Arc::new(ntt))
	};
	let fri_params = fri_params.as_ref();
	let ntt = ntt.as_ref();

	let commit_span =
		tracing::info_span!("[phase] Commit", phase = "commit", perfetto_category = "phase.main")
			.entered();
	let CommitOutput {
		commitment,
		committed,
		mut codeword,
	} = r7x_piop::commit_packed(
		fri_params,
		ntt,
		&merkle_prover,
		&packed_committed_multilins,
		codeword_scratch.as_deref_mut(),
	)?;
	let packed_committed_ranges =
		r7x_piop::build_packed_committed_ranges(&packed_committed_multilins);
	let packed_device = r7x_piop::prepare_packed_committed_device(
		compute_data,
		&packed_committed_multilins,
		&packed_committed_ranges,
	)?;
	let packed_device_available = packed_device.is_some();
	let packed_committed_multilins = if packed_device_available {
		Vec::new()
	} else {
		packed_committed_multilins
	};
	emit_max_rss();
	drop(commit_span);

	let mut writer = transcript.message();
	writer.write(&commitment);
	super::trace_transcript_checkpoint(&transcript, "commitment");

	let exp_span = tracing::info_span!(
		"[phase] Exponentiation",
		phase = "exp",
		perfetto_category = "phase.main"
	)
	.entered();
	let exp_challenge = transcript.sample_vec(instance.exp_max_n_vars);

	let exp_evals: Vec<FExt<Tower>> = if has_exponents {
		gkr_exp::get_evals_in_point_from_witnesses(&exp_witnesses, &exp_challenge)?
			.into_iter()
			.map(|x| x.into())
			.collect::<Vec<_>>()
	} else {
		Vec::new()
	};

	let mut writer = transcript.message();
	writer.write_scalar_slice(&exp_evals);
	super::trace_transcript_checkpoint(&transcript, "exp_evals");

	let exp_challenge = exp_challenge
		.into_iter()
		.map(|x| x.into())
		.collect::<Vec<_>>();

	let exp_claims = if has_exponents {
		exp::make_claims(exponents, oracles.as_ref(), &exp_challenge, &exp_evals)?
			.into_iter()
			.map(|claim| claim.isomorphic())
			.collect::<Vec<_>>()
	} else {
		Vec::new()
	};
	drop(exp_evals);
	drop(exp_challenge);

	let base_exp_output: gkr_exp::BaseExpReductionOutput<FExt<Tower>> = if has_exponents
	{
		gkr_exp::batch_prove::<_, _, FFastExt<Tower>, _, _>(
			EvaluationOrder::HighToLow,
			exp_witnesses,
			&exp_claims,
			fast_domain_factory.clone(),
			&mut transcript,
			backend,
		)?
		.isomorphic()
	} else {
		gkr_exp::BaseExpReductionOutput {
			layers_claims: Vec::new(),
		}
	};

	let exp_eval_claims = if has_exponents {
		exp::make_eval_claims(exponents, base_exp_output)?
	} else {
		Vec::new()
	};
	emit_max_rss();
	drop(exp_span);

	let prodcheck_span = tracing::info_span!(
		"[phase] Product Check",
		phase = "prodcheck",
		perfetto_category = "phase.main"
	)
	.entered();

	let has_non_zero = flags.has_non_zero;
	let non_zero_fast_witnesses = if has_non_zero {
		let nonzero_convert_span = tracing::info_span!(
			"[task] Convert Non-Zero to Fast Field",
			phase = "prodcheck",
			perfetto_category = "task.main"
		)
		.entered();
		let witnesses =
			convert_witnesses_to_fast_ext::<U, _>(oracles.as_ref(), &witness, non_zero_oracle_ids)?;
		emit_max_rss();
		drop(nonzero_convert_span);
		witnesses
	} else {
		Vec::new()
	};

	let non_zero_prodcheck_witnesses = if has_non_zero {
		let nonzero_prodcheck_compute_layer_span = tracing::info_span!(
			"[step] Compute Non-Zero Product Layers",
			phase = "prodcheck",
			perfetto_category = "phase.sub"
		)
		.entered();
		let witnesses = non_zero_fast_witnesses
			.into_par_iter()
			.map(|(n_vars, evals)| GrandProductWitness::new(n_vars, evals))
			.collect::<Result<Vec<_>, _>>()?;
		emit_max_rss();
		drop(nonzero_prodcheck_compute_layer_span);
		witnesses
	} else {
		Vec::new()
	};

	let non_zero_products = if has_non_zero {
		gkr_gpa::get_grand_products_from_witnesses(&non_zero_prodcheck_witnesses)
	} else {
		Vec::new()
	};
	if non_zero_products
		.iter()
		.any(|count| *count == Tower::B128::zero())
	{
		bail!(super::Error::Zeros);
	}

	let mut writer = transcript.message();
	writer.write_scalar_slice(&non_zero_products);
	super::trace_transcript_checkpoint(&transcript, "non_zero_products");

	if challenge_count > 0 {
		let challenges: Vec<Tower::B128> = transcript.sample_vec(challenge_count as usize);
		crate::transparent::challenge::set_challenge_values(challenges);
	}

	let non_zero_prodcheck_claims = if has_non_zero {
		gkr_gpa::construct_grand_product_claims(
			non_zero_oracle_ids,
			oracles.as_ref(),
			&non_zero_products,
		)?
	} else {
		Vec::new()
	};
	drop(non_zero_products);

	let mixing_challenge = transcript.sample();
	let permutation_challenges = transcript.sample_vec(channel_count);
	if !flushes_sorted {
		flushes.sort_by_key(|flush| flush.channel_id);
	}
	if !flushes.is_empty() {
		let po2_step_down_polys = augment_flush_po2_step_down(
			oracles.to_mut(),
			&mut flushes,
			table_size_specs,
			table_sizes,
		)?;
		populate_flush_po2_step_down_witnesses::<U, _>(po2_step_down_polys, &mut witness)?;
	}
	let flush_oracle_ids = if flushes.is_empty() {
		Vec::new()
	} else {
		make_flush_oracles(
			oracles.to_mut(),
			&flushes,
			mixing_challenge,
			&permutation_challenges,
		)?
	};

	let mut fast_witness = MultilinearExtensionIndex::<PackedType<U, FFastExt<Tower>>>::new();
	let flush_witnesses = if flush_oracle_ids.is_empty() {
		Vec::new()
	} else {
		let flush_convert_span = tracing::info_span!(
			"[task] Convert Flushes to Fast Field",
			phase = "prodcheck",
			perfetto_category = "task.main"
		)
		.entered();
		make_masked_flush_witnesses::<U, _>(
			oracles.as_ref(),
			&mut witness,
			&mut fast_witness,
			&flush_oracle_ids,
			&flushes,
			mixing_challenge,
			&permutation_challenges,
		)?;
		let flush_witnesses = convert_witnesses_to_fast_ext::<U, _>(
			oracles.as_ref(),
			&witness,
			&flush_oracle_ids,
		)?;
		emit_max_rss();
		drop(flush_convert_span);
		flush_witnesses
	};
	drop(flushes);
	let _ = mixing_challenge;
	drop(permutation_challenges);

	let (flush_prodcheck_witnesses, flush_prodcheck_claims) = if flush_oracle_ids.is_empty() {
		(Vec::new(), Vec::new())
	} else {
		let flush_prodcheck_compute_layer_span = tracing::info_span!(
			"[step] Compute Flush Product Layers",
			phase = "prodcheck",
			perfetto_category = "phase.sub"
		)
		.entered();
		let flush_prodcheck_witnesses = flush_witnesses
			.into_par_iter()
			.map(|(n_vars, evals)| GrandProductWitness::new(n_vars, evals))
			.collect::<Result<Vec<_>, _>>()?;
		emit_max_rss();
		drop(flush_prodcheck_compute_layer_span);

		let flush_products = gkr_gpa::get_grand_products_from_witnesses(&flush_prodcheck_witnesses);
		transcript.message().write_scalar_slice(&flush_products);
		super::trace_transcript_checkpoint(&transcript, "flush_products");
		let flush_prodcheck_claims = gkr_gpa::construct_grand_product_claims(
			&flush_oracle_ids,
			oracles.as_ref(),
			&flush_products,
		)?;
		(flush_prodcheck_witnesses, flush_prodcheck_claims)
	};

	let (all_gpa_witnesses, all_gpa_claims) = match (
		flush_prodcheck_witnesses.is_empty(),
		non_zero_prodcheck_witnesses.is_empty(),
	) {
		(true, true) => (Vec::new(), Vec::new()),
		(true, false) => (
			non_zero_prodcheck_witnesses,
			non_zero_prodcheck_claims
				.into_iter()
				.map(|claim| claim.isomorphic())
				.collect::<Vec<_>>(),
		),
		(false, true) => (
			flush_prodcheck_witnesses,
			flush_prodcheck_claims
				.into_iter()
				.map(|claim| claim.isomorphic())
				.collect::<Vec<_>>(),
		),
		(false, false) => {
			let all_gpa_witnesses = chain!(flush_prodcheck_witnesses, non_zero_prodcheck_witnesses)
				.collect::<Vec<_>>();
			let all_gpa_claims = chain!(flush_prodcheck_claims, non_zero_prodcheck_claims)
				.map(|claim| claim.isomorphic())
				.collect::<Vec<_>>();
			(all_gpa_witnesses, all_gpa_claims)
		}
	};

	let final_layer_claims = if all_gpa_claims.is_empty() {
		Vec::new()
	} else {
		let GrandProductBatchProveOutput { final_layer_claims } =
			gkr_gpa::batch_prove::<FFastExt<Tower>, _, FFastExt<Tower>, _, _>(
				EvaluationOrder::HighToLow,
				all_gpa_witnesses,
				&all_gpa_claims,
				&fast_domain_factory,
				&mut transcript,
				backend,
			)?;
		final_layer_claims
	};

	let final_layer_claims = final_layer_claims
		.into_iter()
		.map(|layer_claim| layer_claim.isomorphic())
		.collect::<Vec<_>>();

	let (flush_eval_claims, prodcheck_eval_claims) = if flush_oracle_ids.is_empty() {
		let prodcheck_eval_claims = gkr_gpa::make_eval_claims(
			non_zero_oracle_ids.iter().copied(),
			final_layer_claims,
		)?;
		(Vec::new(), prodcheck_eval_claims)
	} else {
		let prodcheck_eval_claims = gkr_gpa::make_eval_claims(
			chain!(flush_oracle_ids.iter().copied(), non_zero_oracle_ids.iter().copied()),
			final_layer_claims,
		)?;
		let mut flush_prodcheck_eval_claims = prodcheck_eval_claims;
		let prodcheck_eval_claims =
			flush_prodcheck_eval_claims.split_off(flush_oracle_ids.len());
		let flush_eval_claims = reduce_flush_evalcheck_claims::<U, Tower, Challenger_, Backend>(
			flush_prodcheck_eval_claims,
			oracles.as_ref(),
			fast_witness,
			fast_domain_factory.clone(),
			&mut transcript,
			backend,
		)?;
		(flush_eval_claims, prodcheck_eval_claims)
	};

	emit_max_rss();
	drop(prodcheck_span);

	let zerocheck_span = tracing::info_span!(
		"[phase] Zerocheck",
		phase = "zerocheck",
		perfetto_category = "phase.main",
	)
	.entered();

	let max_n_vars = zerocheck_max_n_vars;
	let domain_max_skip_rounds =
		FDomain::<Tower>::N_BITS.saturating_sub(zerocheck_min_log_degree);
	let skip_rounds = domain_max_skip_rounds.min(max_n_vars);

	let zerocheck_challenges = transcript.sample_vec(max_n_vars - skip_rounds);

	let mut zerocheck_provers = Vec::with_capacity(table_constraints_len);

	for (constraint_set, base_tower_level) in table_constraints
		.iter()
		.zip(constraint_set_base_tower_levels.iter().copied()) {
		let n_vars = constraint_set.n_vars;
		let (constraints, multilinears) =
			sumcheck::prove::split_constraint_set_ref(constraint_set, &witness)?;

		let zerocheck_challenges = &zerocheck_challenges[max_n_vars - n_vars.max(skip_rounds)..];
		let domain_factory = domain_factory.clone();

		let constructor =
			ZerocheckProverConstructor::<PackedType<U, FExt<Tower>>, FDomain<Tower>, _, _> {
				constraints,
				multilinears,
				zerocheck_challenges,
				domain_factory,
				backend,
				_fdomain_marker: PhantomData,
			};

		let zerocheck_prover = match base_tower_level {
			0..=3 => constructor.create::<Tower::B8>()?,
			4 => constructor.create::<Tower::B16>()?,
			5 => constructor.create::<Tower::B32>()?,
			6 => constructor.create::<Tower::B64>()?,
			7 => constructor.create::<Tower::B128>()?,
			_ => unreachable!(),
		};

		zerocheck_provers.push(zerocheck_prover);
	}

	let zerocheck_output = sumcheck::prove::batch_prove_zerocheck::<
		FExt<Tower>,
		FDomain<Tower>,
		PackedType<U, FExt<Tower>>,
		_,
		_,
	>(zerocheck_provers, skip_rounds, &mut transcript)?;

	let zerocheck_eval_claims =
		sumcheck::make_zerocheck_eval_claims(zerocheck_oracle_metas.iter().cloned(), zerocheck_output)?;

	emit_max_rss();
	drop(zerocheck_span);

	let evalcheck_span = tracing::info_span!(
		"[phase] Evalcheck",
		phase = "evalcheck",
		perfetto_category = "phase.main"
	)
	.entered();

	let GreedyEvalcheckProveOutput {
		eval_claims,
		memoized_data,
	} = greedy_evalcheck::prove::<_, _, FDomain<Tower>, _, _>(
		oracles.to_mut(),
		&mut witness,
		chain!(flush_eval_claims, prodcheck_eval_claims, zerocheck_eval_claims, exp_eval_claims,),
		standard_switchover_heuristic(-2),
		&mut transcript,
		&domain_factory,
		backend,
	)?;

	let system = ring_switch::EvalClaimSystem::new(
		oracles.as_ref(),
		commit_meta,
		oracle_to_commit_index,
		&eval_claims,
	)?;

	emit_max_rss();
	drop(evalcheck_span);

	let ring_switch_span = tracing::info_span!(
		"[phase] Ring Switch",
		phase = "ring_switch",
		perfetto_category = "phase.main"
	)
	.entered();

	let hal = compute_data.hal;
	let dev_alloc = &compute_data.dev_alloc;
	let host_alloc = &compute_data.host_alloc;

	let ring_switch::ReducedWitness {
		transparents: transparent_multilins,
		sumcheck_claims: piop_sumcheck_claims,
	} = ring_switch::prove(
		&system,
		&committed_multilins,
		&mut transcript,
		memoized_data,
		hal,
		dev_alloc,
		host_alloc,
	)?;
	emit_max_rss();
	drop(ring_switch_span);

	let piop_compiler_span = tracing::info_span!(
		"[phase] PIOP Compiler",
		phase = "piop_compiler",
		perfetto_category = "phase.main"
	)
	.entered();

	r7x_piop::prove_with_packed(
		compute_data,
		fri_params,
		ntt,
		&merkle_prover,
		commit_meta,
		committed,
		&codeword,
		&packed_committed_multilins,
		Some(&packed_committed_ranges),
		&transparent_multilins,
		&piop_sumcheck_claims,
		Some(instance.piop_committed_ranges.as_slice()),
		packed_device,
		&mut transcript,
	)?;
	if let Some(buf) = codeword_scratch.as_deref_mut() {
		*buf = codeword;
	}
	super::trace_transcript_checkpoint(&transcript, "piop_prove");
	emit_max_rss();
	drop(piop_compiler_span);

	let proof = Proof {
		transcript: transcript.finalize(),
	};

	tracing::event!(
		name: "proof_size",
		tracing::Level::INFO,
		counter = true,
		value = proof.get_proof_size() as u64,
		unit = "bytes",
	);

	Ok(proof)
}
