// Copyright 2024-2025 Irreducible Inc.

use std::{
	any::{Any, TypeId},
	borrow::Cow,
	cell::RefCell,
	collections::HashMap,
	env,
	iter,
	marker::PhantomData,
	sync::{Arc, Mutex, OnceLock},
};

use binius_compute::{ComputeData, ComputeLayer, alloc::ComputeAllocator, cpu::CpuMemory};
use binius_fast_compute::arith_circuit::ArithCircuitPoly;
use binius_field::{
	BinaryField, ExtensionField, Field, PackedExtension, PackedField, PackedFieldIndexable,
	RepackedExtension, TowerField,
	as_packed_field::PackedType,
	linear_transformation::{PackedTransformationFactory, Transformation},
	tower::{PackedTop, ProverTowerFamily, ProverTowerUnderlier},
	underlier::WithUnderlier,
	util::powers,
};
use binius_hal::ComputationBackend;
use binius_hash::{PseudoCompressionFunction, multi_digest::ParallelDigest};
use binius_math::{
	CompositionPoly, DefaultEvaluationDomainFactory, EvaluationDomainFactory, EvaluationOrder,
	IsomorphicEvaluationDomainFactory, MLEDirectAdapter, MultilinearExtension, MultilinearPoly,
};
use binius_maybe_rayon::prelude::*;
use binius_ntt::{SingleThreadedNTT, MultithreadedNTT, twiddle::PrecomputedTwiddleAccess};
use binius_utils::{bail, checked_arithmetics::log2_ceil_usize};
use bytemuck::zeroed_vec;
use digest::{FixedOutputReset, Output, core_api::BlockSizeUser};
use itertools::chain;
use tracing::instrument;
#[cfg(not(windows))]
use tracing_profile::utils::emit_max_rss as emit_max_rss_inner;

#[cfg(windows)]
fn emit_max_rss_inner() {}

thread_local! {
	static PIOP_CODEWORD_SCRATCH: RefCell<HashMap<TypeId, Box<dyn Any>>> =
		RefCell::new(HashMap::new());
}

use super::{
	ConstraintSystem, Proof,
	channel::Boundary,
	error::Error,
	verify::make_flush_oracles,
};

mod r7x_core;
pub use r7x_core::{prove_r7x_core, prove_r7x_core_with_precomputed};
use crate::{
	constraint_system::{
		Exp,
		Flush,
		channel::OracleOrConst,
		common::{FDomain, FEncode, FExt, FFastExt},
		exp::{self, reorder_exponents},
		verify::augment_flush_po2_step_down,
	},
	fiat_shamir::{CanSample, Challenger},
	merkle_tree::BinaryMerkleTreeProver,
	oracle::{
		Constraint, ConstraintSetBuilder, MultilinearOracleSet, MultilinearPolyVariant, OracleId,
		SizedConstraintSet,
	},
	piop,
	protocols::{
		evalcheck::{
			ConstraintSetEqIndPoint, EvalPoint, EvalcheckMultilinearClaim,
			subclaims::{MemoizedData, prove_mlecheck_with_switchover},
		},
		fri::CommitOutput,
		gkr_exp,
		gkr_gpa::{self, GrandProductBatchProveOutput, GrandProductWitness},
		greedy_evalcheck::{self, GreedyEvalcheckProveOutput},
		sumcheck::{
			self, immediate_switchover_heuristic,
			prove::ZerocheckProver, standard_switchover_heuristic,
		},
	},
	ring_switch,
	transcript::ProverTranscript,
	transparent::step_down::StepDown,
	witness::{IndexEntry, MultilinearExtensionIndex, MultilinearWitness},
};

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct ProveCacheKey {
	field_type_id: TypeId,
	merkle_type_id: TypeId,
	total_vars: usize,
	total_multilins: usize,
	log_inv_rate: usize,
	security_bits: usize,
}

struct ProveCacheEntry<F, FE>
where
	F: BinaryField,
	FE: BinaryField,
{
	fri_params: Arc<crate::protocols::fri::FRIParams<F, FE>>,
	ntt: Arc<MultithreadedNTT<FE, PrecomputedTwiddleAccess<FE>>>,
}

#[derive(Debug)]
pub(crate) struct CsInstance<F: TowerField> {
	oracles: MultilinearOracleSet<F>,
	commit_meta: piop::CommitMeta,
	oracle_to_commit_index: binius_utils::sparse_index::SparseIndex<usize>,
	commit_oracle_ids: Vec<OracleId>,
	piop_committed_ranges: Vec<std::ops::Range<usize>>,
	fri_cache: Arc<Mutex<HashMap<ProveCacheKey, Box<dyn std::any::Any + Send + Sync>>>>,
	#[allow(dead_code)]
	oracle_count: usize,
	#[allow(dead_code)]
	max_oracle_id: usize,
	exp_max_n_vars: usize,
	table_constraints: Vec<SizedConstraintSet<F>>,
	constraint_set_base_tower_levels: Vec<usize>,
	zerocheck_claims: Vec<sumcheck::ZerocheckClaim<F, ArithCircuitPoly<F>>>,
	zerocheck_oracle_metas: Vec<sumcheck::OracleClaimMeta>,
	zerocheck_max_n_vars: usize,
	zerocheck_min_log_degree: usize,
	flushes: Vec<Flush<F>>,
	flushes_sorted: bool,
	exponents: Vec<Exp<F>>,
	non_zero_oracle_ids: Vec<OracleId>,
	channel_count: usize,
	challenge_count: u32,
	table_size_specs: Vec<crate::constraint_system::TableSizeSpec>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ProveFlags {
	has_exponents: bool,
	has_non_zero: bool,
	has_flushes: bool,
}

pub struct ProvePrecomputed<Tower: ProverTowerFamily> {
	pub(crate) instance: Arc<CsInstance<FExt<Tower>>>,
	pub(crate) log_inv_rate: usize,
	pub(crate) security_bits: usize,
	pub(crate) flags: ProveFlags,
	pub(crate) fri_params: Arc<crate::protocols::fri::FRIParams<FExt<Tower>, FEncode<Tower>>>,
	pub(crate) ntt: Arc<MultithreadedNTT<FEncode<Tower>, PrecomputedTwiddleAccess<FEncode<Tower>>>>,
	pub(crate) domain_factory: DefaultEvaluationDomainFactory<FDomain<Tower>>,
	pub(crate) fast_domain_factory: IsomorphicEvaluationDomainFactory<FFastExt<Tower>>,
}

impl<Tower: ProverTowerFamily> std::fmt::Debug for ProvePrecomputed<Tower> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("ProvePrecomputed")
			.field("log_inv_rate", &self.log_inv_rate)
			.field("security_bits", &self.security_bits)
			.field("flags", &self.flags)
			.finish()
	}
}

impl<Tower: ProverTowerFamily> Clone for ProvePrecomputed<Tower> {
	fn clone(&self) -> Self {
		Self {
			instance: self.instance.clone(),
			log_inv_rate: self.log_inv_rate,
			security_bits: self.security_bits,
			flags: self.flags,
			fri_params: self.fri_params.clone(),
			ntt: self.ntt.clone(),
			domain_factory: self.domain_factory.clone(),
			fast_domain_factory: self.fast_domain_factory.clone(),
		}
	}
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct CsInstanceCacheKey {
	field_type_id: TypeId,
	cs_digest: Box<[u8]>,
	table_sizes: Vec<usize>,
}

static CS_INSTANCE_CACHE: OnceLock<
	Mutex<HashMap<CsInstanceCacheKey, Box<dyn std::any::Any + Send + Sync>>>,
> = OnceLock::new();

pub(crate) fn prove_cache_enabled() -> bool {
	env::var("ORIGAMI_BN254_R7X_CORE_CACHE")
		.ok()
		.as_deref()
		.map(|v| v == "1")
		.unwrap_or(false)
}

fn r7x_core_fast_enabled() -> bool {
	env::var("ORIGAMI_BN254_R7X_CORE_FAST")
		.ok()
		.as_deref()
		.map(|v| v == "1")
		.unwrap_or(false)
}

fn emit_max_rss() {
	if !r7x_core_fast_enabled() {
		emit_max_rss_inner();
	}
}

fn trace_transcript_checkpoint<Challenger_: Challenger>(
	transcript: &ProverTranscript<Challenger_>,
	label: &str,
) {
	if env::var("ORIGAMI_BN254_R7X_TRACE_TRANSCRIPT")
		.ok()
		.as_deref()
		!= Some("1")
	{
		return;
	}
	let bytes = transcript.debug_bytes();
	let len = bytes.len();
	let tail_len = 16usize.min(len);
	let tail = &bytes[len.saturating_sub(tail_len)..];
	let prefix = env::var("ORIGAMI_BN254_R7X_TRACE_TRANSCRIPT_PREFIX")
		.unwrap_or_else(|_| "r7x".to_string());
	eprintln!(
		"r7x transcript [{}] {} len={} tail={:02x?}",
		prefix, label, len, tail
	);
}

fn get_cached_fri_params<Tower, MTScheme>(
	commit_meta: &piop::CommitMeta,
	merkle_scheme: &MTScheme,
	security_bits: usize,
	log_inv_rate: usize,
	cache: &Mutex<HashMap<ProveCacheKey, Box<dyn std::any::Any + Send + Sync>>>,
) -> Result<
	(
		Arc<crate::protocols::fri::FRIParams<FExt<Tower>, FEncode<Tower>>>,
		Arc<MultithreadedNTT<FEncode<Tower>, PrecomputedTwiddleAccess<FEncode<Tower>>>>,
	),
	Error,
>
where
	Tower: ProverTowerFamily,
	MTScheme: crate::merkle_tree::MerkleTreeScheme<FExt<Tower>> + 'static,
{
	let key = ProveCacheKey {
		field_type_id: TypeId::of::<FEncode<Tower>>(),
		merkle_type_id: TypeId::of::<MTScheme>(),
		total_vars: commit_meta.total_vars(),
		total_multilins: commit_meta.total_multilins(),
		log_inv_rate,
		security_bits,
	};
	{
		let cache_guard = cache.lock().expect("prove cache mutex");
		if let Some(entry) = cache_guard.get(&key) {
			let typed = entry
				.downcast_ref::<ProveCacheEntry<FExt<Tower>, FEncode<Tower>>>()
				.expect("prove cache type mismatch");
			return Ok((typed.fri_params.clone(), typed.ntt.clone()));
		}
	}
	let fri_params = piop::make_commit_params_with_optimal_arity::<_, FEncode<Tower>, _>(
		commit_meta,
		merkle_scheme,
		security_bits,
		log_inv_rate,
	)?;
	let ntt = SingleThreadedNTT::with_subspace(fri_params.rs_code().subspace())?
		.precompute_twiddles()
		.multithreaded();
	let entry = ProveCacheEntry::<FExt<Tower>, FEncode<Tower>> {
		fri_params: Arc::new(fri_params),
		ntt: Arc::new(ntt),
	};
	let mut cache_guard = cache.lock().expect("prove cache mutex");
	cache_guard.insert(key, Box::new(ProveCacheEntry::<FExt<Tower>, FEncode<Tower>> {
		fri_params: entry.fri_params.clone(),
		ntt: entry.ntt.clone(),
	}));
	Ok((entry.fri_params, entry.ntt))
}

pub(crate) fn prepare_constraint_system<F: TowerField>(
	constraint_system: &ConstraintSystem<F>,
	table_sizes: &[usize],
) -> Result<CsInstance<F>, Error> {
	let ConstraintSystem {
		oracles,
		table_constraints,
		mut flushes,
		mut exponents,
		mut non_zero_oracle_ids,
		channel_count,
		challenge_count,
		table_size_specs,
	} = constraint_system.clone();

	let oracles = oracles.instantiate(table_sizes)?;
	let (commit_meta, oracle_to_commit_index) = piop::make_oracle_commit_meta(&oracles)?;
	let mut commit_oracle_ids = vec![None; commit_meta.total_multilins()];
	let mut oracle_count = 0usize;
	let mut max_oracle_id = 0usize;
	for oracle_id in oracles.ids() {
		oracle_count += 1;
		let idx = oracle_id.index();
		if idx > max_oracle_id {
			max_oracle_id = idx;
		}
		if let Some(commit_idx) = oracle_to_commit_index.get(idx) {
			commit_oracle_ids[*commit_idx] = Some(oracle_id);
		}
	}
	let commit_oracle_ids = commit_oracle_ids
		.into_iter()
		.map(|oracle_id| {
			oracle_id.expect("commit oracle index is surjective over committed oracles")
		})
		.collect::<Vec<_>>();
	let mut piop_committed_ranges = Vec::with_capacity(commit_meta.max_n_vars() + 1);
	let mut committed_offset = 0usize;
	for &n_multilins in commit_meta.n_multilins_by_vars() {
		let next = committed_offset + n_multilins;
		piop_committed_ranges.push(committed_offset..next);
		committed_offset = next;
	}
	let fri_cache = Arc::new(Mutex::new(HashMap::new()));

	flushes.retain(|flush| table_sizes[flush.table_id] > 0);
	flushes.sort_by_key(|flush| flush.channel_id);
	let flushes_sorted = true;

	non_zero_oracle_ids.retain(|oracle| !oracles.is_zero_sized(*oracle));
	exponents.retain(|exp| !oracles.is_zero_sized(exp.exp_result_id));

	let mut table_constraints = table_constraints
		.into_iter()
		.filter_map(|u| {
			if table_sizes[u.table_id] == 0 {
				None
			} else {
				let n_vars = u.log_values_per_row + log2_ceil_usize(table_sizes[u.table_id]);
				Some(SizedConstraintSet::new(n_vars, u))
			}
		})
		.collect::<Vec<_>>();
	table_constraints.sort_by_key(|constraint_set| constraint_set.n_vars);

	reorder_exponents(&mut exponents, &oracles);
	let exp_max_n_vars = exp::max_n_vars(&exponents, &oracles);

	let constraint_set_base_tower_levels = table_constraints
		.iter()
		.map(|constraint_set| {
			let oracle_level = constraint_set
				.oracle_ids
				.iter()
				.map(|id| oracles[*id].tower_level)
				.max()
				.unwrap_or(0);
			let constraint_level = constraint_set
				.constraints
				.iter()
				.map(|constraint| constraint.composition.binary_tower_level())
				.max()
				.unwrap_or(0);
			oracle_level.max(constraint_level)
		})
		.collect::<Vec<_>>();

	let (zerocheck_claims, zerocheck_oracle_metas) = table_constraints
		.iter()
		.cloned()
		.map(sumcheck::constraint_set_zerocheck_claim)
		.collect::<Result<Vec<_>, _>>()?
		.into_iter()
		.unzip::<_, _, Vec<_>, Vec<_>>();
	let zerocheck_max_n_vars = zerocheck_claims
		.iter()
		.map(|claim| claim.n_vars())
		.max()
		.unwrap_or(0);
	let zerocheck_min_log_degree = zerocheck_claims
		.iter()
		.map(|claim| log2_ceil_usize(claim.max_individual_degree()))
		.max()
		.unwrap_or(0);

	Ok(CsInstance {
		oracles,
		commit_meta,
		oracle_to_commit_index,
		commit_oracle_ids,
		piop_committed_ranges,
		fri_cache,
		oracle_count,
		max_oracle_id,
		exp_max_n_vars,
		table_constraints,
		zerocheck_claims,
		zerocheck_oracle_metas,
		constraint_set_base_tower_levels,
		zerocheck_max_n_vars,
		zerocheck_min_log_degree,
		flushes,
		flushes_sorted,
		exponents,
		non_zero_oracle_ids,
		channel_count,
		challenge_count,
		table_size_specs,
	})
}

pub(crate) fn get_cached_cs_instance<F: TowerField + 'static>(
	constraint_system: &ConstraintSystem<F>,
	constraint_system_digest: &[u8],
	table_sizes: &[usize],
) -> Result<Arc<CsInstance<F>>, Error> {
	let key = CsInstanceCacheKey {
		field_type_id: TypeId::of::<F>(),
		cs_digest: constraint_system_digest.to_vec().into_boxed_slice(),
		table_sizes: table_sizes.to_vec(),
	};
	let cache = CS_INSTANCE_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
	{
		let cache_guard = cache.lock().expect("constraint system cache mutex");
		if let Some(entry) = cache_guard.get(&key) {
			let typed = entry
				.downcast_ref::<Arc<CsInstance<F>>>()
				.expect("constraint system cache type mismatch");
			return Ok(typed.clone());
		}
	}
	let instance = Arc::new(prepare_constraint_system(constraint_system, table_sizes)?);
	let mut cache_guard = cache.lock().expect("constraint system cache mutex");
	cache_guard.insert(key, Box::new(instance.clone()));
	Ok(instance)
}

/// Precompute and cache constraint-system and FRI parameters for repeated proofs.
#[allow(clippy::too_many_arguments)]
pub fn prepare_precomputed<Tower, Hash, Compress>(
	constraint_system: &ConstraintSystem<FExt<Tower>>,
	constraint_system_digest: &Output<Hash::Digest>,
	table_sizes: &[usize],
	log_inv_rate: usize,
	security_bits: usize,
) -> Result<ProvePrecomputed<Tower>, Error>
where
	Tower: ProverTowerFamily,
	Tower::B128:
		binius_math::TowerTop + binius_math::PackedTop + PackedTop<Tower> + From<FFastExt<Tower>>,
	Hash: ParallelDigest,
	Hash::Digest: BlockSizeUser + FixedOutputReset + Send + Sync + Clone + 'static,
	Compress: PseudoCompressionFunction<Output<Hash::Digest>, 2> + Default + Sync + 'static,
{
	constraint_system.check_table_sizes(table_sizes)?;
	let instance = if prove_cache_enabled() {
		get_cached_cs_instance(
			constraint_system,
			constraint_system_digest.as_ref(),
			table_sizes,
		)?
	} else {
		Arc::new(prepare_constraint_system(constraint_system, table_sizes)?)
	};
	let flags = ProveFlags {
		has_exponents: !instance.exponents.is_empty(),
		has_non_zero: !instance.non_zero_oracle_ids.is_empty(),
		has_flushes: !instance.flushes.is_empty(),
	};
	let merkle_prover = BinaryMerkleTreeProver::<_, Hash, _>::new(Compress::default());
	let merkle_scheme = merkle_prover.scheme();
	let (fri_params, ntt) = if prove_cache_enabled() {
		get_cached_fri_params::<Tower, _>(
			&instance.commit_meta,
			merkle_scheme,
			security_bits,
			log_inv_rate,
			&instance.fri_cache,
		)?
	} else {
		let fri_params = piop::make_commit_params_with_optimal_arity::<_, FEncode<Tower>, _>(
			&instance.commit_meta,
			merkle_scheme,
			security_bits,
			log_inv_rate,
		)?;
		let ntt = SingleThreadedNTT::with_subspace(fri_params.rs_code().subspace())?
			.precompute_twiddles()
			.multithreaded();
		(Arc::new(fri_params), Arc::new(ntt))
	};
	Ok(ProvePrecomputed {
		instance,
		log_inv_rate,
		security_bits,
		flags,
		fri_params,
		ntt,
		domain_factory: DefaultEvaluationDomainFactory::<FDomain<Tower>>::default(),
		fast_domain_factory: IsomorphicEvaluationDomainFactory::<FFastExt<Tower>>::default(),
	})
}

#[allow(clippy::too_many_arguments)]
#[instrument("constraint_system::prove_with_instance", skip_all, level = "debug")]
pub(crate) fn prove_with_instance<
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
) -> Result<Proof, Error>
where
	Hal: ComputeLayer<Tower::B128> + Default,
	U: ProverTowerUnderlier<Tower>,
	Tower: ProverTowerFamily,
	Tower::B128:
		binius_math::TowerTop + binius_math::PackedTop + PackedTop<Tower> + From<FFastExt<Tower>>,
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
	PackedType<U, Tower::FastB128>: PackedTransformationFactory<PackedType<U, Tower::B128>>,
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
	transcript
		.observe()
		.write_slice(constraint_system_digest.as_ref());
	transcript.observe().write_slice(boundaries);
	let mut writer = transcript.message();
	writer.write_slice(table_sizes);
	trace_transcript_checkpoint(&transcript, "table_sizes");

	let witness_span = tracing::info_span!(
		"[phase] Witness Finalization",
		phase = "witness",
		perfetto_category = "phase.main"
	)
	.entered();

	// We must generate multiplication witnesses before committing, as this function
	// adds the committed witnesses for exponentiation results to the witness index.
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

	// Commit polynomials
	let merkle_prover = BinaryMerkleTreeProver::<_, Hash, _>::new(Compress::default());
	let merkle_scheme = merkle_prover.scheme();

	let commit_meta = &instance.commit_meta;
	let oracle_to_commit_index = &instance.oracle_to_commit_index;
	let committed_multilins = instance
		.commit_oracle_ids
		.par_iter()
		.map(|oracle_id| witness.get_multilin_poly(*oracle_id))
		.collect::<Result<Vec<_>, _>>()?;

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
	} = PIOP_CODEWORD_SCRATCH.with(|cell| {
		let mut map = cell.borrow_mut();
		let entry = map
			.entry(TypeId::of::<PackedType<U, FExt<Tower>>>())
			.or_insert_with(|| Box::new(Vec::<PackedType<U, FExt<Tower>>>::new()));
		let scratch = entry
			.downcast_mut::<Vec<PackedType<U, FExt<Tower>>>>()
			.expect("codeword scratch type mismatch");
		piop::commit(
			fri_params,
			ntt,
			&merkle_prover,
			&committed_multilins,
			Some(scratch),
		)
	})?;
	emit_max_rss();
	drop(commit_span);

	// Observe polynomial commitment
	let mut writer = transcript.message();
	writer.write(&commitment);
	trace_transcript_checkpoint(&transcript, "commitment");

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
	trace_transcript_checkpoint(&transcript, "exp_evals");

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

	let base_exp_output: gkr_exp::BaseExpReductionOutput<FExt<Tower>> = if has_exponents {
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

	// Grand product arguments
	// Grand products for non-zero checking
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
		bail!(Error::Zeros);
	}

	let mut writer = transcript.message();

	writer.write_scalar_slice(&non_zero_products);
	trace_transcript_checkpoint(&transcript, "non_zero_products");

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

	// Grand products for flushing
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
		trace_transcript_checkpoint(&transcript, "flush_products");
		let flush_prodcheck_claims = gkr_gpa::construct_grand_product_claims(
			&flush_oracle_ids,
			oracles.as_ref(),
			&flush_products,
		)?;
		(flush_prodcheck_witnesses, flush_prodcheck_claims)
	};

	// Prove grand products
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

	// Apply isomorphism to the layer claims
	let final_layer_claims = final_layer_claims
		.into_iter()
		.map(|layer_claim| layer_claim.isomorphic())
		.collect::<Vec<_>>();

	// Reduce non_zero_final_layer_claims to evalcheck claims
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

	// Zerocheck
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

		// Per prover zerocheck challenges are justified on the high indexed variables
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

	// Prove evaluation claims
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

	// Reduce committed evaluation claims to PIOP sumcheck claims
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

	// Prove evaluation claims using PIOP compiler
	let piop_compiler_span = tracing::info_span!(
		"[phase] PIOP Compiler",
		phase = "piop_compiler",
		perfetto_category = "phase.main"
	)
	.entered();

	piop::prove(
		compute_data,
		fri_params,
		ntt,
		&merkle_prover,
		commit_meta,
		committed,
		&codeword,
		&committed_multilins,
		transparent_multilins,
		&piop_sumcheck_claims,
		&mut transcript,
	)?;
	PIOP_CODEWORD_SCRATCH.with(|cell| {
		let mut map = cell.borrow_mut();
		let entry = map
			.entry(TypeId::of::<PackedType<U, FExt<Tower>>>())
			.or_insert_with(|| Box::new(Vec::<PackedType<U, FExt<Tower>>>::new()));
		let scratch = entry
			.downcast_mut::<Vec<PackedType<U, FExt<Tower>>>>()
			.expect("codeword scratch type mismatch");
		*scratch = codeword;
	});
	drop(committed_multilins);
	trace_transcript_checkpoint(&transcript, "piop_prove");
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

/// Generates a proof that a witness satisfies a constraint system with the standard FRI PCS.
#[allow(clippy::too_many_arguments)]
#[instrument("constraint_system::prove", skip_all, level = "debug")]
pub fn prove<
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
	witness: MultilinearExtensionIndex<PackedType<U, FExt<Tower>>>,
	backend: &Backend,
) -> Result<Proof, Error>
where
	Hal: ComputeLayer<Tower::B128> + Default,
	U: ProverTowerUnderlier<Tower>,
	Tower: ProverTowerFamily,
	Tower::B128:
		binius_math::TowerTop + binius_math::PackedTop + PackedTop<Tower> + From<FFastExt<Tower>>,
	Hash: ParallelDigest,
	Hash::Digest: BlockSizeUser + FixedOutputReset + Send + Sync + Clone + 'static,
	Compress: PseudoCompressionFunction<Output<Hash::Digest>, 2> + Default + Sync + 'static,
	Challenger_: Challenger + Default,
	Backend: ComputationBackend,
	// REVIEW: Consider changing TowerFamily and associated traits to shorten/remove these bounds
	PackedType<U, Tower::B128>: PackedTop<Tower>
		+ PackedFieldIndexable
		// REVIEW: remove this bound after piop::commit is adjusted
		+ RepackedExtension<PackedType<U, Tower::B1>>
		+ RepackedExtension<PackedType<U, Tower::B8>>
		+ RepackedExtension<PackedType<U, Tower::B16>>
		+ RepackedExtension<PackedType<U, Tower::B32>>
		+ RepackedExtension<PackedType<U, Tower::B64>>
		+ RepackedExtension<PackedType<U, Tower::B128>>
		+ PackedTransformationFactory<PackedType<U, Tower::FastB128>>
		+ binius_math::PackedTop,
	PackedType<U, Tower::FastB128>: PackedTransformationFactory<PackedType<U, Tower::B128>>,
	HostAllocatorType: ComputeAllocator<Tower::B128, CpuMemory>,
	DeviceAllocatorType: ComputeAllocator<Tower::B128, Hal::DevMem>,
{
	if env::var("ORIGAMI_M3_USE_LEGACY_PROVE")
		.ok()
		.as_deref()
		.map(|v| v == "1")
		.unwrap_or(false)
	{
		return prove_legacy::<
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
			constraint_system,
			log_inv_rate,
			security_bits,
			constraint_system_digest,
			boundaries,
			table_sizes,
			witness,
			backend,
		);
	}
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
	prove_with_instance::<
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
	)
}

/// Generates a proof using precomputed constraint-system and FRI cache state.
#[allow(clippy::too_many_arguments)]
#[instrument("constraint_system::prove_with_precomputed", skip_all, level = "debug")]
pub fn prove_with_precomputed<
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
	witness: MultilinearExtensionIndex<PackedType<U, FExt<Tower>>>,
	backend: &Backend,
) -> Result<Proof, Error>
where
	Hal: ComputeLayer<Tower::B128> + Default,
	U: ProverTowerUnderlier<Tower>,
	Tower: ProverTowerFamily,
	Tower::B128:
		binius_math::TowerTop + binius_math::PackedTop + PackedTop<Tower> + From<FFastExt<Tower>>,
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
	PackedType<U, Tower::FastB128>: PackedTransformationFactory<PackedType<U, Tower::B128>>,
	HostAllocatorType: ComputeAllocator<Tower::B128, CpuMemory>,
	DeviceAllocatorType: ComputeAllocator<Tower::B128, Hal::DevMem>,
{
	let instance = &precomputed.instance;
	let flags = precomputed.flags;
	prove_with_instance::<
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
	)
}

/// Legacy proof pipeline retained during R7X core refactor.
#[allow(dead_code, clippy::too_many_arguments)]
#[instrument("constraint_system::prove_legacy", skip_all, level = "debug")]
fn prove_legacy<
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
	mut witness: MultilinearExtensionIndex<PackedType<U, FExt<Tower>>>,
	backend: &Backend,
) -> Result<Proof, Error>
where
	Hal: ComputeLayer<Tower::B128> + Default,
	U: ProverTowerUnderlier<Tower>,
	Tower: ProverTowerFamily,
	Tower::B128:
		binius_math::TowerTop + binius_math::PackedTop + PackedTop<Tower> + From<FFastExt<Tower>>,
	Hash: ParallelDigest,
	Hash::Digest: BlockSizeUser + FixedOutputReset + Send + Sync + Clone + 'static,
	Compress: PseudoCompressionFunction<Output<Hash::Digest>, 2> + Default + Sync + 'static,
	Challenger_: Challenger + Default,
	Backend: ComputationBackend,
	// REVIEW: Consider changing TowerFamily and associated traits to shorten/remove these bounds
	PackedType<U, Tower::B128>: PackedTop<Tower>
		+ PackedFieldIndexable
		// REVIEW: remove this bound after piop::commit is adjusted
		+ RepackedExtension<PackedType<U, Tower::B1>>
		+ RepackedExtension<PackedType<U, Tower::B8>>
		+ RepackedExtension<PackedType<U, Tower::B16>>
		+ RepackedExtension<PackedType<U, Tower::B32>>
		+ RepackedExtension<PackedType<U, Tower::B64>>
		+ RepackedExtension<PackedType<U, Tower::B128>>
		+ PackedTransformationFactory<PackedType<U, Tower::FastB128>>
		+ binius_math::PackedTop,
	PackedType<U, Tower::FastB128>: PackedTransformationFactory<PackedType<U, Tower::B128>>,
	HostAllocatorType: ComputeAllocator<Tower::B128, CpuMemory>,
	DeviceAllocatorType: ComputeAllocator<Tower::B128, Hal::DevMem>,
{
	tracing::debug!(
		arch = env::consts::ARCH,
		rayon_threads = binius_maybe_rayon::current_num_threads(),
		"using computation backend: {backend:?}"
	);

	let domain_factory = DefaultEvaluationDomainFactory::<FDomain<Tower>>::default();
	let fast_domain_factory = IsomorphicEvaluationDomainFactory::<FFastExt<Tower>>::default();

	constraint_system.check_table_sizes(table_sizes)?;
	let instance = if prove_cache_enabled() {
		get_cached_cs_instance(constraint_system, constraint_system_digest.as_ref(), table_sizes)?
	} else {
		Arc::new(prepare_constraint_system(constraint_system, table_sizes)?)
	};
	let mut oracles = if instance.flushes.is_empty() {
		Cow::Borrowed(&instance.oracles)
	} else {
		Cow::Owned(instance.oracles.clone())
	};
	let table_constraints = instance.table_constraints.as_slice();
	let table_constraints_len = table_constraints.len();
	let _zerocheck_claims = instance.zerocheck_claims.as_slice();
	let zerocheck_oracle_metas = instance.zerocheck_oracle_metas.as_slice();
	let constraint_set_base_tower_levels = instance.constraint_set_base_tower_levels.as_slice();
	let zerocheck_max_n_vars = instance.zerocheck_max_n_vars;
	let zerocheck_min_log_degree = instance.zerocheck_min_log_degree;
	let mut flushes = if instance.flushes.is_empty() {
		Vec::new()
	} else {
		instance.flushes.clone()
	};
	let flushes_sorted = instance.flushes_sorted;
	let exponents = instance.exponents.as_slice();
	let non_zero_oracle_ids = instance.non_zero_oracle_ids.as_slice();
	let channel_count = instance.channel_count;
	let challenge_count = instance.challenge_count;
	let table_size_specs = instance.table_size_specs.as_slice();

	let mut transcript = ProverTranscript::<Challenger_>::new();
	transcript
		.observe()
		.write_slice(constraint_system_digest.as_ref());
	transcript.observe().write_slice(boundaries);
	let mut writer = transcript.message();
	writer.write_slice(table_sizes);

	let witness_span = tracing::info_span!(
		"[phase] Witness Finalization",
		phase = "witness",
		perfetto_category = "phase.main"
	)
	.entered();

	// We must generate multiplication witnesses before committing, as this function
	// adds the committed witnesses for exponentiation results to the witness index.
	let exp_compute_layer_span = tracing::info_span!(
		"[step] Compute Exponentiation Layers",
		phase = "witness",
		perfetto_category = "phase.sub"
	)
	.entered();
	let has_exponents = !exponents.is_empty();
	let exp_witnesses = if has_exponents {
		exp::make_exp_witnesses::<U, Tower>(&mut witness, oracles.as_ref(), exponents)?
	} else {
		Vec::new()
	};
	drop(exp_compute_layer_span);

	drop(witness_span);

	// Commit polynomials
	let merkle_prover = BinaryMerkleTreeProver::<_, Hash, _>::new(Compress::default());
	let merkle_scheme = merkle_prover.scheme();

	let commit_meta = &instance.commit_meta;
	let oracle_to_commit_index = &instance.oracle_to_commit_index;
	let mut committed_multilins = Vec::with_capacity(instance.commit_oracle_ids.len());
	for oracle_id in instance.commit_oracle_ids.iter() {
		committed_multilins.push(witness.get_multilin_poly(*oracle_id)?);
	}

	let (fri_params, ntt) = if prove_cache_enabled() {
		get_cached_fri_params::<Tower, _>(
			commit_meta,
			merkle_scheme,
			security_bits,
			log_inv_rate,
			&instance.fri_cache,
		)?
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
	} = PIOP_CODEWORD_SCRATCH.with(|cell| {
		let mut map = cell.borrow_mut();
		let entry = map
			.entry(TypeId::of::<PackedType<U, FExt<Tower>>>())
			.or_insert_with(|| Box::new(Vec::<PackedType<U, FExt<Tower>>>::new()));
		let scratch = entry
			.downcast_mut::<Vec<PackedType<U, FExt<Tower>>>>()
			.expect("codeword scratch type mismatch");
		piop::commit(
			fri_params,
			ntt,
			&merkle_prover,
			&committed_multilins,
			Some(scratch),
		)
	})?;
	emit_max_rss();
	drop(commit_span);

	// Observe polynomial commitment
	let mut writer = transcript.message();
	writer.write(&commitment);

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

	let base_exp_output: gkr_exp::BaseExpReductionOutput<FExt<Tower>> = if has_exponents {
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
		gkr_exp::BaseExpReductionOutput { layers_claims: Vec::new() }
	};

	let exp_eval_claims = if has_exponents {
		exp::make_eval_claims(exponents, base_exp_output)?
	} else {
		Vec::new()
	};
	emit_max_rss();
	drop(exp_span);

	// Grand product arguments
	// Grand products for non-zero checking
	let prodcheck_span = tracing::info_span!(
		"[phase] Product Check",
		phase = "prodcheck",
		perfetto_category = "phase.main"
	)
	.entered();

	let has_non_zero = !non_zero_oracle_ids.is_empty();
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
		bail!(Error::Zeros);
	}

	let mut writer = transcript.message();

	writer.write_scalar_slice(&non_zero_products);

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

	// Grand products for flushing
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
		let flush_prodcheck_claims = gkr_gpa::construct_grand_product_claims(
			&flush_oracle_ids,
			oracles.as_ref(),
			&flush_products,
		)?;
		(flush_prodcheck_witnesses, flush_prodcheck_claims)
	};

	// Prove grand products
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

	// Apply isomorphism to the layer claims
	let final_layer_claims = final_layer_claims
		.into_iter()
		.map(|layer_claim| layer_claim.isomorphic())
		.collect::<Vec<_>>();

	// Reduce non_zero_final_layer_claims to evalcheck claims
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

	// Zerocheck
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

		// Per prover zerocheck challenges are justified on the high indexed variables
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

	// Prove evaluation claims
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

	// Reduce committed evaluation claims to PIOP sumcheck claims
	let system = ring_switch::EvalClaimSystem::new(
		oracles.as_ref(),
		&commit_meta,
		&oracle_to_commit_index,
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

	// Prove evaluation claims using PIOP compiler
	let piop_compiler_span = tracing::info_span!(
		"[phase] PIOP Compiler",
		phase = "piop_compiler",
		perfetto_category = "phase.main"
	)
	.entered();

	piop::prove(
		compute_data,
		fri_params,
		ntt,
		&merkle_prover,
		commit_meta,
		committed,
		&codeword,
		&committed_multilins,
		transparent_multilins,
		&piop_sumcheck_claims,
		&mut transcript,
	)?;
	PIOP_CODEWORD_SCRATCH.with(|cell| {
		let mut map = cell.borrow_mut();
		let entry = map
			.entry(TypeId::of::<PackedType<U, FExt<Tower>>>())
			.or_insert_with(|| Box::new(Vec::<PackedType<U, FExt<Tower>>>::new()));
		let scratch = entry
			.downcast_mut::<Vec<PackedType<U, FExt<Tower>>>>()
			.expect("codeword scratch type mismatch");
		*scratch = codeword;
	});
	drop(committed_multilins);
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

type TypeErasedZerocheck<'a, P> = Box<dyn ZerocheckProver<'a, P> + 'a>;

struct ZerocheckProverConstructor<'a, P, FDomain, DomainFactory, Backend>
where
	P: PackedField,
{
	constraints: Vec<Constraint<P::Scalar>>,
	multilinears: Vec<MultilinearWitness<'a, P>>,
	domain_factory: DomainFactory,
	zerocheck_challenges: &'a [P::Scalar],
	backend: &'a Backend,
	_fdomain_marker: PhantomData<FDomain>,
}

impl<'a, P, F, FDomain, DomainFactory, Backend>
	ZerocheckProverConstructor<'a, P, FDomain, DomainFactory, Backend>
where
	F: Field,
	P: PackedField<Scalar = F>,
	FDomain: TowerField,
	DomainFactory: EvaluationDomainFactory<FDomain> + 'a,
	Backend: ComputationBackend,
{
	fn create<FBase>(self) -> Result<TypeErasedZerocheck<'a, P>, Error>
	where
		FBase: TowerField + ExtensionField<FDomain> + TryFrom<F>,
		P: PackedExtension<F, PackedSubfield = P>
			+ PackedExtension<FDomain>
			+ PackedExtension<FBase>,
		F: TowerField,
	{
		let zerocheck_prover =
			sumcheck::prove::constraint_set_zerocheck_prover::<_, _, FBase, _, _, _>(
				self.constraints,
				self.multilinears,
				self.domain_factory,
				self.zerocheck_challenges,
				self.backend,
			)?;

		let type_erased_zerocheck_prover = Box::new(zerocheck_prover) as TypeErasedZerocheck<'a, P>;

		Ok(type_erased_zerocheck_prover)
	}
}

fn populate_flush_po2_step_down_witnesses<'a, U, Tower>(
	step_down_polys: Vec<(OracleId, StepDown)>,
	witness: &mut MultilinearExtensionIndex<'a, PackedType<U, FExt<Tower>>>,
) -> Result<(), Error>
where
	U: ProverTowerUnderlier<Tower>,
	Tower: ProverTowerFamily,
{
	for (oracle_id, step_down_poly) in step_down_polys {
		let witness_poly = step_down_poly
			.multilinear_extension::<PackedType<U, Tower::B1>>()?
			.specialize_arc_dyn();
		witness.update_multilin_poly([(oracle_id, witness_poly)])?
	}
	Ok(())
}

#[instrument(skip_all, level = "debug")]
pub fn make_masked_flush_witnesses<'a, U, Tower>(
	oracles: &MultilinearOracleSet<FExt<Tower>>,
	witness_index: &mut MultilinearExtensionIndex<'a, PackedType<U, FExt<Tower>>>,
	fast_witness_index: &mut MultilinearExtensionIndex<'a, PackedType<U, FFastExt<Tower>>>,
	flush_oracle_ids: &[OracleId],
	flushes: &[Flush<FExt<Tower>>],
	mixing_challenge: FExt<Tower>,
	permutation_challenges: &[FExt<Tower>],
) -> Result<(), Error>
where
	U: ProverTowerUnderlier<Tower>,
	Tower: ProverTowerFamily,
	PackedType<U, Tower::B128>: PackedTransformationFactory<PackedType<U, Tower::FastB128>>
		+ RepackedExtension<PackedType<U, Tower::B1>>,
{
	// TODO: Move me out into a separate function & deduplicate.
	// Count the suffix zeros on all selectors.
	for flush in flushes {
		let fast_selectors =
			convert_1b_witnesses_to_fast_ext::<U, Tower>(witness_index, &flush.selectors)?;

		for (&selector_id, fast_selector) in flush.selectors.iter().zip(fast_selectors) {
			let selector = witness_index.get_multilin_poly(selector_id)?;
			let zero_suffix_len = count_zero_suffixes(&selector);

			let nonzero_prefix_len = (1 << selector.n_vars()) - zero_suffix_len;
			witness_index.update_multilin_poly_with_nonzero_scalars_prefixes([(
				selector_id,
				selector,
				nonzero_prefix_len,
			)])?;

			fast_witness_index.update_multilin_poly_with_nonzero_scalars_prefixes([(
				selector_id,
				fast_selector,
				nonzero_prefix_len,
			)])?;
		}
	}

	let mut inner_oracles_ids = flushes
		.iter()
		.flat_map(|flush| {
			flush
				.oracles
				.iter()
				.filter_map(|oracle_or_const| match oracle_or_const {
					OracleOrConst::Oracle(oracle_id) => Some(*oracle_id),
					_ => None,
				})
		})
		.collect::<Vec<_>>();
	inner_oracles_ids.sort();
	inner_oracles_ids.dedup();

	let fast_inner_oracles =
		convert_witnesses_to_fast_ext::<U, Tower>(oracles, witness_index, &inner_oracles_ids)?;

	for ((n_vars, witness_data), id) in fast_inner_oracles.into_iter().zip(inner_oracles_ids) {
		let fast_witness = MLEDirectAdapter::from(
			MultilinearExtension::new(n_vars, witness_data)
				.expect("witness_data created with correct n_vars"),
		);

		let nonzero_scalars_prefix = witness_index.get_index_entry(id)?.nonzero_scalars_prefix;

		fast_witness_index.update_multilin_poly_with_nonzero_scalars_prefixes([(
			id,
			fast_witness.upcast_arc_dyn(),
			nonzero_scalars_prefix,
		)])?;
	}

	// Find the maximum power of the mixing challenge needed.
	let max_n_mixed = flushes
		.iter()
		.map(|flush| flush.oracles.len())
		.max()
		.unwrap_or_default();
	let mixing_powers = powers(mixing_challenge)
		.take(max_n_mixed)
		.collect::<Vec<_>>();

	// The function is on the critical path, parallelize.
	let indices_to_update = flush_oracle_ids
		.par_iter()
		.zip(flushes)
		.map(|(&flush_oracle, flush)| {
			let n_vars = oracles.n_vars(flush_oracle);

			let const_term = flush
				.oracles
				.iter()
				.copied()
				.zip(mixing_powers.iter())
				.filter_map(|(oracle_or_const, coeff)| match oracle_or_const {
					OracleOrConst::Const { base, .. } => Some(base * coeff),
					_ => None,
				})
				.sum::<FExt<Tower>>();
			let const_term = permutation_challenges[flush.channel_id] + const_term;

			let inner_oracles = flush
				.oracles
				.iter()
				.copied()
				.zip(mixing_powers.iter())
				.filter_map(|(oracle_or_const, &coeff)| match oracle_or_const {
					OracleOrConst::Oracle(oracle_id) => Some((oracle_id, coeff)),
					_ => None,
				})
				.map(|(inner_id, coeff)| {
					let witness = witness_index.get_multilin_poly(inner_id)?;
					Ok((witness, coeff))
				})
				.collect::<Result<Vec<_>, Error>>()?;

			let selector_entries = flush
				.selectors
				.iter()
				.map(|id| witness_index.get_index_entry(*id))
				.collect::<Result<Vec<_>, _>>()?;

			// Get the number of entries before any selector column is fully disabled.
			let selector_prefix_len = selector_entries
				.iter()
				.map(|selector_entry| selector_entry.nonzero_scalars_prefix)
				.min()
				.unwrap_or(1 << n_vars);

			let selectors = selector_entries
				.into_iter()
				.map(|entry| entry.multilin_poly)
				.collect::<Vec<_>>();

			let log_width = <PackedType<U, FExt<Tower>>>::LOG_WIDTH;
			let packed_selector_prefix_len = selector_prefix_len.div_ceil(1 << log_width);

			let mut witness_data = Vec::with_capacity(1 << n_vars.saturating_sub(log_width));
			(0..packed_selector_prefix_len)
				.into_par_iter()
				.map(|i| {
					<PackedType<U, FExt<Tower>>>::from_fn(|j| {
						let index = i << log_width | j;

						// If n_vars < P::LOG_WIDTH, fill the remaining scalars with zeroes.
						if index >= 1 << n_vars {
							return <FExt<Tower>>::ZERO;
						}

						// Compute the product of all selectors at this point
						let selector_off = selectors.iter().any(|selector| {
							let sel_val = selector
								.evaluate_on_hypercube(index)
								.expect("index < 1 << n_vars");
							sel_val.is_zero()
						});

						if selector_off {
							// If any selector is zero, the result is 1
							<FExt<Tower>>::ONE
						} else {
							// Otherwise, compute the linear combination
							let mut inner_oracles_iter = inner_oracles.iter();

							// Handle the first one specially because the mixing power is ONE,
							// unless the first oracle was a constant.
							if let Some((poly, coeff)) = inner_oracles_iter.next() {
								let first_term = if *coeff == FExt::<Tower>::ONE {
									poly.evaluate_on_hypercube(index).expect("index in bounds")
								} else {
									poly.evaluate_on_hypercube_and_scale(index, *coeff)
										.expect("index in bounds")
								};
								inner_oracles_iter.fold(
									const_term + first_term,
									|sum, (poly, coeff)| {
										let scaled_eval = poly
											.evaluate_on_hypercube_and_scale(index, *coeff)
											.expect("index in bounds");
										sum + scaled_eval
									},
								)
							} else {
								const_term
							}
						}
					})
				})
				.collect_into_vec(&mut witness_data);
			witness_data.resize(witness_data.capacity(), PackedType::<U, FExt<Tower>>::one());

			let witness = MLEDirectAdapter::from(
				MultilinearExtension::new(n_vars, witness_data)
					.expect("witness_data created with correct n_vars"),
			);
			// TODO: This is sketchy. The field on witness index is called "nonzero_prefix", but
			// I'm setting it when the suffix is 1, not zero.
			Ok((witness, selector_prefix_len))
		})
		.collect::<Result<Vec<_>, Error>>()?;

	witness_index.update_multilin_poly_with_nonzero_scalars_prefixes(
		iter::zip(flush_oracle_ids, indices_to_update).map(
			|(&oracle_id, (witness, nonzero_scalars_prefix))| {
				(oracle_id, witness.upcast_arc_dyn(), nonzero_scalars_prefix)
			},
		),
	)?;
	Ok(())
}

fn count_zero_suffixes<P: PackedField, M: MultilinearPoly<P>>(poly: &M) -> usize {
	let zeros = P::zero();
	if let Some(packed_evals) = poly.packed_evals() {
		let packed_zero_suffix_len = packed_evals
			.iter()
			.rev()
			.position(|&packed_eval| packed_eval != zeros)
			.unwrap_or(packed_evals.len());

		let log_scalars_per_elem = P::LOG_WIDTH + poly.log_extension_degree();
		if poly.n_vars() < log_scalars_per_elem {
			debug_assert_eq!(packed_evals.len(), 1, "invariant of MultilinearPoly");
			packed_zero_suffix_len << poly.n_vars()
		} else {
			packed_zero_suffix_len << log_scalars_per_elem
		}
	} else {
		0
	}
}

/// Converts specified oracles' witness representations from the base extension field
/// to the fast extension field format for optimized grand product calculations.
///
/// This function processes the provided list of oracle IDs, extracting the corresponding
/// multilinear polynomials from the witness index, and converting their evaluations
/// to the fast field representation. The conversion is performed efficiently using
/// the tower transformation infrastructure.
///
/// # Performance Considerations
/// - This function is optimized for parallel execution as it's on the critical path of the proving
///   system.
///
/// # Arguments
/// * `oracles` - Reference to the multilinear oracle set containing metadata for all oracles
/// * `witness` - Reference to the witness index containing the multilinear polynomial evaluations
/// * `oracle_ids` - Slice of oracle IDs for which to generate fast field representations
///
/// # Returns
/// A vector of tuples, where each tuple contains:
/// - The number of variables in the oracle's multilinear polynomial
/// - A vector of packed field elements representing the polynomial's evaluations in the fast field
///
/// # Errors
/// Returns an error if:
/// - Any oracle ID is invalid or not found in the witness index
/// - Subcube evaluation fails for any polynomial
#[allow(clippy::type_complexity)]
#[instrument(skip_all, level = "debug")]
fn convert_witnesses_to_fast_ext<'a, U, Tower>(
	oracles: &MultilinearOracleSet<FExt<Tower>>,
	witness: &MultilinearExtensionIndex<'a, PackedType<U, FExt<Tower>>>,
	oracle_ids: &[OracleId],
) -> Result<Vec<(usize, Vec<PackedType<U, FFastExt<Tower>>>)>, Error>
where
	U: ProverTowerUnderlier<Tower>,
	Tower: ProverTowerFamily,
	PackedType<U, Tower::B128>: PackedTransformationFactory<PackedType<U, Tower::FastB128>>,
{
	let to_fast = Tower::packed_transformation_to_fast();

	// The function is on the critical path, parallelize.
	oracle_ids
		.into_par_iter()
		.map(|&flush_oracle_id| {
			let n_vars = oracles.n_vars(flush_oracle_id);

			let log_width = <PackedType<U, FFastExt<Tower>>>::LOG_WIDTH;

			let IndexEntry {
				multilin_poly: poly,
				nonzero_scalars_prefix,
			} = witness.get_index_entry(flush_oracle_id)?;

			const MAX_SUBCUBE_VARS: usize = 8;
			let subcube_vars = MAX_SUBCUBE_VARS.min(n_vars);
			let subcube_packed_size = 1 << subcube_vars.saturating_sub(log_width);
			let non_const_scalars = nonzero_scalars_prefix;
			let non_const_subcubes = non_const_scalars.div_ceil(1 << subcube_vars);

			let mut fast_ext_result = zeroed_vec(non_const_subcubes * subcube_packed_size);
			fast_ext_result
				.par_chunks_exact_mut(subcube_packed_size)
				.enumerate()
				.for_each(|(subcube_index, fast_subcube)| {
					let underliers =
						PackedType::<U, FFastExt<Tower>>::to_underliers_ref_mut(fast_subcube);

					let subcube_evals =
						PackedType::<U, FExt<Tower>>::from_underliers_ref_mut(underliers);
					poly.subcube_evals(subcube_vars, subcube_index, 0, subcube_evals)
						.expect("witness data populated by make_unmasked_flush_witnesses()");

					for underlier in underliers.iter_mut() {
						let src = PackedType::<U, FExt<Tower>>::from_underlier(*underlier);
						let dest = to_fast.transform(&src);
						*underlier = PackedType::<U, FFastExt<Tower>>::to_underlier(dest);
					}
				});

			fast_ext_result.truncate(non_const_scalars);
			Ok((n_vars, fast_ext_result))
		})
		.collect()
}

#[allow(clippy::type_complexity)]
pub fn convert_1b_witnesses_to_fast_ext<'a, U, Tower>(
	witness: &MultilinearExtensionIndex<'a, PackedType<U, FExt<Tower>>>,
	ids: &[OracleId],
) -> Result<Vec<MultilinearWitness<'a, PackedType<U, FFastExt<Tower>>>>, Error>
where
	U: ProverTowerUnderlier<Tower>,
	Tower: ProverTowerFamily,
	PackedType<U, Tower::B128>: PackedTransformationFactory<PackedType<U, Tower::FastB128>>
		+ RepackedExtension<PackedType<U, Tower::B1>>,
{
	ids.iter()
		.map(|&id| {
			let exp_witness = witness.get_multilin_poly(id)?;

			let packed_evals = exp_witness
				.packed_evals()
				.expect("poly contain packed_evals");

			let packed_evals = PackedType::<U, Tower::B128>::cast_bases(packed_evals);

			MultilinearExtension::new(exp_witness.n_vars(), packed_evals.to_vec())
				.map(|mle| mle.specialize_arc_dyn())
				.map_err(Error::from)
		})
		.collect::<Result<Vec<_>, _>>()
}

#[instrument(skip_all, name = "flush::reduce_flush_evalcheck_claims")]
fn reduce_flush_evalcheck_claims<
	U,
	Tower: ProverTowerFamily,
	Challenger_,
	Backend: ComputationBackend,
>(
	claims: Vec<EvalcheckMultilinearClaim<FExt<Tower>>>,
	oracles: &MultilinearOracleSet<FExt<Tower>>,
	witness_index: MultilinearExtensionIndex<PackedType<U, FFastExt<Tower>>>,
	domain_factory: IsomorphicEvaluationDomainFactory<FFastExt<Tower>>,
	transcript: &mut ProverTranscript<Challenger_>,
	backend: &Backend,
) -> Result<Vec<EvalcheckMultilinearClaim<FExt<Tower>>>, Error>
where
	FExt<Tower>: From<FFastExt<Tower>>,
	FFastExt<Tower>: From<FExt<Tower>>,
	U: ProverTowerUnderlier<Tower>,
	Challenger_: Challenger + Default,
{
	let mut linear_claims = Vec::new();
	let mut eval_point_index = HashMap::<EvalPoint<FFastExt<Tower>>, usize>::new();

	#[allow(clippy::type_complexity)]
	let mut new_mlechecks_constraints: Vec<(
		EvalPoint<FFastExt<Tower>>,
		ConstraintSetBuilder<FFastExt<Tower>>,
	)> = Vec::new();

	for claim in &claims {
		match &oracles[claim.id].variant {
			MultilinearPolyVariant::LinearCombination(_) => linear_claims.push(claim.clone()),
			MultilinearPolyVariant::Composite(composite) => {
				let eval_point = claim.eval_point.isomorphic();

				let eval = claim.eval.into();

				let oracle_ids = composite.inner().clone();

				let exp = <_ as CompositionPoly<FExt<Tower>>>::expression(composite.c());
				let fast_exp = exp.convert_field::<FFastExt<Tower>>();

				let position = if let Some(&idx) = eval_point_index.get(&eval_point) {
					idx
				} else {
					let idx = new_mlechecks_constraints.len();
					new_mlechecks_constraints.push((eval_point.clone(), ConstraintSetBuilder::new()));
					eval_point_index.insert(eval_point, idx);
					idx
				};

				if let Some((_, constraint_builder)) = new_mlechecks_constraints.get_mut(position) {
					constraint_builder.add_sumcheck(oracle_ids, fast_exp, eval);
				}
			}
			_ => unreachable!(),
		}
	}

	let new_mlechecks = new_mlechecks_constraints
		.into_iter()
		.map(|(ep, builder)| {
			builder
				.build_one(oracles)
				.map(|constraint| ConstraintSetEqIndPoint {
					eq_ind_challenges: ep.clone(),
					constraint_set: constraint,
				})
				.map_err(Error::from)
		})
		.collect::<Result<Vec<_>, Error>>()?;

	let mut memoized_data = MemoizedData::new();

	let mut fast_new_evalcheck_claims = Vec::new();

	for ConstraintSetEqIndPoint {
		eq_ind_challenges,
		constraint_set,
	} in new_mlechecks
	{
		let evalcheck_claims = prove_mlecheck_with_switchover::<_, _, FFastExt<Tower>, _, _>(
			&witness_index,
			constraint_set,
			eq_ind_challenges,
			&mut memoized_data,
			transcript,
			immediate_switchover_heuristic,
			domain_factory.clone(),
			backend,
		)?;
		fast_new_evalcheck_claims.extend(evalcheck_claims);
	}

	Ok(chain!(
		fast_new_evalcheck_claims
			.into_iter()
			.map(|claim| claim.isomorphic::<FExt<Tower>>()),
		linear_claims.into_iter()
	)
	.collect::<Vec<_>>())
}
