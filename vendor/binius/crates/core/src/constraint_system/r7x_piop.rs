// Copyright 2024-2025 Irreducible Inc.

use std::{borrow::Cow, cell::RefCell, ops::Deref, ops::Range};

use binius_compute::{
	ComputeData, ComputeLayer, ComputeMemory, FSlice, SizedSlice, alloc::ComputeAllocator,
	cpu::CpuMemory,
};
use binius_field::{
	BinaryField, PackedExtension, PackedField, PackedFieldIndexable, TowerField,
	packed::PackedSliceMut,
};
use binius_math::{MultilinearExtension, MultilinearPoly};
use binius_maybe_rayon::{iter::IntoParallelIterator, prelude::*};
use binius_ntt::AdditiveNTT;
use binius_utils::{
	SerializeBytes, bail,
	checked_arithmetics::checked_log_2,
	random_access_sequence::{RandomAccessSequenceMut, SequenceSubrangeMut},
	sorting::is_sorted_ascending,
};
use bytemuck::zeroed_vec;

use crate::{
	fiat_shamir::{CanSample, Challenger},
	merkle_tree::{MerkleTreeProver, MerkleTreeScheme},
	oracle::OracleId,
	piop::{
		CommitMeta,
		logging::{FriFoldRoundsData, SumcheckBatchProverDimensionsData},
		verify::{
			PIOPSumcheckClaim,
			SumcheckClaimDesc,
			make_sumcheck_claim_descs,
			make_sumcheck_claim_descs_with_committed,
		},
	},
	protocols::{
		fri::{self, FRIFolder, FRIParams, FoldRoundOutput},
		sumcheck::{
			self, SumcheckClaim,
			prove::{SumcheckProver, front_loaded::BatchProver as SumcheckBatchProver},
			v3::bivariate_product::BivariateSumcheckProver,
		},
	},
	transcript::ProverTranscript,
};

thread_local! {
	static R7X_MERGE_SCRATCH: RefCell<Vec<(usize, usize, usize)>> = RefCell::new(Vec::new());
}

pub struct PackedCommittedDevice<'a, F: TowerField, Hal: ComputeLayer<F>> {
	pub block: <<Hal as ComputeLayer<F>>::DevMem as ComputeMemory<F>>::FSlice<'a>,
}

pub(crate) fn build_packed_committed_ranges<P, Data>(
	packed_committed_multilins: &[MultilinearExtension<P, Data>],
) -> Vec<Range<usize>>
where
	P: PackedField,
	Data: Deref<Target = [P]>,
{
	let mut committed_ranges = Vec::with_capacity(packed_committed_multilins.len());
	let mut committed_offset = 0usize;
	for packed_committed_multilin in packed_committed_multilins {
		let len = 1usize << packed_committed_multilin.n_vars();
		committed_ranges.push(committed_offset..committed_offset + len);
		committed_offset += len;
	}
	committed_ranges
}

fn build_sumcheck_provers_from_block<'a, F, Hal, HostAllocatorType, DeviceAllocatorType>(
	sumcheck_claim_descs: &[SumcheckClaimDesc<F>],
	committed_block: Option<<<Hal as ComputeLayer<F>>::DevMem as ComputeMemory<F>>::FSlice<'a>>,
	committed_ranges: &[Range<usize>],
	transparent_multilins: &[<<Hal as ComputeLayer<F>>::DevMem as ComputeMemory<F>>::FSlice<'a>],
	hal: &'a Hal,
	dev_alloc: &'a DeviceAllocatorType,
	host_alloc: &'a HostAllocatorType,
) -> Result<
	Vec<BivariateSumcheckProver<'a, 'a, F, Hal, DeviceAllocatorType, HostAllocatorType>>,
	Error,
>
where
	F: TowerField,
	Hal: ComputeLayer<F>,
	DeviceAllocatorType: ComputeAllocator<F, Hal::DevMem>,
	HostAllocatorType: ComputeAllocator<F, CpuMemory>,
{
	let mut sumcheck_provers = Vec::with_capacity(
		sumcheck_claim_descs
			.iter()
			.filter(|desc| !desc.committed_indices.is_empty())
			.count(),
	);

	for (n_vars, desc) in sumcheck_claim_descs
		.iter()
		.enumerate()
		.filter(|(_, desc)| !desc.committed_indices.is_empty())
	{
		let mut multilins =
			Vec::with_capacity(desc.committed_indices.len() + desc.transparent_indices.len());
		if let Some(committed_block) = committed_block {
			for idx in desc.committed_indices.clone() {
				let range = committed_ranges
					.get(idx)
					.expect("committed range missing");
				multilins.push(Hal::DevMem::slice(committed_block, range.clone()));
			}
		}
		multilins.extend(
			transparent_multilins[desc.transparent_indices.clone()]
				.iter()
				.copied(),
		);

		let claim = SumcheckClaim::new(n_vars, multilins.len(), desc.composite_sums.clone())?;
		sumcheck_provers.push(BivariateSumcheckProver::new(
			hal,
			dev_alloc,
			host_alloc,
			&claim,
			multilins,
		)?);
	}

	Ok(sumcheck_provers)
}

use crate::piop::Error;

#[inline(always)]
fn reverse_bits(x: usize, log_len: usize) -> usize {
	x.reverse_bits()
		.wrapping_shr((usize::BITS as usize - log_len) as _)
}

fn reverse_index_bits<T: Copy>(collection: &mut impl RandomAccessSequenceMut<T>) {
	let log_len = checked_log_2(collection.len());
	for i in 0..collection.len() {
		let bit_reversed_index = reverse_bits(i, log_len);
		if i < bit_reversed_index {
			unsafe {
				let tmp = collection.get_unchecked(i);
				collection.set_unchecked(i, collection.get_unchecked(bit_reversed_index));
				collection.set_unchecked(bit_reversed_index, tmp);
			}
		}
	}
}

fn merge_multilins<F, P, Data>(
	multilins: &[MultilinearExtension<P, Data>],
	message_buffer: &mut [P],
) where
	F: TowerField,
	P: PackedField<Scalar = F>,
	Data: Deref<Target = [P]>,
{
	let mut remaining_offset = 0usize;
	let mut first_scalar_idx = None;
	R7X_MERGE_SCRATCH.with(|cell| {
		let mut scratch = cell.borrow_mut();
		scratch.clear();

		for i in (0..multilins.len()).rev() {
			let mle = &multilins[i];
			if mle.n_vars() >= P::LOG_WIDTH {
				let len = mle.evals().len();
				scratch.push((i, remaining_offset, len));
				remaining_offset += len;
			} else {
				first_scalar_idx = Some(i);
				break;
			}
		}

		let buffer_ptr = message_buffer.as_mut_ptr();
		let buffer_len = message_buffer.len();
		scratch.par_iter().for_each(|(idx, offset, len)| {
			debug_assert!(offset + len <= buffer_len);
			let mle = &multilins[*idx];
			let evals = mle.evals();
			unsafe {
				let chunk = std::slice::from_raw_parts_mut(buffer_ptr.add(*offset), *len);
				chunk.copy_from_slice(evals);
				reverse_index_bits(&mut PackedSliceMut::new(chunk));
			}
		});
	});

	let mut remaining_buffer = PackedSliceMut::new(&mut message_buffer[remaining_offset..]);
	if let Some(mut i) = first_scalar_idx {
		let mut scalar_offset = 0;
		loop {
			let mle = &multilins[i];
			let packed_eval = mle.evals()[0];
			let len = 1 << mle.n_vars();
			let mut packed_chunk =
				SequenceSubrangeMut::new(&mut remaining_buffer, scalar_offset, len);
			for j in 0..len {
				packed_chunk.set(j, packed_eval.get(j));
			}
			reverse_index_bits(&mut packed_chunk);
			scalar_offset += len;
			if i == 0 {
				break;
			}
			i -= 1;
		}
	}
}

pub(crate) fn pack_committed_multilins<'a, F, P, M>(
	committed_multilins: &'a [M],
) -> Result<Vec<MultilinearExtension<P, Cow<'a, [P]>>>, Error>
where
	F: TowerField,
	P: PackedField<Scalar = F>,
	M: MultilinearPoly<P>,
{
	let mut packed =
		Vec::<Result<MultilinearExtension<P, Cow<'a, [P]>>, Error>>::with_capacity(
			committed_multilins.len(),
		);
	committed_multilins
		.par_iter()
		.enumerate()
		.map(|(i, unpacked_committed)| {
			packed_committed(OracleId::from_index(i), unpacked_committed)
		})
		.collect_into_vec(&mut packed);
	packed.into_iter().collect::<Result<Vec<_>, _>>()
}

pub fn commit_packed<F, FEncode, P, NTT, MTScheme, MTProver, Data>(
	fri_params: &FRIParams<F, FEncode>,
	ntt: &NTT,
	merkle_prover: &MTProver,
	packed_multilins: &[MultilinearExtension<P, Data>],
	codeword_scratch: Option<&mut Vec<P>>,
) -> Result<fri::CommitOutput<P, MTScheme::Digest, MTProver::Committed>, Error>
where
	F: TowerField,
	FEncode: BinaryField,
	P: PackedField<Scalar = F> + PackedExtension<FEncode> + bytemuck::Zeroable,
	NTT: AdditiveNTT<FEncode> + Sync,
	MTScheme: MerkleTreeScheme<F>,
	MTProver: MerkleTreeProver<F, Scheme = MTScheme>,
	Data: Deref<Target = [P]>,
{
	if !is_sorted_ascending(packed_multilins.iter().map(|mle| mle.n_vars())) {
		return Err(Error::CommittedsNotSorted);
	}
	if std::env::var("ORIGAMI_BN254_R7X_TRACE_COMMIT")
		.ok()
		.as_deref()
		== Some("1")
	{
		let prefix = std::env::var("ORIGAMI_BN254_R7X_TRACE_COMMIT_PREFIX")
			.unwrap_or_else(|_| "r7x".to_string());
		let rs_code = fri_params.rs_code();
		eprintln!(
			"r7x commit [{prefix}] fri log_batch_size={} log_dim={} log_inv_rate={} n_test_queries={}",
			fri_params.log_batch_size(),
			rs_code.log_dim(),
			rs_code.log_inv_rate(),
			fri_params.n_test_queries()
		);
		let sample_count = packed_multilins.len().min(3);
		for (idx, mle) in packed_multilins.iter().take(sample_count).enumerate() {
			let evals = mle.evals();
			let first = evals.get(0).copied();
			eprintln!(
				"r7x commit [{prefix}] idx={idx} n_vars={} evals={} first={:?}",
				mle.n_vars(),
				evals.len(),
				first
			);
		}
	}
	let output = match codeword_scratch {
		Some(encoded) => fri::commit_interleaved_with_buffer(
			fri_params,
			ntt,
			merkle_prover,
			encoded,
			|message_buffer| {
				merge_multilins::<F, P, _>(packed_multilins, message_buffer)
			},
		)?,
		None => fri::commit_interleaved_with(fri_params, ntt, merkle_prover, |message_buffer| {
			merge_multilins::<F, P, _>(packed_multilins, message_buffer)
		})?,
	};
	Ok(output)
}

#[allow(dead_code)]
pub fn commit<F, FEncode, P, M, NTT, MTScheme, MTProver>(
    fri_params: &FRIParams<F, FEncode>,
    ntt: &NTT,
	merkle_prover: &MTProver,
	multilins: &[M],
) -> Result<fri::CommitOutput<P, MTScheme::Digest, MTProver::Committed>, Error>
where
	F: TowerField,
	FEncode: BinaryField,
	P: PackedField<Scalar = F> + PackedExtension<FEncode> + bytemuck::Zeroable,
	M: MultilinearPoly<P>,
	NTT: AdditiveNTT<FEncode> + Sync,
	MTScheme: MerkleTreeScheme<F>,
	MTProver: MerkleTreeProver<F, Scheme = MTScheme>,
{
	let packed_multilins = pack_committed_multilins::<F, P, _>(multilins)?;
	commit_packed(fri_params, ntt, merkle_prover, &packed_multilins, None)
}

pub fn prepare_packed_committed_device<
	'a,
	F,
	P,
	Hal,
	HostComputeAllocatorType,
	DeviceComputeAllocatorType,
>(
	compute_data: &'a ComputeData<'a, F, Hal, HostComputeAllocatorType, DeviceComputeAllocatorType>,
	packed_committed_multilins: &[MultilinearExtension<P, Cow<'a, [P]>>],
	packed_committed_ranges: &[Range<usize>],
) -> Result<Option<PackedCommittedDevice<'a, F, Hal>>, Error>
where
	F: TowerField,
	P: PackedField<Scalar = F>
		+ PackedExtension<F, PackedSubfield = P>
		+ PackedFieldIndexable<Scalar = F>,
	Hal: ComputeLayer<F>,
	HostComputeAllocatorType: ComputeAllocator<F, CpuMemory>,
	DeviceComputeAllocatorType: ComputeAllocator<F, Hal::DevMem>,
{
	if packed_committed_multilins.is_empty() {
		return Ok(None);
	}
	if packed_committed_multilins.len() != packed_committed_ranges.len() {
		return Err(Error::CommittedsNotSorted);
	}
	let total_committed_len = packed_committed_ranges
		.last()
		.map(|range| range.end)
		.unwrap_or(0);
	if total_committed_len == 0 {
		return Ok(None);
	}
	let hal = compute_data.hal;
	let dev_alloc = &compute_data.dev_alloc;
	let mut committed_block = dev_alloc.alloc(total_committed_len)?;
	for (packed_committed_multilin, range) in packed_committed_multilins
		.iter()
		.zip(packed_committed_ranges.iter())
	{
		let hypercube_evals = packed_committed_multilin.evals();
		let unpacked_hypercube_evals = <P as PackedFieldIndexable>::unpack_scalars(hypercube_evals);
		let len = 1usize << packed_committed_multilin.n_vars();
		debug_assert_eq!(range.len(), len);
		let mut dst = Hal::DevMem::slice_mut(&mut committed_block, range.clone());
		hal.copy_h2d(&unpacked_hypercube_evals[0..len], &mut dst)?;
	}
	let committed_block = Hal::DevMem::to_const(committed_block);
	Ok(Some(PackedCommittedDevice {
		block: committed_block,
	}))
}

#[allow(clippy::too_many_arguments)]
pub fn prove_with_packed<
	'a,
	Hal,
	F,
	FEncode,
	P,
	NTT,
	MTScheme,
	MTProver,
	Challenger_,
	HostComputeAllocatorType,
	DeviceComputeAllocatorType,
>(
	compute_data: &'a ComputeData<'a, F, Hal, HostComputeAllocatorType, DeviceComputeAllocatorType>,
	fri_params: &FRIParams<F, FEncode>,
	ntt: &NTT,
	merkle_prover: &MTProver,
	commit_meta: &CommitMeta,
	committed: MTProver::Committed,
	codeword: &[P],
	packed_committed_multilins: &[MultilinearExtension<P, Cow<'a, [P]>>],
	packed_committed_ranges_opt: Option<&[Range<usize>]>,
	transparent_multilins: &[<<Hal as ComputeLayer<F>>::DevMem as ComputeMemory<F>>::FSlice<'a>],
	claims: &[PIOPSumcheckClaim<F>],
	committed_ranges_opt: Option<&[Range<usize>]>,
	packed_device: Option<PackedCommittedDevice<'a, F, Hal>>,
	transcript: &mut ProverTranscript<Challenger_>,
) -> Result<(), Error>
where
	F: TowerField,
	FEncode: BinaryField,
	P: PackedField<Scalar = F>
		+ PackedExtension<F, PackedSubfield = P>
		+ PackedExtension<FEncode>
		+ PackedFieldIndexable<Scalar = F>,
	NTT: AdditiveNTT<FEncode> + Sync,
	MTScheme: MerkleTreeScheme<F, Digest: SerializeBytes>,
	MTProver: MerkleTreeProver<F, Scheme = MTScheme>,
	Challenger_: Challenger,
	Hal: ComputeLayer<F>,
	HostComputeAllocatorType: ComputeAllocator<F, CpuMemory>,
	DeviceComputeAllocatorType: ComputeAllocator<F, Hal::DevMem>,
{
	let host_alloc = &compute_data.host_alloc;
	let dev_alloc = &compute_data.dev_alloc;
	let hal = compute_data.hal;

	let sumcheck_claim_descs = match committed_ranges_opt {
		Some(committed_ranges) => make_sumcheck_claim_descs_with_committed(
			committed_ranges,
			transparent_multilins
				.iter()
				.map(|poly| checked_log_2(poly.len())),
			claims,
		)?,
		None => make_sumcheck_claim_descs(
			commit_meta,
			transparent_multilins
				.iter()
				.map(|poly| checked_log_2(poly.len())),
			claims,
		)?,
	};

	let packed_committed_ranges_owned;
	let packed_committed_ranges = if let Some(ranges) = packed_committed_ranges_opt {
		ranges
	} else {
		packed_committed_ranges_owned =
			build_packed_committed_ranges(&packed_committed_multilins);
		packed_committed_ranges_owned.as_slice()
	};

	let copy_span = tracing::debug_span!(
		"[task] Copy polynomials to device memory",
		phase = "piop_compiler",
		perfetto_category = "phase.sub",
	)
	.entered();
	let packed_device = match packed_device {
		Some(device) => Some(device),
		None => prepare_packed_committed_device(
			compute_data,
			&packed_committed_multilins,
			packed_committed_ranges,
		)?,
	};
	let committed_block = packed_device.map(|device| device.block);

	drop(copy_span);

	let sumcheck_provers = build_sumcheck_provers_from_block(
		&sumcheck_claim_descs,
		committed_block,
		&packed_committed_ranges,
		transparent_multilins,
		hal,
		dev_alloc,
		host_alloc,
	)?;

	prove_interleaved_fri_sumcheck(
		hal,
		dev_alloc,
		commit_meta.total_vars(),
		fri_params,
		ntt,
		merkle_prover,
		sumcheck_provers,
		codeword,
		&committed,
		transcript,
	)?;

	Ok(())
}

#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
pub fn prove<
	'a,
    Hal,
    F,
	FEncode,
	P,
	M,
	NTT,
	MTScheme,
	MTProver,
	Challenger_,
	HostComputeAllocatorType,
	DeviceComputeAllocatorType,
>(
	compute_data: &'a ComputeData<'a, F, Hal, HostComputeAllocatorType, DeviceComputeAllocatorType>,
	fri_params: &FRIParams<F, FEncode>,
	ntt: &NTT,
	merkle_prover: &MTProver,
	commit_meta: &CommitMeta,
	committed: MTProver::Committed,
	codeword: &[P],
	committed_multilins: &'a [M],
	transparent_multilins: &[<<Hal as ComputeLayer<F>>::DevMem as ComputeMemory<F>>::FSlice<'a>],
	claims: &[PIOPSumcheckClaim<F>],
	transcript: &mut ProverTranscript<Challenger_>,
) -> Result<(), Error>
where
	F: TowerField,
	FEncode: BinaryField,
	P: PackedField<Scalar = F>
		+ PackedExtension<F, PackedSubfield = P>
		+ PackedExtension<FEncode>
		+ PackedFieldIndexable<Scalar = F>,
	M: MultilinearPoly<P> + Send + Sync,
	NTT: AdditiveNTT<FEncode> + Sync,
	MTScheme: MerkleTreeScheme<F, Digest: SerializeBytes>,
	MTProver: MerkleTreeProver<F, Scheme = MTScheme>,
	Challenger_: Challenger,
	Hal: ComputeLayer<F>,
	HostComputeAllocatorType: ComputeAllocator<F, CpuMemory>,
	DeviceComputeAllocatorType: ComputeAllocator<F, Hal::DevMem>,
{
	let packed_committed_multilins = pack_committed_multilins::<F, P, _>(committed_multilins)?;
	prove_with_packed(
		compute_data,
		fri_params,
		ntt,
		merkle_prover,
		commit_meta,
		committed,
		codeword,
		&packed_committed_multilins,
		None,
		transparent_multilins,
		claims,
		None,
		None,
		transcript,
	)
}

#[allow(clippy::too_many_arguments)]
fn prove_interleaved_fri_sumcheck<Hal, F, FEncode, P, NTT, MTScheme, MTProver, Challenger_>(
	hal: &Hal,
	dev_alloc: &impl ComputeAllocator<F, Hal::DevMem>,
	n_rounds: usize,
	fri_params: &FRIParams<F, FEncode>,
	ntt: &NTT,
	merkle_prover: &MTProver,
	sumcheck_provers: Vec<impl SumcheckProver<F>>,
	codeword: &[P],
	committed: &MTProver::Committed,
	transcript: &mut ProverTranscript<Challenger_>,
) -> Result<(), Error>
where
	Hal: ComputeLayer<F>,
	F: TowerField,
	FEncode: BinaryField,
	P: PackedField<Scalar = F> + PackedExtension<FEncode>,
	NTT: AdditiveNTT<FEncode> + Sync,
	MTScheme: MerkleTreeScheme<F, Digest: SerializeBytes>,
	MTProver: MerkleTreeProver<F, Scheme = MTScheme>,
	Challenger_: Challenger,
{
	let mut fri_prover = FRIFolder::new(hal, fri_params, ntt, merkle_prover, codeword, committed)?;

	let mut sumcheck_batch_prover = SumcheckBatchProver::new(sumcheck_provers, transcript)?;

	for round in 0..n_rounds {
		let _span =
			tracing::debug_span!("PIOP Compiler Round", phase = "piop_compiler", round = round)
				.entered();

		let bivariate_sumcheck_span = tracing::debug_span!(
			"[step] Bivariate Sumcheck",
			phase = "piop_compiler",
			round = round,
			perfetto_category = "phase.sub"
		)
		.entered();
		let provers_dimensions_data =
			SumcheckBatchProverDimensionsData::new(round, sumcheck_batch_prover.provers());
		let bivariate_sumcheck_calculate_coeffs_span = tracing::debug_span!(
			"[task] (PIOP Compiler) Calculate Coeffs",
			phase = "piop_compiler",
			round = round,
			perfetto_category = "task.main",
			dimensions_data = ?provers_dimensions_data,
		)
		.entered();

		sumcheck_batch_prover.send_round_proof(&mut transcript.message())?;
		drop(bivariate_sumcheck_calculate_coeffs_span);

		let challenge = transcript.sample();
		let bivariate_sumcheck_all_folds_span = tracing::debug_span!(
			"[task] (PIOP Compiler) Fold (All Rounds)",
			phase = "piop_compiler",
			round = round,
			perfetto_category = "task.main",
			dimensions_data = ?provers_dimensions_data,
		)
		.entered();
		sumcheck_batch_prover.receive_challenge(challenge)?;
		drop(bivariate_sumcheck_all_folds_span);
		drop(bivariate_sumcheck_span);

		let dimensions_data = FriFoldRoundsData::new(
			round,
			fri_params.log_batch_size(),
			fri_prover.current_codeword_len(),
		);
		let fri_fold_rounds_span = tracing::debug_span!(
			"[step] FRI Fold Rounds",
			phase = "piop_compiler",
			round = round,
			perfetto_category = "phase.sub",
			?dimensions_data,
		)
		.entered();
		match fri_prover.execute_fold_round(dev_alloc, challenge)? {
			FoldRoundOutput::NoCommitment => {}
			FoldRoundOutput::Commitment(round_commitment) => {
				transcript.message().write(&round_commitment);
			}
		}
		drop(fri_fold_rounds_span);
	}

	sumcheck_batch_prover.finish(&mut transcript.message())?;
	fri_prover.finish_proof(transcript)?;
	Ok(())
}

#[allow(dead_code)]
pub fn validate_sumcheck_witness<'a, F, P, M, Hal: ComputeLayer<F>>(
	committed_multilins: &[M],
	transparent_multilins: &[FSlice<'a, F, Hal>],
	claims: &[PIOPSumcheckClaim<F>],
	hal: &Hal,
) -> Result<(), Error>
where
	F: TowerField,
	P: PackedField<Scalar = F>,
	M: MultilinearPoly<P> + Send + Sync,
{
	let packed_committed = committed_multilins
		.iter()
		.enumerate()
		.map(|(i, unpacked_committed)| {
			packed_committed(OracleId::from_index(i), unpacked_committed)
		})
		.collect::<Result<Vec<_>, _>>()?;

	for (i, claim) in claims.iter().enumerate() {
		let committed = &packed_committed[claim.committed];
		if committed.n_vars() != claim.n_vars {
			bail!(sumcheck::Error::NumberOfVariablesMismatch);
		}

		let transparent = &transparent_multilins[claim.transparent];
		if transparent.len() != 1 << claim.n_vars {
			bail!(sumcheck::Error::NumberOfVariablesMismatch);
		}

		let mut transparent_evals = zeroed_vec(transparent.len());

		hal.copy_d2h(*transparent, &mut transparent_evals)?;

		let sum = (0..(1 << claim.n_vars))
			.into_par_iter()
			.map(|j| {
				let committed_eval = committed
					.evaluate_on_hypercube(j)
					.expect("j is less than 1 << n_vars; committed.n_vars is checked above");
				let transparent_eval = transparent_evals
					.get(j)
					.expect("j is less than 1 << n_vars; transparent.n_vars is checked above");
				committed_eval * transparent_eval
			})
			.sum::<F>();

		if sum != claim.sum {
			bail!(sumcheck::Error::SumcheckNaiveValidationFailure {
				composition_index: i,
			});
		}
	}
	Ok(())
}

fn packed_committed<F, P, M>(
	id: OracleId,
	unpacked_committed: &M,
) -> Result<MultilinearExtension<P, Cow<'_, [P]>>, Error>
where
	F: TowerField,
	P: PackedField<Scalar = F>,
	M: MultilinearPoly<P>,
{
	let unpacked_n_vars = unpacked_committed.n_vars();
	let packed_committed = if unpacked_n_vars < unpacked_committed.log_extension_degree() {
		let packed_eval = padded_packed_eval(unpacked_committed);
		MultilinearExtension::new(0, Cow::Owned(vec![P::set_single(packed_eval)]))
	} else {
		let packed_evals = unpacked_committed
			.packed_evals()
			.ok_or(Error::CommittedPackedEvaluationsMissing { id })?;

		MultilinearExtension::new(
			unpacked_n_vars - unpacked_committed.log_extension_degree(),
			Cow::Borrowed(packed_evals),
		)
	}?;
	Ok(packed_committed)
}

#[inline]
fn padded_packed_eval<F, P, M>(multilin: &M) -> F
where
	F: TowerField,
	P: PackedField<Scalar = F>,
	M: MultilinearPoly<P>,
{
	let n_vars = multilin.n_vars();
	let kappa = multilin.log_extension_degree();
	assert!(n_vars < kappa);

	(0..1 << kappa)
		.map(|i| {
			let iota = F::TOWER_LEVEL - kappa;
			let scalar = <F as TowerField>::basis(iota, i)
				.expect("i is in range 0..1 << log_extension_degree");
			multilin
				.evaluate_on_hypercube_and_scale(i % (1 << n_vars), scalar)
				.expect("i is in range 0..1 << n_vars")
		})
		.sum()
}
