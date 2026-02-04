// Copyright 2024-2025 Irreducible Inc.

use std::{borrow::Cow, cell::RefCell, ops::Deref};

use binius_compute::{
	ComputeData, ComputeLayer, ComputeMemory, FSlice, SizedSlice, alloc::ComputeAllocator,
	cpu::CpuMemory,
};
use binius_field::{
	BinaryField, PackedExtension, PackedField, PackedFieldIndexable, TowerField,
	packed::PackedSliceMut,
};
use binius_math::{MLEDirectAdapter, MultilinearExtension, MultilinearPoly};
use binius_maybe_rayon::{iter::IntoParallelIterator, prelude::*};
use binius_ntt::AdditiveNTT;
use binius_utils::{
	SerializeBytes, bail,
	checked_arithmetics::checked_log_2,
	random_access_sequence::{RandomAccessSequenceMut, SequenceSubrangeMut},
	sorting::is_sorted_ascending,
};
use bytemuck::zeroed_vec;

use super::{
	error::Error,
	verify::{PIOPSumcheckClaim, SumcheckClaimDesc, make_sumcheck_claim_descs},
};
use crate::{
	fiat_shamir::{CanSample, Challenger},
	merkle_tree::{MerkleTreeProver, MerkleTreeScheme},
	oracle::OracleId,
	piop::{
		CommitMeta,
		logging::{FriFoldRoundsData, SumcheckBatchProverDimensionsData},
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
	static PIOP_MERGE_SCRATCH: RefCell<Vec<(usize, usize, usize)>> = RefCell::new(Vec::new());
}

#[inline(always)]
fn reverse_bits(x: usize, log_len: usize) -> usize {
	x.reverse_bits()
		.wrapping_shr((usize::BITS as usize - log_len) as _)
}

/// Reorders the scalars in a slice of packed field elements by reversing the bits of their indices.
/// TODO: investigate if we can optimize this.
fn reverse_index_bits<T: Copy>(collection: &mut impl RandomAccessSequenceMut<T>) {
	let log_len = checked_log_2(collection.len());
	for i in 0..collection.len() {
		let bit_reversed_index = reverse_bits(i, log_len);
		if i < bit_reversed_index {
			// Safety: `i` and `j` are guaranteed to be in bounds of the slice
			unsafe {
				let tmp = collection.get_unchecked(i);
				collection.set_unchecked(i, collection.get_unchecked(bit_reversed_index));
				collection.set_unchecked(bit_reversed_index, tmp);
			}
		}
	}
}

// ## Preconditions
//
// * all multilinears in `multilins` have at least log_extension_degree packed variables
// * all multilinears in `multilins` have `packed_evals()` is Some
// * multilinears are sorted in ascending order by number of packed variables
// * `message_buffer` is initialized to all zeros
// * `message_buffer` is larger than the total number of scalars in the multilinears
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
	PIOP_MERGE_SCRATCH.with(|cell| {
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

	// Now copy scalars from the remaining multilinears, which have too few elements to copy full
	// packed elements.
	if let Some(mut i) = first_scalar_idx {
		let mut remaining_buffer = PackedSliceMut::new(&mut message_buffer[remaining_offset..]);
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

pub(crate) fn build_sumcheck_provers<'a, F, Hal, HostAllocatorType, DeviceAllocatorType>(
	sumcheck_claim_descs: &[SumcheckClaimDesc<F>],
	packed_committed_fslices: &'a [<<Hal as ComputeLayer<F>>::DevMem as ComputeMemory<F>>::FSlice<'a>],
	transparent_multilins: &'a [<<Hal as ComputeLayer<F>>::DevMem as ComputeMemory<F>>::FSlice<'a>],
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
		multilins.extend(
			packed_committed_fslices[desc.committed_indices.clone()]
				.iter()
				.copied(),
		);
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

pub(crate) fn build_sumcheck_provers_from_block<'a, F, Hal, HostAllocatorType, DeviceAllocatorType>(
	sumcheck_claim_descs: &[SumcheckClaimDesc<F>],
	committed_block: Option<<<Hal as ComputeLayer<F>>::DevMem as ComputeMemory<F>>::FSlice<'a>>,
	committed_ranges: &[std::ops::Range<usize>],
	transparent_multilins: Vec<<<Hal as ComputeLayer<F>>::DevMem as ComputeMemory<F>>::FSlice<'a>>,
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


/// Commits a batch of multilinear polynomials.
///
/// The multilinears this function accepts as arguments may be defined over subfields of `F`. In
/// this case, we commit to these multilinears by instead committing to their "packed"
/// multilinears. These are the multilinear extensions of their packed coefficients over subcubes
/// of the size of the extension degree.
///
/// ## Arguments
///
/// * `fri_params` - the FRI parameters for the commitment opening protocol
/// * `merkle_prover` - the Merkle tree prover used in FRI
/// * `multilins` - a batch of multilinear polynomials to commit. The multilinears provided may be
///   defined over subfields of `F`. They must be in ascending order by the number of variables in
///   the packed multilinear (ie. number of variables minus log extension degree).
pub fn commit<F, FEncode, P, M, NTT, MTScheme, MTProver>(
        fri_params: &FRIParams<F, FEncode>,
        ntt: &NTT,
        merkle_prover: &MTProver,
        multilins: &[M],
        codeword_scratch: Option<&mut Vec<P>>,
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
        let trace = std::env::var("GLYPH_PCS_BASEFOLD_TRACE").ok().as_deref() == Some("1");
        if trace {
                let rs_code = fri_params.rs_code();
                eprintln!(
                        "piop commit: start log_dim={} log_inv_rate={} log_batch_size={} log_len={} n_multilins={}",
                        rs_code.log_dim(),
                        rs_code.log_inv_rate(),
                        fri_params.log_batch_size(),
                        fri_params.log_len(),
                        multilins.len(),
                );
        }
        let mut packed_multilins =
                Vec::<Result<MultilinearExtension<P, Cow<'_, [P]>>, Error>>::with_capacity(multilins.len());
	multilins
		.par_iter()
		.enumerate()
		.map(|(i, unpacked_committed)| {
			packed_committed(OracleId::from_index(i), unpacked_committed)
		})
		.collect_into_vec(&mut packed_multilins);
        let packed_multilins = packed_multilins.into_iter().collect::<Result<Vec<_>, _>>()?;
        if !is_sorted_ascending(packed_multilins.iter().map(|mle| mle.n_vars())) {
                return Err(Error::CommittedsNotSorted);
        }
	if std::env::var("ORIGAMI_BN254_R7X_TRACE_COMMIT")
		.ok()
		.as_deref()
		== Some("1")
	{
		let prefix = std::env::var("ORIGAMI_BN254_R7X_TRACE_COMMIT_PREFIX")
			.unwrap_or_else(|_| "m3".to_string());
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

        if trace {
                let total_packed = packed_multilins
                        .iter()
                        .map(|mle| 1usize << mle.n_vars())
                        .sum::<usize>();
                eprintln!("piop commit: packed multilins total_elems={}", total_packed);
        }
        let output = match codeword_scratch {
                Some(encoded) => fri::commit_interleaved_with_buffer(
                        fri_params,
                        ntt,
                        merkle_prover,
                        encoded,
                        |message_buffer| merge_multilins(&packed_multilins, message_buffer),
                )?,
		None => fri::commit_interleaved_with(fri_params, ntt, merkle_prover, |message_buffer| {
			merge_multilins(&packed_multilins, message_buffer)
		})?,
	};

        if trace {
                eprintln!("piop commit: done codeword_len={}", output.codeword.len());
        }
        Ok(output)
}

/// Proves a batch of sumcheck claims that are products of committed polynomials from a committed
/// batch and transparent polynomials.
///
/// The arguments corresponding to the committed multilinears must be the output of [`commit`].
#[allow(clippy::too_many_arguments)]
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
	committed_multilins: &[M],
	transparent_multilins: Vec<<<Hal as ComputeLayer<F>>::DevMem as ComputeMemory<F>>::FSlice<'a>>,
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
	let host_alloc = &compute_data.host_alloc;
	let dev_alloc = &compute_data.dev_alloc;
	let hal = compute_data.hal;

	let sumcheck_claim_descs = make_sumcheck_claim_descs(
		commit_meta,
		transparent_multilins
			.iter()
			.map(|poly| checked_log_2(poly.len())),
		claims,
	)?;

	// The committed multilinears provided by argument are committed *small field* multilinears.
	// Create multilinears representing the packed polynomials here. Eventually, we would like to
	// refactor the calling code so that the PIOP only handles *big field* multilinear witnesses.
	let mut packed_committed_multilins = Vec::<
		Result<MultilinearExtension<P, Cow<'_, [P]>>, Error>,
	>::with_capacity(committed_multilins.len());
	committed_multilins
		.par_iter()
		.enumerate()
		.map(|(i, unpacked_committed)| {
			packed_committed(OracleId::from_index(i), unpacked_committed)
		})
		.collect_into_vec(&mut packed_committed_multilins);
	let packed_committed_multilins = packed_committed_multilins
		.into_iter()
		.collect::<Result<Vec<_>, _>>()?
		.into_iter()
		.map(MLEDirectAdapter::from)
		.collect::<Vec<_>>();

	let copy_span = tracing::debug_span!(
		"[task] Copy polynomials to device memory",
		phase = "piop_compiler",
		perfetto_category = "phase.sub",
	)
	.entered();
	let total_committed_len = packed_committed_multilins
		.iter()
		.map(|poly| 1usize << poly.n_vars())
		.sum::<usize>();
	let mut committed_block = if total_committed_len == 0 {
		None
	} else {
		Some(dev_alloc.alloc(total_committed_len)?)
	};
	let mut committed_ranges = Vec::with_capacity(packed_committed_multilins.len());
	let mut committed_offset = 0usize;
	for packed_committed_multilin in &packed_committed_multilins {
		let hypercube_evals = packed_committed_multilin
			.packed_evals()
			.expect("Prover should always populate witnesses");
		let unpacked_hypercube_evals =
			<P as PackedFieldIndexable>::unpack_scalars(hypercube_evals);
		let len = 1usize << packed_committed_multilin.n_vars();
		let block = committed_block.as_mut().expect("committed block missing");
		let mut dst = Hal::DevMem::slice_mut(block, committed_offset..committed_offset + len);

		hal.copy_h2d(&unpacked_hypercube_evals[0..len], &mut dst)?;
		committed_ranges.push(committed_offset..committed_offset + len);
		committed_offset += len;
	}
	let committed_block = committed_block.map(Hal::DevMem::to_const);

	drop(copy_span);

	let sumcheck_provers = build_sumcheck_provers_from_block(
		&sumcheck_claim_descs,
		committed_block,
		&committed_ranges,
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
	let mut packed_committed_vec = Vec::<Result<MultilinearExtension<P, Cow<'_, [P]>>, Error>>::with_capacity(
		committed_multilins.len(),
	);
	committed_multilins
		.par_iter()
		.enumerate()
		.map(|(i, unpacked_committed)| {
			packed_committed(OracleId::from_index(i), unpacked_committed)
		})
		.collect_into_vec(&mut packed_committed_vec);
	let packed_committed = packed_committed_vec.into_iter().collect::<Result<Vec<_>, _>>()?;

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

/// Creates a multilinear extension of the packed evaluations of a small-field multilinear.
///
/// Given a multilinear $P \in T_{\iota}[X_0, \ldots, X_{n-1}]$, this creates the multilinear
/// extension $\hat{P} \in T_{\tau}[X_0, \ldots, X_{n - \kappa - 1}]$. In the case where
/// $n < \kappa$, which is when a polynomial is too full to have even a single packed evaluation,
/// the polynomial is extended by padding with more variables, which corresponds to repeating its
/// subcube evaluations.
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

#[cfg(test)]
mod tests {
	use std::iter::repeat_with;

	use binius_field::PackedBinaryField2x128b;
	use rand::{SeedableRng, rngs::StdRng};

	use super::*;

	#[test]
	fn test_merge_multilins() {
		let mut rng = StdRng::seed_from_u64(0);

		let multilins = (0usize..8)
			.map(|n_vars| {
				let data = repeat_with(|| PackedBinaryField2x128b::random(&mut rng))
					.take(1 << n_vars.saturating_sub(PackedBinaryField2x128b::LOG_WIDTH))
					.collect::<Vec<_>>();

				MultilinearExtension::new(n_vars, data).unwrap()
			})
			.collect::<Vec<_>>();
		let scalars = (0..8).map(|i| 1usize << i).sum::<usize>();
		let mut buffer =
			vec![PackedBinaryField2x128b::zero(); scalars.div_ceil(PackedBinaryField2x128b::WIDTH)];
		merge_multilins(&multilins, &mut buffer);

		let scalars = PackedField::iter_slice(&buffer).take(scalars).collect_vec();
		let mut offset = 0;
		for multilin in multilins.iter().rev() {
			let scalars = &scalars[offset..];
			for (i, v) in PackedField::iter_slice(multilin.evals())
				.take(1 << multilin.n_vars())
				.enumerate()
			{
				assert_eq!(scalars[reverse_bits(i, multilin.n_vars())], v);
			}
			offset += 1 << multilin.n_vars();
		}
	}
}
