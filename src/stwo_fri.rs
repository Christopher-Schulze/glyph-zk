use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};

use itertools::{zip_eq, Itertools};
use rayon::prelude::*;

use crate::stwo_types::{
    bit_reverse_index,
    Blake2sChannel,
    Blake2sHash,
    CircleDomain,
    CirclePoint,
    Coset,
    FriConfig,
    FriLayerProof,
    FriProof,
    LineDomain,
    LinePoly,
    MerkleDecommitment,
    MerkleVerifier,
    M31,
    QM31,
    SecureField,
    SECURE_EXTENSION_DEGREE,
};

pub const CIRCLE_TO_LINE_FOLD_STEP: u32 = 1;
const FOLD_STEP: u32 = 1;
const STWO_PAR_MIN_DEFAULT: usize = 1 << 10;

fn stwo_par_min() -> usize {
    std::env::var("GLYPH_STWO_PAR_MIN")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(STWO_PAR_MIN_DEFAULT)
        .max(1)
}

pub fn draw_queries(channel: &mut Blake2sChannel, log_domain_size: u32, n_queries: usize) -> Vec<usize> {
    let mut raw_positions = Vec::new();
    let query_mask = (1usize << log_domain_size) - 1;
    loop {
        let random_words = channel.draw_u32s();
        for word in random_words {
            let quotient_query = (word as usize) & query_mask;
            raw_positions.push(quotient_query);
            if raw_positions.len() == n_queries {
                return raw_positions;
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct Queries {
    pub positions: Vec<usize>,
    pub log_domain_size: u32,
}

impl Queries {
    pub fn new(raw_positions: &[usize], log_domain_size: u32) -> Self {
        Self {
            positions: BTreeSet::from_iter(raw_positions.iter())
                .into_iter()
                .cloned()
                .collect(),
            log_domain_size,
        }
    }

    pub fn fold(&self, n_folds: u32) -> Result<Self, FriVerificationError> {
        if n_folds > self.log_domain_size {
            return Err(FriVerificationError::QueryFoldInvalid);
        }
        Ok(Self {
            positions: self
                .positions
                .iter()
                .map(|q| q >> n_folds)
                .dedup()
                .collect(),
            log_domain_size: self.log_domain_size - n_folds,
        })
    }

    pub fn len(&self) -> usize {
        self.positions.len()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, usize> {
        self.positions.iter()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CirclePolyDegreeBound {
    pub log_degree_bound: u32,
}

impl CirclePolyDegreeBound {
    pub fn new(log_degree_bound: u32) -> Self {
        Self { log_degree_bound }
    }

    pub fn fold_to_line(self) -> LinePolyDegreeBound {
        LinePolyDegreeBound {
            log_degree_bound: self
                .log_degree_bound
                .saturating_sub(CIRCLE_TO_LINE_FOLD_STEP),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct LinePolyDegreeBound {
    pub log_degree_bound: u32,
}

impl LinePolyDegreeBound {
    pub fn fold(self, fold_step: u32) -> Option<Self> {
        if self.log_degree_bound < fold_step {
            return None;
        }
        Some(Self {
            log_degree_bound: self.log_degree_bound - fold_step,
        })
    }
}

#[derive(Debug)]
pub enum FriVerificationError {
    InvalidNumFriLayers,
    QueryFoldInvalid,
    FirstLayerDomainMismatch,
    LastLayerDegreeInvalid,
    FoldInputInvalid,
    SparseEvaluationInvalid,
    FirstLayerEvaluationsInvalid,
    FirstLayerCommitmentInvalid { error: String },
    InnerLayerEvaluationsInvalid { inner_layer: usize },
    InnerLayerDomainMismatch { inner_layer: usize },
    InnerLayerCommitmentInvalid { inner_layer: usize, error: String },
    LastLayerEvaluationsInvalid,
}

pub struct FriVerifier {
    config: FriConfig,
    first_layer: FriFirstLayerVerifier,
    inner_layers: Vec<FriInnerLayerVerifier>,
    last_layer_domain: LineDomain,
    last_layer_poly: LinePoly,
    queries: Option<Queries>,
}

impl FriVerifier {
    pub fn commit(
        channel: &mut Blake2sChannel,
        config: FriConfig,
        proof: FriProof,
        column_bounds: Vec<CirclePolyDegreeBound>,
    ) -> Result<Self, FriVerificationError> {
        if column_bounds.is_empty() {
            return Err(FriVerificationError::InvalidNumFriLayers);
        }
        let mut sorted_bounds = column_bounds;
        sorted_bounds.sort_by_key(|b| Reverse(b.log_degree_bound));
        let max_column_bound = sorted_bounds[0];

        channel.mix_root(proof.first_layer.commitment);

        let column_commitment_domains = sorted_bounds
            .iter()
            .map(|bound| {
                let commitment_log_size = bound.log_degree_bound + config.log_blowup_factor;
                CircleDomain::new(Coset::half_odds(commitment_log_size))
            })
            .collect();

        let first_layer = FriFirstLayerVerifier {
            column_bounds: sorted_bounds,
            column_commitment_domains,
            proof: proof.first_layer,
            folding_alpha: channel.draw_secure_felt(),
        };

        let mut inner_layers = Vec::new();
        let mut layer_bound = max_column_bound.fold_to_line();
        let mut layer_domain = LineDomain::new(Coset::half_odds(
            layer_bound.log_degree_bound + config.log_blowup_factor,
        ));

        for (layer_index, layer_proof) in proof.inner_layers.into_iter().enumerate() {
            channel.mix_root(layer_proof.commitment);
            inner_layers.push(FriInnerLayerVerifier {
                degree_bound: layer_bound,
                domain: layer_domain,
                folding_alpha: channel.draw_secure_felt(),
                layer_index,
                proof: layer_proof,
            });
            layer_bound = layer_bound.fold(FOLD_STEP).ok_or(FriVerificationError::InvalidNumFriLayers)?;
            layer_domain = layer_domain.double();
        }

        if layer_bound.log_degree_bound != config.log_last_layer_degree_bound {
            return Err(FriVerificationError::InvalidNumFriLayers);
        }

        let last_layer_domain = layer_domain;
        let last_layer_poly = proof.last_layer_poly;
        if last_layer_poly.len() > (1 << config.log_last_layer_degree_bound) {
            return Err(FriVerificationError::LastLayerDegreeInvalid);
        }

        channel.mix_felts(last_layer_poly.coeffs());

        Ok(Self {
            config,
            first_layer,
            inner_layers,
            last_layer_domain,
            last_layer_poly,
            queries: None,
        })
    }

    pub fn sample_query_positions(
        &mut self,
        channel: &mut Blake2sChannel,
    ) -> Result<BTreeMap<u32, Vec<usize>>, FriVerificationError> {
        let column_log_sizes = self
            .first_layer
            .column_commitment_domains
            .iter()
            .map(|domain| domain.log_size())
            .collect::<BTreeSet<u32>>();
        let max_column_log_size = *column_log_sizes
            .iter()
            .max()
            .ok_or(FriVerificationError::InvalidNumFriLayers)?;
        let raw_positions = draw_queries(channel, max_column_log_size, self.config.n_queries);
        let queries = Queries::new(&raw_positions, max_column_log_size);
        let query_positions_by_log_size =
            get_query_positions_by_log_size(&queries, column_log_sizes)?;
        self.queries = Some(queries);
        Ok(query_positions_by_log_size)
    }

    pub fn decommit(
        mut self,
        first_layer_query_evals: Vec<Vec<SecureField>>,
    ) -> Result<(), FriVerificationError> {
        let queries = self
            .queries
            .take()
            .ok_or(FriVerificationError::FirstLayerEvaluationsInvalid)?;
        self.decommit_on_queries(&queries, first_layer_query_evals)
    }

    fn decommit_on_queries(
        self,
        queries: &Queries,
        first_layer_query_evals: Vec<Vec<SecureField>>,
    ) -> Result<(), FriVerificationError> {
        let first_layer_sparse_evals =
            self.first_layer.verify(queries, first_layer_query_evals)?;
        let inner_layer_queries = queries.fold(CIRCLE_TO_LINE_FOLD_STEP)?;
        let (last_layer_queries, last_layer_query_evals) =
            self.decommit_inner_layers(&inner_layer_queries, first_layer_sparse_evals)?;
        self.decommit_last_layer(last_layer_queries, last_layer_query_evals)
    }

    fn decommit_inner_layers(
        &self,
        queries: &Queries,
        first_layer_sparse_evals: Vec<SparseEvaluation>,
    ) -> Result<(Queries, Vec<SecureField>), FriVerificationError> {
        let mut layer_queries = queries.clone();
        let mut layer_query_evals = vec![SecureField::zero(); layer_queries.len()];
        let mut first_layer_sparse_evals = first_layer_sparse_evals.into_iter();
        let first_layer_column_bounds = self.first_layer.column_bounds.iter();
        let first_layer_column_domains = self.first_layer.column_commitment_domains.iter();
        let mut first_layer_columns = first_layer_column_bounds
            .zip_eq(first_layer_column_domains)
            .peekable();
        let mut previous_folding_alpha = self.first_layer.folding_alpha;

        for layer in self.inner_layers.iter() {
            while let Some((_, column_domain)) =
                first_layer_columns.next_if(|(b, _)| b.fold_to_line() == layer.degree_bound)
            {
                let folded_column_evals = first_layer_sparse_evals
                    .next()
                    .ok_or(FriVerificationError::FirstLayerEvaluationsInvalid)?
                    .fold_circle(previous_folding_alpha, *column_domain)?;
                accumulate_line(&mut layer_query_evals, &folded_column_evals, previous_folding_alpha);
            }

            (layer_queries, layer_query_evals) =
                layer.verify_and_fold(layer_queries, layer_query_evals)?;
            previous_folding_alpha = layer.folding_alpha;
        }

        if first_layer_columns.next().is_some() {
            return Err(FriVerificationError::FirstLayerEvaluationsInvalid);
        }
        if first_layer_sparse_evals.next().is_some() {
            return Err(FriVerificationError::FirstLayerEvaluationsInvalid);
        }

        Ok((layer_queries, layer_query_evals))
    }

    fn decommit_last_layer(
        &self,
        queries: Queries,
        evals_at_queries: Vec<SecureField>,
    ) -> Result<(), FriVerificationError> {
        if queries.len() >= stwo_par_min() && rayon::current_num_threads() > 1 {
            queries
                .positions
                .par_iter()
                .zip(evals_at_queries.par_iter())
                .try_for_each(|(&query, query_eval)| -> Result<(), FriVerificationError> {
                    let x = self
                        .last_layer_domain
                        .at(bit_reverse_index(query, self.last_layer_domain.log_size()));
                    if *query_eval != self.last_layer_poly.eval_at_point(x.into()) {
                        return Err(FriVerificationError::LastLayerEvaluationsInvalid);
                    }
                    Ok(())
                })?;
            Ok(())
        } else {
            for (&query, query_eval) in queries.iter().zip_eq(evals_at_queries.iter()) {
                let x = self
                    .last_layer_domain
                    .at(bit_reverse_index(query, self.last_layer_domain.log_size()));
                if *query_eval != self.last_layer_poly.eval_at_point(x.into()) {
                    return Err(FriVerificationError::LastLayerEvaluationsInvalid);
                }
            }
            Ok(())
        }
    }
}

struct FriFirstLayerVerifier {
    column_bounds: Vec<CirclePolyDegreeBound>,
    column_commitment_domains: Vec<CircleDomain>,
    proof: FriLayerProof,
    folding_alpha: SecureField,
}

impl FriFirstLayerVerifier {
    fn verify(
        &self,
        queries: &Queries,
        query_evals_by_column: Vec<Vec<SecureField>>,
    ) -> Result<Vec<SparseEvaluation>, FriVerificationError> {
        let max_column_log_size = self.column_commitment_domains[0].log_size();
        if queries.log_domain_size != max_column_log_size {
            return Err(FriVerificationError::FirstLayerDomainMismatch);
        }

        let mut fri_witness = self.proof.fri_witness.iter().copied();
        let mut decommitment_positions_by_log_size = BTreeMap::new();
        let mut sparse_evals_by_column = Vec::new();
        let mut decommitmented_values = Vec::new();

        for (column_domain, column_query_evals) in zip_eq(&self.column_commitment_domains, &query_evals_by_column) {
            let column_queries =
                queries.fold(queries.log_domain_size - column_domain.log_size())
                    .map_err(|_| FriVerificationError::FirstLayerEvaluationsInvalid)?;
            let (column_decommitment_positions, sparse_evaluation) =
                compute_decommitment_positions_and_rebuild_evals(
                    &column_queries,
                    column_query_evals,
                    &mut fri_witness,
                    CIRCLE_TO_LINE_FOLD_STEP,
                )
                .map_err(|InsufficientWitnessError| {
                    FriVerificationError::FirstLayerEvaluationsInvalid
                })?;

            decommitment_positions_by_log_size
                .insert(column_domain.log_size(), column_decommitment_positions);
            decommitmented_values.extend(
                sparse_evaluation
                    .subset_evals
                    .iter()
                    .flatten()
                    .flat_map(|qm31| qm31.to_m31_array()),
            );
            sparse_evals_by_column.push(sparse_evaluation);
        }

        if fri_witness.next().is_some() {
            return Err(FriVerificationError::FirstLayerEvaluationsInvalid);
        }

        let merkle_verifier = MerkleVerifier::new(
            self.proof.commitment,
            self.column_commitment_domains
                .iter()
                .flat_map(|column_domain| [column_domain.log_size(); SECURE_EXTENSION_DEGREE])
                .collect(),
        );

        merkle_verifier
            .verify(
                &decommitment_positions_by_log_size,
                decommitmented_values,
                self.proof.decommitment.clone(),
            )
            .map_err(|error| FriVerificationError::FirstLayerCommitmentInvalid { error })?;

        Ok(sparse_evals_by_column)
    }
}

struct FriInnerLayerVerifier {
    degree_bound: LinePolyDegreeBound,
    domain: LineDomain,
    folding_alpha: SecureField,
    layer_index: usize,
    proof: FriLayerProof,
}

impl FriInnerLayerVerifier {
    fn verify_and_fold(
        &self,
        queries: Queries,
        evals_at_queries: Vec<SecureField>,
    ) -> Result<(Queries, Vec<SecureField>), FriVerificationError> {
        if queries.log_domain_size != self.domain.log_size() {
            return Err(FriVerificationError::InnerLayerDomainMismatch {
                inner_layer: self.layer_index,
            });
        }

        let mut fri_witness = self.proof.fri_witness.iter().copied();
        let (decommitment_positions, sparse_evaluation) =
            compute_decommitment_positions_and_rebuild_evals(
                &queries,
                &evals_at_queries,
                &mut fri_witness,
                FOLD_STEP,
            )
            .map_err(|InsufficientWitnessError| FriVerificationError::InnerLayerEvaluationsInvalid {
                inner_layer: self.layer_index,
            })?;

        if fri_witness.next().is_some() {
            return Err(FriVerificationError::InnerLayerEvaluationsInvalid {
                inner_layer: self.layer_index,
            });
        }

        let decommitmented_values = sparse_evaluation
            .subset_evals
            .iter()
            .flatten()
            .flat_map(|qm31| qm31.to_m31_array())
            .collect_vec();

        let merkle_verifier = MerkleVerifier::new(
            self.proof.commitment,
            vec![self.domain.log_size(); SECURE_EXTENSION_DEGREE],
        );

        merkle_verifier
            .verify(
                &BTreeMap::from_iter([(self.domain.log_size(), decommitment_positions)]),
                decommitmented_values,
                self.proof.decommitment.clone(),
            )
            .map_err(|e| FriVerificationError::InnerLayerCommitmentInvalid {
                inner_layer: self.layer_index,
                error: e,
            })?;

        let folded_queries = queries.fold(FOLD_STEP)?;
        let folded_evals = sparse_evaluation.fold_line(self.folding_alpha, self.domain)?;

        Ok((folded_queries, folded_evals))
    }
}

fn compute_decommitment_positions_and_rebuild_evals(
    queries: &Queries,
    query_evals: &[QM31],
    mut witness_evals: impl Iterator<Item = QM31>,
    fold_step: u32,
) -> Result<(Vec<usize>, SparseEvaluation), InsufficientWitnessError> {
    let mut query_evals = query_evals.iter().copied();

    let mut decommitment_positions = Vec::new();
    let mut subset_evals = Vec::new();
    let mut subset_domain_index_initials = Vec::new();

    for subset_queries in queries.positions.iter().chunk_by(|a, b| (*a >> fold_step) == (*b >> fold_step)) {
        let subset_queries = subset_queries.map(|v| *v).collect_vec();
        let subset_start = (subset_queries[0] >> fold_step) << fold_step;
        let subset_decommitment_positions = subset_start..subset_start + (1 << fold_step);
        decommitment_positions.extend(subset_decommitment_positions.clone());

        let mut subset_queries_iter = subset_queries.iter().copied().peekable();
        let subset_eval = subset_decommitment_positions
            .map(|position| match subset_queries_iter.next_if_eq(&position) {
                Some(_) => query_evals.next().ok_or(InsufficientWitnessError),
                None => witness_evals.next().ok_or(InsufficientWitnessError),
            })
            .collect::<Result<_, _>>()?;

        subset_evals.push(subset_eval);
        subset_domain_index_initials.push(bit_reverse_index(subset_start, queries.log_domain_size));
    }

    let sparse_evaluation =
        SparseEvaluation::new(subset_evals, subset_domain_index_initials)
            .map_err(|InsufficientWitnessError| InsufficientWitnessError)?;
    Ok((decommitment_positions, sparse_evaluation))
}

#[derive(Debug)]
struct InsufficientWitnessError;

struct SparseEvaluation {
    subset_evals: Vec<Vec<SecureField>>,
    subset_domain_initial_indexes: Vec<usize>,
}

impl SparseEvaluation {
    fn new(
        subset_evals: Vec<Vec<SecureField>>,
        subset_domain_initial_indexes: Vec<usize>,
    ) -> Result<Self, InsufficientWitnessError> {
        let fold_factor = 1 << FOLD_STEP;
        if !subset_evals.iter().all(|e| e.len() == fold_factor) {
            return Err(InsufficientWitnessError);
        }
        if subset_evals.len() != subset_domain_initial_indexes.len() {
            return Err(InsufficientWitnessError);
        }
        Ok(Self {
            subset_evals,
            subset_domain_initial_indexes,
        })
    }

    fn fold_line(
        self,
        fold_alpha: SecureField,
        source_domain: LineDomain,
    ) -> Result<Vec<SecureField>, FriVerificationError> {
        let n = self.subset_evals.len();
        if n >= stwo_par_min() && rayon::current_num_threads() > 1 {
            let out = self.subset_evals
                .into_par_iter()
                .zip(self.subset_domain_initial_indexes.into_par_iter())
                .map(|(eval, domain_initial_index)| {
                    let fold_domain_initial = source_domain.coset().index_at(domain_initial_index);
                    let fold_domain = LineDomain::new(Coset::new(fold_domain_initial, FOLD_STEP));
                    let (_, folded_values) = fold_line(&eval, fold_domain, fold_alpha)?;
                    Ok(folded_values[0])
                })
                .collect::<Result<Vec<_>, FriVerificationError>>()?;
            Ok(out)
        } else {
            let out = zip_eq(self.subset_evals, self.subset_domain_initial_indexes)
                .map(|(eval, domain_initial_index)| {
                    let fold_domain_initial = source_domain.coset().index_at(domain_initial_index);
                    let fold_domain = LineDomain::new(Coset::new(fold_domain_initial, FOLD_STEP));
                    let (_, folded_values) = fold_line(&eval, fold_domain, fold_alpha)?;
                    Ok(folded_values[0])
                })
                .collect::<Result<Vec<_>, FriVerificationError>>()?;
            Ok(out)
        }
    }

    fn fold_circle(
        self,
        fold_alpha: SecureField,
        source_domain: CircleDomain,
    ) -> Result<Vec<SecureField>, FriVerificationError> {
        let n = self.subset_evals.len();
        if n >= stwo_par_min() && rayon::current_num_threads() > 1 {
            let out = self.subset_evals
                .into_par_iter()
                .zip(self.subset_domain_initial_indexes.into_par_iter())
                .map(|(eval, domain_initial_index)| {
                    let fold_domain_initial = source_domain.index_at(domain_initial_index);
                    let fold_domain = CircleDomain::new(Coset::new(
                        fold_domain_initial,
                        CIRCLE_TO_LINE_FOLD_STEP - 1,
                    ));
                    let eval = eval.into_iter().collect_vec();
                    let mut buffer = vec![SecureField::zero(); fold_domain.half_coset().size()];
                    fold_circle_into_line(&mut buffer, &eval, fold_domain, fold_alpha)?;
                    Ok(buffer[0])
                })
                .collect::<Result<Vec<_>, FriVerificationError>>()?;
            Ok(out)
        } else {
            let out = zip_eq(self.subset_evals, self.subset_domain_initial_indexes)
                .map(|(eval, domain_initial_index)| {
                    let fold_domain_initial = source_domain.index_at(domain_initial_index);
                    let fold_domain = CircleDomain::new(Coset::new(
                        fold_domain_initial,
                        CIRCLE_TO_LINE_FOLD_STEP - 1,
                    ));
                    let eval = eval.into_iter().collect_vec();
                    let mut buffer = vec![SecureField::zero(); fold_domain.half_coset().size()];
                    fold_circle_into_line(&mut buffer, &eval, fold_domain, fold_alpha)?;
                    Ok(buffer[0])
                })
                .collect::<Result<Vec<_>, FriVerificationError>>()?;
            Ok(out)
        }
    }
}

fn accumulate_line(
    layer_query_evals: &mut [SecureField],
    column_query_evals: &[SecureField],
    folding_alpha: SecureField,
) {
    let folding_alpha_squared = folding_alpha.square();
    if layer_query_evals.len() >= stwo_par_min() && rayon::current_num_threads() > 1 {
        layer_query_evals
            .par_iter_mut()
            .enumerate()
            .for_each(|(idx, curr_layer_eval)| {
                let folded_column_eval = column_query_evals[idx];
                *curr_layer_eval *= folding_alpha_squared;
                *curr_layer_eval += folded_column_eval;
            });
    } else {
        for (curr_layer_eval, folded_column_eval) in zip_eq(layer_query_evals, column_query_evals) {
            *curr_layer_eval *= folding_alpha_squared;
            *curr_layer_eval += *folded_column_eval;
        }
    }
}

pub fn get_query_positions_by_log_size(
    queries: &Queries,
    column_log_sizes: BTreeSet<u32>,
) -> Result<BTreeMap<u32, Vec<usize>>, FriVerificationError> {
    let out = column_log_sizes
        .into_iter()
        .map(|column_log_size| {
            let column_queries =
                queries.fold(queries.log_domain_size - column_log_size)?;
            Ok((column_log_size, column_queries.positions))
        })
        .collect::<Result<BTreeMap<_, _>, FriVerificationError>>()?;
    Ok(out)
}

pub fn fold_line(
    eval: &[SecureField],
    domain: LineDomain,
    alpha: SecureField,
) -> Result<(LineDomain, Vec<SecureField>), FriVerificationError> {
    let n = eval.len();
    if n < 2 {
        return Err(FriVerificationError::FoldInputInvalid);
    }
    let out_len = n >> FOLD_STEP;
    let mut folded_values = vec![SecureField::zero(); out_len];
    if out_len >= stwo_par_min() && rayon::current_num_threads() > 1 {
        folded_values
            .par_iter_mut()
            .enumerate()
            .for_each(|(i, slot)| {
                let base = i << FOLD_STEP;
                let f_x = eval[base];
                let f_neg_x = eval[base + 1];
                let x = domain.at(bit_reverse_index(base, domain.log_size()));
                let (mut f0, mut f1) = (f_x, f_neg_x);
                ibutterfly(&mut f0, &mut f1, x.inverse());
                *slot = f0 + alpha * f1;
            });
    } else {
        for (i, slot) in folded_values.iter_mut().enumerate() {
            let base = i << FOLD_STEP;
            let f_x = eval[base];
            let f_neg_x = eval[base + 1];
            let x = domain.at(bit_reverse_index(base, domain.log_size()));
            let (mut f0, mut f1) = (f_x, f_neg_x);
            ibutterfly(&mut f0, &mut f1, x.inverse());
            *slot = f0 + alpha * f1;
        }
    }
    let folded_domain = domain.double();
    Ok((folded_domain, folded_values))
}

pub fn fold_circle_into_line(
    buffer: &mut [SecureField],
    eval: &[SecureField],
    domain: CircleDomain,
    alpha: SecureField,
) -> Result<(), FriVerificationError> {
    if (eval.len() >> CIRCLE_TO_LINE_FOLD_STEP) != buffer.len() {
        return Err(FriVerificationError::FoldInputInvalid);
    }
    let alpha_sq = alpha * alpha;
    let out_len = buffer.len();
    if out_len >= stwo_par_min() && rayon::current_num_threads() > 1 {
        buffer
            .par_iter_mut()
            .enumerate()
            .for_each(|(i, slot)| {
                let base = i << CIRCLE_TO_LINE_FOLD_STEP;
                let f_p = eval[base];
                let f_neg_p = eval[base + 1];
                let p = domain.at(bit_reverse_index(base, domain.log_size()));
                let (mut f0_px, mut f1_px) = (f_p, f_neg_p);
                ibutterfly(&mut f0_px, &mut f1_px, p.y.inverse());
                let f_prime = alpha * f1_px + f0_px;
                *slot = *slot * alpha_sq + f_prime;
            });
    } else {
        eval.iter()
            .tuples()
            .enumerate()
            .for_each(|(i, (&f_p, &f_neg_p))| {
                let p = domain.at(bit_reverse_index(
                    i << CIRCLE_TO_LINE_FOLD_STEP,
                    domain.log_size(),
                ));
                let (mut f0_px, mut f1_px) = (f_p, f_neg_p);
                ibutterfly(&mut f0_px, &mut f1_px, p.y.inverse());
                let f_prime = alpha * f1_px + f0_px;
                buffer[i] = buffer[i] * alpha_sq + f_prime;
            });
    }
    Ok(())
}

pub fn fold_circle_eval(
    eval: &[SecureField],
    domain: CircleDomain,
    alpha: SecureField,
) -> Result<Vec<SecureField>, FriVerificationError> {
    let mut buffer = vec![SecureField::zero(); domain.half_coset().size()];
    fold_circle_into_line(&mut buffer, eval, domain, alpha)?;
    Ok(buffer)
}

fn ibutterfly(v0: &mut SecureField, v1: &mut SecureField, itwid: M31) {
    let tmp = *v0;
    *v0 = tmp + *v1;
    *v1 = (tmp - *v1) * SecureField::from(itwid);
}

impl From<M31> for SecureField {
    fn from(value: M31) -> Self {
        QM31::from_m31_array([value, M31::zero(), M31::zero(), M31::zero()])
    }
}
