use crate::glyph_core::{ProverConfig, ProverError, UniversalProof};
use crate::glyph_field_simd::Goldilocks;
use crate::glyph_ir::Ucir2;
use crate::glyph_ir_compiler::CompiledUcir;
use crate::state_transition_vm::{compile_state_transition_batch, StateTransitionBatch};

#[derive(Clone, Debug)]
pub struct ProveUcirRequest {
    pub ucir: Ucir2,
    pub public_inputs: Vec<Goldilocks>,
    pub wire_values: Option<Vec<Goldilocks>>,
    pub config: ProverConfig,
}

#[derive(Clone, Debug)]
pub struct ProveUcirResponse {
    pub proof: UniversalProof,
}

#[derive(Clone, Debug)]
pub struct ProveStateTransitionRequest {
    pub batch: StateTransitionBatch,
    pub config: ProverConfig,
}

#[derive(Clone, Debug)]
pub struct ProveStateTransitionResponse {
    pub proof: UniversalProof,
}

pub struct GlyphSdk;

impl GlyphSdk {
    pub fn prove_ucir(req: ProveUcirRequest) -> Result<ProveUcirResponse, ProverError> {
        let proof = crate::glyph_core::prove_universal(
            req.ucir,
            &req.public_inputs,
            req.wire_values.as_deref(),
            req.config,
        )?;
        Ok(ProveUcirResponse { proof })
    }

    pub fn prove_compiled(compiled: CompiledUcir, config: ProverConfig) -> Result<UniversalProof, ProverError> {
        crate::glyph_core::prove_compiled(compiled, config)
    }

    pub fn prove_state_transition(
        req: ProveStateTransitionRequest,
    ) -> Result<ProveStateTransitionResponse, String> {
        let compiled = compile_state_transition_batch(&req.batch)?;
        let proof = crate::glyph_core::prove_compiled(compiled, req.config)
            .map_err(|e| format!("state transition proof failed: {e:?}"))?;
        Ok(ProveStateTransitionResponse { proof })
    }
}
