//! Canonical verifier IR (bytecode).
//!
//! The goal of this IR is "verifier logic as data": the verifier path is selected and fully
//! specified by bytes embedded in `CanonicalStarkVk.program_bytes`, not by Rust hardcoding.
//!
//! The IR is intentionally a small, kernel-oriented encoding:
//! - A program is a sequence of kernel invocations with canonical, length-prefixed arguments.
//! - Heavy operations live in dedicated kernels (GLYPH custom gates), not as bit-level instructions.
//! - The IR is non-Turing complete: no unbounded loops, no dynamic memory, no jumps.
//!
//! The interpreter (Rust for witness construction, GLYPH custom gates for soundness) must treat
//! this encoding as canonical. Any malformed encoding must be rejected.

pub const STARK_VERIFIER_IR_TAG: &[u8] = b"STARK_VERIFIER_IR";
pub const STARK_VERIFIER_IR_VERSION: u16 = 1;

/// Kernel identifiers are stable protocol surface, not Rust internal enums.
pub mod kernel_id {
    /// Winterfell `DefaultRandomCoin<Sha3_256>` transcript derivation for do_work-style verifiers.
    ///
    /// This kernel is expected to prove:
    /// - coin init from `proof.context.to_elements() || public_inputs.to_elements()`
    /// - reseed merges with commitments and OOD digest
    /// - query positions via `draw_integers`
    /// - all required `draw::<BaseElement>()` challenges (composition coeffs, z, deep coeffs, alphas)
    pub const WINTERFELL_SHA3_TRANSCRIPT: u16 = 0x0001;
    /// Winterfell SHA3 main-trace openings, including leaf values.
    pub const WINTERFELL_SHA3_TRACE_OPENINGS: u16 = 0x0002;
    /// Winterfell SHA3 constraint-composition openings, including leaf values.
    pub const WINTERFELL_SHA3_CONSTRAINT_OPENINGS: u16 = 0x0003;
    /// Winterfell SHA3 FRI layer openings, including leaf values.
    pub const WINTERFELL_SHA3_FRI_OPENINGS: u16 = 0x0004;
    /// Winterfell SHA3 FRI remainder commitment and coefficients.
    pub const WINTERFELL_SHA3_FRI_REMAINDER: u16 = 0x0005;
    /// Winterfell FRI verification kernel.
    pub const WINTERFELL_FRI_VERIFY: u16 = 0x0006;
    /// Winterfell AIR verification kernel.
    pub const WINTERFELL_AIR_VERIFY: u16 = 0x0007;
    /// Winterfell DEEP composition kernel.
    pub const WINTERFELL_DEEP_COMPOSITION: u16 = 0x0008;
    /// Winterfell BLAKE3 transcript derivation kernel.
    pub const WINTERFELL_BLAKE3_TRANSCRIPT: u16 = 0x0101;
    /// Winterfell BLAKE3 main-trace openings kernel.
    pub const WINTERFELL_BLAKE3_TRACE_OPENINGS: u16 = 0x0102;
    /// Winterfell BLAKE3 constraint-composition openings kernel.
    pub const WINTERFELL_BLAKE3_CONSTRAINT_OPENINGS: u16 = 0x0103;
    /// Winterfell BLAKE3 FRI layer openings kernel.
    pub const WINTERFELL_BLAKE3_FRI_OPENINGS: u16 = 0x0104;
    /// Winterfell BLAKE3 FRI remainder commitment kernel.
    pub const WINTERFELL_BLAKE3_FRI_REMAINDER: u16 = 0x0105;
    /// Winterfell BLAKE3 FRI verification kernel.
    pub const WINTERFELL_BLAKE3_FRI_VERIFY: u16 = 0x0106;
    /// Winterfell BLAKE3 AIR verification kernel.
    pub const WINTERFELL_BLAKE3_AIR_VERIFY: u16 = 0x0107;
    /// Winterfell BLAKE3 DEEP composition kernel.
    pub const WINTERFELL_BLAKE3_DEEP_COMPOSITION: u16 = 0x0108;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StarkVerifierIr {
    pub version: u16,
    pub ops: Vec<IrOp>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IrOp {
    pub kernel_id: u16,
    pub args: Vec<u8>,
}

impl StarkVerifierIr {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(STARK_VERIFIER_IR_TAG);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&(self.ops.len() as u16).to_be_bytes());
        for op in self.ops.iter() {
            out.extend_from_slice(&op.kernel_id.to_be_bytes());
            out.extend_from_slice(&(op.args.len() as u32).to_be_bytes());
            out.extend_from_slice(&op.args);
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if !bytes.starts_with(STARK_VERIFIER_IR_TAG) {
            return Err("ir bytes missing STARK_VERIFIER_IR_TAG prefix".to_string());
        }
        let mut off = STARK_VERIFIER_IR_TAG.len();

        let version = read_u16_be(bytes, &mut off)?;
        if version != STARK_VERIFIER_IR_VERSION {
            return Err(format!(
                "unsupported ir version={version} (expected {STARK_VERIFIER_IR_VERSION})"
            ));
        }

        let op_count = read_u16_be(bytes, &mut off)? as usize;
        let mut ops = Vec::with_capacity(op_count);
        for _ in 0..op_count {
            let kernel_id = read_u16_be(bytes, &mut off)?;
            let args_len = read_u32_be(bytes, &mut off)? as usize;
            let args = read_vec(bytes, &mut off, args_len)?;
            ops.push(IrOp { kernel_id, args });
        }

        if off != bytes.len() {
            return Err("ir bytes have trailing data".to_string());
        }

        Ok(Self { version, ops })
    }
}

fn read_u16_be(bytes: &[u8], off: &mut usize) -> Result<u16, String> {
    let s = bytes
        .get(*off..*off + 2)
        .ok_or_else(|| "unexpected EOF".to_string())?;
    *off += 2;
    Ok(u16::from_be_bytes([s[0], s[1]]))
}

fn read_u32_be(bytes: &[u8], off: &mut usize) -> Result<u32, String> {
    let s = bytes
        .get(*off..*off + 4)
        .ok_or_else(|| "unexpected EOF".to_string())?;
    *off += 4;
    Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_vec(bytes: &[u8], off: &mut usize, len: usize) -> Result<Vec<u8>, String> {
    let s = bytes
        .get(*off..*off + len)
        .ok_or_else(|| "unexpected EOF".to_string())?;
    *off += len;
    Ok(s.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ir_roundtrip_and_tamper_fails() {
        let ir = StarkVerifierIr {
            version: STARK_VERIFIER_IR_VERSION,
            ops: vec![
                IrOp {
                    kernel_id: kernel_id::WINTERFELL_SHA3_TRANSCRIPT,
                    args: vec![1, 2, 3],
                },
                IrOp {
                    kernel_id: 0xBEEF,
                    args: vec![],
                },
            ],
        };
        let enc = ir.encode();
        let dec = match StarkVerifierIr::decode(&enc) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "decode must succeed");
                return;
            }
        };
        assert_eq!(ir, dec);

        let mut tampered_trailing = enc.clone();
        tampered_trailing.push(0);
        assert!(StarkVerifierIr::decode(&tampered_trailing).is_err());

        let mut tampered_version = enc.clone();
        let version_pos = STARK_VERIFIER_IR_TAG.len();
        tampered_version[version_pos] ^= 1;
        assert!(StarkVerifierIr::decode(&tampered_version).is_err());
    }
}
