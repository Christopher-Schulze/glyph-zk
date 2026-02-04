//! Canonical verifier-program encoding for the STARK adapter.
//!
//! This is the "verifier logic as data" hook.
//! The program bytes are embedded in `CanonicalStarkVk` and bound via `program_hash`.
//!
//! Note: This encoding is intentionally minimal. It provides a stable, canonical boundary and
//! strict parsing rules. Execution is still driven by higher-level adapter code.

pub const WINTERFELL_STARK_PROGRAM_TAG: &[u8] = b"WINTERFELL_STARK_PROGRAM";
pub const WINTERFELL_STARK_PROGRAM_VERSION: u16 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WinterfellStarkProgram {
    pub version: u16,
    pub impl_id: [u8; 16],
    pub field_id: u8,
    pub hash_id: u8,
    pub commitment_scheme_id: u8,
    pub air_id: Vec<u8>,
    /// Canonical verifier IR, interpreted by the adapter and proved in-circuit.
    pub ir_bytes: Vec<u8>,
}

impl WinterfellStarkProgram {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            WINTERFELL_STARK_PROGRAM_TAG.len()
                + 2
                + 16
                + 3
                + 2
                + self.air_id.len()
                + 4
                + self.ir_bytes.len(),
        );
        out.extend_from_slice(WINTERFELL_STARK_PROGRAM_TAG);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.impl_id);
        out.push(self.field_id);
        out.push(self.hash_id);
        out.push(self.commitment_scheme_id);
        out.extend_from_slice(&(self.air_id.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.air_id);
        out.extend_from_slice(&(self.ir_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.ir_bytes);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if !bytes.starts_with(WINTERFELL_STARK_PROGRAM_TAG) {
            return Err("program bytes missing WINTERFELL_STARK_PROGRAM_TAG prefix".to_string());
        }
        let mut off = WINTERFELL_STARK_PROGRAM_TAG.len();

        let version = read_u16_be(bytes, &mut off)?;
        if version != WINTERFELL_STARK_PROGRAM_VERSION {
            return Err(format!(
                "unsupported winterfell program version={version} (expected {WINTERFELL_STARK_PROGRAM_VERSION})"
            ));
        }
        let impl_id = read_16(bytes, &mut off)?;
        let field_id = read_u8(bytes, &mut off)?;
        let hash_id = read_u8(bytes, &mut off)?;
        let commitment_scheme_id = read_u8(bytes, &mut off)?;
        let air_len = read_u16_be(bytes, &mut off)? as usize;
        let air_id = read_vec(bytes, &mut off, air_len)?;
        let ir_len = read_u32_be(bytes, &mut off)? as usize;
        let ir_bytes = read_vec(bytes, &mut off, ir_len)?;

        crate::stark_ir::StarkVerifierIr::decode(&ir_bytes)
            .map_err(|e| format!("program ir_bytes decode failed: {e}"))?;

        if off != bytes.len() {
            return Err("program bytes have trailing data".to_string());
        }

        Ok(Self {
            version,
            impl_id,
            field_id,
            hash_id,
            commitment_scheme_id,
            air_id,
            ir_bytes,
        })
    }
}

fn read_u8(bytes: &[u8], off: &mut usize) -> Result<u8, String> {
    let v = bytes
        .get(*off)
        .copied()
        .ok_or_else(|| "unexpected EOF".to_string())?;
    *off += 1;
    Ok(v)
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

fn read_16(bytes: &[u8], off: &mut usize) -> Result<[u8; 16], String> {
    let s = bytes
        .get(*off..*off + 16)
        .ok_or_else(|| "unexpected EOF".to_string())?;
    *off += 16;
    let mut out = [0u8; 16];
    out.copy_from_slice(s);
    Ok(out)
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
    fn test_winterfell_program_roundtrip_and_tamper_fails() {
        let ir = crate::stark_ir::StarkVerifierIr {
            version: crate::stark_ir::STARK_VERIFIER_IR_VERSION,
            ops: vec![crate::stark_ir::IrOp {
                kernel_id: crate::stark_ir::kernel_id::WINTERFELL_SHA3_TRANSCRIPT,
                args: vec![],
            }],
        };
        let p = WinterfellStarkProgram {
            version: WINTERFELL_STARK_PROGRAM_VERSION,
            impl_id: *b"winterfell-0.13\0",
            field_id: 0x01,
            hash_id: 0x02,
            commitment_scheme_id: 0x01,
            air_id: b"do_work:x^3+42".to_vec(),
            ir_bytes: ir.encode(),
        };
        let enc = p.encode();
        let dec = match WinterfellStarkProgram::decode(&enc) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "decode must succeed");
                return;
            }
        };
        assert_eq!(p, dec);

        let mut tampered_trailing = enc.clone();
        tampered_trailing.push(0x00);
        assert!(WinterfellStarkProgram::decode(&tampered_trailing).is_err());

        let mut tampered_version = enc.clone();
        let version_pos = WINTERFELL_STARK_PROGRAM_TAG.len();
        tampered_version[version_pos] ^= 1;
        assert!(WinterfellStarkProgram::decode(&tampered_version).is_err());
    }
}
