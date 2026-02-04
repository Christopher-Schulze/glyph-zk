//! Adapter Binius proofs into GLYPH artifacts.
//!
//! This adapter verifies native Binius constraint-system proofs using the
//! official Binius layout and derives GLYPH artifact tags from the verified
//! proof and statement bytes.

use bytes::Bytes;
use binius_core::{
    constraint_system::{self, ConstraintSystem, Proof},
    constraint_system::channel::Boundary,
    fiat_shamir::HasherChallenger,
};
use binius_field::{
    arch::OptimalUnderlier,
    tower::{CanonicalTowerFamily, TowerFamily},
};
use binius_hash::groestl::{Groestl256, Groestl256ByteCompression};
use binius_utils::{DeserializeBytes, SerializationMode};

use crate::adapters::{
    BiniusStatement, BiniusVk, decode_binius_statement_bytes, decode_binius_vk_bytes,
    keccak256,
};

pub const BINIUS_PROOF_TAG: &[u8] = b"GLYPH_BINIUS_PROOF";
pub const BINIUS_COMMITMENT_TAG_DOMAIN: &[u8] = b"GLYPH_BINIUS_COMMITMENT_TAG";
pub const BINIUS_POINT_TAG_DOMAIN: &[u8] = b"GLYPH_BINIUS_POINT_TAG";
pub const BINIUS_CLAIM_DOMAIN: &[u8] = b"GLYPH_BINIUS_CLAIM";
pub const BINIUS_STATEMENT_DOMAIN: &[u8] = b"GLYPH_BINIUS_STATEMENT";

#[derive(Clone, Debug)]
pub struct BiniusProof {
    pub transcript: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
pub struct BiniusProofView<'a> {
    pub transcript: &'a [u8],
}

impl<'a> BiniusProofView<'a> {
    pub fn to_owned(&self) -> BiniusProof {
        BiniusProof {
            transcript: self.transcript.to_vec(),
        }
    }
}

pub fn encode_binius_proof_bytes(proof: &BiniusProof) -> Vec<u8> {
    let mut out = Vec::with_capacity(BINIUS_PROOF_TAG.len() + 4 + proof.transcript.len());
    out.extend_from_slice(BINIUS_PROOF_TAG);
    out.extend_from_slice(&(proof.transcript.len() as u32).to_be_bytes());
    out.extend_from_slice(&proof.transcript);
    out
}

pub fn decode_binius_proof_bytes(bytes: &[u8]) -> Result<BiniusProof, String> {
    let view = decode_binius_proof_view(bytes)?;
    Ok(view.to_owned())
}

pub fn decode_binius_proof_view(bytes: &[u8]) -> Result<BiniusProofView<'_>, String> {
    if !bytes.starts_with(BINIUS_PROOF_TAG) {
        return Err("binius proof bytes missing tag".to_string());
    }
    let mut off = BINIUS_PROOF_TAG.len();
    let transcript_len = read_u32_be(bytes, &mut off)? as usize;
    let transcript = read_slice(bytes, &mut off, transcript_len)?;
    if off != bytes.len() {
        return Err("binius proof bytes trailing data".to_string());
    }
    Ok(BiniusProofView { transcript })
}

pub fn derive_glyph_artifact_from_binius_receipt(
    adapter_vk_bytes: &[u8],
    adapter_statement_bytes: &[u8],
    proof_bytes: &[u8],
) -> Result<([u8; 32], [u8; 32], u128), String> {
    let vk = decode_binius_vk_bytes(adapter_vk_bytes)?;
    let statement = decode_binius_statement_bytes(adapter_statement_bytes)?;
    let proof = decode_binius_proof_view(proof_bytes)?;

    let (cs, boundaries) = decode_binius_payload(&vk, &statement)?;
    let cs_digest = cs.digest::<Groestl256>();

    constraint_system::verify::<
        OptimalUnderlier,
        CanonicalTowerFamily,
        Groestl256,
        Groestl256ByteCompression,
        HasherChallenger<Groestl256>,
    >(
        &cs,
        vk.log_inv_rate as usize,
        vk.security_bits as usize,
        &cs_digest,
        &boundaries,
        Proof {
            transcript: proof.transcript.to_vec(),
        },
    )
    .map_err(|e| format!("binius verify failed: {e:?}"))?;

    let statement_hash = binius_statement_hash(adapter_vk_bytes, adapter_statement_bytes);
    let proof_hash = keccak256(proof_bytes);
    let commitment_tag =
        keccak256_concat_domain(BINIUS_COMMITMENT_TAG_DOMAIN, &proof_hash, &statement_hash);
    let point_tag =
        keccak256_concat_domain(BINIUS_POINT_TAG_DOMAIN, &proof_hash, &statement_hash);
    let claim_hash =
        keccak256_concat_domain(BINIUS_CLAIM_DOMAIN, &commitment_tag, &point_tag);
    let mut claim_bytes = [0u8; 16];
    claim_bytes.copy_from_slice(&claim_hash[..16]);
    let claim128 = u128::from_be_bytes(claim_bytes);

    Ok((commitment_tag, point_tag, claim128))
}

fn binius_statement_hash(adapter_vk_bytes: &[u8], adapter_statement_bytes: &[u8]) -> [u8; 32] {
    let vk_hash = keccak256(adapter_vk_bytes);
    let stmt_hash = keccak256(adapter_statement_bytes);
    keccak256_concat_domain(BINIUS_STATEMENT_DOMAIN, &vk_hash, &stmt_hash)
}

#[allow(clippy::type_complexity)]
fn decode_binius_payload(
    vk: &BiniusVk,
    statement: &BiniusStatement,
) -> Result<
    (
        ConstraintSystem<<CanonicalTowerFamily as TowerFamily>::B128>,
        Vec<Boundary<<CanonicalTowerFamily as TowerFamily>::B128>>,
    ),
    String,
> {
    if vk.cs_bytes.is_empty() {
        return Err("binius vk constraint system bytes empty".to_string());
    }
    if statement.boundaries_bytes.is_empty() {
        return Err("binius statement boundaries bytes empty".to_string());
    }
    let cs = ConstraintSystem::<<CanonicalTowerFamily as TowerFamily>::B128>::deserialize(
        Bytes::copy_from_slice(&vk.cs_bytes),
        SerializationMode::CanonicalTower,
    )
    .map_err(|e| format!("binius constraint system decode failed: {e}"))?;
    let boundaries =
        Vec::<Boundary<<CanonicalTowerFamily as TowerFamily>::B128>>::deserialize(
            Bytes::copy_from_slice(&statement.boundaries_bytes),
            SerializationMode::CanonicalTower,
        )
        .map_err(|e| format!("binius boundaries decode failed: {e}"))?;
    Ok((cs, boundaries))
}

fn keccak256_concat_domain(domain: &[u8], left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(domain.len() + 64);
    buf.extend_from_slice(domain);
    buf.extend_from_slice(left);
    buf.extend_from_slice(right);
    keccak256(&buf)
}

fn read_u32_be(bytes: &[u8], off: &mut usize) -> Result<u32, String> {
    let s = bytes
        .get(*off..*off + 4)
        .ok_or_else(|| "unexpected EOF".to_string())?;
    *off += 4;
    Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_slice<'a>(bytes: &'a [u8], off: &mut usize, len: usize) -> Result<&'a [u8], String> {
    let s = bytes
        .get(*off..*off + len)
        .ok_or_else(|| "unexpected EOF".to_string())?;
    *off += len;
    Ok(s)
}

#[cfg(all(test, feature = "binius", feature = "dev-tools"))]
mod tests {
    use super::*;
    use binius_compute::ComputeHolder;
    use binius_compute::cpu::alloc::CpuComputeAllocator;
    use binius_core::fiat_shamir::HasherChallenger;
    use binius_fast_compute::layer::FastCpuLayerHolder;
    use binius_field::as_packed_field::PackedType;
    use binius_hash::groestl::{Groestl256Parallel};
    use binius_hal::make_portable_backend;
    use binius_m3::builder::{B32, B128, ConstraintSystem, WitnessIndex, test_utils::ClosureFiller};
    use binius_utils::{checked_arithmetics::log2_ceil_usize, SerializeBytes};

    #[test]
    fn test_binius_receipt_roundtrip() {
        let mut cs = ConstraintSystem::new();
        let mut table = cs.add_table("b32_mul");
        let in_a = table.add_committed::<B32, 1>("in_a");
        let in_b = table.add_committed::<B32, 1>("in_b");
        let out = table.add_committed::<B32, 1>("out");
        table.assert_zero("b32_mul", in_a * in_b - out);

        let table_id = table.id();
        let boundaries = vec![];
        let table_sizes = vec![64usize];

        let mut allocator = CpuComputeAllocator::new(
            1 << (log2_ceil_usize(table_sizes[0]) - PackedType::<OptimalUnderlier, B128>::LOG_WIDTH),
        );
        let allocator = allocator.into_bump_allocator();
        let mut witness = WitnessIndex::<PackedType<OptimalUnderlier, B128>>::new(&cs, &allocator);

        match witness
            .fill_table_parallel(
                &ClosureFiller::new(table_id, |events, index| {
                    let mut in_a_vals = match index.get_mut_as::<B32, _, 1>(in_a) {
                        Ok(values) => values,
                        Err(err) => return Err(err.into()),
                    };
                    let mut in_b_vals = match index.get_mut_as::<B32, _, 1>(in_b) {
                        Ok(values) => values,
                        Err(err) => return Err(err.into()),
                    };
                    let mut out_vals = match index.get_mut_as::<B32, _, 1>(out) {
                        Ok(values) => values,
                        Err(err) => return Err(err.into()),
                    };
                    for (i, (a, b)) in events.iter().enumerate() {
                        let a_field = B32::new(*a);
                        let b_field = B32::new(*b);
                        let result = a_field * b_field;
                        in_a_vals[i] = a_field;
                        in_b_vals[i] = b_field;
                        out_vals[i] = result;
                    }
                    Ok(())
                }),
                &vec![(3u32, 5u32); 64],
            )
            {
                Ok(()) => {}
                Err(err) => {
                    assert!(false, "fill table: {err}");
                    return;
                }
            }

        let ccs = match cs.compile() {
            Ok(ccs) => ccs,
            Err(err) => {
                assert!(false, "compile: {err}");
                return;
            }
        };
        let cs_digest = ccs.digest::<Groestl256>();
        let witness = witness.into_multilinear_extension_index();

        let mut compute_holder = FastCpuLayerHolder::<
            CanonicalTowerFamily,
            PackedType<OptimalUnderlier, B128>,
        >::new(1 << 10, 1 << 16);

        let proof = match constraint_system::prove::<
            _,
            OptimalUnderlier,
            CanonicalTowerFamily,
            Groestl256Parallel,
            Groestl256ByteCompression,
            HasherChallenger<Groestl256>,
            _,
            _,
            _,
        >(
            &mut compute_holder.to_data(),
            &ccs,
            1,
            100,
            &cs_digest,
            &boundaries,
            &table_sizes,
            witness,
            &make_portable_backend(),
        )
        {
            Ok(proof) => proof,
            Err(err) => {
                assert!(false, "prove: {err:?}");
                return;
            }
        };

        let mut cs_bytes = Vec::new();
        if let Err(err) = ccs.serialize(&mut cs_bytes, SerializationMode::CanonicalTower) {
            assert!(false, "cs serialize: {err}");
            return;
        }
        let mut boundaries_bytes = Vec::new();
        if let Err(err) =
            boundaries.serialize(&mut boundaries_bytes, SerializationMode::CanonicalTower)
        {
            assert!(false, "boundaries serialize: {err}");
            return;
        }

        let vk_bytes = crate::adapters::binius_vk_bytes(1, 100, &cs_bytes);
        let stmt_bytes = crate::adapters::binius_statement_bytes(&boundaries_bytes);
        let proof_bytes = encode_binius_proof_bytes(&BiniusProof {
            transcript: proof.transcript.clone(),
        });

        let (commitment_tag, point_tag, claim128) =
            match derive_glyph_artifact_from_binius_receipt(&vk_bytes, &stmt_bytes, &proof_bytes) {
                Ok(values) => values,
                Err(err) => {
                    assert!(false, "artifact: {err}");
                    return;
                }
            };
        assert_ne!(commitment_tag, [0u8; 32]);
        assert_ne!(point_tag, [0u8; 32]);
        assert_ne!(claim128, 0u128);
    }
}
