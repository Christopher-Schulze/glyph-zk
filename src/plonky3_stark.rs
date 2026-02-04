//! Plonky3 (p3-uni-stark) receipt verification for GLYPH.
//!
//! Supports a canonical program schema with fixed AIR ids and field/hash profiles.

use bincode::Options;
use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir};
use p3_challenger::{
    DuplexChallenger, HashChallenger, SerializingChallenger32, SerializingChallenger64,
};
use p3_circle::CirclePcs;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32, PrimeField64, TwoAdicField};
use p3_field::integers::QuotientMap;
use p3_field::extension::{BinomialExtensionField, BinomiallyExtendable};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_mds::coset_mds::CosetMds;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_poseidon::Poseidon;
use p3_rescue::Rescue;
use p3_symmetric::{
    CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher, TruncatedPermutation,
};
use p3_uni_stark::{prove, verify, Proof, StarkConfig, StarkGenericConfig, Val};
use rand09::rngs::StdRng;
use rand09::SeedableRng;

use p3_baby_bear::BabyBear;
use p3_goldilocks::Goldilocks;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

use crate::stark_receipt::{CanonicalStarkReceipt, CanonicalStarkVk};

pub const FIELD_P3_M31_ID: u8 = 0x0a;
pub const FIELD_P3_BABY_BEAR_ID: u8 = 0x0b;
pub const FIELD_P3_KOALA_BEAR_ID: u8 = 0x0c;
pub const FIELD_P3_GOLDILOCKS_ID: u8 = 0x0d;

pub const VC_MERKLE_ID: u8 = 0x01;

pub const HASH_P3_POSEIDON2_ID: u8 = 0x06;
pub const HASH_P3_POSEIDON_ID: u8 = crate::stark_hash::HASH_POSEIDON_ID;
pub const HASH_P3_RESCUE_ID: u8 = crate::stark_hash::HASH_RESCUE_ID;
pub const HASH_P3_BLAKE3_ID: u8 = crate::stark_hash::HASH_BLAKE3_ID;
pub const HASH_P3_KECCAK_ID: u8 = crate::stark_hash::HASH_SHA3_ID;

pub const PLONKY3_STARK_PROFILE_TAG: &[u8] = b"PLONKY3_STARK_PROFILE";
pub const PLONKY3_STARK_PROFILE_VERSION: u16 = 1;

pub const PLONKY3_STARK_PROGRAM_TAG: &[u8] = b"PLONKY3_STARK_PROGRAM";
pub const PLONKY3_STARK_PROGRAM_VERSION: u16 = 1;

pub const PLONKY3_HASH_PARAMS_POSEIDON2_TAG: &[u8] = b"PLONKY3_HASH_PARAMS_POSEIDON2";
pub const PLONKY3_HASH_PARAMS_POSEIDON_TAG: &[u8] = b"PLONKY3_HASH_PARAMS_POSEIDON";
pub const PLONKY3_HASH_PARAMS_RESCUE_TAG: &[u8] = b"PLONKY3_HASH_PARAMS_RESCUE";

pub const PLONKY3_AIR_PARAMS_MUL_TAG: &[u8] = b"PLONKY3_AIR_PARAMS_MUL";

pub const PLONKY3_PCS_FRI_ID: u8 = 0x01;
pub const PLONKY3_PCS_HIDING_ID: u8 = 0x02;

pub const PLONKY3_AIR_FIBONACCI_ID: u8 = 0x01;
pub const PLONKY3_AIR_MUL_ID: u8 = 0x02;
pub const PLONKY3_AIR_TRIBONACCI_ID: u8 = 0x03;

pub const PLONKY3_DEFAULT_DIGEST_ELEMS: usize = 8;
pub const PLONKY3_DEFAULT_SALT_ELEMS: usize = 4;

type P3Hash<Perm, const WIDTH: usize> = PaddingFreeSponge<Perm, WIDTH, 8, 8>;
type P3Compress<Perm, const WIDTH: usize> = TruncatedPermutation<Perm, 2, 8, WIDTH>;
type P3Challenger<Val, Perm, const WIDTH: usize> = DuplexChallenger<Val, Perm, WIDTH, 8>;
type P3ValMmcs<Val, Perm, const WIDTH: usize> = MerkleTreeMmcs<
    <Val as Field>::Packing,
    <Val as Field>::Packing,
    P3Hash<Perm, WIDTH>,
    P3Compress<Perm, WIDTH>,
    PLONKY3_DEFAULT_DIGEST_ELEMS,
>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plonky3StarkProfile {
    pub version: u16,
    pub pcs_type: u8,
    pub log_blowup: u8,
    pub log_final_poly_len: u8,
    pub num_queries: u16,
    pub commit_pow_bits: u8,
    pub query_pow_bits: u8,
    pub num_random_codewords: u8,
    pub hash_params_bytes: Vec<u8>,
}

impl Plonky3StarkProfile {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            PLONKY3_STARK_PROFILE_TAG.len()
                + 2
                + 7
                + 2
                + self.hash_params_bytes.len(),
        );
        out.extend_from_slice(PLONKY3_STARK_PROFILE_TAG);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.push(self.pcs_type);
        out.push(self.log_blowup);
        out.push(self.log_final_poly_len);
        out.extend_from_slice(&self.num_queries.to_be_bytes());
        out.push(self.commit_pow_bits);
        out.push(self.query_pow_bits);
        out.push(self.num_random_codewords);
        out.extend_from_slice(&(self.hash_params_bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.hash_params_bytes);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut off = tag_offset(bytes, PLONKY3_STARK_PROFILE_TAG)?;
        let version = read_u16_be(bytes, &mut off)?;
        if version != PLONKY3_STARK_PROFILE_VERSION {
            return Err(format!(
                "unsupported plonky3 profile version={version} (expected {PLONKY3_STARK_PROFILE_VERSION})"
            ));
        }
        let pcs_type = read_u8(bytes, &mut off)?;
        let log_blowup = read_u8(bytes, &mut off)?;
        let log_final_poly_len = read_u8(bytes, &mut off)?;
        let num_queries = read_u16_be(bytes, &mut off)?;
        let commit_pow_bits = read_u8(bytes, &mut off)?;
        let query_pow_bits = read_u8(bytes, &mut off)?;
        let num_random_codewords = read_u8(bytes, &mut off)?;
        let params_len = read_u16_be(bytes, &mut off)? as usize;
        let hash_params_bytes = read_vec(bytes, &mut off, params_len)?;
        if off != bytes.len() {
            return Err("plonky3 profile trailing data".to_string());
        }
        if log_blowup == 0 {
            return Err("plonky3 profile log_blowup must be > 0".to_string());
        }
        if num_queries == 0 {
            return Err("plonky3 profile num_queries must be > 0".to_string());
        }
        Ok(Self {
            version,
            pcs_type,
            log_blowup,
            log_final_poly_len,
            num_queries,
            commit_pow_bits,
            query_pow_bits,
            num_random_codewords,
            hash_params_bytes,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plonky3StarkProgram {
    pub version: u16,
    pub field_id: u8,
    pub hash_id: u8,
    pub commitment_scheme_id: u8,
    pub air_id: u8,
    pub air_params_bytes: Vec<u8>,
}

impl Plonky3StarkProgram {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            PLONKY3_STARK_PROGRAM_TAG.len()
                + 2
                + 4
                + 2
                + self.air_params_bytes.len(),
        );
        out.extend_from_slice(PLONKY3_STARK_PROGRAM_TAG);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.push(self.field_id);
        out.push(self.hash_id);
        out.push(self.commitment_scheme_id);
        out.push(self.air_id);
        out.extend_from_slice(&(self.air_params_bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.air_params_bytes);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut off = tag_offset(bytes, PLONKY3_STARK_PROGRAM_TAG)?;
        let version = read_u16_be(bytes, &mut off)?;
        if version != PLONKY3_STARK_PROGRAM_VERSION {
            return Err(format!(
                "unsupported plonky3 program version={version} (expected {PLONKY3_STARK_PROGRAM_VERSION})"
            ));
        }
        let field_id = read_u8(bytes, &mut off)?;
        let hash_id = read_u8(bytes, &mut off)?;
        let commitment_scheme_id = read_u8(bytes, &mut off)?;
        let air_id = read_u8(bytes, &mut off)?;
        let params_len = read_u16_be(bytes, &mut off)? as usize;
        let air_params_bytes = read_vec(bytes, &mut off, params_len)?;
        if off != bytes.len() {
            return Err("plonky3 program trailing data".to_string());
        }
        Ok(Self {
            version,
            field_id,
            hash_id,
            commitment_scheme_id,
            air_id,
            air_params_bytes,
        })
    }
}

pub fn decode_plonky3_program(bytes: &[u8]) -> Result<Plonky3StarkProgram, String> {
    Plonky3StarkProgram::decode(bytes)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Poseidon2Params {
    pub width: u8,
    pub seed: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoseidonParams {
    pub width: u8,
    pub alpha: u64,
    pub half_full_rounds: u8,
    pub partial_rounds: u16,
    pub seed: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RescueParams {
    pub width: u8,
    pub alpha: u64,
    pub capacity: u8,
    pub sec_level: u16,
    pub seed: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MulAirParams {
    pub degree: u64,
    pub uses_boundary_constraints: bool,
    pub uses_transition_constraints: bool,
}

pub fn encode_poseidon2_params(params: &Poseidon2Params) -> Vec<u8> {
    let mut out = Vec::with_capacity(PLONKY3_HASH_PARAMS_POSEIDON2_TAG.len() + 2 + 1 + 8);
    out.extend_from_slice(PLONKY3_HASH_PARAMS_POSEIDON2_TAG);
    out.extend_from_slice(&PLONKY3_STARK_PROFILE_VERSION.to_be_bytes());
    out.push(params.width);
    out.extend_from_slice(&params.seed.to_be_bytes());
    out
}

pub fn encode_poseidon_params(params: &PoseidonParams) -> Vec<u8> {
    let mut out = Vec::with_capacity(PLONKY3_HASH_PARAMS_POSEIDON_TAG.len() + 2 + 1 + 8 + 1 + 2 + 8);
    out.extend_from_slice(PLONKY3_HASH_PARAMS_POSEIDON_TAG);
    out.extend_from_slice(&PLONKY3_STARK_PROFILE_VERSION.to_be_bytes());
    out.push(params.width);
    out.extend_from_slice(&params.alpha.to_be_bytes());
    out.push(params.half_full_rounds);
    out.extend_from_slice(&params.partial_rounds.to_be_bytes());
    out.extend_from_slice(&params.seed.to_be_bytes());
    out
}

pub fn encode_rescue_params(params: &RescueParams) -> Vec<u8> {
    let mut out = Vec::with_capacity(PLONKY3_HASH_PARAMS_RESCUE_TAG.len() + 2 + 1 + 8 + 1 + 2 + 8);
    out.extend_from_slice(PLONKY3_HASH_PARAMS_RESCUE_TAG);
    out.extend_from_slice(&PLONKY3_STARK_PROFILE_VERSION.to_be_bytes());
    out.push(params.width);
    out.extend_from_slice(&params.alpha.to_be_bytes());
    out.push(params.capacity);
    out.extend_from_slice(&params.sec_level.to_be_bytes());
    out.extend_from_slice(&params.seed.to_be_bytes());
    out
}

fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e3779b97f4a7c15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}

fn derive_constants_from_seed<Val: p3_field::PrimeField + QuotientMap<u64>>(
    seed: u64,
    count: usize,
) -> Vec<Val> {
    let mut out = Vec::with_capacity(count);
    let mut state = seed ^ (count as u64).wrapping_mul(0x9e3779b97f4a7c15);
    for _ in 0..count {
        state = splitmix64(state);
        out.push(Val::from_int(state));
    }
    out
}

pub fn decode_poseidon2_params(bytes: &[u8]) -> Result<Poseidon2Params, String> {
    let mut off = tag_offset(bytes, PLONKY3_HASH_PARAMS_POSEIDON2_TAG)?;
    let version = read_u16_be(bytes, &mut off)?;
    if version != PLONKY3_STARK_PROFILE_VERSION {
        return Err(format!("poseidon2 params version={version} unsupported"));
    }
    let width = read_u8(bytes, &mut off)?;
    let seed = read_u64_be(bytes, &mut off)?;
    if off != bytes.len() {
        return Err("poseidon2 params trailing data".to_string());
    }
    Ok(Poseidon2Params { width, seed })
}

pub fn decode_poseidon_params(bytes: &[u8]) -> Result<PoseidonParams, String> {
    let mut off = tag_offset(bytes, PLONKY3_HASH_PARAMS_POSEIDON_TAG)?;
    let version = read_u16_be(bytes, &mut off)?;
    if version != PLONKY3_STARK_PROFILE_VERSION {
        return Err(format!("poseidon params version={version} unsupported"));
    }
    let width = read_u8(bytes, &mut off)?;
    let alpha = read_u64_be(bytes, &mut off)?;
    let half_full_rounds = read_u8(bytes, &mut off)?;
    let partial_rounds = read_u16_be(bytes, &mut off)?;
    let seed = read_u64_be(bytes, &mut off)?;
    if off != bytes.len() {
        return Err("poseidon params trailing data".to_string());
    }
    Ok(PoseidonParams {
        width,
        alpha,
        half_full_rounds,
        partial_rounds,
        seed,
    })
}

pub fn decode_rescue_params(bytes: &[u8]) -> Result<RescueParams, String> {
    let mut off = tag_offset(bytes, PLONKY3_HASH_PARAMS_RESCUE_TAG)?;
    let version = read_u16_be(bytes, &mut off)?;
    if version != PLONKY3_STARK_PROFILE_VERSION {
        return Err(format!("rescue params version={version} unsupported"));
    }
    let width = read_u8(bytes, &mut off)?;
    let alpha = read_u64_be(bytes, &mut off)?;
    let capacity = read_u8(bytes, &mut off)?;
    let sec_level = read_u16_be(bytes, &mut off)?;
    let seed = read_u64_be(bytes, &mut off)?;
    if off != bytes.len() {
        return Err("rescue params trailing data".to_string());
    }
    Ok(RescueParams {
        width,
        alpha,
        capacity,
        sec_level,
        seed,
    })
}

pub fn encode_mul_air_params(params: &MulAirParams) -> Vec<u8> {
    let mut out = Vec::with_capacity(PLONKY3_AIR_PARAMS_MUL_TAG.len() + 2 + 8 + 2);
    out.extend_from_slice(PLONKY3_AIR_PARAMS_MUL_TAG);
    out.extend_from_slice(&PLONKY3_STARK_PROGRAM_VERSION.to_be_bytes());
    out.extend_from_slice(&params.degree.to_be_bytes());
    out.push(params.uses_boundary_constraints as u8);
    out.push(params.uses_transition_constraints as u8);
    out
}

pub fn decode_mul_air_params(bytes: &[u8]) -> Result<MulAirParams, String> {
    let mut off = tag_offset(bytes, PLONKY3_AIR_PARAMS_MUL_TAG)?;
    let version = read_u16_be(bytes, &mut off)?;
    if version != PLONKY3_STARK_PROGRAM_VERSION {
        return Err(format!("mul air params version={version} unsupported"));
    }
    let degree = read_u64_be(bytes, &mut off)?;
    let uses_boundary_constraints = read_u8(bytes, &mut off)? != 0;
    let uses_transition_constraints = read_u8(bytes, &mut off)? != 0;
    if off != bytes.len() {
        return Err("mul air params trailing data".to_string());
    }
    if degree < 2 {
        return Err("mul air params degree must be >= 2".to_string());
    }
    Ok(MulAirParams {
        degree,
        uses_boundary_constraints,
        uses_transition_constraints,
    })
}

pub fn verify_plonky3_receipt(
    receipt: &CanonicalStarkReceipt,
    vk: &CanonicalStarkVk,
    program: &Plonky3StarkProgram,
) -> Result<(), String> {
    if vk.commitment_scheme_id != VC_MERKLE_ID {
        return Err("plonky3 commitment_scheme_id mismatch".to_string());
    }
    if vk.field_id != program.field_id {
        return Err("plonky3 field_id mismatch between vk and program".to_string());
    }
    if vk.hash_id != program.hash_id {
        return Err("plonky3 hash_id mismatch between vk and program".to_string());
    }
    if vk.consts_bytes.is_empty() {
        return Err("plonky3 profile bytes missing".to_string());
    }
    let profile = Plonky3StarkProfile::decode(&vk.consts_bytes)?;

    match program.field_id {
        FIELD_P3_BABY_BEAR_ID => verify_plonky3_babybear(receipt, &profile, program),
        FIELD_P3_KOALA_BEAR_ID => verify_plonky3_koalabear(receipt, &profile, program),
        FIELD_P3_GOLDILOCKS_ID => verify_plonky3_goldilocks(receipt, &profile, program),
        FIELD_P3_M31_ID => verify_plonky3_m31(receipt, &profile, program),
        _ => Err("unsupported plonky3 field_id".to_string()),
    }
}

fn verify_plonky3_babybear(
    receipt: &CanonicalStarkReceipt,
    profile: &Plonky3StarkProfile,
    program: &Plonky3StarkProgram,
) -> Result<(), String> {
    match program.hash_id {
        HASH_P3_POSEIDON2_ID => {
            let params = decode_poseidon2_params(&profile.hash_params_bytes)?;
            if params.width != 16 {
                return Err("poseidon2 width unsupported (expected 16)".to_string());
            }
            use p3_baby_bear::{BabyBear, Poseidon2BabyBear, default_babybear_poseidon2_16};
            let perm = if params.seed == 0 {
                default_babybear_poseidon2_16()
            } else {
                let mut rng = StdRng::seed_from_u64(params.seed);
                Poseidon2BabyBear::<16>::new_from_rng_128(&mut rng)
            };
            verify_twoadic_poseidon2::<BabyBear, Poseidon2BabyBear<16>, 4>(
                receipt, profile, program, perm,
            )
        }
        HASH_P3_POSEIDON_ID => verify_twoadic_poseidon_7::<BabyBear, 4>(receipt, profile, program),
        HASH_P3_RESCUE_ID => verify_twoadic_rescue_7::<BabyBear, 4>(receipt, profile, program),
        HASH_P3_BLAKE3_ID => verify_twoadic_blake3_32::<BabyBear, 4>(receipt, profile, program),
        _ => Err("unsupported plonky3 hash_id".to_string()),
    }
}

fn verify_plonky3_koalabear(
    receipt: &CanonicalStarkReceipt,
    profile: &Plonky3StarkProfile,
    program: &Plonky3StarkProgram,
) -> Result<(), String> {
    match program.hash_id {
        HASH_P3_POSEIDON2_ID => {
            let params = decode_poseidon2_params(&profile.hash_params_bytes)?;
            if params.width != 16 {
                return Err("poseidon2 width unsupported (expected 16)".to_string());
            }
            use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear, default_koalabear_poseidon2_16};
            let perm = if params.seed == 0 {
                default_koalabear_poseidon2_16()
            } else {
                let mut rng = StdRng::seed_from_u64(params.seed);
                Poseidon2KoalaBear::<16>::new_from_rng_128(&mut rng)
            };
            verify_twoadic_poseidon2::<KoalaBear, Poseidon2KoalaBear<16>, 4>(
                receipt, profile, program, perm,
            )
        }
        HASH_P3_POSEIDON_ID => verify_twoadic_poseidon_3::<KoalaBear, 4>(receipt, profile, program),
        HASH_P3_RESCUE_ID => verify_twoadic_rescue_3::<KoalaBear, 4>(receipt, profile, program),
        HASH_P3_BLAKE3_ID => verify_twoadic_blake3_32::<KoalaBear, 4>(receipt, profile, program),
        _ => Err("unsupported plonky3 hash_id".to_string()),
    }
}

fn verify_plonky3_goldilocks(
    receipt: &CanonicalStarkReceipt,
    profile: &Plonky3StarkProfile,
    program: &Plonky3StarkProgram,
) -> Result<(), String> {
    match program.hash_id {
        HASH_P3_POSEIDON2_ID => {
            let params = decode_poseidon2_params(&profile.hash_params_bytes)?;
            if params.width != 16 {
                return Err("poseidon2 width unsupported (expected 16)".to_string());
            }
            use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
            let mut rng = StdRng::seed_from_u64(params.seed);
            let perm = Poseidon2Goldilocks::<16>::new_from_rng_128(&mut rng);
            verify_twoadic_poseidon2::<Goldilocks, Poseidon2Goldilocks<16>, 2>(
                receipt, profile, program, perm,
            )
        }
        HASH_P3_POSEIDON_ID => verify_twoadic_poseidon_7::<Goldilocks, 2>(receipt, profile, program),
        HASH_P3_RESCUE_ID => verify_twoadic_rescue_7::<Goldilocks, 2>(receipt, profile, program),
        HASH_P3_BLAKE3_ID => verify_twoadic_blake3_64::<Goldilocks, 2>(receipt, profile, program),
        _ => Err("unsupported plonky3 hash_id".to_string()),
    }
}

fn verify_plonky3_m31(
    receipt: &CanonicalStarkReceipt,
    profile: &Plonky3StarkProfile,
    program: &Plonky3StarkProgram,
) -> Result<(), String> {
    if program.hash_id != HASH_P3_KECCAK_ID {
        return Err("plonky3 m31 requires keccak hash profile".to_string());
    }
    use p3_keccak::Keccak256Hash;
    use p3_mersenne_31::Mersenne31;
    type Challenge = BinomialExtensionField<Mersenne31, 3>;
    type ByteHash = Keccak256Hash;
    type FieldHash = SerializingHasher<ByteHash>;
    let byte_hash = ByteHash {};
    let field_hash = FieldHash::new(byte_hash);
    type MyCompress = CompressionFunctionFromHasher<ByteHash, 2, 32>;
    let compress = MyCompress::new(byte_hash);
    type ValMmcs = MerkleTreeMmcs<Mersenne31, u8, FieldHash, MyCompress, 32>;
    let val_mmcs = ValMmcs::new(field_hash, compress);
    type ChallengeMmcs = ExtensionMmcs<Mersenne31, Challenge, ValMmcs>;
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    let fri_params = FriParameters {
        log_blowup: profile.log_blowup as usize,
        log_final_poly_len: profile.log_final_poly_len as usize,
        num_queries: profile.num_queries as usize,
        commit_proof_of_work_bits: profile.commit_pow_bits as usize,
        query_proof_of_work_bits: profile.query_pow_bits as usize,
        mmcs: challenge_mmcs,
    };

    type Pcs = CirclePcs<Mersenne31, ValMmcs, ChallengeMmcs>;
    let pcs = Pcs {
        mmcs: val_mmcs,
        fri_params,
        _phantom: std::marker::PhantomData,
    };
    type Challenger = SerializingChallenger32<Mersenne31, HashChallenger<u8, ByteHash, 32>>;
    let challenger = Challenger::from_hasher(vec![], byte_hash);
    let config = StarkConfig::new(pcs, challenger);
    verify_receipt_with_config(receipt, profile, program, &config)
}

fn verify_twoadic_poseidon2<Val, Perm, const D: usize>(
    receipt: &CanonicalStarkReceipt,
    profile: &Plonky3StarkProfile,
    program: &Plonky3StarkProgram,
    perm: Perm,
) -> Result<(), String>
where
    Val: Field
        + PrimeCharacteristicRing
        + PrimeField64
        + TwoAdicField
        + BinomiallyExtendable<D>
        + Send
        + Sync
        + 'static,
    Perm: Clone
        + Send
        + Sync
        + p3_symmetric::CryptographicPermutation<[Val; 16]>
        + p3_symmetric::CryptographicPermutation<[<Val as p3_field::Field>::Packing; 16]>,
{
    type Challenge<Val, const D: usize> = BinomialExtensionField<Val, D>;

    let hash = P3Hash::<Perm, 16>::new(perm.clone());
    let compress = P3Compress::<Perm, 16>::new(perm.clone());
    let val_mmcs = P3ValMmcs::<Val, Perm, 16>::new(hash, compress);
    let challenge_mmcs = ExtensionMmcs::<Val, Challenge<Val, D>, _>::new(val_mmcs.clone());
    let dft = Radix2DitParallel::<Val>::default();

    let fri_params = build_fri_params(profile, challenge_mmcs);
    let pcs = TwoAdicFriPcs::new(dft, val_mmcs, fri_params);
    let challenger = P3Challenger::<Val, Perm, 16>::new(perm);

    let config = StarkConfig::new(pcs, challenger);
    verify_receipt_with_config(receipt, profile, program, &config)
}

fn verify_twoadic_poseidon_3<Val, const D: usize>(
    receipt: &CanonicalStarkReceipt,
    profile: &Plonky3StarkProfile,
    program: &Plonky3StarkProgram,
) -> Result<(), String>
where
    Val: Field
        + PrimeCharacteristicRing
        + PrimeField64
        + TwoAdicField
        + BinomiallyExtendable<D>
        + p3_field::InjectiveMonomial<3>
        + Send
        + Sync
        + 'static,
    <Val as p3_field::Field>::Packing: p3_field::InjectiveMonomial<3>,
{
    let params = decode_poseidon_params(&profile.hash_params_bytes)?;
    if params.alpha != 3 {
        return Err("plonky3 poseidon alpha unsupported for this field (expected 3)".to_string());
    }
    if params.width != 16 {
        return Err("unsupported plonky3 poseidon width (expected 16)".to_string());
    }
    build_poseidon_and_verify::<Val, 16, 3, D>(receipt, profile, program, &params)
}

fn verify_twoadic_poseidon_7<Val, const D: usize>(
    receipt: &CanonicalStarkReceipt,
    profile: &Plonky3StarkProfile,
    program: &Plonky3StarkProgram,
) -> Result<(), String>
where
    Val: Field
        + PrimeCharacteristicRing
        + PrimeField64
        + TwoAdicField
        + BinomiallyExtendable<D>
        + p3_field::InjectiveMonomial<7>
        + Send
        + Sync
        + 'static,
    <Val as p3_field::Field>::Packing: p3_field::InjectiveMonomial<7>,
{
    let params = decode_poseidon_params(&profile.hash_params_bytes)?;
    if params.alpha != 7 {
        return Err("plonky3 poseidon alpha unsupported for this field (expected 7)".to_string());
    }
    if params.width != 16 {
        return Err("unsupported plonky3 poseidon width (expected 16)".to_string());
    }
    build_poseidon_and_verify::<Val, 16, 7, D>(receipt, profile, program, &params)
}

fn build_poseidon_and_verify<Val, const WIDTH: usize, const ALPHA: u64, const D: usize>(
    receipt: &CanonicalStarkReceipt,
    profile: &Plonky3StarkProfile,
    program: &Plonky3StarkProgram,
    params: &PoseidonParams,
) -> Result<(), String>
where
    Val: Field
        + PrimeCharacteristicRing
        + PrimeField64
        + TwoAdicField
        + BinomiallyExtendable<D>
        + p3_field::InjectiveMonomial<ALPHA>
        + Send
        + Sync
        + 'static,
    <Val as p3_field::Field>::Packing: p3_field::InjectiveMonomial<ALPHA>,
{
    let mds = CosetMds::<Val, WIDTH>::default();
    let num_rounds = 2usize
        .saturating_mul(params.half_full_rounds as usize)
        .saturating_add(params.partial_rounds as usize);
    let num_constants = WIDTH.saturating_mul(num_rounds);
    let constants = derive_constants_from_seed::<Val>(params.seed, num_constants);
    let perm = Poseidon::<Val, CosetMds<Val, WIDTH>, WIDTH, ALPHA>::new(
        params.half_full_rounds as usize,
        params.partial_rounds as usize,
        constants,
        mds,
    );
    verify_twoadic_poseidon_generic::<Val, _, WIDTH, D>(receipt, profile, program, perm)
}

fn verify_twoadic_poseidon_generic<Val, Perm, const WIDTH: usize, const D: usize>(
    receipt: &CanonicalStarkReceipt,
    profile: &Plonky3StarkProfile,
    program: &Plonky3StarkProgram,
    perm: Perm,
) -> Result<(), String>
where
    Val: Field
        + PrimeCharacteristicRing
        + PrimeField64
        + TwoAdicField
        + BinomiallyExtendable<D>
        + Send
        + Sync
        + 'static,
    Perm: Clone
        + Send
        + Sync
        + p3_symmetric::CryptographicPermutation<[Val; WIDTH]>
        + p3_symmetric::CryptographicPermutation<[<Val as p3_field::Field>::Packing; WIDTH]>,
{
    type Challenge<Val, const D: usize> = BinomialExtensionField<Val, D>;
    let hash = P3Hash::<Perm, WIDTH>::new(perm.clone());
    let compress = P3Compress::<Perm, WIDTH>::new(perm.clone());
    let val_mmcs = P3ValMmcs::<Val, Perm, WIDTH>::new(hash, compress);
    let challenge_mmcs = ExtensionMmcs::<Val, Challenge<Val, D>, _>::new(val_mmcs.clone());
    let dft = Radix2DitParallel::<Val>::default();
    let fri_params = build_fri_params(profile, challenge_mmcs);
    let pcs = TwoAdicFriPcs::new(dft, val_mmcs, fri_params);
    let challenger = P3Challenger::<Val, Perm, WIDTH>::new(perm);
    let config = StarkConfig::new(pcs, challenger);
    verify_receipt_with_config(receipt, profile, program, &config)
}

fn verify_twoadic_rescue_3<Val, const D: usize>(
    receipt: &CanonicalStarkReceipt,
    profile: &Plonky3StarkProfile,
    program: &Plonky3StarkProgram,
) -> Result<(), String>
where
    Val: Field
        + PrimeCharacteristicRing
        + PrimeField64
        + TwoAdicField
        + BinomiallyExtendable<D>
        + p3_field::PermutationMonomial<3>
        + Send
        + Sync
        + 'static,
    <Val as p3_field::Field>::Packing: p3_field::PermutationMonomial<3>,
{
    let params = decode_rescue_params(&profile.hash_params_bytes)?;
    if params.alpha != 3 {
        return Err("plonky3 rescue alpha unsupported for this field (expected 3)".to_string());
    }
    if params.width != 16 {
        return Err("unsupported plonky3 rescue width (expected 16)".to_string());
    }
    build_rescue_and_verify::<Val, 16, 3, D>(receipt, profile, program, &params)
}

fn verify_twoadic_rescue_7<Val, const D: usize>(
    receipt: &CanonicalStarkReceipt,
    profile: &Plonky3StarkProfile,
    program: &Plonky3StarkProgram,
) -> Result<(), String>
where
    Val: Field
        + PrimeCharacteristicRing
        + PrimeField64
        + TwoAdicField
        + BinomiallyExtendable<D>
        + p3_field::PermutationMonomial<7>
        + Send
        + Sync
        + 'static,
    <Val as p3_field::Field>::Packing: p3_field::PermutationMonomial<7>,
{
    let params = decode_rescue_params(&profile.hash_params_bytes)?;
    if params.alpha != 7 {
        return Err("plonky3 rescue alpha unsupported for this field (expected 7)".to_string());
    }
    if params.width != 16 {
        return Err("unsupported plonky3 rescue width (expected 16)".to_string());
    }
    build_rescue_and_verify::<Val, 16, 7, D>(receipt, profile, program, &params)
}

fn build_rescue_and_verify<Val, const WIDTH: usize, const ALPHA: u64, const D: usize>(
    receipt: &CanonicalStarkReceipt,
    profile: &Plonky3StarkProfile,
    program: &Plonky3StarkProgram,
    params: &RescueParams,
) -> Result<(), String>
where
    Val: Field
        + PrimeCharacteristicRing
        + PrimeField64
        + TwoAdicField
        + BinomiallyExtendable<D>
        + p3_field::PermutationMonomial<ALPHA>
        + Send
        + Sync
        + 'static,
    <Val as p3_field::Field>::Packing: p3_field::PermutationMonomial<ALPHA>,
{
    let num_rounds = Rescue::<Val, CosetMds<Val, WIDTH>, WIDTH, ALPHA>::num_rounds(
        params.capacity as usize,
        params.sec_level as usize,
    );
    let num_constants = 2usize.saturating_mul(WIDTH).saturating_mul(num_rounds);
    let round_constants = derive_constants_from_seed::<Val>(params.seed, num_constants);
    let mds = CosetMds::<Val, WIDTH>::default();
    let perm =
        Rescue::<Val, CosetMds<Val, WIDTH>, WIDTH, ALPHA>::new(num_rounds, round_constants, mds);
    verify_twoadic_poseidon_generic::<Val, _, WIDTH, D>(receipt, profile, program, perm)
}

fn verify_twoadic_blake3_32<Val, const D: usize>(
    receipt: &CanonicalStarkReceipt,
    profile: &Plonky3StarkProfile,
    program: &Plonky3StarkProgram,
) -> Result<(), String>
where
    Val: Field
        + PrimeCharacteristicRing
        + PrimeField32
        + PrimeField64
        + TwoAdicField
        + BinomiallyExtendable<D>
        + Send
        + Sync
        + 'static,
{
    use p3_blake3::Blake3;
    type ByteHash = Blake3;
    type FieldHash = SerializingHasher<ByteHash>;
    let byte_hash = ByteHash {};
    let field_hash = FieldHash::new(byte_hash);
    type MyCompress = CompressionFunctionFromHasher<ByteHash, 2, 32>;
    let compress = MyCompress::new(byte_hash);
    type ValMmcs<V> = MerkleTreeMmcs<V, u8, FieldHash, MyCompress, 32>;
    let val_mmcs = ValMmcs::<Val>::new(field_hash, compress);
    type ChallengeMmcs<V, const D: usize> =
        ExtensionMmcs<V, BinomialExtensionField<V, { D }>, ValMmcs<V>>;
    let challenge_mmcs = ChallengeMmcs::<Val, D>::new(val_mmcs.clone());
    let fri_params = build_fri_params(profile, challenge_mmcs);
    let pcs = TwoAdicFriPcs::new(Radix2DitParallel::<Val>::default(), val_mmcs, fri_params);
    type Challenger<V> = SerializingChallenger32<V, HashChallenger<u8, ByteHash, 32>>;
    let challenger = Challenger::<Val>::from_hasher(vec![], byte_hash);
    let config = StarkConfig::new(pcs, challenger);
    verify_receipt_with_config(receipt, profile, program, &config)
}

fn verify_twoadic_blake3_64<Val, const D: usize>(
    receipt: &CanonicalStarkReceipt,
    profile: &Plonky3StarkProfile,
    program: &Plonky3StarkProgram,
) -> Result<(), String>
where
    Val: Field
        + PrimeCharacteristicRing
        + PrimeField64
        + TwoAdicField
        + BinomiallyExtendable<D>
        + Send
        + Sync
        + 'static,
{
    use p3_blake3::Blake3;
    type ByteHash = Blake3;
    type FieldHash = SerializingHasher<ByteHash>;
    let byte_hash = ByteHash {};
    let field_hash = FieldHash::new(byte_hash);
    type MyCompress = CompressionFunctionFromHasher<ByteHash, 2, 32>;
    let compress = MyCompress::new(byte_hash);
    type ValMmcs<V> = MerkleTreeMmcs<V, u8, FieldHash, MyCompress, 32>;
    let val_mmcs = ValMmcs::<Val>::new(field_hash, compress);
    type ChallengeMmcs<V, const D: usize> =
        ExtensionMmcs<V, BinomialExtensionField<V, { D }>, ValMmcs<V>>;
    let challenge_mmcs = ChallengeMmcs::<Val, D>::new(val_mmcs.clone());
    let fri_params = build_fri_params(profile, challenge_mmcs);
    let pcs = TwoAdicFriPcs::new(Radix2DitParallel::<Val>::default(), val_mmcs, fri_params);
    type Challenger<V> = SerializingChallenger64<V, HashChallenger<u8, ByteHash, 32>>;
    let challenger = Challenger::<Val>::from_hasher(vec![], byte_hash);
    let config = StarkConfig::new(pcs, challenger);
    verify_receipt_with_config(receipt, profile, program, &config)
}

fn verify_receipt_with_config<Pcs, Challenge, Challenger>(
    receipt: &CanonicalStarkReceipt,
    profile: &Plonky3StarkProfile,
    program: &Plonky3StarkProgram,
    config: &StarkConfig<Pcs, Challenge, Challenger>,
) -> Result<(), String>
where
    StarkConfig<Pcs, Challenge, Challenger>: StarkGenericConfig,
    Challenger: Clone,
{
    if profile.pcs_type != PLONKY3_PCS_FRI_ID {
        return Err("plonky3 pcs_type unsupported (expected fri)".to_string());
    }

    let proof: Proof<StarkConfig<Pcs, Challenge, Challenger>> = bincode_options()
        .deserialize(&receipt.proof_bytes)
        .map_err(|e| format!("plonky3 proof decode failed: {e}"))?;
    let public_inputs: Vec<Val<StarkConfig<Pcs, Challenge, Challenger>>> = bincode_options()
        .deserialize(&receipt.pub_inputs_bytes)
        .map_err(|e| format!("plonky3 public inputs decode failed: {e}"))?;

    match program.air_id {
        PLONKY3_AIR_FIBONACCI_ID => {
            let air = FibonacciAir {};
            if public_inputs.len() != 3 {
                return Err("plonky3 fibonacci expects 3 public inputs".to_string());
            }
            verify(config, &air, &proof, &public_inputs)
                .map_err(|e| format!("plonky3 fibonacci verify failed: {e:?}"))?;
        }
        PLONKY3_AIR_TRIBONACCI_ID => {
            let air = TribonacciAir {};
            if public_inputs.len() != 4 {
                return Err("plonky3 tribonacci expects 4 public inputs".to_string());
            }
            verify(config, &air, &proof, &public_inputs)
                .map_err(|e| format!("plonky3 tribonacci verify failed: {e:?}"))?;
        }
        PLONKY3_AIR_MUL_ID => {
            let params = decode_mul_air_params(&program.air_params_bytes)?;
            let air = MulAir {
                degree: params.degree,
                uses_boundary_constraints: params.uses_boundary_constraints,
                uses_transition_constraints: params.uses_transition_constraints,
            };
            verify(config, &air, &proof, &public_inputs)
                .map_err(|e| format!("plonky3 mul verify failed: {e:?}"))?;
        }
        _ => {
            return Err("unsupported plonky3 air_id".to_string());
        }
    }

    Ok(())
}

fn build_fri_params<M>(profile: &Plonky3StarkProfile, mmcs: M) -> FriParameters<M> {
    FriParameters {
        log_blowup: profile.log_blowup as usize,
        log_final_poly_len: profile.log_final_poly_len as usize,
        num_queries: profile.num_queries as usize,
        commit_proof_of_work_bits: profile.commit_pow_bits as usize,
        query_proof_of_work_bits: profile.query_pow_bits as usize,
        mmcs,
    }
}

fn bincode_options() -> impl bincode::Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
}

fn tag_offset(bytes: &[u8], tag: &[u8]) -> Result<usize, String> {
    if !bytes.starts_with(tag) {
        return Err("plonky3 tag mismatch".to_string());
    }
    let mut off = tag.len();
    if bytes.len() >= off + 3 && bytes[off] == b'_' && bytes[off + 1] == b'V' && bytes[off + 2].is_ascii_digit() {
        off += 2;
        while off < bytes.len() && bytes[off].is_ascii_digit() {
            off += 1;
        }
    }
    Ok(off)
}

fn read_u8(bytes: &[u8], off: &mut usize) -> Result<u8, String> {
    let b = *bytes.get(*off).ok_or_else(|| "unexpected EOF".to_string())?;
    *off += 1;
    Ok(b)
}

fn read_u16_be(bytes: &[u8], off: &mut usize) -> Result<u16, String> {
    let s = bytes.get(*off..*off + 2).ok_or_else(|| "unexpected EOF".to_string())?;
    *off += 2;
    Ok(u16::from_be_bytes([s[0], s[1]]))
}

fn read_u64_be(bytes: &[u8], off: &mut usize) -> Result<u64, String> {
    let s = bytes.get(*off..*off + 8).ok_or_else(|| "unexpected EOF".to_string())?;
    *off += 8;
    Ok(u64::from_be_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}

fn read_vec(bytes: &[u8], off: &mut usize, len: usize) -> Result<Vec<u8>, String> {
    let s = bytes.get(*off..*off + len).ok_or_else(|| "unexpected EOF".to_string())?;
    *off += len;
    Ok(s.to_vec())
}

#[derive(Clone)]
pub struct FibonacciAir {}

impl<F> BaseAir<F> for FibonacciAir {
    fn width(&self) -> usize {
        2
    }
}

impl<AB: AirBuilderWithPublicValues> Air<AB> for FibonacciAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let pis = builder.public_values();
        let a = pis[0];
        let b = pis[1];
        let x = pis[2];

        let Some(local) = main.row_slice(0) else {
            debug_assert!(false, "fibonacci air missing row 0");
            builder.assert_zero(AB::Expr::ONE);
            return;
        };
        let Some(next) = main.row_slice(1) else {
            debug_assert!(false, "fibonacci air missing row 1");
            builder.assert_zero(AB::Expr::ONE);
            return;
        };
        let left = local[0].clone();
        let right = local[1].clone();
        let next_left = next[0].clone();
        let next_right = next[1].clone();

        let mut when_first = builder.when_first_row();
        when_first.assert_eq(left.clone(), a);
        when_first.assert_eq(right.clone(), b);

        let mut when_transition = builder.when_transition();
        when_transition.assert_eq(right.clone(), next_left);
        when_transition.assert_eq(left + right.clone(), next_right);

        builder.when_last_row().assert_eq(right, x);
    }
}

#[derive(Clone)]
pub struct TribonacciAir {}

impl<F> BaseAir<F> for TribonacciAir {
    fn width(&self) -> usize {
        3
    }
}

impl<AB: AirBuilderWithPublicValues> Air<AB> for TribonacciAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let pis = builder.public_values();
        let a = pis[0];
        let b = pis[1];
        let c = pis[2];
        let x = pis[3];

        let Some(local) = main.row_slice(0) else {
            debug_assert!(false, "tribonacci air missing row 0");
            builder.assert_zero(AB::Expr::ONE);
            return;
        };
        let Some(next) = main.row_slice(1) else {
            debug_assert!(false, "tribonacci air missing row 1");
            builder.assert_zero(AB::Expr::ONE);
            return;
        };
        let left = local[0].clone();
        let mid = local[1].clone();
        let right = local[2].clone();
        let next_left = next[0].clone();
        let next_mid = next[1].clone();
        let next_right = next[2].clone();

        let mut when_first = builder.when_first_row();
        when_first.assert_eq(left.clone(), a);
        when_first.assert_eq(mid.clone(), b);
        when_first.assert_eq(right.clone(), c);

        let mut when_transition = builder.when_transition();
        when_transition.assert_eq(mid.clone(), next_left);
        when_transition.assert_eq(right.clone(), next_mid);
        when_transition.assert_eq(left + mid + right.clone(), next_right);

        builder.when_last_row().assert_eq(right, x);
    }
}

#[derive(Clone)]
pub struct MulAir {
    pub degree: u64,
    pub uses_boundary_constraints: bool,
    pub uses_transition_constraints: bool,
}

impl Default for MulAir {
    fn default() -> Self {
        Self {
            degree: 3,
            uses_boundary_constraints: true,
            uses_transition_constraints: true,
        }
    }
}

impl<F> BaseAir<F> for MulAir {
    fn width(&self) -> usize {
        60
    }
}

impl<AB: AirBuilder> Air<AB> for MulAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let Some(main_local) = main.row_slice(0) else {
            debug_assert!(false, "mul air missing row 0");
            builder.assert_zero(AB::Expr::ONE);
            return;
        };
        let Some(main_next) = main.row_slice(1) else {
            debug_assert!(false, "mul air missing row 1");
            builder.assert_zero(AB::Expr::ONE);
            return;
        };
        for i in 0..20 {
            let start = i * 3;
            let a = main_local[start].clone();
            let b = main_local[start + 1].clone();
            let c = main_local[start + 2].clone();
            builder.assert_zero(a.clone().into().exp_u64(self.degree - 1) * b.clone() - c);
            if self.uses_boundary_constraints {
                builder
                    .when_first_row()
                    .assert_eq(a.clone() * a.clone() + AB::Expr::ONE, b.clone());
            }
            if self.uses_transition_constraints {
                let next_a = main_next[start].clone();
                builder
                    .when_transition()
                    .assert_eq(a + AB::Expr::from_u8(20), next_a);
            }
        }
    }
}

fn build_fib_trace<F>(a: u64, b: u64, n: usize) -> RowMajorMatrix<F>
where
    F: PrimeCharacteristicRing + Clone + Send + Sync,
{
    if !n.is_power_of_two() {
        debug_assert!(false, "fibonacci trace length must be power of two");
    }
    let mut values = vec![F::ZERO; n * 2];
    values[0] = F::from_u64(a);
    values[1] = F::from_u64(b);
    for i in 1..n {
        let left = values[(i - 1) * 2].clone();
        let right = values[(i - 1) * 2 + 1].clone();
        values[i * 2] = right.clone();
        values[i * 2 + 1] = left + right;
    }
    RowMajorMatrix::new(values, 2)
}

fn build_trib_trace<F>(a: u64, b: u64, c: u64, n: usize) -> RowMajorMatrix<F>
where
    F: PrimeCharacteristicRing + Clone + Send + Sync,
{
    if !n.is_power_of_two() {
        debug_assert!(false, "tribonacci trace length must be power of two");
    }
    let mut values = vec![F::ZERO; n * 3];
    values[0] = F::from_u64(a);
    values[1] = F::from_u64(b);
    values[2] = F::from_u64(c);
    for i in 1..n {
        let prev_left = values[(i - 1) * 3].clone();
        let prev_mid = values[(i - 1) * 3 + 1].clone();
        let prev_right = values[(i - 1) * 3 + 2].clone();
        values[i * 3] = prev_mid.clone();
        values[i * 3 + 1] = prev_right.clone();
        values[i * 3 + 2] = prev_left + prev_mid + prev_right;
    }
    RowMajorMatrix::new(values, 3)
}

#[allow(clippy::type_complexity)]
fn build_poseidon_config<Val, Perm, const WIDTH: usize, const D: usize>(
    profile: &Plonky3StarkProfile,
    perm: Perm,
) -> StarkConfig<
    TwoAdicFriPcs<Val, Radix2DitParallel<Val>, P3ValMmcs<Val, Perm, WIDTH>, ExtensionMmcs<Val, BinomialExtensionField<Val, D>, P3ValMmcs<Val, Perm, WIDTH>>>,
    BinomialExtensionField<Val, D>,
    P3Challenger<Val, Perm, WIDTH>,
>
where
    Val: Field
        + PrimeCharacteristicRing
        + PrimeField64
        + TwoAdicField
        + BinomiallyExtendable<D>
        + Send
        + Sync
        + 'static,
    Perm: Clone
        + Send
        + Sync
        + p3_symmetric::CryptographicPermutation<[Val; WIDTH]>
        + p3_symmetric::CryptographicPermutation<[<Val as p3_field::Field>::Packing; WIDTH]>,
{
    type Challenge<Val, const D: usize> = BinomialExtensionField<Val, D>;
    let hash = P3Hash::<Perm, WIDTH>::new(perm.clone());
    let compress = P3Compress::<Perm, WIDTH>::new(perm.clone());
    let val_mmcs = P3ValMmcs::<Val, Perm, WIDTH>::new(hash, compress);
    let challenge_mmcs = ExtensionMmcs::<Val, Challenge<Val, D>, _>::new(val_mmcs.clone());
    let dft = Radix2DitParallel::<Val>::default();
    let fri_params = build_fri_params(profile, challenge_mmcs);
    let pcs = TwoAdicFriPcs::new(dft, val_mmcs, fri_params);
    let challenger = P3Challenger::<Val, Perm, WIDTH>::new(perm);
    StarkConfig::new(pcs, challenger)
}

#[allow(clippy::type_complexity)]
fn build_blake3_config_32<Val, const D: usize>(
    profile: &Plonky3StarkProfile,
) -> StarkConfig<
    TwoAdicFriPcs<Val, Radix2DitParallel<Val>, MerkleTreeMmcs<Val, u8, SerializingHasher<p3_blake3::Blake3>, CompressionFunctionFromHasher<p3_blake3::Blake3, 2, 32>, 32>, ExtensionMmcs<Val, BinomialExtensionField<Val, D>, MerkleTreeMmcs<Val, u8, SerializingHasher<p3_blake3::Blake3>, CompressionFunctionFromHasher<p3_blake3::Blake3, 2, 32>, 32>>>,
    BinomialExtensionField<Val, D>,
    SerializingChallenger32<Val, HashChallenger<u8, p3_blake3::Blake3, 32>>,
>
where
    Val: Field
        + PrimeCharacteristicRing
        + PrimeField32
        + PrimeField64
        + TwoAdicField
        + BinomiallyExtendable<D>
        + Send
        + Sync
        + 'static,
{
    use p3_blake3::Blake3;
    type ByteHash = Blake3;
    type FieldHash = SerializingHasher<ByteHash>;
    let byte_hash = ByteHash {};
    let field_hash = FieldHash::new(byte_hash);
    type MyCompress = CompressionFunctionFromHasher<ByteHash, 2, 32>;
    let compress = MyCompress::new(byte_hash);
    type ValMmcs<V> = MerkleTreeMmcs<V, u8, FieldHash, MyCompress, 32>;
    let val_mmcs = ValMmcs::<Val>::new(field_hash, compress);
    type ChallengeMmcs<V, const D: usize> =
        ExtensionMmcs<V, BinomialExtensionField<V, { D }>, ValMmcs<V>>;
    let challenge_mmcs = ChallengeMmcs::<Val, D>::new(val_mmcs.clone());
    let fri_params = build_fri_params(profile, challenge_mmcs);
    let pcs = TwoAdicFriPcs::new(Radix2DitParallel::<Val>::default(), val_mmcs, fri_params);
    type Challenger<V> = SerializingChallenger32<V, HashChallenger<u8, ByteHash, 32>>;
    let challenger = Challenger::<Val>::from_hasher(vec![], byte_hash);
    StarkConfig::new(pcs, challenger)
}

#[allow(clippy::type_complexity)]
fn build_blake3_config_64<Val, const D: usize>(
    profile: &Plonky3StarkProfile,
) -> StarkConfig<
    TwoAdicFriPcs<Val, Radix2DitParallel<Val>, MerkleTreeMmcs<Val, u8, SerializingHasher<p3_blake3::Blake3>, CompressionFunctionFromHasher<p3_blake3::Blake3, 2, 32>, 32>, ExtensionMmcs<Val, BinomialExtensionField<Val, D>, MerkleTreeMmcs<Val, u8, SerializingHasher<p3_blake3::Blake3>, CompressionFunctionFromHasher<p3_blake3::Blake3, 2, 32>, 32>>>,
    BinomialExtensionField<Val, D>,
    SerializingChallenger64<Val, HashChallenger<u8, p3_blake3::Blake3, 32>>,
>
where
    Val: Field
        + PrimeCharacteristicRing
        + PrimeField64
        + TwoAdicField
        + BinomiallyExtendable<D>
        + Send
        + Sync
        + 'static,
{
    use p3_blake3::Blake3;
    type ByteHash = Blake3;
    type FieldHash = SerializingHasher<ByteHash>;
    let byte_hash = ByteHash {};
    let field_hash = FieldHash::new(byte_hash);
    type MyCompress = CompressionFunctionFromHasher<ByteHash, 2, 32>;
    let compress = MyCompress::new(byte_hash);
    type ValMmcs<V> = MerkleTreeMmcs<V, u8, FieldHash, MyCompress, 32>;
    let val_mmcs = ValMmcs::<Val>::new(field_hash, compress);
    type ChallengeMmcs<V, const D: usize> =
        ExtensionMmcs<V, BinomialExtensionField<V, { D }>, ValMmcs<V>>;
    let challenge_mmcs = ChallengeMmcs::<Val, D>::new(val_mmcs.clone());
    let fri_params = build_fri_params(profile, challenge_mmcs);
    let pcs = TwoAdicFriPcs::new(Radix2DitParallel::<Val>::default(), val_mmcs, fri_params);
    type Challenger<V> = SerializingChallenger64<V, HashChallenger<u8, ByteHash, 32>>;
    let challenger = Challenger::<Val>::from_hasher(vec![], byte_hash);
    StarkConfig::new(pcs, challenger)
}

fn build_fibonacci_receipt_with_config<Pcs, Challenge, Challenger>(
    config: StarkConfig<Pcs, Challenge, Challenger>,
    profile: &Plonky3StarkProfile,
    program: &Plonky3StarkProgram,
) -> Result<CanonicalStarkReceipt, String>
where
    StarkConfig<Pcs, Challenge, Challenger>: StarkGenericConfig,
    Val<StarkConfig<Pcs, Challenge, Challenger>>: serde::Serialize,
{
    let trace: RowMajorMatrix<Val<StarkConfig<Pcs, Challenge, Challenger>>> =
        build_fib_trace::<Val<StarkConfig<Pcs, Challenge, Challenger>>>(0, 1, 8);
    let public_inputs: Vec<Val<StarkConfig<Pcs, Challenge, Challenger>>> = vec![
        Val::<StarkConfig<Pcs, Challenge, Challenger>>::ZERO,
        Val::<StarkConfig<Pcs, Challenge, Challenger>>::ONE,
        Val::<StarkConfig<Pcs, Challenge, Challenger>>::from_u64(21),
    ];
    let proof = prove(&config, &FibonacciAir {}, trace, &public_inputs);
    let proof_bytes = bincode_options()
        .serialize(&proof)
        .map_err(|err| format!("plonky3 proof encode failed: {err}"))?;
    let pub_inputs_bytes = bincode_options()
        .serialize(&public_inputs)
        .map_err(|err| format!("plonky3 public inputs encode failed: {err}"))?;

    let vk = CanonicalStarkVk {
        version: 1,
        field_id: program.field_id,
        hash_id: program.hash_id,
        commitment_scheme_id: program.commitment_scheme_id,
        consts_bytes: profile.encode(),
        program_bytes: program.encode(),
    };
    Ok(CanonicalStarkReceipt {
        proof_bytes,
        pub_inputs_bytes,
        vk_bytes: vk.encode(),
    })
}

fn build_tribonacci_receipt_with_config<Pcs, Challenge, Challenger>(
    config: StarkConfig<Pcs, Challenge, Challenger>,
    profile: &Plonky3StarkProfile,
    program: &Plonky3StarkProgram,
) -> Result<CanonicalStarkReceipt, String>
where
    StarkConfig<Pcs, Challenge, Challenger>: StarkGenericConfig,
    Val<StarkConfig<Pcs, Challenge, Challenger>>: serde::Serialize,
{
    let trace: RowMajorMatrix<Val<StarkConfig<Pcs, Challenge, Challenger>>> =
        build_trib_trace::<Val<StarkConfig<Pcs, Challenge, Challenger>>>(0, 1, 1, 8);
    let a0 = Val::<StarkConfig<Pcs, Challenge, Challenger>>::ZERO;
    let b0 = Val::<StarkConfig<Pcs, Challenge, Challenger>>::ONE;
    let c0 = Val::<StarkConfig<Pcs, Challenge, Challenger>>::ONE;
    let mut a = a0;
    let mut b = b0;
    let mut c = c0;
    for _ in 1..8 {
        let next = a + b + c;
        a = b;
        b = c;
        c = next;
    }
    let public_inputs: Vec<Val<StarkConfig<Pcs, Challenge, Challenger>>> = vec![a0, b0, c0, c];
    let proof = prove(&config, &TribonacciAir {}, trace, &public_inputs);
    let proof_bytes = bincode_options()
        .serialize(&proof)
        .map_err(|err| format!("plonky3 proof encode failed: {err}"))?;
    let pub_inputs_bytes = bincode_options()
        .serialize(&public_inputs)
        .map_err(|err| format!("plonky3 public inputs encode failed: {err}"))?;

    let vk = CanonicalStarkVk {
        version: 1,
        field_id: program.field_id,
        hash_id: program.hash_id,
        commitment_scheme_id: program.commitment_scheme_id,
        consts_bytes: profile.encode(),
        program_bytes: program.encode(),
    };
    Ok(CanonicalStarkReceipt {
        proof_bytes,
        pub_inputs_bytes,
        vk_bytes: vk.encode(),
    })
}

pub fn build_plonky3_fibonacci_receipt(
    profile: &Plonky3StarkProfile,
    program: &Plonky3StarkProgram,
) -> Result<CanonicalStarkReceipt, String> {
    if program.air_id != PLONKY3_AIR_FIBONACCI_ID {
        return Err("plonky3 receipt builder only supports fibonacci air".to_string());
    }
    match program.field_id {
        FIELD_P3_BABY_BEAR_ID => build_plonky3_fibonacci_receipt_babybear(profile, program),
        FIELD_P3_KOALA_BEAR_ID => build_plonky3_fibonacci_receipt_koalabear(profile, program),
        FIELD_P3_GOLDILOCKS_ID => build_plonky3_fibonacci_receipt_goldilocks(profile, program),
        _ => Err("plonky3 receipt builder unsupported field".to_string()),
    }
}

pub fn build_plonky3_tribonacci_receipt(
    profile: &Plonky3StarkProfile,
    program: &Plonky3StarkProgram,
) -> Result<CanonicalStarkReceipt, String> {
    if program.air_id != PLONKY3_AIR_TRIBONACCI_ID {
        return Err("plonky3 receipt builder only supports tribonacci air".to_string());
    }
    match program.field_id {
        FIELD_P3_BABY_BEAR_ID => build_plonky3_tribonacci_receipt_babybear(profile, program),
        FIELD_P3_KOALA_BEAR_ID => build_plonky3_tribonacci_receipt_koalabear(profile, program),
        FIELD_P3_GOLDILOCKS_ID => build_plonky3_tribonacci_receipt_goldilocks(profile, program),
        _ => Err("plonky3 receipt builder unsupported field".to_string()),
    }
}

pub fn build_plonky3_receipt(
    profile: &Plonky3StarkProfile,
    program: &Plonky3StarkProgram,
) -> Result<CanonicalStarkReceipt, String> {
    match program.air_id {
        PLONKY3_AIR_FIBONACCI_ID => build_plonky3_fibonacci_receipt(profile, program),
        PLONKY3_AIR_TRIBONACCI_ID => build_plonky3_tribonacci_receipt(profile, program),
        _ => Err("plonky3 receipt builder unsupported air".to_string()),
    }
}

fn build_plonky3_fibonacci_receipt_babybear(
    profile: &Plonky3StarkProfile,
    program: &Plonky3StarkProgram,
) -> Result<CanonicalStarkReceipt, String> {
    match program.hash_id {
        HASH_P3_POSEIDON2_ID => {
            use p3_baby_bear::{default_babybear_poseidon2_16, Poseidon2BabyBear};
            let params = decode_poseidon2_params(&profile.hash_params_bytes)?;
            if params.width != 16 {
                return Err("plonky3 poseidon2 width unsupported (expected 16)".to_string());
            }
            let perm = if params.seed == 0 {
                default_babybear_poseidon2_16()
            } else {
                let mut rng = StdRng::seed_from_u64(params.seed);
                Poseidon2BabyBear::<16>::new_from_rng_128(&mut rng)
            };
            let config = build_poseidon_config::<BabyBear, _, 16, 4>(profile, perm);
            build_fibonacci_receipt_with_config(config, profile, program)
        }
        HASH_P3_POSEIDON_ID => {
            let params = decode_poseidon_params(&profile.hash_params_bytes)?;
            if params.alpha != 7 {
                return Err("plonky3 poseidon alpha unsupported for babybear (expected 7)".to_string());
            }
            let perm = build_poseidon_perm::<BabyBear, 7>(params)?;
            let config = build_poseidon_config::<BabyBear, _, 16, 4>(profile, perm);
            build_fibonacci_receipt_with_config(config, profile, program)
        }
        HASH_P3_RESCUE_ID => {
            let params = decode_rescue_params(&profile.hash_params_bytes)?;
            if params.alpha != 7 {
                return Err("plonky3 rescue alpha unsupported for babybear (expected 7)".to_string());
            }
            let perm = build_rescue_perm::<BabyBear, 7>(params)?;
            let config = build_poseidon_config::<BabyBear, _, 16, 4>(profile, perm);
            build_fibonacci_receipt_with_config(config, profile, program)
        }
        HASH_P3_BLAKE3_ID => {
            let config = build_blake3_config_32::<BabyBear, 4>(profile);
            build_fibonacci_receipt_with_config(config, profile, program)
        }
        _ => Err("plonky3 babybear hash unsupported".to_string()),
    }
}

fn build_plonky3_tribonacci_receipt_babybear(
    profile: &Plonky3StarkProfile,
    program: &Plonky3StarkProgram,
) -> Result<CanonicalStarkReceipt, String> {
    match program.hash_id {
        HASH_P3_POSEIDON2_ID => {
            use p3_baby_bear::{default_babybear_poseidon2_16, Poseidon2BabyBear};
            let params = decode_poseidon2_params(&profile.hash_params_bytes)?;
            if params.width != 16 {
                return Err("plonky3 poseidon2 width unsupported (expected 16)".to_string());
            }
            let perm = if params.seed == 0 {
                default_babybear_poseidon2_16()
            } else {
                let mut rng = StdRng::seed_from_u64(params.seed);
                Poseidon2BabyBear::<16>::new_from_rng_128(&mut rng)
            };
            let config = build_poseidon_config::<BabyBear, _, 16, 4>(profile, perm);
            build_tribonacci_receipt_with_config(config, profile, program)
        }
        HASH_P3_POSEIDON_ID => {
            let params = decode_poseidon_params(&profile.hash_params_bytes)?;
            if params.alpha != 7 {
                return Err("plonky3 poseidon alpha unsupported for babybear (expected 7)".to_string());
            }
            let perm = build_poseidon_perm::<BabyBear, 7>(params)?;
            let config = build_poseidon_config::<BabyBear, _, 16, 4>(profile, perm);
            build_tribonacci_receipt_with_config(config, profile, program)
        }
        HASH_P3_RESCUE_ID => {
            let params = decode_rescue_params(&profile.hash_params_bytes)?;
            if params.alpha != 7 {
                return Err("plonky3 rescue alpha unsupported for babybear (expected 7)".to_string());
            }
            let perm = build_rescue_perm::<BabyBear, 7>(params)?;
            let config = build_poseidon_config::<BabyBear, _, 16, 4>(profile, perm);
            build_tribonacci_receipt_with_config(config, profile, program)
        }
        HASH_P3_BLAKE3_ID => {
            let config = build_blake3_config_32::<BabyBear, 4>(profile);
            build_tribonacci_receipt_with_config(config, profile, program)
        }
        _ => Err("plonky3 babybear hash unsupported".to_string()),
    }
}

fn build_plonky3_fibonacci_receipt_koalabear(
    profile: &Plonky3StarkProfile,
    program: &Plonky3StarkProgram,
) -> Result<CanonicalStarkReceipt, String> {
    match program.hash_id {
        HASH_P3_POSEIDON2_ID => {
            use p3_koala_bear::{default_koalabear_poseidon2_16, Poseidon2KoalaBear};
            let params = decode_poseidon2_params(&profile.hash_params_bytes)?;
            if params.width != 16 {
                return Err("plonky3 poseidon2 width unsupported (expected 16)".to_string());
            }
            let perm = if params.seed == 0 {
                default_koalabear_poseidon2_16()
            } else {
                let mut rng = StdRng::seed_from_u64(params.seed);
                Poseidon2KoalaBear::<16>::new_from_rng_128(&mut rng)
            };
            let config = build_poseidon_config::<KoalaBear, _, 16, 4>(profile, perm);
            build_fibonacci_receipt_with_config(config, profile, program)
        }
        HASH_P3_POSEIDON_ID => {
            let params = decode_poseidon_params(&profile.hash_params_bytes)?;
            if params.alpha != 3 {
                return Err("plonky3 poseidon alpha unsupported for koalabear (expected 3)".to_string());
            }
            let perm = build_poseidon_perm::<KoalaBear, 3>(params)?;
            let config = build_poseidon_config::<KoalaBear, _, 16, 4>(profile, perm);
            build_fibonacci_receipt_with_config(config, profile, program)
        }
        HASH_P3_RESCUE_ID => {
            let params = decode_rescue_params(&profile.hash_params_bytes)?;
            if params.alpha != 3 {
                return Err("plonky3 rescue alpha unsupported for koalabear (expected 3)".to_string());
            }
            let perm = build_rescue_perm::<KoalaBear, 3>(params)?;
            let config = build_poseidon_config::<KoalaBear, _, 16, 4>(profile, perm);
            build_fibonacci_receipt_with_config(config, profile, program)
        }
        HASH_P3_BLAKE3_ID => {
            let config = build_blake3_config_32::<KoalaBear, 4>(profile);
            build_fibonacci_receipt_with_config(config, profile, program)
        }
        _ => Err("plonky3 koalabear hash unsupported".to_string()),
    }
}

fn build_plonky3_tribonacci_receipt_koalabear(
    profile: &Plonky3StarkProfile,
    program: &Plonky3StarkProgram,
) -> Result<CanonicalStarkReceipt, String> {
    match program.hash_id {
        HASH_P3_POSEIDON2_ID => {
            use p3_koala_bear::{default_koalabear_poseidon2_16, Poseidon2KoalaBear};
            let params = decode_poseidon2_params(&profile.hash_params_bytes)?;
            if params.width != 16 {
                return Err("plonky3 poseidon2 width unsupported (expected 16)".to_string());
            }
            let perm = if params.seed == 0 {
                default_koalabear_poseidon2_16()
            } else {
                let mut rng = StdRng::seed_from_u64(params.seed);
                Poseidon2KoalaBear::<16>::new_from_rng_128(&mut rng)
            };
            let config = build_poseidon_config::<KoalaBear, _, 16, 4>(profile, perm);
            build_tribonacci_receipt_with_config(config, profile, program)
        }
        HASH_P3_POSEIDON_ID => {
            let params = decode_poseidon_params(&profile.hash_params_bytes)?;
            if params.alpha != 3 {
                return Err("plonky3 poseidon alpha unsupported for koalabear (expected 3)".to_string());
            }
            let perm = build_poseidon_perm::<KoalaBear, 3>(params)?;
            let config = build_poseidon_config::<KoalaBear, _, 16, 4>(profile, perm);
            build_tribonacci_receipt_with_config(config, profile, program)
        }
        HASH_P3_RESCUE_ID => {
            let params = decode_rescue_params(&profile.hash_params_bytes)?;
            if params.alpha != 3 {
                return Err("plonky3 rescue alpha unsupported for koalabear (expected 3)".to_string());
            }
            let perm = build_rescue_perm::<KoalaBear, 3>(params)?;
            let config = build_poseidon_config::<KoalaBear, _, 16, 4>(profile, perm);
            build_tribonacci_receipt_with_config(config, profile, program)
        }
        HASH_P3_BLAKE3_ID => {
            let config = build_blake3_config_32::<KoalaBear, 4>(profile);
            build_tribonacci_receipt_with_config(config, profile, program)
        }
        _ => Err("plonky3 koalabear hash unsupported".to_string()),
    }
}

fn build_plonky3_fibonacci_receipt_goldilocks(
    profile: &Plonky3StarkProfile,
    program: &Plonky3StarkProgram,
) -> Result<CanonicalStarkReceipt, String> {
    match program.hash_id {
        HASH_P3_POSEIDON2_ID => {
            use p3_goldilocks::Poseidon2Goldilocks;
            let params = decode_poseidon2_params(&profile.hash_params_bytes)?;
            if params.width != 16 {
                return Err("plonky3 poseidon2 width unsupported (expected 16)".to_string());
            }
            let mut rng = StdRng::seed_from_u64(params.seed);
            let perm = Poseidon2Goldilocks::<16>::new_from_rng_128(&mut rng);
            let config = build_poseidon_config::<Goldilocks, _, 16, 2>(profile, perm);
            build_fibonacci_receipt_with_config(config, profile, program)
        }
        HASH_P3_POSEIDON_ID => {
            let params = decode_poseidon_params(&profile.hash_params_bytes)?;
            if params.alpha != 7 {
                return Err("plonky3 poseidon alpha unsupported for goldilocks (expected 7)".to_string());
            }
            let perm = build_poseidon_perm::<Goldilocks, 7>(params)?;
            let config = build_poseidon_config::<Goldilocks, _, 16, 2>(profile, perm);
            build_fibonacci_receipt_with_config(config, profile, program)
        }
        HASH_P3_RESCUE_ID => {
            let params = decode_rescue_params(&profile.hash_params_bytes)?;
            if params.alpha != 7 {
                return Err("plonky3 rescue alpha unsupported for goldilocks (expected 7)".to_string());
            }
            let perm = build_rescue_perm::<Goldilocks, 7>(params)?;
            let config = build_poseidon_config::<Goldilocks, _, 16, 2>(profile, perm);
            build_fibonacci_receipt_with_config(config, profile, program)
        }
        HASH_P3_BLAKE3_ID => {
            let config = build_blake3_config_64::<Goldilocks, 2>(profile);
            build_fibonacci_receipt_with_config(config, profile, program)
        }
        _ => Err("plonky3 goldilocks hash unsupported".to_string()),
    }
}

fn build_plonky3_tribonacci_receipt_goldilocks(
    profile: &Plonky3StarkProfile,
    program: &Plonky3StarkProgram,
) -> Result<CanonicalStarkReceipt, String> {
    match program.hash_id {
        HASH_P3_POSEIDON2_ID => {
            use p3_goldilocks::Poseidon2Goldilocks;
            let params = decode_poseidon2_params(&profile.hash_params_bytes)?;
            if params.width != 16 {
                return Err("plonky3 poseidon2 width unsupported (expected 16)".to_string());
            }
            let mut rng = StdRng::seed_from_u64(params.seed);
            let perm = Poseidon2Goldilocks::<16>::new_from_rng_128(&mut rng);
            let config = build_poseidon_config::<Goldilocks, _, 16, 2>(profile, perm);
            build_tribonacci_receipt_with_config(config, profile, program)
        }
        HASH_P3_POSEIDON_ID => {
            let params = decode_poseidon_params(&profile.hash_params_bytes)?;
            if params.alpha != 7 {
                return Err("plonky3 poseidon alpha unsupported for goldilocks (expected 7)".to_string());
            }
            let perm = build_poseidon_perm::<Goldilocks, 7>(params)?;
            let config = build_poseidon_config::<Goldilocks, _, 16, 2>(profile, perm);
            build_tribonacci_receipt_with_config(config, profile, program)
        }
        HASH_P3_RESCUE_ID => {
            let params = decode_rescue_params(&profile.hash_params_bytes)?;
            if params.alpha != 7 {
                return Err("plonky3 rescue alpha unsupported for goldilocks (expected 7)".to_string());
            }
            let perm = build_rescue_perm::<Goldilocks, 7>(params)?;
            let config = build_poseidon_config::<Goldilocks, _, 16, 2>(profile, perm);
            build_tribonacci_receipt_with_config(config, profile, program)
        }
        HASH_P3_BLAKE3_ID => {
            let config = build_blake3_config_64::<Goldilocks, 2>(profile);
            build_tribonacci_receipt_with_config(config, profile, program)
        }
        _ => Err("plonky3 goldilocks hash unsupported".to_string()),
    }
}

fn build_poseidon_perm<Val, const ALPHA: u64>(
    params: PoseidonParams,
) -> Result<Poseidon<Val, CosetMds<Val, 16>, 16, ALPHA>, String>
where
    Val: Field
        + PrimeCharacteristicRing
        + PrimeField64
        + TwoAdicField
        + p3_field::InjectiveMonomial<ALPHA>
        + Send
        + Sync
        + 'static,
{
    if params.width != 16 {
        return Err("plonky3 poseidon width unsupported (expected 16)".to_string());
    }
    let num_rounds = 2usize
        .saturating_mul(params.half_full_rounds as usize)
        .saturating_add(params.partial_rounds as usize);
    let constants = derive_constants_from_seed::<Val>(params.seed, 16usize * num_rounds);
    Ok(Poseidon::<Val, CosetMds<Val, 16>, 16, ALPHA>::new(
        params.half_full_rounds as usize,
        params.partial_rounds as usize,
        constants,
        CosetMds::<Val, 16>::default(),
    ))
}

fn build_rescue_perm<Val, const ALPHA: u64>(
    params: RescueParams,
) -> Result<Rescue<Val, CosetMds<Val, 16>, 16, ALPHA>, String>
where
    Val: Field
        + PrimeCharacteristicRing
        + PrimeField64
        + TwoAdicField
        + p3_field::PermutationMonomial<ALPHA>
        + Send
        + Sync
        + 'static,
{
    if params.width != 16 {
        return Err("plonky3 rescue width unsupported (expected 16)".to_string());
    }
    let num_rounds = Rescue::<Val, CosetMds<Val, 16>, 16, ALPHA>::num_rounds(
        params.capacity as usize,
        params.sec_level as usize,
    );
    let num_constants = 2usize.saturating_mul(16).saturating_mul(num_rounds);
    let round_constants = derive_constants_from_seed::<Val>(params.seed, num_constants);
    Ok(Rescue::<Val, CosetMds<Val, 16>, 16, ALPHA>::new(
        num_rounds,
        round_constants,
        CosetMds::<Val, 16>::default(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_baby_bear::{BabyBear, Poseidon2BabyBear, default_babybear_poseidon2_16};
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_uni_stark::{prove, StarkConfig};

fn build_fib_trace<F: PrimeCharacteristicRing + Send + Sync>(
    a: u64,
    b: u64,
    n: usize,
) -> RowMajorMatrix<F> {
        assert!(n.is_power_of_two());
        let mut values = vec![F::ZERO; n * 2];
        values[0] = F::from_u64(a);
        values[1] = F::from_u64(b);
        for i in 1..n {
            let left = values[(i - 1) * 2].clone();
            let right = values[(i - 1) * 2 + 1].clone();
            values[i * 2] = right.clone();
            values[i * 2 + 1] = left + right;
        }
        RowMajorMatrix::new(values, 2)
    }

    #[test]
    fn test_plonky3_poseidon2_fibonacci_receipt() {
        type Challenge = BinomialExtensionField<BabyBear, 4>;
        type Hash = PaddingFreeSponge<Poseidon2BabyBear<16>, 16, 8, 8>;
        type Compress = TruncatedPermutation<Poseidon2BabyBear<16>, 2, 8, 16>;
        type ValMmcs = MerkleTreeMmcs<
            <BabyBear as Field>::Packing,
            <BabyBear as Field>::Packing,
            Hash,
            Compress,
            PLONKY3_DEFAULT_DIGEST_ELEMS,
        >;
        type ChallengeMmcs = ExtensionMmcs<BabyBear, Challenge, ValMmcs>;
        type Pcs = TwoAdicFriPcs<BabyBear, Radix2DitParallel<BabyBear>, ValMmcs, ChallengeMmcs>;
        type Challenger = DuplexChallenger<BabyBear, Poseidon2BabyBear<16>, 16, 8>;

        let perm = default_babybear_poseidon2_16();
        let hash = Hash::new(perm.clone());
        let compress = Compress::new(perm.clone());
        let val_mmcs = ValMmcs::new(hash, compress);
        let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
        let fri_params = FriParameters {
            log_blowup: 2,
            log_final_poly_len: 0,
            num_queries: 2,
            commit_proof_of_work_bits: 0,
            query_proof_of_work_bits: 0,
            mmcs: challenge_mmcs,
        };
        let pcs = Pcs::new(Radix2DitParallel::default(), val_mmcs, fri_params);
        let challenger = Challenger::new(perm);
        let config = StarkConfig::new(pcs, challenger);

        let trace = build_fib_trace::<BabyBear>(0, 1, 8);
        let pis = vec![BabyBear::ZERO, BabyBear::ONE, BabyBear::from_u64(21)];
        let proof = prove(&config, &FibonacciAir {}, trace, &pis);
        let proof_bytes = bincode_options()
            .serialize(&proof)
            .unwrap_or_else(|_| {
                assert!(false, "proof encode");
                Vec::new()
            });
        let pub_inputs_bytes = bincode_options()
            .serialize(&pis)
            .unwrap_or_else(|_| {
                assert!(false, "pi encode");
                Vec::new()
            });

        let program = Plonky3StarkProgram {
            version: PLONKY3_STARK_PROGRAM_VERSION,
            field_id: FIELD_P3_BABY_BEAR_ID,
            hash_id: HASH_P3_POSEIDON2_ID,
            commitment_scheme_id: VC_MERKLE_ID,
            air_id: PLONKY3_AIR_FIBONACCI_ID,
            air_params_bytes: Vec::new(),
        };
        let profile = Plonky3StarkProfile {
            version: PLONKY3_STARK_PROFILE_VERSION,
            pcs_type: PLONKY3_PCS_FRI_ID,
            log_blowup: 2,
            log_final_poly_len: 0,
            num_queries: 2,
            commit_pow_bits: 0,
            query_pow_bits: 0,
            num_random_codewords: 0,
            hash_params_bytes: encode_poseidon2_params(&Poseidon2Params { width: 16, seed: 0 }),
        };
        let vk = CanonicalStarkVk {
            version: 1,
            field_id: program.field_id,
            hash_id: program.hash_id,
            commitment_scheme_id: program.commitment_scheme_id,
            consts_bytes: profile.encode(),
            program_bytes: program.encode(),
        };
        let receipt = CanonicalStarkReceipt {
            proof_bytes,
            pub_inputs_bytes,
            vk_bytes: vk.encode(),
        };
        let decoded_vk = match CanonicalStarkReceipt::decode_and_validate_vk(&receipt) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "vk");
                return;
            }
        };
        let decoded_program = match Plonky3StarkProgram::decode(&decoded_vk.program_bytes) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "program");
                return;
            }
        };
        if let Err(_) = verify_plonky3_receipt(&receipt, &decoded_vk, &decoded_program) {
            assert!(false, "verify");
        }
    }

    #[test]
    fn test_plonky3_poseidon2_tribonacci_receipt() {
        type Challenge = BinomialExtensionField<BabyBear, 4>;
        type Hash = PaddingFreeSponge<Poseidon2BabyBear<16>, 16, 8, 8>;
        type Compress = TruncatedPermutation<Poseidon2BabyBear<16>, 2, 8, 16>;
        type ValMmcs = MerkleTreeMmcs<
            <BabyBear as Field>::Packing,
            <BabyBear as Field>::Packing,
            Hash,
            Compress,
            PLONKY3_DEFAULT_DIGEST_ELEMS,
        >;
        type ChallengeMmcs = ExtensionMmcs<BabyBear, Challenge, ValMmcs>;
        type Pcs = TwoAdicFriPcs<BabyBear, Radix2DitParallel<BabyBear>, ValMmcs, ChallengeMmcs>;
        type Challenger = DuplexChallenger<BabyBear, Poseidon2BabyBear<16>, 16, 8>;

        let perm = default_babybear_poseidon2_16();
        let hash = Hash::new(perm.clone());
        let compress = Compress::new(perm.clone());
        let val_mmcs = ValMmcs::new(hash, compress);
        let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
        let fri_params = FriParameters {
            log_blowup: 2,
            log_final_poly_len: 0,
            num_queries: 2,
            commit_proof_of_work_bits: 0,
            query_proof_of_work_bits: 0,
            mmcs: challenge_mmcs,
        };
        let pcs = Pcs::new(Radix2DitParallel::default(), val_mmcs, fri_params);
        let challenger = Challenger::new(perm);
        let config = StarkConfig::new(pcs, challenger);

        let trace = build_trib_trace::<BabyBear>(0, 1, 1, 8);
        let mut t0 = 0u64;
        let mut t1 = 1u64;
        let mut t2 = 1u64;
        for _ in 1..8 {
            let next = t0 + t1 + t2;
            t0 = t1;
            t1 = t2;
            t2 = next;
        }
        let pis = vec![
            BabyBear::from_u64(0),
            BabyBear::from_u64(1),
            BabyBear::from_u64(1),
            BabyBear::from_u64(t2),
        ];
        let proof = prove(&config, &TribonacciAir {}, trace, &pis);
        let proof_bytes = bincode_options()
            .serialize(&proof)
            .unwrap_or_else(|_| {
                assert!(false, "proof encode");
                Vec::new()
            });
        let pub_inputs_bytes = bincode_options()
            .serialize(&pis)
            .unwrap_or_else(|_| {
                assert!(false, "pi encode");
                Vec::new()
            });

        let program = Plonky3StarkProgram {
            version: PLONKY3_STARK_PROGRAM_VERSION,
            field_id: FIELD_P3_BABY_BEAR_ID,
            hash_id: HASH_P3_POSEIDON2_ID,
            commitment_scheme_id: VC_MERKLE_ID,
            air_id: PLONKY3_AIR_TRIBONACCI_ID,
            air_params_bytes: Vec::new(),
        };
        let profile = Plonky3StarkProfile {
            version: PLONKY3_STARK_PROFILE_VERSION,
            pcs_type: PLONKY3_PCS_FRI_ID,
            log_blowup: 2,
            log_final_poly_len: 0,
            num_queries: 2,
            commit_pow_bits: 0,
            query_pow_bits: 0,
            num_random_codewords: 0,
            hash_params_bytes: encode_poseidon2_params(&Poseidon2Params { width: 16, seed: 0 }),
        };
        let vk = CanonicalStarkVk {
            version: 1,
            field_id: program.field_id,
            hash_id: program.hash_id,
            commitment_scheme_id: program.commitment_scheme_id,
            consts_bytes: profile.encode(),
            program_bytes: program.encode(),
        };
        let receipt = CanonicalStarkReceipt {
            proof_bytes,
            pub_inputs_bytes,
            vk_bytes: vk.encode(),
        };
        let decoded_vk = match CanonicalStarkReceipt::decode_and_validate_vk(&receipt) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "vk");
                return;
            }
        };
        let decoded_program = match Plonky3StarkProgram::decode(&decoded_vk.program_bytes) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "program");
                return;
            }
        };
        if let Err(_) = verify_plonky3_receipt(&receipt, &decoded_vk, &decoded_program) {
            assert!(false, "verify");
        }
    }
}
