use super::*;
use crate::glyph_ir::{ArithmeticGate, WitnessLayout, WRef};

fn eval_round_poly(round: &SumcheckRound, t: Goldilocks) -> Goldilocks {
    let t2 = t * t;
    let t3 = t2 * t;
    round.c0 + round.c1 * t + round.c2 * t2 + round.c3 * t3
}

#[test]
fn test_sumcheck_inv_constants_via_interpolation_roundtrip() {
    let c0 = Goldilocks::new(5);
    let c1 = Goldilocks::new(7);
    let c2 = Goldilocks::new(11);
    let c3 = Goldilocks::new(13);

    let f = |t: u64| -> Goldilocks {
        let tt = Goldilocks::new(t);
        let tt2 = tt * tt;
        let tt3 = tt2 * tt;
        c0 + c1 * tt + c2 * tt2 + c3 * tt3
    };

    let y0 = f(0);
    let y1 = f(1);
    let y2 = f(2);
    let y3 = f(3);

    let round = sumcheck::interpolate_cubic_from_values(y0, y1, y2, y3);
    assert_eq!(round.c0, c0);
    assert_eq!(round.c1, c1);
    assert_eq!(round.c2, c2);
    assert_eq!(round.c3, c3);

    for t in 0u64..=3 {
        let tt = Goldilocks::new(t);
        assert_eq!(eval_round_poly(&round, tt), f(t));
    }
}

#[test]
fn test_sumcheck_inv_constants() {
    let two = Goldilocks::new(2);
    let six = Goldilocks::new(6);
    assert_eq!(sumcheck::INV2 * two, Goldilocks::ONE);
    assert_eq!(sumcheck::INV6 * six, Goldilocks::ONE);
    let inv2 = match two.inverse() {
        Some(value) => value,
        None => {
            assert!(false, "inv2");
            return;
        }
    };
    let inv6 = match six.inverse() {
        Some(value) => value,
        None => {
            assert!(false, "inv6");
            return;
        }
    };
    assert_eq!(sumcheck::INV2, inv2);
    assert_eq!(sumcheck::INV6, inv6);
}

#[test]
fn test_prover_mode_default() {
    let config = ProverConfig::default();
    assert_eq!(config.mode, ProverMode::ZkMode);
    println!("Prover mode default test passed.");
}

#[test]
fn test_glyph_artifact_claim_word() {
    let artifact = GlyphArtifact {
        commitment_tag: [1u8; 32],
        point_tag: [2u8; 32],
        claim128: 0x123456789ABCDEF0_FEDCBA9876543210,
        initial_claim: [3u8; 32],
    };

    let claim_word = artifact.claim_word_bytes32();
    assert_eq!(claim_word.len(), 32);
    // Upper 128 bits should be zero
    assert!(claim_word[..16].iter().all(|&x| x == 0));
    assert_eq!(claim_word[16..32], artifact.claim128.to_be_bytes());

    println!("GLYPH artifact claim word test passed.");
}

#[test]
fn test_prove_universal_simple() {
    // Create minimal UCIR
    let mut ucir = Ucir2::new();
    ucir.witness_layout = WitnessLayout::fast_mode(2, 1, 0);

    // Add: a + b = c constraint
    ucir.add_arithmetic_gate(ArithmeticGate::add(WRef(0), WRef(1), WRef(2)));

    // Public inputs: a=3, b=7
    let public_inputs = vec![Goldilocks(3), Goldilocks(7)];

    let config = ProverConfig {
        sumcheck_rounds: 0,
        ..Default::default()
    };
    let result = prove_universal(ucir, &public_inputs, None, config);

    assert!(result.is_ok());

    println!("Prove universal simple test completed.");
}

#[test]
fn test_sumcheck_constants() {
    // Goldilocks moduli: p = 2^64 - 2^32 + 1
    // p = 0xFFFFFFFF00000001

    let one = Goldilocks::ONE;
    let two = Goldilocks(2);
    let six = Goldilocks(6);

    // Verify INV2 * 2 == 1
    assert_eq!(sumcheck::INV2 * two, one, "INV2 must be modular inverse of 2");

    // Verify INV6 * 6 == 1
    assert_eq!(sumcheck::INV6 * six, one, "INV6 must be modular inverse of 6");

    // Verify inv3 derivation in interpolate code (inv3 = INV6 + INV6 = 2/6 = 1/3)
    let three = Goldilocks(3);
    let inv3 = sumcheck::INV6 + sumcheck::INV6;
    assert_eq!(inv3 * three, one, "inv3 must be modular inverse of 3");
}
