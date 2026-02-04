//! Property tests for Adapter IR encoding/decoding invariants.

use proptest::prelude::*;

use glyph::adapter_ir::{kernel_id, AdapterIr, AdapterIrOp, ADAPTER_IR_VERSION};

fn kernel_id_strategy() -> impl Strategy<Value = u16> {
    prop_oneof![
        Just(kernel_id::HASH_SHA3_MERGE),
        Just(kernel_id::GROTH16_BN254_VERIFY),
        Just(kernel_id::KZG_BN254_VERIFY),
        Just(kernel_id::IVC_VERIFY),
        Just(kernel_id::IPA_VERIFY),
        Just(kernel_id::STARK_VERIFY),
        Just(kernel_id::BINIUS_VERIFY),
        Just(kernel_id::WINTERFELL_SHA3_TRANSCRIPT),
        Just(kernel_id::CIRCLE_STARK_TRANSCRIPT),
    ]
}

prop_compose! {
    fn any_op()(kernel_id in kernel_id_strategy(),
        args in proptest::collection::vec(any::<u8>(), 0..256)) -> AdapterIrOp {
        AdapterIrOp { kernel_id, args }
    }
}

prop_compose! {
    fn any_ir()(ops in proptest::collection::vec(any_op(), 0..16)) -> AdapterIr {
        AdapterIr {
            version: ADAPTER_IR_VERSION,
            ops,
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]
    #[test]
    fn adapter_ir_roundtrip(ir in any_ir()) {
        let enc = ir.encode();
        let dec = AdapterIr::decode(&enc).expect("decode must succeed");
        prop_assert_eq!(ir, dec);
    }
}

#[test]
fn adapter_ir_rejects_trailing_data() {
    let ir = AdapterIr {
        version: ADAPTER_IR_VERSION,
        ops: vec![AdapterIrOp {
            kernel_id: kernel_id::HASH_SHA3_MERGE,
            args: vec![1, 2, 3],
        }],
    };
    let mut enc = ir.encode();
    enc.push(0);
    assert!(AdapterIr::decode(&enc).is_err());
}

#[test]
fn adapter_ir_rejects_wrong_version() {
    let ir = AdapterIr {
        version: ADAPTER_IR_VERSION + 1,
        ops: vec![],
    };
    let enc = ir.encode();
    assert!(AdapterIr::decode(&enc).is_err());
}

#[test]
fn adapter_ir_rejects_bad_tag() {
    let ir = AdapterIr {
        version: ADAPTER_IR_VERSION,
        ops: vec![],
    };
    let mut enc = ir.encode();
    enc[0] ^= 0x01;
    assert!(AdapterIr::decode(&enc).is_err());
}
