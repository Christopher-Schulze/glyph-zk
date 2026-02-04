//! Adapter SNARK: PLONK and Halo2 receipts.

use crate::halo2_receipt;
use crate::plonk_adapter;

pub fn derive_glyph_artifact_from_plonk_halo2_receipt(
    receipt_bytes: &[u8],
) -> Result<([u8; 32], [u8; 32], u128), String> {
    if receipt_bytes.starts_with(plonk_adapter::PLONK_RECEIPT_TAG) {
        return plonk_adapter::derive_glyph_artifact_from_plonk_receipt(receipt_bytes);
    }
    if receipt_bytes.starts_with(halo2_receipt::HALO2_RECEIPT_TAG) {
        return halo2_receipt::derive_glyph_artifact_from_halo2_receipt(receipt_bytes);
    }
    Err("plonk or halo2 receipt tag unsupported".to_string())
}
