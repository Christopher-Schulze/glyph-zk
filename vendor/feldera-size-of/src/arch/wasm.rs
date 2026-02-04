#![cfg(any(target_arch = "wasm32", target_arch = "wasm64"))]

use core::arch::wasm::v128;

impl_total_size_childless! {
    v128,
}
