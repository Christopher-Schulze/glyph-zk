#![no_main]

sp1_zkvm::entrypoint!(main);

pub fn main() {
    // No inputs, no outputs. This guest is used only to generate deterministic fixtures.
}
