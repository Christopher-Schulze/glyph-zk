// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./GLYPHVerifierConstants.sol";

/**
 * @title GLYPHVerifier
 * @notice GLYPH packed sumcheck verifier for an artifact-defined public quadratic polynomial.
 * @dev This contract expects tightly packed calldata (no selector).
 *
 *      Layout (always bound):
 *      - Bound (GKR artifact-poly): [artifact_tag] [claim128||initial_claim] [packed round coeffs...]
 *
 *      Per round encoding uses two 128-bit coefficients packed as 32 bytes:
 *      - bytes0..15 = c0, bytes16..31 = c1
 *      - c2 is recovered from the sumcheck constraint
 *      - each coeff is a 128-bit field element < MODULUS
 *
 *      The per-round polynomial is `g(t) = c0 + c1*t + c2*t^2`.
 *      The sumcheck constraint is `g(0) + ... + g(7) == current_claim`.
 *      Using `current_claim = 8*c0 + 28*c1 + 140*c2`, we recover
 *      `c2 = (current_claim - (8*c0 + 28*c1)) * inv(140)`.
 *
 *      `claim128` must fit in 128 bits (upper 128 bits are zero). This models a simple
 *      embedding of a binary-field claim into BN254 as an unsigned integer.
 *
 *      Chain binding:
 *        r0 = keccak256(chainid || address(this) || artifact_tag || claim128 || initial_claim) mod MODULUS
 *      `claim128` and `initial_claim` are hashed as 16-byte big-endian values (claim then initial).
 *      artifact_tag = keccak256(commitment_tag || point_tag)
 *
 *      Fiat-Shamir:
 *      - r0 = keccak256(chainid || address(this) || artifact_tag || claim128(16) || initial_claim(16)) mod MODULUS
 *      - per round: r = keccak256(r || xor(c0, c1, c2)) mod MODULUS        
 *
 *      Public polynomial (degree 2 in each variable):
 *        f(x_0..x_{R-1}) = (lin_0 + claim128 + Σ_{i=0..R-1} lin_{i+1} * x_i)^2
 *        lin_hash = keccak256(LIN_DOMAIN || artifact_tag || claim128) mod MODULUS
 *        lin_0 = lin_hash[0..16] mod MODULUS
 *        lin_step = lin_hash[16..32] mod MODULUS
 *        lin_j = lin_0 * lin_step^j (mod MODULUS)
 *
 *      The verifier accumulates the evaluation point from the Fiat-Shamir challenges r_i and
 *      checks the final claim against f(r_0..r_{R-1}).
 */
contract GLYPHVerifier is GLYPHVerifierConstants {
    fallback() external payable {
        assembly {
            // Phase 1: input sizing and header parse.
            let q := MODULUS
            let size := calldatasize()

            // Header: artifact_tag(32) + claim+initial(32) = 64 bytes.
            // Minimum packed: header(64) + one round(32) = 96 bytes.
            if lt(size, 96) { revert(0, 0) }

            // Determine stride (packed: 2 coeffs = 32 bytes).
            let rem := sub(size, 64)
            if and(rem, 31) { revert(0, 0) }
            let end := add(64, rem)

            let artifact_tag := calldataload(0)

            let mask := 0xffffffffffffffffffffffffffffffff
            let claim_initial := calldataload(32)
            let claim := shr(128, claim_initial)
            let current_claim := and(claim_initial, mask)
            if or(iszero(lt(claim, q)), iszero(lt(current_claim, q))) { revert(0, 0) }

            // Phase 2: Fiat-Shamir initialization r0.
            // Initial challenge r0 = keccak256(chainid || address(this) || artifact_tag || claim(16) || initial_claim(16)) mod q.
            mstore(0x00, chainid())
            mstore(0x20, address())
            mstore(0x40, artifact_tag)
            mstore(0x60, claim_initial)
            let r := mod(keccak256(0x00, 0x80), q)

            // Phase 3: linear hash precompute.
            // Preload lin hash inputs once: LIN_DOMAIN || artifact_tag || claim.
            // Kept out of the r-hash scratch space (0x00..0x9f) to avoid re-storing constants.
            mstore(0xa0, LIN_DOMAIN)
            mstore(0xc0, artifact_tag)
            mstore(0xe0, shl(128, claim))

            // lin_hash = keccak256(LIN_DOMAIN || artifact_tag || claim) mod q.
            let lin_hash := keccak256(0xa0, 0x50)
            let lin0 := shr(128, lin_hash)
            let lin_step := and(lin_hash, mask)
            if iszero(lt(lin0, q)) { lin0 := sub(lin0, q) }
            if iszero(lt(lin_step, q)) { lin_step := sub(lin_step, q) }

            // lin starts at lin_0, then lin_{i+1} = lin_i * lin_step.
            let lin_acc := lin0

            // Accumulate Σ lin_{i+1} * r_i where r_i is the per-round Fiat-Shamir challenge.
            let eval_lin := 0

            // Coefficients start after header.
            let ptr := 64

            // Phase 4: per-round decode and transcript update.
            for { } lt(ptr, end) { ptr := add(ptr, 32) } {
                let w0 := calldataload(ptr)
                let c0 := shr(128, w0)
                let c1 := and(w0, mask)

                {
                    if or(iszero(lt(c0, q)), iszero(lt(c1, q))) { revert(0, 0) }
                }

                // Recover c2 from the sumcheck constraint.
                let partial := mod(add(shl(3, c0), mul(c1, 28)), q)
                let c2 := mulmod(addmod(current_claim, sub(q, partial), q), INV140, q)

                // Update challenge r = keccak256(r(16) || xor(c0, c1, c2)(16)) mod q.
                let mix := xor(xor(c0, c1), c2)
                mstore(0x00, or(shl(128, r), mix))
                r := mod(keccak256(0x00, 0x20), q)

                // lin_{i+1} = lin_i * lin_step.
                lin_acc := mulmod(lin_acc, lin_step, q)
                eval_lin := addmod(eval_lin, mul(lin_acc, r), q)

                // State update: current_claim = g(r) via Horner.
                let acc := addmod(mul(c2, r), c1, q)
                current_claim := addmod(mul(acc, r), c0, q)

            }

            // Phase 5: final polynomial check.
            // expected_final = (lin0 + claim + eval_lin)^2.
            let base := addmod(addmod(lin0, claim, q), eval_lin, q)
            let expected_final := mulmod(base, base, q)

            if iszero(eq(current_claim, expected_final)) { revert(0, 0) }

            mstore(0x00, 1)
            return(0x00, 0x20)
        }
    }
}
