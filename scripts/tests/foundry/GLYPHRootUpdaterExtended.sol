// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title GLYPHRootUpdaterExtended
/// @notice Optional L2 root updater with extra commitment binding.
/// @dev Calls GLYPHVerifier via packed calldata. Stores only state_root and batch_id.
contract GLYPHRootUpdaterExtended {
    bytes32 public state_root;
    uint64 public batch_id;
    address public immutable glyph_verifier;

    bytes constant L2_STATE_DOMAIN = "GLYPH_L2_STATE";
    bytes constant L2_COMMIT_DOMAIN = "GLYPH_L2_COMMIT";
    bytes constant L2_POINT_DOMAIN = "GLYPH_L2_POINT";

    error InvalidCalldata();
    error InvalidArtifactTag();
    error InvalidProof();
    error InvalidVerifier();

    event RootUpdated(
        bytes32 old_root,
        bytes32 new_root,
        bytes32 da_commitment,
        uint64 batch_id,
        bytes32 extra_commitment
    );

    constructor(address verifier, bytes32 initial_root) {
        if (verifier == address(0)) {
            revert InvalidVerifier();
        }
        glyph_verifier = verifier;
        state_root = initial_root;
        batch_id = 0;
    }

    function verifyRootUpdate(
        bytes32 new_root,
        bytes32 da_commitment,
        bytes32 extra_commitment,
        bytes32 extra_schema_id,
        bytes calldata glyph_proof
    ) external {
        bytes32 old_root = state_root;
        uint64 current_batch = batch_id;
        bytes32 statement_hash = keccak256(
            abi.encodePacked(
                L2_STATE_DOMAIN,
                block.chainid,
                address(this),
                old_root,
                new_root,
                da_commitment,
                current_batch,
                extra_commitment,
                extra_schema_id
            )
        );
        bytes32 artifact_tag = _artifact_tag(statement_hash);
        _check_artifact_tag(glyph_proof, artifact_tag);

        (bool ok, bytes memory ret) = glyph_verifier.staticcall(glyph_proof);
        if (!ok || ret.length < 32 || abi.decode(ret, (uint256)) != 1) {
            revert InvalidProof();
        }

        state_root = new_root;
        batch_id = current_batch + 1;
        emit RootUpdated(old_root, new_root, da_commitment, current_batch, extra_commitment);
    }

    function _artifact_tag(bytes32 statement_hash) internal pure returns (bytes32) {
        bytes32 commitment_tag = keccak256(
            abi.encodePacked(L2_COMMIT_DOMAIN, statement_hash)
        );
        bytes32 point_tag = keccak256(
            abi.encodePacked(L2_POINT_DOMAIN, commitment_tag)
        );
        return keccak256(abi.encodePacked(commitment_tag, point_tag));
    }

    function _check_artifact_tag(bytes calldata glyph_proof, bytes32 expected) internal pure {
        if (glyph_proof.length < 32) {
            revert InvalidCalldata();
        }
        bytes32 tag;
        assembly {
            tag := calldataload(glyph_proof.offset)
        }
        if (tag != expected) {
            revert InvalidArtifactTag();
        }
    }
}
