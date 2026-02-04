// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "./GLYPHVerifier.sol";
import "./GLYPHRootUpdaterMinimal.sol";

contract GLYPHRootUpdaterMinimalTest is Test {
    address internal constant VERIFIER_ADDR = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;
    address internal constant UPDATER_ADDR = 0x1111111111111111111111111111111111111111;

    bytes32 internal constant INITIAL_ROOT =
        0x1111111111111111111111111111111111111111111111111111111111111111;
    bytes32 internal constant NEW_ROOT =
        0x2222222222222222222222222222222222222222222222222222222222222222;
    bytes32 internal constant DA_COMMITMENT =
        0x3333333333333333333333333333333333333333333333333333333333333333;

    GLYPHRootUpdaterMinimal internal updater;

    function setUp() public {
        vm.chainId(31337);

        GLYPHVerifier impl = new GLYPHVerifier();
        vm.etch(VERIFIER_ADDR, address(impl).code);

        GLYPHRootUpdaterMinimal temp =
            new GLYPHRootUpdaterMinimal(VERIFIER_ADDR, INITIAL_ROOT);
        vm.etch(UPDATER_ADDR, address(temp).code);
        vm.store(UPDATER_ADDR, bytes32(uint256(0)), INITIAL_ROOT);
        vm.store(UPDATER_ADDR, bytes32(uint256(1)), bytes32(uint256(0)));

        updater = GLYPHRootUpdaterMinimal(UPDATER_ADDR);
    }

    function test_GLYPHRootUpdaterMinimal_Succeeds() public {
        bytes memory proof = _proof();
        updater.verifyRootUpdate(NEW_ROOT, DA_COMMITMENT, proof);
        assertEq(updater.state_root(), NEW_ROOT, "state root updated");
        assertEq(updater.batch_id(), 1, "batch id incremented");
    }

    function test_GLYPHRootUpdaterMinimal_TamperProof_Fails() public {
        bytes memory proof = _proof();
        proof[0] = bytes1(uint8(proof[0]) ^ 1);
        vm.expectRevert();
        updater.verifyRootUpdate(NEW_ROOT, DA_COMMITMENT, proof);
    }

    function test_GLYPHRootUpdaterMinimal_TamperNewRoot_Fails() public {
        bytes memory proof = _proof();
        bytes32 bad_root =
            0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;
        vm.expectRevert();
        updater.verifyRootUpdate(bad_root, DA_COMMITMENT, proof);
    }

    function test_GLYPHRootUpdaterMinimal_BatchId_Monotonic() public {
        bytes memory proof = _proof();
        updater.verifyRootUpdate(NEW_ROOT, DA_COMMITMENT, proof);
        vm.expectRevert();
        updater.verifyRootUpdate(NEW_ROOT, DA_COMMITMENT, proof);
    }

    function _proof() internal pure returns (bytes memory) {
        return hex"fda7d45ee004235e731138ef2dcbedc0042ea4d273a2ff8431098afe8df7a1d5d773c1832aa1fc9eafe7bcb489fae97a6e94bf78293ba38f6901f2a6c6af0a8b09ea87ff4df7c8860cfb26bee09624fdd7c41de4273e7d1a24f3beaca40bbb98c2b55c40fd5bc7ac055e240a82e441e4df9858d024d42a212a032011da0b0919897af5bc3f32502db04a75d887862a725f5d6caabb92070541a83385e18d3c11c0290674020ad5b8166161f6d462ef409e237df51c0dd69707d560355b75e3a49682366b1d04fa1f0b82a0fd68f0744e4e3e7e20abe574be423058009a435ef8";
    }
}
