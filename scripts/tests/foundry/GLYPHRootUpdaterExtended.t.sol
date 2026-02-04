// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "./GLYPHVerifier.sol";
import "./GLYPHRootUpdaterExtended.sol";

contract GLYPHRootUpdaterExtendedTest is Test {
    address internal constant VERIFIER_ADDR = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;
    address internal constant UPDATER_ADDR = 0x1111111111111111111111111111111111111111;

    bytes32 internal constant INITIAL_ROOT =
        0x1111111111111111111111111111111111111111111111111111111111111111;
    bytes32 internal constant NEW_ROOT =
        0x2222222222222222222222222222222222222222222222222222222222222222;
    bytes32 internal constant DA_COMMITMENT =
        0x3333333333333333333333333333333333333333333333333333333333333333;
    bytes32 internal constant EXTRA_COMMITMENT =
        0x4444444444444444444444444444444444444444444444444444444444444444;
    bytes32 internal constant EXTRA_SCHEMA_ID =
        0x5555555555555555555555555555555555555555555555555555555555555555;

    GLYPHRootUpdaterExtended internal updater;

    function setUp() public {
        vm.chainId(31337);

        GLYPHVerifier impl = new GLYPHVerifier();
        vm.etch(VERIFIER_ADDR, address(impl).code);

        GLYPHRootUpdaterExtended temp =
            new GLYPHRootUpdaterExtended(VERIFIER_ADDR, INITIAL_ROOT);
        vm.etch(UPDATER_ADDR, address(temp).code);
        vm.store(UPDATER_ADDR, bytes32(uint256(0)), INITIAL_ROOT);
        vm.store(UPDATER_ADDR, bytes32(uint256(1)), bytes32(uint256(0)));

        updater = GLYPHRootUpdaterExtended(UPDATER_ADDR);
    }

    function test_GLYPHRootUpdaterExtended_Succeeds() public {
        bytes memory proof = _proof();
        updater.verifyRootUpdate(
            NEW_ROOT,
            DA_COMMITMENT,
            EXTRA_COMMITMENT,
            EXTRA_SCHEMA_ID,
            proof
        );
        assertEq(updater.state_root(), NEW_ROOT, "state root updated");
        assertEq(updater.batch_id(), 1, "batch id incremented");
    }

    function test_GLYPHRootUpdaterExtended_TamperProof_Fails() public {
        bytes memory proof = _proof();
        proof[0] = bytes1(uint8(proof[0]) ^ 1);
        vm.expectRevert();
        updater.verifyRootUpdate(
            NEW_ROOT,
            DA_COMMITMENT,
            EXTRA_COMMITMENT,
            EXTRA_SCHEMA_ID,
            proof
        );
    }

    function test_GLYPHRootUpdaterExtended_TamperExtraCommitment_Fails() public {
        bytes memory proof = _proof();
        bytes32 bad_extra =
            0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;
        vm.expectRevert();
        updater.verifyRootUpdate(
            NEW_ROOT,
            DA_COMMITMENT,
            bad_extra,
            EXTRA_SCHEMA_ID,
            proof
        );
    }

    function test_GLYPHRootUpdaterExtended_BatchId_Monotonic() public {
        bytes memory proof = _proof();
        updater.verifyRootUpdate(
            NEW_ROOT,
            DA_COMMITMENT,
            EXTRA_COMMITMENT,
            EXTRA_SCHEMA_ID,
            proof
        );
        vm.expectRevert();
        updater.verifyRootUpdate(
            NEW_ROOT,
            DA_COMMITMENT,
            EXTRA_COMMITMENT,
            EXTRA_SCHEMA_ID,
            proof
        );
    }

    function _proof() internal pure returns (bytes memory) {
        return hex"a2921b9c85da87889bdb49147e44e906c868040679516f2d0820c2d87115fbfaf5bcab6e0e47cac846a824b02b65f699638cd2bea132d792e7e590e1a81055c24e770f40637a1c2e848cc0daf67aaa254cb6f016cbdb12797163371f96e0f1f1fdbb0aeb306cb02c38f3ccb88b2d3fff4f1a9f60dd203536d6087d5eda775823280b2011cfb74c3c1b6e3f409cce2d8eca1b88bae7d72a0914544cae3d2c46d44d4b5ab239a9fb6aa0035d278a9ce5ad9242d4e26c68cbac96bc0a40b8ebe20fb489915f9799c2d5830ec54afb35e4f4184a06c0670b8e9fc63f4264e8bbece5";
    }
}
