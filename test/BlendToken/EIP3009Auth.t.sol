// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {BlendToken} from "src/BlendToken.sol";
import {EIP3009} from "src/EIP3009.sol";
import {IEIP3009} from "src/IEIP3009.sol";
import {BlendTokenBase} from "test/BlendToken/Base.t.sol";

contract DummyRecipient {
    function callTransferWithAuthorization(
        BlendToken token,
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        token.transferWithAuthorization(from, to, value, validAfter, validBefore, nonce, v, r, s);
    }
}

contract MockERC1271Wallet {
    bytes4 internal constant MAGICVALUE = 0x1626ba7e;

    function isValidSignature(bytes32, bytes memory) external pure returns (bytes4) {
        return MAGICVALUE;
    }
}

contract BlendTokenEIP3009AuthTest is BlendTokenBase {
    function test_transferWithAuthorization_valid() public {
        uint256 value = 100 * UNIT;
        _mintTo(alice, value);

        uint256 validAfter = block.timestamp - 1;
        uint256 validBefore = block.timestamp + 1 days;
        bytes32 nonce = keccak256("nonce-1");

        (uint8 v, bytes32 r, bytes32 s) =
            _signTransferWithAuthorization(alicePk, alice, bob, value, validAfter, validBefore, nonce);

        vm.prank(relayer);
        vm.expectEmit(true, true, true, true);
        emit IEIP3009.AuthorizationUsed(alice, nonce);
        vm.expectEmit(true, true, true, true);
        emit IERC20.Transfer(alice, bob, value);
        token.transferWithAuthorization(alice, bob, value, validAfter, validBefore, nonce, v, r, s);

        assertTrue(token.authorizationState(alice, nonce));
        assertEq(token.balanceOf(bob), value);
    }

    function test_receiveWithAuthorization_valid() public {
        uint256 value = 50 * UNIT;
        _mintTo(alice, value);

        uint256 validAfter = block.timestamp - 1;
        uint256 validBefore = block.timestamp + 1 days;
        bytes32 nonce = keccak256("nonce-2");

        (uint8 v, bytes32 r, bytes32 s) =
            _signReceiveWithAuthorization(alicePk, alice, bob, value, validAfter, validBefore, nonce);

        vm.prank(bob);
        vm.expectEmit(true, true, true, true);
        emit IEIP3009.AuthorizationUsed(alice, nonce);
        vm.expectEmit(true, true, true, true);
        emit IERC20.Transfer(alice, bob, value);
        token.receiveWithAuthorization(alice, bob, value, validAfter, validBefore, nonce, v, r, s);

        assertTrue(token.authorizationState(alice, nonce));
        assertEq(token.balanceOf(bob), value);
    }

    function test_transferWithAuthorization_erc1271Wallet_valid() public {
        uint256 value = 25 * UNIT;
        MockERC1271Wallet wallet = new MockERC1271Wallet();
        _mintTo(address(wallet), value);

        uint256 validAfter = block.timestamp - 1;
        uint256 validBefore = block.timestamp + 1 days;
        bytes32 nonce = keccak256("nonce-erc1271");

        uint8 v = 0;
        bytes32 r = bytes32(uint256(1));
        bytes32 s = bytes32(uint256(2));

        vm.prank(relayer);
        vm.expectEmit(true, true, true, true);
        emit IEIP3009.AuthorizationUsed(address(wallet), nonce);
        vm.expectEmit(true, true, true, true);
        emit IERC20.Transfer(address(wallet), bob, value);
        token.transferWithAuthorization(address(wallet), bob, value, validAfter, validBefore, nonce, v, r, s);

        assertTrue(token.authorizationState(address(wallet), nonce));
        assertEq(token.balanceOf(bob), value);
    }

    function test_cancelAuthorization_marksUsed() public {
        bytes32 nonce = keccak256("nonce-3");

        (uint8 v, bytes32 r, bytes32 s) = _signCancelAuthorization(alicePk, alice, nonce);

        vm.prank(relayer);
        vm.expectEmit(true, true, true, true);
        emit IEIP3009.AuthorizationCanceled(alice, nonce);
        token.cancelAuthorization(alice, nonce, v, r, s);

        assertTrue(token.authorizationState(alice, nonce));
    }

    function test_reuseNonce_reverts() public {
        uint256 value = 10 * UNIT;
        _mintTo(alice, value);

        uint256 validAfter = block.timestamp - 1;
        uint256 validBefore = block.timestamp + 1 days;
        bytes32 nonce = keccak256("nonce-4");

        (uint8 v, bytes32 r, bytes32 s) =
            _signTransferWithAuthorization(alicePk, alice, bob, value, validAfter, validBefore, nonce);

        vm.prank(relayer);
        token.transferWithAuthorization(alice, bob, value, validAfter, validBefore, nonce, v, r, s);

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(EIP3009.AuthorizationAlreadyUsed.selector, alice, nonce));
        token.transferWithAuthorization(alice, bob, value, validAfter, validBefore, nonce, v, r, s);
    }

    function test_notYetValid_reverts() public {
        uint256 value = 10 * UNIT;
        _mintTo(alice, value);

        uint256 validAfter = block.timestamp;
        uint256 validBefore = block.timestamp + 1 days;
        bytes32 nonce = keccak256("nonce-5");

        (uint8 v, bytes32 r, bytes32 s) =
            _signTransferWithAuthorization(alicePk, alice, bob, value, validAfter, validBefore, nonce);

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(EIP3009.AuthorizationNotYetValid.selector, validAfter));
        token.transferWithAuthorization(alice, bob, value, validAfter, validBefore, nonce, v, r, s);
    }

    function test_transferWithAuthorization_atValidAfter_reverts() public {
        uint256 value = 10 * UNIT;
        _mintTo(alice, value);

        uint256 validAfter = block.timestamp;
        uint256 validBefore = block.timestamp + 1 days;
        bytes32 nonce = keccak256("nonce-at-valid-after");

        (uint8 v, bytes32 r, bytes32 s) =
            _signTransferWithAuthorization(alicePk, alice, bob, value, validAfter, validBefore, nonce);

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(EIP3009.AuthorizationNotYetValid.selector, validAfter));
        token.transferWithAuthorization(alice, bob, value, validAfter, validBefore, nonce, v, r, s);
    }

    function test_expired_reverts() public {
        vm.warp(100);
        uint256 value = 10 * UNIT;
        _mintTo(alice, value);

        uint256 validAfter = block.timestamp - 1;
        uint256 validBefore = block.timestamp;
        bytes32 nonce = keccak256("nonce-6");

        (uint8 v, bytes32 r, bytes32 s) =
            _signTransferWithAuthorization(alicePk, alice, bob, value, validAfter, validBefore, nonce);

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(EIP3009.AuthorizationExpired.selector, validBefore));
        token.transferWithAuthorization(alice, bob, value, validAfter, validBefore, nonce, v, r, s);
    }

    function test_transferWithAuthorization_atValidBefore_reverts() public {
        uint256 value = 10 * UNIT;
        _mintTo(alice, value);

        uint256 validAfter = block.timestamp - 1;
        uint256 validBefore = block.timestamp;
        bytes32 nonce = keccak256("nonce-at-valid-before");

        (uint8 v, bytes32 r, bytes32 s) =
            _signTransferWithAuthorization(alicePk, alice, bob, value, validAfter, validBefore, nonce);

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(EIP3009.AuthorizationExpired.selector, validBefore));
        token.transferWithAuthorization(alice, bob, value, validAfter, validBefore, nonce, v, r, s);
    }

    function test_invalidSignature_reverts() public {
        uint256 value = 10 * UNIT;
        _mintTo(alice, value);

        uint256 validAfter = block.timestamp - 1;
        uint256 validBefore = block.timestamp + 1 days;
        bytes32 nonce = keccak256("nonce-7");

        (uint8 v, bytes32 r, bytes32 s) =
            _signTransferWithAuthorization(bobPk, alice, bob, value, validAfter, validBefore, nonce);

        vm.prank(relayer);
        vm.expectRevert(EIP3009.InvalidSignature.selector);
        token.transferWithAuthorization(alice, bob, value, validAfter, validBefore, nonce, v, r, s);
    }

    function test_receiveWithAuthorization_payeeMismatch_reverts() public {
        uint256 value = 10 * UNIT;
        _mintTo(alice, value);

        uint256 validAfter = block.timestamp - 1;
        uint256 validBefore = block.timestamp + 1 days;
        bytes32 nonce = keccak256("nonce-8");

        (uint8 v, bytes32 r, bytes32 s) =
            _signReceiveWithAuthorization(alicePk, alice, bob, value, validAfter, validBefore, nonce);

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(EIP3009.InvalidPayee.selector, relayer, bob));
        token.receiveWithAuthorization(alice, bob, value, validAfter, validBefore, nonce, v, r, s);
    }

    function test_cancelAuthorization_thenTransferWithAuthorization_reverts() public {
        uint256 value = 10 * UNIT;
        _mintTo(alice, value);

        uint256 validAfter = block.timestamp - 1;
        uint256 validBefore = block.timestamp + 1 days;
        bytes32 nonce = keccak256("nonce-cancel-transfer");

        (uint8 cancelV, bytes32 cancelR, bytes32 cancelS) = _signCancelAuthorization(alicePk, alice, nonce);

        vm.prank(relayer);
        token.cancelAuthorization(alice, nonce, cancelV, cancelR, cancelS);

        (uint8 v, bytes32 r, bytes32 s) =
            _signTransferWithAuthorization(alicePk, alice, bob, value, validAfter, validBefore, nonce);

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(EIP3009.AuthorizationAlreadyUsed.selector, alice, nonce));
        token.transferWithAuthorization(alice, bob, value, validAfter, validBefore, nonce, v, r, s);
    }

    function test_cancelAuthorization_thenReceiveWithAuthorization_reverts() public {
        uint256 value = 10 * UNIT;
        _mintTo(alice, value);

        uint256 validAfter = block.timestamp - 1;
        uint256 validBefore = block.timestamp + 1 days;
        bytes32 nonce = keccak256("nonce-cancel-receive");

        (uint8 cancelV, bytes32 cancelR, bytes32 cancelS) = _signCancelAuthorization(alicePk, alice, nonce);

        vm.prank(relayer);
        token.cancelAuthorization(alice, nonce, cancelV, cancelR, cancelS);

        (uint8 v, bytes32 r, bytes32 s) =
            _signReceiveWithAuthorization(alicePk, alice, bob, value, validAfter, validBefore, nonce);

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(EIP3009.AuthorizationAlreadyUsed.selector, alice, nonce));
        token.receiveWithAuthorization(alice, bob, value, validAfter, validBefore, nonce, v, r, s);
    }

    function test_transferWithAuthorization_contractRecipient_allowsRelayer() public {
        uint256 value = 10 * UNIT;
        _mintTo(alice, value);

        DummyRecipient recipient = new DummyRecipient();

        uint256 validAfter = block.timestamp - 1;
        uint256 validBefore = block.timestamp + 1 days;
        bytes32 nonce = keccak256("nonce-9");

        (uint8 v, bytes32 r, bytes32 s) =
            _signTransferWithAuthorization(alicePk, alice, address(recipient), value, validAfter, validBefore, nonce);

        vm.prank(relayer);
        vm.expectEmit(true, true, true, true);
        emit IEIP3009.AuthorizationUsed(alice, nonce);
        vm.expectEmit(true, true, true, true);
        emit IERC20.Transfer(alice, address(recipient), value);
        token.transferWithAuthorization(alice, address(recipient), value, validAfter, validBefore, nonce, v, r, s);

        assertTrue(token.authorizationState(alice, nonce));
        assertEq(token.balanceOf(address(recipient)), value);
    }

    function test_authorizationState_falseThenTrue() public {
        bytes32 nonce = keccak256("nonce-10");
        assertFalse(token.authorizationState(alice, nonce));

        (uint8 v, bytes32 r, bytes32 s) = _signCancelAuthorization(alicePk, alice, nonce);

        vm.prank(relayer);
        token.cancelAuthorization(alice, nonce, v, r, s);

        assertTrue(token.authorizationState(alice, nonce));
    }
}
