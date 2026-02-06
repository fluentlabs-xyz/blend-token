// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {BlendToken} from "src/BlendToken.sol";
import {EIP3009} from "src/EIP3009.sol";
import {IEIP3009} from "src/IEIP3009.sol";
import {BlendTokenBase} from "test/BlendToken/Base.t.sol";

contract DummyRecipient {
    // Used to prove "recipient contract can be the caller / relayer".
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

    // NOTE: This mock always returns MAGICVALUE (does not validate digest).
    // The test that uses it only asserts the code path supports ERC-1271.
    function isValidSignature(bytes32, bytes memory) external pure returns (bytes4) {
        return MAGICVALUE;
    }
}

contract BlendTokenEIP3009AuthTest is BlendTokenBase {
    function test_transferWithAuthorization_valid_updatesBalancesAndState() public {
        uint256 amount = 100 * UNIT;
        _mintTo(alice, amount);

        uint256 aliceBefore = token.balanceOf(alice);
        uint256 bobBefore = token.balanceOf(bob);

        uint256 validAfter = block.timestamp - 1;
        uint256 validBefore = block.timestamp + 1 days;
        bytes32 nonce = keccak256("nonce-1");

        (uint8 v, bytes32 r, bytes32 s) =
            _signTransferWithAuthorization(alicePk, alice, bob, amount, validAfter, validBefore, nonce);

        vm.prank(relayer);
        vm.expectEmit(true, true, true, true);
        emit IEIP3009.AuthorizationUsed(alice, nonce);
        vm.expectEmit(true, true, true, true);
        emit IERC20.Transfer(alice, bob, amount);
        token.transferWithAuthorization(alice, bob, amount, validAfter, validBefore, nonce, v, r, s);

        assertTrue(token.authorizationState(alice, nonce));
        assertEq(token.balanceOf(alice), aliceBefore - amount);
        assertEq(token.balanceOf(bob), bobBefore + amount);
    }

    function test_receiveWithAuthorization_valid_isPayeeBound_andUpdatesBalancesAndState() public {
        uint256 amount = 50 * UNIT;
        _mintTo(alice, amount);

        uint256 aliceBefore = token.balanceOf(alice);
        uint256 bobBefore = token.balanceOf(bob);

        uint256 validAfter = block.timestamp - 1;
        uint256 validBefore = block.timestamp + 1 days;
        bytes32 nonce = keccak256("nonce-2");

        (uint8 v, bytes32 r, bytes32 s) =
            _signReceiveWithAuthorization(alicePk, alice, bob, amount, validAfter, validBefore, nonce);

        // Only `to` (payee) can execute receiveWithAuthorization
        vm.prank(bob);
        vm.expectEmit(true, true, true, true);
        emit IEIP3009.AuthorizationUsed(alice, nonce);
        vm.expectEmit(true, true, true, true);
        emit IERC20.Transfer(alice, bob, amount);
        token.receiveWithAuthorization(alice, bob, amount, validAfter, validBefore, nonce, v, r, s);

        assertTrue(token.authorizationState(alice, nonce));
        assertEq(token.balanceOf(alice), aliceBefore - amount);
        assertEq(token.balanceOf(bob), bobBefore + amount);
    }

    function test_transferWithAuthorization_erc1271Wallet_valid_path() public {
        uint256 amount = 25 * UNIT;
        MockERC1271Wallet wallet = new MockERC1271Wallet();
        _mintTo(address(wallet), amount);

        uint256 walletBefore = token.balanceOf(address(wallet));
        uint256 bobBefore = token.balanceOf(bob);

        uint256 validAfter = block.timestamp - 1;
        uint256 validBefore = block.timestamp + 1 days;
        bytes32 nonce = keccak256("nonce-erc1271");

        // Signature contents are irrelevant for this mock (always MAGICVALUE).
        uint8 v = 0;
        bytes32 r = bytes32(uint256(1));
        bytes32 s = bytes32(uint256(2));

        vm.prank(relayer);
        vm.expectEmit(true, true, true, true);
        emit IEIP3009.AuthorizationUsed(address(wallet), nonce);
        vm.expectEmit(true, true, true, true);
        emit IERC20.Transfer(address(wallet), bob, amount);
        token.transferWithAuthorization(address(wallet), bob, amount, validAfter, validBefore, nonce, v, r, s);

        assertTrue(token.authorizationState(address(wallet), nonce));
        assertEq(token.balanceOf(address(wallet)), walletBefore - amount);
        assertEq(token.balanceOf(bob), bobBefore + amount);
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
        uint256 amount = 10 * UNIT;
        _mintTo(alice, amount);

        uint256 validAfter = block.timestamp - 1;
        uint256 validBefore = block.timestamp + 1 days;
        bytes32 nonce = keccak256("nonce-4");

        (uint8 v, bytes32 r, bytes32 s) =
            _signTransferWithAuthorization(alicePk, alice, bob, amount, validAfter, validBefore, nonce);

        vm.prank(relayer);
        token.transferWithAuthorization(alice, bob, amount, validAfter, validBefore, nonce, v, r, s);

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(EIP3009.AuthorizationAlreadyUsed.selector, alice, nonce));
        token.transferWithAuthorization(alice, bob, amount, validAfter, validBefore, nonce, v, r, s);
    }

    function test_notYetValid_reverts_whenValidAfterInFuture() public {
        uint256 amount = 10 * UNIT;
        _mintTo(alice, amount);

        uint256 validAfter = block.timestamp + 1;
        uint256 validBefore = block.timestamp + 1 days;
        bytes32 nonce = keccak256("nonce-5");

        (uint8 v, bytes32 r, bytes32 s) =
            _signTransferWithAuthorization(alicePk, alice, bob, amount, validAfter, validBefore, nonce);

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(EIP3009.AuthorizationNotYetValid.selector, validAfter));
        token.transferWithAuthorization(alice, bob, amount, validAfter, validBefore, nonce, v, r, s);
    }

    function test_atValidAfter_reverts_whenValidAfterEqualsNow() public {
        uint256 amount = 10 * UNIT;
        _mintTo(alice, amount);

        // In this implementation, validAfter is exclusive: block.timestamp must be > validAfter.
        uint256 validAfter = block.timestamp;
        uint256 validBefore = block.timestamp + 1 days;
        bytes32 nonce = keccak256("nonce-at-valid-after");

        (uint8 v, bytes32 r, bytes32 s) =
            _signTransferWithAuthorization(alicePk, alice, bob, amount, validAfter, validBefore, nonce);

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(EIP3009.AuthorizationNotYetValid.selector, validAfter));
        token.transferWithAuthorization(alice, bob, amount, validAfter, validBefore, nonce, v, r, s);
    }

    function test_expired_reverts_whenValidBeforeInPast() public {
        vm.warp(100);

        uint256 amount = 10 * UNIT;
        _mintTo(alice, amount);

        uint256 validAfter = block.timestamp - 2;
        uint256 validBefore = block.timestamp - 1;
        bytes32 nonce = keccak256("nonce-6");

        (uint8 v, bytes32 r, bytes32 s) =
            _signTransferWithAuthorization(alicePk, alice, bob, amount, validAfter, validBefore, nonce);

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(EIP3009.AuthorizationExpired.selector, validBefore));
        token.transferWithAuthorization(alice, bob, amount, validAfter, validBefore, nonce, v, r, s);
    }

    function test_atValidBefore_reverts_whenValidBeforeEqualsNow() public {
        uint256 amount = 10 * UNIT;
        _mintTo(alice, amount);

        // In this implementation, validBefore is exclusive: block.timestamp must be < validBefore.
        uint256 validAfter = block.timestamp - 1;
        uint256 validBefore = block.timestamp;
        bytes32 nonce = keccak256("nonce-at-valid-before");

        (uint8 v, bytes32 r, bytes32 s) =
            _signTransferWithAuthorization(alicePk, alice, bob, amount, validAfter, validBefore, nonce);

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(EIP3009.AuthorizationExpired.selector, validBefore));
        token.transferWithAuthorization(alice, bob, amount, validAfter, validBefore, nonce, v, r, s);
    }

    function test_invalidSignature_reverts() public {
        uint256 amount = 10 * UNIT;
        _mintTo(alice, amount);

        uint256 validAfter = block.timestamp - 1;
        uint256 validBefore = block.timestamp + 1 days;
        bytes32 nonce = keccak256("nonce-7");

        (uint8 v, bytes32 r, bytes32 s) =
            _signTransferWithAuthorization(bobPk, alice, bob, amount, validAfter, validBefore, nonce);

        vm.prank(relayer);
        vm.expectRevert(EIP3009.InvalidSignature.selector);
        token.transferWithAuthorization(alice, bob, amount, validAfter, validBefore, nonce, v, r, s);
    }

    function test_receiveWithAuthorization_payeeMismatch_reverts() public {
        uint256 amount = 10 * UNIT;
        _mintTo(alice, amount);

        uint256 validAfter = block.timestamp - 1;
        uint256 validBefore = block.timestamp + 1 days;
        bytes32 nonce = keccak256("nonce-8");

        (uint8 v, bytes32 r, bytes32 s) =
            _signReceiveWithAuthorization(alicePk, alice, bob, amount, validAfter, validBefore, nonce);

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(EIP3009.InvalidPayee.selector, relayer, bob));
        token.receiveWithAuthorization(alice, bob, amount, validAfter, validBefore, nonce, v, r, s);
    }

    function test_cancelAuthorization_thenTransferWithAuthorization_reverts() public {
        uint256 amount = 10 * UNIT;
        _mintTo(alice, amount);

        uint256 validAfter = block.timestamp - 1;
        uint256 validBefore = block.timestamp + 1 days;
        bytes32 nonce = keccak256("nonce-cancel-transfer");

        (uint8 cancelV, bytes32 cancelR, bytes32 cancelS) = _signCancelAuthorization(alicePk, alice, nonce);

        vm.prank(relayer);
        token.cancelAuthorization(alice, nonce, cancelV, cancelR, cancelS);

        (uint8 v, bytes32 r, bytes32 s) =
            _signTransferWithAuthorization(alicePk, alice, bob, amount, validAfter, validBefore, nonce);

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(EIP3009.AuthorizationAlreadyUsed.selector, alice, nonce));
        token.transferWithAuthorization(alice, bob, amount, validAfter, validBefore, nonce, v, r, s);
    }

    function test_cancelAuthorization_thenReceiveWithAuthorization_reverts() public {
        uint256 amount = 10 * UNIT;
        _mintTo(alice, amount);

        uint256 validAfter = block.timestamp - 1;
        uint256 validBefore = block.timestamp + 1 days;
        bytes32 nonce = keccak256("nonce-cancel-receive");

        (uint8 cancelV, bytes32 cancelR, bytes32 cancelS) = _signCancelAuthorization(alicePk, alice, nonce);

        vm.prank(relayer);
        token.cancelAuthorization(alice, nonce, cancelV, cancelR, cancelS);

        (uint8 v, bytes32 r, bytes32 s) =
            _signReceiveWithAuthorization(alicePk, alice, bob, amount, validAfter, validBefore, nonce);

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(EIP3009.AuthorizationAlreadyUsed.selector, alice, nonce));
        token.receiveWithAuthorization(alice, bob, amount, validAfter, validBefore, nonce, v, r, s);
    }

    function test_transferWithAuthorization_contractRecipient_canBeCaller() public {
        uint256 amount = 10 * UNIT;
        _mintTo(alice, amount);

        DummyRecipient recipient = new DummyRecipient();

        uint256 aliceBefore = token.balanceOf(alice);
        uint256 recipientBefore = token.balanceOf(address(recipient));

        uint256 validAfter = block.timestamp - 1;
        uint256 validBefore = block.timestamp + 1 days;
        bytes32 nonce = keccak256("nonce-9");

        (uint8 v, bytes32 r, bytes32 s) =
            _signTransferWithAuthorization(alicePk, alice, address(recipient), amount, validAfter, validBefore, nonce);

        // Prove a contract can act as the relayer/caller.
        vm.prank(relayer);
        vm.expectEmit(true, true, true, true);
        emit IEIP3009.AuthorizationUsed(alice, nonce);
        vm.expectEmit(true, true, true, true);
        emit IERC20.Transfer(alice, address(recipient), amount);
        recipient.callTransferWithAuthorization(
            token, alice, address(recipient), amount, validAfter, validBefore, nonce, v, r, s
        );

        assertTrue(token.authorizationState(alice, nonce));
        assertEq(token.balanceOf(alice), aliceBefore - amount);
        assertEq(token.balanceOf(address(recipient)), recipientBefore + amount);
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
