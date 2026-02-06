// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

import {BlendToken} from "src/BlendToken.sol";
import {BlendTokenBase} from "test/BlendToken/Base.t.sol";

contract BlendTokenMulticallTest is BlendTokenBase {
    function test_multicall_batchesCalls() public {
        bytes[] memory data = new bytes[](2);
        data[0] = abi.encodeWithSelector(token.mint.selector, alice, 10 * UNIT);
        data[1] = abi.encodeWithSelector(token.mint.selector, bob, 20 * UNIT);

        vm.prank(minter);
        bytes[] memory results = token.multicall(data);

        assertEq(results.length, 2);
        assertEq(token.balanceOf(alice), 10 * UNIT);
        assertEq(token.balanceOf(bob), 20 * UNIT);
    }

    function test_multicall_revertsOnUnauthorizedSubcall() public {
        bytes[] memory data = new bytes[](1);
        data[0] = abi.encodeWithSelector(token.mint.selector, alice, 1);

        bytes32 role = token.MINTER_ROLE();
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, alice, role));
        token.multicall(data);
    }

    function test_multicall_revertsAndRollsBackOnFailure() public {
        bytes[] memory data = new bytes[](2);
        data[0] = abi.encodeWithSelector(token.mint.selector, alice, 10 * UNIT);
        data[1] = abi.encodeWithSelector(token.mint.selector, address(0), 1);

        uint256 aliceBefore = token.balanceOf(alice);

        vm.prank(minter);
        vm.expectRevert(BlendToken.ZeroAddress.selector);
        token.multicall(data);

        assertEq(token.balanceOf(alice), aliceBefore);
    }

    function test_multicall_empty_returnsEmpty() public {
        bytes[] memory data = new bytes[](0);
        vm.prank(alice);
        bytes[] memory results = token.multicall(data);
        assertEq(results.length, 0);
    }
}
