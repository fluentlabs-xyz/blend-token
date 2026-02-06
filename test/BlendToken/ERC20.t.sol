// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {StdStorage, stdStorage} from "forge-std/StdStorage.sol";

import {BlendToken} from "src/BlendToken.sol";
import {BlendTokenBase} from "test/BlendToken/Base.t.sol";

contract BlendTokenERC20Test is BlendTokenBase {
    using stdStorage for StdStorage;

    function setUp() public override {
        super.setUp();
        _mintTo(alice, 1_000 * UNIT);
        _mintTo(bob, 500 * UNIT);
    }

    function test_transfer_updatesBalancesAndEmits() public {
        uint256 amount = 100 * UNIT;
        uint256 aliceBefore = token.balanceOf(alice);
        uint256 bobBefore = token.balanceOf(bob);

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit IERC20.Transfer(alice, bob, amount);
        token.transfer(bob, amount);

        assertEq(token.balanceOf(alice), aliceBefore - amount);
        assertEq(token.balanceOf(bob), bobBefore + amount);
    }

    function test_approve_setsAllowanceAndEmits() public {
        uint256 amount = 123 * UNIT;

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit IERC20.Approval(alice, bob, amount);
        token.approve(bob, amount);

        assertEq(token.allowance(alice, bob), amount);
    }

    function test_transferFrom_spendsAllowance() public {
        uint256 amount = 200 * UNIT;

        vm.prank(alice);
        token.approve(bob, amount);

        vm.prank(bob);
        vm.expectEmit(true, true, true, true);
        emit IERC20.Transfer(alice, charlie, amount);
        token.transferFrom(alice, charlie, amount);

        assertEq(token.allowance(alice, bob), 0);
        assertEq(token.balanceOf(charlie), amount);
    }

    function test_transferFrom_withMaxAllowance_doesNotDecrease() public {
        uint256 amount = 10 * UNIT;

        vm.prank(alice);
        token.approve(bob, type(uint256).max);

        vm.prank(bob);
        token.transferFrom(alice, charlie, amount);

        assertEq(token.allowance(alice, bob), type(uint256).max);
    }

    function test_transfer_insufficientBalance_reverts() public {
        uint256 balance = token.balanceOf(alice);
        uint256 amount = balance + 1;

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IERC20Errors.ERC20InsufficientBalance.selector, alice, balance, amount));
        token.transfer(bob, amount);
    }

    function test_transferFrom_insufficientBalance_reverts() public {
        uint256 balance = token.balanceOf(alice);
        uint256 amount = balance + 1;

        vm.prank(alice);
        token.approve(bob, type(uint256).max);

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(IERC20Errors.ERC20InsufficientBalance.selector, alice, balance, amount));
        token.transferFrom(alice, charlie, amount);
    }

    function test_transferFrom_exceedsAllowance_reverts() public {
        uint256 allowance = 10 * UNIT;
        uint256 amount = 11 * UNIT;

        vm.prank(alice);
        token.approve(bob, allowance);

        vm.prank(bob);
        vm.expectRevert(
            abi.encodeWithSelector(IERC20Errors.ERC20InsufficientAllowance.selector, bob, allowance, amount)
        );
        token.transferFrom(alice, charlie, amount);
    }

    function test_transfer_toZero_reverts() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IERC20Errors.ERC20InvalidReceiver.selector, address(0)));
        token.transfer(address(0), 1);
    }

    function test_transfer_fromZero_reverts() public {
        vm.prank(address(0));
        vm.expectRevert(abi.encodeWithSelector(IERC20Errors.ERC20InvalidSender.selector, address(0)));
        token.transfer(alice, 1);
    }

    function test_transferFrom_fromZero_reverts() public {
        uint256 slot =
            stdstore.target(address(token)).sig("allowance(address,address)").with_key(address(0)).with_key(bob).find();
        vm.store(address(token), bytes32(slot), bytes32(type(uint256).max));

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(IERC20Errors.ERC20InvalidSender.selector, address(0)));
        token.transferFrom(address(0), alice, 1);
    }

    function test_approve_fromZero_reverts() public {
        vm.prank(address(0));
        vm.expectRevert(abi.encodeWithSelector(IERC20Errors.ERC20InvalidApprover.selector, address(0)));
        token.approve(bob, 1);
    }

    function test_approve_toZero_reverts() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IERC20Errors.ERC20InvalidSpender.selector, address(0)));
        token.approve(address(0), 1);
    }

    function test_transfer_zeroValue_succeeds() public {
        uint256 aliceBefore = token.balanceOf(alice);
        uint256 bobBefore = token.balanceOf(bob);

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit IERC20.Transfer(alice, bob, 0);
        token.transfer(bob, 0);

        assertEq(token.balanceOf(alice), aliceBefore);
        assertEq(token.balanceOf(bob), bobBefore);
    }

    function test_selfTransfer_noBalanceChange() public {
        uint256 aliceBefore = token.balanceOf(alice);

        vm.prank(alice);
        token.transfer(alice, 10 * UNIT);

        assertEq(token.balanceOf(alice), aliceBefore);
    }
}
