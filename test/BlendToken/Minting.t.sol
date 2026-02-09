// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";

import {BlendToken} from "src/BlendToken.sol";
import {BlendTokenBase} from "test/BlendToken/Base.t.sol";

contract BlendTokenMintingTest is BlendTokenBase {
    function test_mint_increasesSupplyAndEmitsTransfer() public {
        uint256 amount = 500 * UNIT;

        vm.prank(minter);
        vm.expectEmit(true, true, true, true);
        emit IERC20.Transfer(address(0), alice, amount);
        token.mint(alice, amount);

        assertEq(token.balanceOf(alice), amount);
        assertEq(token.totalSupply(), INITIAL_SUPPLY + amount);
    }

    function test_mintBatch_mintsAllRecipients() public {
        address[] memory recipients = new address[](2);
        recipients[0] = alice;
        recipients[1] = bob;

        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 100 * UNIT;
        amounts[1] = 200 * UNIT;

        vm.prank(minter);
        token.mintBatch(recipients, amounts);

        assertEq(token.balanceOf(alice), 100 * UNIT);
        assertEq(token.balanceOf(bob), 200 * UNIT);
        assertEq(token.totalSupply(), INITIAL_SUPPLY + 300 * UNIT);
    }

    function test_mint_upToCap_succeeds() public {
        uint256 remaining = token.cap() - token.totalSupply();
        vm.prank(minter);
        token.mint(alice, remaining);
        assertEq(token.totalSupply(), token.cap());
    }

    function test_nonMinter_mint_reverts() public {
        bytes32 role = token.MINTER_ROLE();
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, alice, role));
        token.mint(alice, 1);
    }

    function test_nonMinter_mintBatch_reverts() public {
        bytes32 role = token.MINTER_ROLE();
        address[] memory recipients = new address[](1);
        recipients[0] = alice;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1;

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, bob, role));
        token.mintBatch(recipients, amounts);
    }

    function test_mint_zeroAddress_reverts() public {
        vm.prank(minter);
        vm.expectRevert(BlendToken.ZeroAddress.selector);
        token.mint(address(0), 1);
    }

    function test_mintBatch_zeroAddress_reverts() public {
        address[] memory recipients = new address[](2);
        recipients[0] = alice;
        recipients[1] = address(0);

        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 1;
        amounts[1] = 1;

        vm.prank(minter);
        vm.expectRevert(BlendToken.ZeroAddress.selector);
        token.mintBatch(recipients, amounts);
    }

    function test_mintBatch_lengthMismatch_reverts() public {
        address[] memory recipients = new address[](1);
        recipients[0] = alice;

        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 1;
        amounts[1] = 2;

        vm.prank(minter);
        vm.expectRevert(BlendToken.ArrayLengthMismatch.selector);
        token.mintBatch(recipients, amounts);
    }

    function test_mint_overCap_reverts() public {
        uint256 remaining = token.cap() - token.totalSupply();
        uint256 amount = remaining + 1;
        uint256 cap = token.cap();
        uint256 attemptedSupply = token.totalSupply() + amount;

        vm.prank(minter);
        vm.expectRevert(abi.encodeWithSelector(BlendToken.CapExceeded.selector, cap, attemptedSupply));
        token.mint(alice, amount);
    }

    function test_mintBatch_overCap_reverts() public {
        uint256 remaining = token.cap() - token.totalSupply();
        address[] memory recipients = new address[](2);
        recipients[0] = alice;
        recipients[1] = bob;

        uint256[] memory amounts = new uint256[](2);
        amounts[0] = remaining;
        amounts[1] = 1;

        uint256 cap = token.cap();
        uint256 attemptedSupply = token.totalSupply() + remaining + 1;

        vm.prank(minter);
        vm.expectRevert(abi.encodeWithSelector(BlendToken.CapExceeded.selector, cap, attemptedSupply));
        token.mintBatch(recipients, amounts);
    }

    function test_burn_reducesSupplyAndBalance() public {
        uint256 amount = 10 * UNIT;

        vm.prank(deployer);
        vm.expectEmit(true, true, true, true);
        emit IERC20.Transfer(deployer, address(0), amount);
        token.burn(amount);

        assertEq(token.balanceOf(deployer), INITIAL_SUPPLY - amount);
        assertEq(token.totalSupply(), INITIAL_SUPPLY - amount);
    }

    function test_burnFrom_spendsAllowanceAndBurns() public {
        uint256 amount = 25 * UNIT;
        _mintTo(alice, amount);

        vm.prank(alice);
        token.approve(bob, amount);

        vm.prank(bob);
        vm.expectEmit(true, true, true, true);
        emit IERC20.Transfer(alice, address(0), amount);
        token.burnFrom(alice, amount);

        assertEq(token.allowance(alice, bob), 0);
        assertEq(token.balanceOf(alice), 0);
    }

    function test_burnFrom_withoutAllowance_reverts() public {
        uint256 amount = 5 * UNIT;
        _mintTo(alice, amount);

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(IERC20Errors.ERC20InsufficientAllowance.selector, bob, 0, amount));
        token.burnFrom(alice, amount);
    }
}
