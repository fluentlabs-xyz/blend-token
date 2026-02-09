// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

import {BlendToken} from "src/BlendToken.sol";
import {BlendTokenBase} from "test/BlendToken/Base.t.sol";

contract BlendTokenV2Mock is BlendToken {
    function newFeature() external pure returns (string memory) {
        return "V2 feature";
    }
}

contract BlendTokenUpgradesTest is BlendTokenBase {
    BlendTokenV2Mock internal v2Implementation;

    function setUp() public override {
        super.setUp();
        v2Implementation = new BlendTokenV2Mock();
    }

    function test_upgrade_onlyAdmin_succeeds() public {
        vm.prank(deployer);
        token.upgradeToAndCall(address(v2Implementation), "");

        assertEq(BlendTokenV2Mock(address(token)).newFeature(), "V2 feature");
    }

    function test_upgrade_nonAdmin_reverts() public {
        bytes32 upgraderRole = token.UPGRADER_ROLE();

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, alice, upgraderRole)
        );
        token.upgradeToAndCall(address(v2Implementation), "");
    }

    function test_upgrade_preservesState() public {
        uint256 aliceBalance = 100 * UNIT;
        _mintTo(alice, aliceBalance);

        vm.prank(alice);
        token.approve(bob, 50 * UNIT);

        uint256 totalSupplyBefore = token.totalSupply();
        uint256 capBefore = token.cap();

        vm.prank(deployer);
        token.upgradeToAndCall(address(v2Implementation), "");

        assertEq(token.balanceOf(alice), aliceBalance);
        assertEq(token.allowance(alice, bob), 50 * UNIT);
        assertEq(token.totalSupply(), totalSupplyBefore);
        assertEq(token.cap(), capBefore);
        assertTrue(token.hasRole(token.DEFAULT_ADMIN_ROLE(), deployer));
        assertTrue(token.hasRole(token.MINTER_ROLE(), minter));
    }

    function test_implementation_cannotBeInitialized() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        implementation.initialize("Test", "TST", 1000e18, 0, address(0), deployer);
    }

    function test_proxy_cannotReinitialize() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        token.initialize("Test", "TST", 1000e18, 0, address(0), deployer);
    }

    function test_version_returnsCorrectValue() public view {
        assertEq(token.VERSION(), 1);
    }
}
