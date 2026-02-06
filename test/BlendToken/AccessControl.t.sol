// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

import {BlendTokenBase} from "test/BlendToken/Base.t.sol";

contract BlendTokenAccessControlTest is BlendTokenBase {
    function test_adminCanGrantAndRevokeMinterRole() public {
        bytes32 role = token.MINTER_ROLE();

        vm.prank(deployer);
        vm.expectEmit(true, true, true, true);
        emit IAccessControl.RoleGranted(role, alice, deployer);
        token.grantRole(role, alice);
        assertTrue(token.hasRole(role, alice));

        vm.prank(deployer);
        vm.expectEmit(true, true, true, true);
        emit IAccessControl.RoleRevoked(role, alice, deployer);
        token.revokeRole(role, alice);
        assertFalse(token.hasRole(role, alice));
    }

    function test_nonAdminCannotGrantOrRevokeRoles() public {
        bytes32 role = token.MINTER_ROLE();
        bytes32 adminRole = token.DEFAULT_ADMIN_ROLE();

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, alice, adminRole)
        );
        token.grantRole(role, alice);

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, alice, adminRole)
        );
        token.revokeRole(role, minter);
    }

    function test_onlyMinterCanMint() public {
        bytes32 role = token.MINTER_ROLE();
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, alice, role));
        token.mint(alice, 1);
    }

    function test_renounceRole_requiresConfirmation() public {
        bytes32 role = token.MINTER_ROLE();

        vm.startPrank(minter);
        vm.expectRevert(IAccessControl.AccessControlBadConfirmation.selector);
        token.renounceRole(role, alice);

        vm.expectEmit(true, true, true, true);
        emit IAccessControl.RoleRevoked(role, minter, minter);
        token.renounceRole(role, minter);
        vm.stopPrank();

        assertFalse(token.hasRole(role, minter));
    }

    function test_grantRole_idempotent() public {
        bytes32 role = token.MINTER_ROLE();
        vm.prank(deployer);
        token.grantRole(role, minter);
        assertTrue(token.hasRole(role, minter));
    }

    function test_revokeRole_missing_isNoop() public {
        bytes32 role = token.MINTER_ROLE();
        vm.prank(deployer);
        token.revokeRole(role, alice);
        assertFalse(token.hasRole(role, alice));
    }
}
