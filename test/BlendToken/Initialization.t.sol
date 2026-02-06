// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {BlendToken} from "src/BlendToken.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract BlendTokenInitializationTest is Test {
    bytes32 internal constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    function _deploy(
        string memory name,
        string memory symbol,
        uint256 cap,
        uint256 initialSupply,
        address initialRecipient
    ) internal returns (BlendToken) {
        return new BlendToken(name, symbol, cap, initialSupply, initialRecipient);
    }

    function test_constructor_setsMetadataCapAndRoles() public {
        address deployer = makeAddr("deployer");
        vm.startPrank(deployer);
        BlendToken token = _deploy("Blend Token", "BLEND", 1_000_000e18, 0, address(0));
        vm.stopPrank();

        assertEq(token.name(), "Blend Token");
        assertEq(token.symbol(), "BLEND");
        assertEq(token.CAP(), 1_000_000e18);

        assertTrue(token.hasRole(token.DEFAULT_ADMIN_ROLE(), deployer));
        assertTrue(token.hasRole(token.MINTER_ROLE(), deployer));

        bytes32 expectedDomain = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("Blend Token")),
                keccak256(bytes("1")),
                block.chainid,
                address(token)
            )
        );
        assertEq(token.DOMAIN_SEPARATOR(), expectedDomain);
    }

    function test_constructor_initialSupply_mintsToRecipient() public {
        address deployer = makeAddr("deployer");
        address recipient = makeAddr("recipient");
        uint256 initialSupply = 500e18;

        vm.startPrank(deployer);
        vm.expectEmit(true, true, true, true);
        emit IERC20.Transfer(address(0), recipient, initialSupply);
        BlendToken token = _deploy("Blend Token", "BLEND", 1_000_000e18, initialSupply, recipient);
        vm.stopPrank();

        assertEq(token.totalSupply(), initialSupply);
        assertEq(token.balanceOf(recipient), initialSupply);
    }

    function test_constructor_capZero_reverts() public {
        vm.expectRevert(abi.encodeWithSelector(BlendToken.CapExceeded.selector, 0, 0));
        _deploy("Blend Token", "BLEND", 0, 0, address(0));
    }

    function test_constructor_initialRecipientZero_revertsWhenSupplyNonZero() public {
        vm.expectRevert(BlendToken.ZeroAddress.selector);
        _deploy("Blend Token", "BLEND", 1_000_000e18, 1e18, address(0));
    }

    function test_constructor_initialSupplyAboveCap_reverts() public {
        vm.expectRevert(abi.encodeWithSelector(BlendToken.CapExceeded.selector, 100e18, 101e18));
        _deploy("Blend Token", "BLEND", 100e18, 101e18, makeAddr("recipient"));
    }

    function test_constructor_initialSupplyEqualsCap_succeeds() public {
        address recipient = makeAddr("recipient");
        BlendToken token = _deploy("Blend Token", "BLEND", 100e18, 100e18, recipient);
        assertEq(token.totalSupply(), 100e18);
        assertEq(token.balanceOf(recipient), 100e18);
    }

    function test_constructor_zeroSupply_allowsZeroRecipient() public {
        BlendToken token = _deploy("Blend Token", "BLEND", 100e18, 0, address(0));
        assertEq(token.totalSupply(), 0);
        assertEq(token.balanceOf(address(0)), 0);
    }
}
