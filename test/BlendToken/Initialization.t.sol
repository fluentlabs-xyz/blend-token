// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {BlendToken} from "src/BlendToken.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract BlendTokenInitializationTest is Test {
    bytes32 internal constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    function _deployProxy(
        BlendToken implementation,
        string memory name,
        string memory symbol,
        uint256 cap,
        uint256 initialSupply,
        address initialRecipient,
        address admin
    ) internal returns (BlendToken token) {
        bytes memory initData = abi.encodeCall(
            BlendToken.initialize, (name, symbol, cap, initialSupply, initialRecipient, admin)
        );
        address proxy = address(new ERC1967Proxy(address(implementation), initData));
        return BlendToken(proxy);
    }

    function _deploy(
        string memory name,
        string memory symbol,
        uint256 cap,
        uint256 initialSupply,
        address initialRecipient,
        address admin
    ) internal returns (BlendToken token) {
        BlendToken implementation = new BlendToken();
        return _deployProxy(implementation, name, symbol, cap, initialSupply, initialRecipient, admin);
    }

    function test_initialize_setsMetadataCapAndRoles() public {
        address deployer = makeAddr("deployer");
        vm.startPrank(deployer);
        BlendToken token = _deploy("Fluent", "BLEND", 1_000_000e18, 0, address(0), deployer);
        vm.stopPrank();

        assertEq(token.name(), "Fluent");
        assertEq(token.symbol(), "BLEND");
        assertEq(token.cap(), 1_000_000e18);
        assertEq(token.mintedTotal(), 0);

        assertTrue(token.hasRole(token.DEFAULT_ADMIN_ROLE(), deployer));
        assertTrue(token.hasRole(token.MINTER_ROLE(), deployer));

        bytes32 expectedDomain = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH, keccak256(bytes("Fluent")), keccak256(bytes("1")), block.chainid, address(token)
            )
        );
        assertEq(token.DOMAIN_SEPARATOR(), expectedDomain);
    }

    function test_initialize_initialSupply_mintsToRecipient() public {
        address deployer = makeAddr("deployer");
        address recipient = makeAddr("recipient");
        uint256 initialSupply = 500e18;

        vm.startPrank(deployer);
        vm.expectEmit(true, true, true, true);
        emit IERC20.Transfer(address(0), recipient, initialSupply);
        BlendToken token = _deploy("Fluent", "BLEND", 1_000_000e18, initialSupply, recipient, deployer);
        vm.stopPrank();

        assertEq(token.totalSupply(), initialSupply);
        assertEq(token.balanceOf(recipient), initialSupply);
        assertEq(token.mintedTotal(), initialSupply);
    }

    function test_initialize_capZero_reverts() public {
        address deployer = makeAddr("deployer");
        BlendToken implementation = new BlendToken();
        vm.expectRevert(BlendToken.InvalidCap.selector);
        _deployProxy(implementation, "Fluent", "BLEND", 0, 0, address(0), deployer);
    }

    function test_initialize_adminZero_reverts() public {
        BlendToken implementation = new BlendToken();
        vm.expectRevert(BlendToken.ZeroAddress.selector);
        _deployProxy(implementation, "Fluent", "BLEND", 1_000_000e18, 0, address(0), address(0));
    }

    function test_initialize_initialRecipientZero_revertsWhenSupplyNonZero() public {
        address deployer = makeAddr("deployer");
        BlendToken implementation = new BlendToken();
        vm.expectRevert(BlendToken.ZeroAddress.selector);
        _deployProxy(implementation, "Fluent", "BLEND", 1_000_000e18, 1e18, address(0), deployer);
    }

    function test_initialize_initialSupplyAboveCap_reverts() public {
        address deployer = makeAddr("deployer");
        BlendToken implementation = new BlendToken();
        vm.expectRevert(abi.encodeWithSelector(BlendToken.CapExceeded.selector, 100e18, 101e18));
        _deployProxy(implementation, "Fluent", "BLEND", 100e18, 101e18, makeAddr("recipient"), deployer);
    }

    function test_initialize_initialSupplyEqualsCap_succeeds() public {
        address deployer = makeAddr("deployer");
        address recipient = makeAddr("recipient");
        BlendToken token = _deploy("Fluent", "BLEND", 100e18, 100e18, recipient, deployer);
        assertEq(token.totalSupply(), 100e18);
        assertEq(token.balanceOf(recipient), 100e18);
        assertEq(token.mintedTotal(), 100e18);
    }

    function test_initialize_zeroSupply_allowsZeroRecipient() public {
        address deployer = makeAddr("deployer");
        BlendToken token = _deploy("Fluent", "BLEND", 100e18, 0, address(0), deployer);
        assertEq(token.totalSupply(), 0);
        assertEq(token.balanceOf(address(0)), 0);
        assertEq(token.mintedTotal(), 0);
    }
}
