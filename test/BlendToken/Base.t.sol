// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {BlendToken} from "src/BlendToken.sol";
import {Signatures} from "test/fixtures/Signatures.sol";

abstract contract BlendTokenBase is Test {
    BlendToken internal token;
    BlendToken internal implementation;
    address internal proxy;

    uint256 internal constant CAP = 1_000_000e18;
    uint256 internal constant INITIAL_SUPPLY = 100_000e18;
    uint256 internal constant UNIT = 1e18;

    uint256 internal deployerPk = 0xA11CE;
    uint256 internal minterPk = 0xB0B;
    uint256 internal alicePk = 0xA1;
    uint256 internal bobPk = 0xB2;
    uint256 internal charliePk = 0xC3;
    uint256 internal relayerPk = 0xD4;

    address internal deployer;
    address internal minter;
    address internal alice;
    address internal bob;
    address internal charlie;
    address internal relayer;

    function setUp() public virtual {
        deployer = vm.addr(deployerPk);
        minter = vm.addr(minterPk);
        alice = vm.addr(alicePk);
        bob = vm.addr(bobPk);
        charlie = vm.addr(charliePk);
        relayer = vm.addr(relayerPk);

        vm.startPrank(deployer);
        implementation = new BlendToken();

        bytes memory initData =
            abi.encodeCall(BlendToken.initialize, ("Fluent", "BLEND", CAP, INITIAL_SUPPLY, deployer, deployer));
        proxy = address(new ERC1967Proxy(address(implementation), initData));
        token = BlendToken(proxy);

        token.grantRole(token.MINTER_ROLE(), minter);
        vm.stopPrank();
    }

    function _mintTo(address to, uint256 amount) internal {
        vm.prank(minter);
        token.mint(to, amount);
    }

    function _signPermit(
        uint256 ownerPk,
        address owner,
        address spender,
        uint256 value,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 digest = Signatures.permitDigest(token.DOMAIN_SEPARATOR(), owner, spender, value, nonce, deadline);
        (v, r, s) = vm.sign(ownerPk, digest);
    }

    function _signTransferWithAuthorization(
        uint256 authorizerPk,
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce
    ) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 digest = Signatures.transferWithAuthorizationDigest(
            token.DOMAIN_SEPARATOR(), from, to, value, validAfter, validBefore, nonce
        );
        (v, r, s) = vm.sign(authorizerPk, digest);
    }

    function _signReceiveWithAuthorization(
        uint256 authorizerPk,
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce
    ) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 digest = Signatures.receiveWithAuthorizationDigest(
            token.DOMAIN_SEPARATOR(), from, to, value, validAfter, validBefore, nonce
        );
        (v, r, s) = vm.sign(authorizerPk, digest);
    }

    function _signCancelAuthorization(uint256 authorizerPk, address authorizer, bytes32 nonce)
        internal
        view
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        bytes32 digest = Signatures.cancelAuthorizationDigest(token.DOMAIN_SEPARATOR(), authorizer, nonce);
        (v, r, s) = vm.sign(authorizerPk, digest);
    }
}
