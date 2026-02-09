// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {
    ERC20PermitUpgradeable
} from "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20PermitUpgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {BlendTokenBase} from "test/BlendToken/Base.t.sol";
import {Signatures} from "test/fixtures/Signatures.sol";

contract BlendTokenEIP2612PermitTest is BlendTokenBase {
    function test_permit_valid_setsAllowance_andIncrementsNonce() public {
        uint256 value = 123 * UNIT;
        uint256 deadline = block.timestamp + 1 days;
        uint256 nonce = token.nonces(alice);

        (uint8 v, bytes32 r, bytes32 s) = _signPermit(alicePk, alice, bob, value, nonce, deadline);

        vm.prank(relayer);
        vm.expectEmit(true, true, true, true);
        emit IERC20.Approval(alice, bob, value);
        token.permit(alice, bob, value, deadline, v, r, s);

        assertEq(token.allowance(alice, bob), value);
        assertEq(token.nonces(alice), nonce + 1);
    }

    function test_permit_invalidSigner_reverts() public {
        uint256 value = 5 * UNIT;
        uint256 deadline = block.timestamp + 1 days;
        uint256 nonce = token.nonces(alice);

        (uint8 v, bytes32 r, bytes32 s) = _signPermit(bobPk, alice, bob, value, nonce, deadline);

        vm.expectRevert(abi.encodeWithSelector(ERC20PermitUpgradeable.ERC2612InvalidSigner.selector, bob, alice));
        token.permit(alice, bob, value, deadline, v, r, s);
    }

    function test_permit_expired_reverts() public {
        uint256 value = 1 * UNIT;
        uint256 deadline = block.timestamp - 1;
        uint256 nonce = token.nonces(alice);

        (uint8 v, bytes32 r, bytes32 s) = _signPermit(alicePk, alice, bob, value, nonce, deadline);

        vm.expectRevert(abi.encodeWithSelector(ERC20PermitUpgradeable.ERC2612ExpiredSignature.selector, deadline));
        token.permit(alice, bob, value, deadline, v, r, s);
    }

    function test_permit_replay_reverts() public {
        uint256 value = 50 * UNIT;
        uint256 deadline = block.timestamp + 1 days;
        uint256 nonce = token.nonces(alice);

        (uint8 v, bytes32 r, bytes32 s) = _signPermit(alicePk, alice, bob, value, nonce, deadline);

        token.permit(alice, bob, value, deadline, v, r, s);

        uint256 currentNonce = token.nonces(alice);
        bytes32 digest = Signatures.permitDigest(token.DOMAIN_SEPARATOR(), alice, bob, value, currentNonce, deadline);
        address recovered = ECDSA.recover(digest, v, r, s);

        vm.expectRevert(abi.encodeWithSelector(ERC20PermitUpgradeable.ERC2612InvalidSigner.selector, recovered, alice));
        token.permit(alice, bob, value, deadline, v, r, s);
    }
}
