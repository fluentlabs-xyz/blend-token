// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

import {IEIP3009} from "./IEIP3009.sol";

/// @title EIP-3009 Authorization Mixin (Upgradeable)
/// @notice Implements EIP-3009 authorization flows for ERC-20 tokens
abstract contract EIP3009Upgradeable is Initializable, IEIP3009 {
    bytes32 internal constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH = keccak256(
        "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );

    bytes32 internal constant RECEIVE_WITH_AUTHORIZATION_TYPEHASH = keccak256(
        "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );

    bytes32 internal constant CANCEL_AUTHORIZATION_TYPEHASH =
        keccak256("CancelAuthorization(address authorizer,bytes32 nonce)");

    mapping(address => mapping(bytes32 => bool)) private _authorizationState;

    /// @dev Storage gap for future upgrades (reserve slots for new state variables).
    uint256[49] private __gap;

    /// @dev Selector: 0xd309466d — "AuthorizationAlreadyUsed(address,bytes32)"
    error AuthorizationAlreadyUsed(address authorizer, bytes32 nonce);
    /// @dev Selector: 0x7a4df079 — "AuthorizationNotYetValid(uint256)"
    error AuthorizationNotYetValid(uint256 validAfter);
    /// @dev Selector: 0x3d91b05f — "AuthorizationExpired(uint256)"
    error AuthorizationExpired(uint256 validBefore);
    /// @dev Selector: 0x8baa579f — "InvalidSignature()"
    error InvalidSignature();
    /// @dev Selector: 0xfea94442 — "InvalidPayee(address,address)"
    error InvalidPayee(address expected, address actual);

    /// @dev Initializes the EIP3009 module.
    function __EIP3009_init() internal onlyInitializing {
        __EIP3009_init_unchained();
    }

    function __EIP3009_init_unchained() internal onlyInitializing {}

    /// @inheritdoc IEIP3009
    /// @dev Selector: 0xe94a0102 — "authorizationState(address,bytes32)"
    function authorizationState(address authorizer, bytes32 nonce) public view virtual returns (bool) {
        return _authorizationState[authorizer][nonce];
    }

    /// @inheritdoc IEIP3009
    /// @dev Selector: 0xe3ee160e — "transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)"
    function transferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external virtual {
        _requireValidAuthorization(from, nonce, validAfter, validBefore);
        _requireValidSignature(
            from,
            _hashTypedDataV4(
                keccak256(
                    abi.encode(TRANSFER_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce)
                )
            ),
            v,
            r,
            s
        );

        _useAuthorization(from, nonce);
        _transferWithAuthorization(from, to, value);
    }

    /// @inheritdoc IEIP3009
    /// @dev Selector: 0xef55bec6 — "receiveWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)"
    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external virtual {
        if (to != msg.sender) revert InvalidPayee(msg.sender, to);
        _requireValidAuthorization(from, nonce, validAfter, validBefore);
        _requireValidSignature(
            from,
            _hashTypedDataV4(
                keccak256(
                    abi.encode(RECEIVE_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce)
                )
            ),
            v,
            r,
            s
        );

        _useAuthorization(from, nonce);
        _transferWithAuthorization(from, to, value);
    }

    /// @inheritdoc IEIP3009
    /// @dev Selector: 0x5a049a70 — "cancelAuthorization(address,bytes32,uint8,bytes32,bytes32)"
    function cancelAuthorization(address authorizer, bytes32 nonce, uint8 v, bytes32 r, bytes32 s) external virtual {
        if (authorizationState(authorizer, nonce)) {
            revert AuthorizationAlreadyUsed(authorizer, nonce);
        }
        _requireValidSignature(
            authorizer,
            _hashTypedDataV4(keccak256(abi.encode(CANCEL_AUTHORIZATION_TYPEHASH, authorizer, nonce))),
            v,
            r,
            s
        );

        _authorizationState[authorizer][nonce] = true;
        emit AuthorizationCanceled(authorizer, nonce);
    }

    function _requireValidAuthorization(address authorizer, bytes32 nonce, uint256 validAfter, uint256 validBefore)
        internal
        view
        virtual
    {
        if (authorizationState(authorizer, nonce)) {
            revert AuthorizationAlreadyUsed(authorizer, nonce);
        }
        if (block.timestamp <= validAfter) {
            revert AuthorizationNotYetValid(validAfter);
        }
        if (block.timestamp >= validBefore) {
            revert AuthorizationExpired(validBefore);
        }
    }

    function _requireValidSignature(address signer, bytes32 digest, uint8 v, bytes32 r, bytes32 s)
        internal
        view
        virtual
    {
        bytes memory signature = abi.encodePacked(r, s, v);
        if (!SignatureChecker.isValidSignatureNow(signer, digest, signature)) {
            revert InvalidSignature();
        }
    }

    function _useAuthorization(address authorizer, bytes32 nonce) internal virtual {
        _authorizationState[authorizer][nonce] = true;
        emit AuthorizationUsed(authorizer, nonce);
    }

    function _hashTypedDataV4(bytes32 structHash) internal view virtual returns (bytes32);

    function _transferWithAuthorization(address from, address to, uint256 value) internal virtual;
}
