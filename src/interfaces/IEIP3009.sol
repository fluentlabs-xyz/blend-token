// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IEIP3009
/// @notice Interface for EIP-3009 gasless token transfers.
interface IEIP3009 {
    /// @notice Emitted when an authorization is used.
    event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce);

    /// @notice Emitted when an authorization is canceled.
    event AuthorizationCanceled(address indexed authorizer, bytes32 indexed nonce);

    /// @notice Transfer tokens based on a signed authorization.
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
    ) external;

    /// @notice Transfer tokens to the caller (payee) based on a signed authorization.
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
    ) external;

    /// @notice Cancel a signed authorization.
    function cancelAuthorization(
        address authorizer,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;

    /// @notice Return true if the authorization is used or canceled.
    function authorizationState(address authorizer, bytes32 nonce) external view returns (bool);
}
