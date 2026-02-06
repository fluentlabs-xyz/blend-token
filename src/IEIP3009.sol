// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IEIP3009
/// @notice Interface for EIP-3009 gasless token transfers.
interface IEIP3009 {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                              EVENTS                            */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Emitted when an authorization is used.
    /// @dev Topic0: 0x98de503528ee59b575ef0c0a2576a82497bfc029a5685b209e9ec333479b10a5
    ///      "AuthorizationUsed(address,bytes32)"
    event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce);

    /// @notice Emitted when an authorization is canceled.
    /// @dev Topic0: 0x1cdd46ff242716cdaa72d159d339a485b3438398348d68f09d7c8c0a59353d81
    ///      "AuthorizationCanceled(address,bytes32)"
    event AuthorizationCanceled(address indexed authorizer, bytes32 indexed nonce);

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                             EXTERNAL                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Transfer tokens based on a signed authorization.
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
    ) external;

    /// @notice Transfer tokens to the caller (payee) based on a signed authorization.
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
    ) external;

    /// @notice Cancel a signed authorization.
    /// @dev Selector: 0x5a049a70 — "cancelAuthorization(address,bytes32,uint8,bytes32,bytes32)"
    function cancelAuthorization(address authorizer, bytes32 nonce, uint8 v, bytes32 r, bytes32 s) external;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                               VIEW                             */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Return true if the authorization is used or canceled.
    /// @dev Selector: 0xe94a0102 — "authorizationState(address,bytes32)"
    function authorizationState(address authorizer, bytes32 nonce) external view returns (bool);
}
