// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
Quickstart
- Run tests: `forge test`
- Deploy:
  export BLEND_CAP=1000000e18
  forge script script/DeployBlendToken.s.sol:DeployBlendToken --rpc-url <RPC_URL> --private-key <PRIVATE_KEY> --broadcast

EIP-3009 typed-data example:
Primary type: TransferWithAuthorization
Fields: from, to, value, validAfter, validBefore, nonce
Domain: name="BLEND", version="1", chainId=<chainId>, verifyingContract=<token>
Example call:
  transferWithAuthorization(
    from, to, value, validAfter, validBefore, nonce, v, r, s
  )
*/

import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";

import {IEIP3009} from "./interfaces/IEIP3009.sol";

/// @title BLEND ERC-20 Token with EIP-2612 Permit and EIP-3009 authorizations
/// @notice Production-grade token with role-based minting and pausing.
contract BlendToken is ERC20, ERC20Permit, AccessControl, Pausable, IEIP3009 {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    bytes32 private constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH = keccak256(
        "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );

    bytes32 private constant RECEIVE_WITH_AUTHORIZATION_TYPEHASH = keccak256(
        "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );

    bytes32 private constant CANCEL_AUTHORIZATION_TYPEHASH =
        keccak256("CancelAuthorization(address authorizer,bytes32 nonce)");

    uint256 public immutable CAP;

    mapping(address => mapping(bytes32 => bool)) private _authorizationState;

    error CapExceeded(uint256 cap, uint256 attemptedSupply);
    error AuthorizationAlreadyUsed(address authorizer, bytes32 nonce);
    error AuthorizationNotYetValid(uint256 validAfter);
    error AuthorizationExpired(uint256 validBefore);
    error InvalidSignature();
    error InvalidPayee(address expected, address actual);
    error UnsafeRecipient(address recipient);
    error ZeroAddress();

    /// @notice Create BLEND token with a fixed cap.
    /// @param cap_ Maximum total supply (must be > 0).
    constructor(uint256 cap_) ERC20("BLEND", "BLEND") ERC20Permit("BLEND") {
        if (cap_ == 0) revert CapExceeded(0, 0);
        CAP = cap_;

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(MINTER_ROLE, msg.sender);
        _grantRole(PAUSER_ROLE, msg.sender);
    }

    /// @notice Mint tokens to a recipient, respecting the cap.
    /// @param to Recipient address.
    /// @param amount Amount to mint.
    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) whenNotPaused {
        if (to == address(0)) revert ZeroAddress();
        uint256 newSupply = totalSupply() + amount;
        if (newSupply > CAP) revert CapExceeded(CAP, newSupply);
        _mint(to, amount);
    }

    /// @notice Pause all transfers and approvals.
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /// @notice Unpause all transfers and approvals.
    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    /// @inheritdoc IEIP3009
    function authorizationState(address authorizer, bytes32 nonce) public view returns (bool) {
        return _authorizationState[authorizer][nonce];
    }

    /// @inheritdoc IEIP3009
    /// @dev Contract recipients must call this function themselves; otherwise use receiveWithAuthorization.
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
    ) external whenNotPaused {
        if (to.code.length > 0 && to != msg.sender) revert UnsafeRecipient(to);
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
        _transfer(from, to, value);
    }

    /// @inheritdoc IEIP3009
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
    ) external whenNotPaused {
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
        _transfer(from, to, value);
    }

    /// @inheritdoc IEIP3009
    function cancelAuthorization(address authorizer, bytes32 nonce, uint8 v, bytes32 r, bytes32 s) external {
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

    /// @inheritdoc ERC20
    function approve(address spender, uint256 value) public override whenNotPaused returns (bool) {
        return super.approve(spender, value);
    }

    /// @inheritdoc ERC20Permit
    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s)
        public
        override
        whenNotPaused
    {
        super.permit(owner, spender, value, deadline, v, r, s);
    }

    /// @dev Prevent transfers and mints/burns while paused.
    function _update(address from, address to, uint256 value) internal override whenNotPaused {
        super._update(from, to, value);
    }

    function _requireValidAuthorization(address authorizer, bytes32 nonce, uint256 validAfter, uint256 validBefore)
        internal
        view
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

    function _requireValidSignature(address signer, bytes32 digest, uint8 v, bytes32 r, bytes32 s) internal view {
        bytes memory signature = abi.encodePacked(r, s, v);
        if (!SignatureChecker.isValidSignatureNow(signer, digest, signature)) {
            revert InvalidSignature();
        }
    }

    function _useAuthorization(address authorizer, bytes32 nonce) internal {
        _authorizationState[authorizer][nonce] = true;
        emit AuthorizationUsed(authorizer, nonce);
    }
}
