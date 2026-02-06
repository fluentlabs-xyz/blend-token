// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Multicall} from "@openzeppelin/contracts/utils/Multicall.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

import {EIP3009} from "./EIP3009.sol";

/// @title BLEND ERC-20 Token with EIP-2612 Permit and EIP-3009 authorizations
/// @notice Production-grade token with role-based minting.
contract BlendToken is ERC20, ERC20Permit, AccessControl, Multicall, EIP3009 {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                               ROLES                            */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Selector: 0xd5391393 — "MINTER_ROLE()"
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                              STORAGE                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Selector: 0xec81b483 — "CAP()"
    uint256 public immutable CAP;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                               ERRORS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Selector: 0xf480e285 — "CapExceeded(uint256,uint256)"
    error CapExceeded(uint256 cap, uint256 attemptedSupply);
    /// @dev Selector: 0xa24a13a6 — "ArrayLengthMismatch()"
    error ArrayLengthMismatch();
    /// @dev Selector: 0xd92e233d — "ZeroAddress()"
    error ZeroAddress();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                            CONSTRUCTOR                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Create BLEND token with a fixed cap.
    /// @param cap_ Maximum total supply (must be > 0).
    /// @param initialSupply_ Initial supply to mint (0 allowed).
    /// @param initialRecipient_ Recipient of the initial supply when non-zero.
    constructor(
        string memory name_,
        string memory symbol_,
        uint256 cap_,
        uint256 initialSupply_,
        address initialRecipient_
    ) ERC20(name_, symbol_) ERC20Permit(name_) {
        if (cap_ == 0) revert CapExceeded(0, 0);
        CAP = cap_;

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(MINTER_ROLE, msg.sender);

        if (initialSupply_ > 0) {
            if (initialRecipient_ == address(0)) revert ZeroAddress();
            uint256 newSupply = totalSupply() + initialSupply_;
            if (newSupply > CAP) revert CapExceeded(CAP, newSupply);
            _mint(initialRecipient_, initialSupply_);
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                             EXTERNAL                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Mint tokens to a recipient, respecting the cap.
    /// @dev Selector: 0x40c10f19 — "mint(address,uint256)"
    /// @param to Recipient address.
    /// @param amount Amount to mint.
    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
        if (to == address(0)) revert ZeroAddress();
        uint256 newSupply = totalSupply() + amount;
        if (newSupply > CAP) revert CapExceeded(CAP, newSupply);
        _mint(to, amount);
    }

    /// @notice Mint tokens to many recipients in a single call.
    /// @dev Selector: 0x7c88e3d9 — "mintBatch(address[],uint256[])"
    /// @param to Recipient addresses.
    /// @param amounts Amounts to mint per recipient.
    function mintBatch(address[] calldata to, uint256[] calldata amounts) external onlyRole(MINTER_ROLE) {
        uint256 length = to.length;
        if (length != amounts.length) revert ArrayLengthMismatch();

        uint256 total;
        for (uint256 i = 0; i < length; i++) {
            if (to[i] == address(0)) revert ZeroAddress();
            total += amounts[i];
        }

        uint256 newSupply = totalSupply() + total;
        if (newSupply > CAP) revert CapExceeded(CAP, newSupply);

        for (uint256 i = 0; i < length; i++) {
            _mint(to[i], amounts[i]);
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                             INTERNAL                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function _hashTypedDataV4(bytes32 structHash) internal view override(EIP712, EIP3009) returns (bytes32) {
        return super._hashTypedDataV4(structHash);
    }

    function _transferWithAuthorization(address from, address to, uint256 value) internal override {
        _transfer(from, to, value);
    }
}
