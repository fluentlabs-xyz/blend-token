// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {MulticallUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/MulticallUpgradeable.sol";
import {ERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import {
    ERC20PermitUpgradeable
} from "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20PermitUpgradeable.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";

import {EIP3009Upgradeable} from "./EIP3009Upgradeable.sol";

/// @title Fluent ERC-20 Token (BLEND) with EIP-2612 Permit and EIP-3009 authorizations
/// @notice Production-grade upgradeable token with role-based minting.
/// @dev Uses UUPS proxy pattern for upgradeability.
contract BlendToken is
    Initializable,
    ERC20Upgradeable,
    ERC20PermitUpgradeable,
    AccessControlUpgradeable,
    MulticallUpgradeable,
    UUPSUpgradeable,
    EIP3009Upgradeable
{
    /// @notice Contract version for tracking upgrades.
    /// @dev Selector: 0xffa1ad74 — "VERSION()"
    uint256 public constant VERSION = 1;

    /// @notice Role allowed to mint.
    /// @dev Selector: 0xd5391393 — "MINTER_ROLE()"
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    /// @notice Role allowed to authorize upgrades.
    /// @dev Selector: 0xf72c0d8b — "UPGRADER_ROLE()"
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    /// @dev Maximum total supply (set once during initialization).
    uint256 private _cap;

    /// @dev Storage gap for future upgrades.
    uint256[48] private __gap;

    /// @dev Selector: 0xf480e285 — "CapExceeded(uint256,uint256)"
    error CapExceeded(uint256 cap, uint256 attemptedSupply);
    /// @dev Selector: 0xa24a13a6 — "ArrayLengthMismatch()"
    error ArrayLengthMismatch();
    /// @dev Selector: 0xd92e233d — "ZeroAddress()"
    error ZeroAddress();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initialize the token contract.
    /// @dev Selector: 0x767ab122 — "initialize(string,string,uint256,uint256,address,address)"
    /// @param name_ Token name.
    /// @param symbol_ Token symbol.
    /// @param cap_ Maximum total supply (must be > 0).
    /// @param initialSupply_ Initial supply to mint (0 allowed).
    /// @param initialRecipient_ Recipient of initial supply (required if initialSupply_ > 0).
    /// @param admin_ Address to receive admin and operational roles.
    function initialize(
        string memory name_,
        string memory symbol_,
        uint256 cap_,
        uint256 initialSupply_,
        address initialRecipient_,
        address admin_
    ) public initializer {
        if (cap_ == 0) revert CapExceeded(0, 0);
        if (admin_ == address(0)) revert ZeroAddress();

        __ERC20_init(name_, symbol_);
        __ERC20Permit_init(name_);
        __AccessControl_init();
        __Multicall_init();
        __EIP3009_init();

        _cap = cap_;

        _grantRole(DEFAULT_ADMIN_ROLE, admin_);
        _grantRole(MINTER_ROLE, admin_);
        _grantRole(UPGRADER_ROLE, admin_);

        if (initialSupply_ > 0) {
            if (initialRecipient_ == address(0)) revert ZeroAddress();
            if (initialSupply_ > cap_) revert CapExceeded(cap_, initialSupply_);
            _mint(initialRecipient_, initialSupply_);
        }
    }

    /// @notice Returns the cap on the token's total supply.
    /// @dev Selector: 0x355274ea — "cap()"
    function cap() public view returns (uint256) {
        return _cap;
    }

    /// @notice Mint tokens to a recipient, respecting the cap.
    /// @dev Selector: 0x40c10f19 — "mint(address,uint256)"
    /// @param to Recipient address.
    /// @param amount Amount to mint.
    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
        if (to == address(0)) revert ZeroAddress();
        uint256 newSupply = totalSupply() + amount;
        if (newSupply > _cap) revert CapExceeded(_cap, newSupply);
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
        if (newSupply > _cap) revert CapExceeded(_cap, newSupply);

        for (uint256 i = 0; i < length; i++) {
            _mint(to[i], amounts[i]);
        }
    }

    /// @dev Required by UUPSUpgradeable - restricts upgrades to upgrader role only.
    function _authorizeUpgrade(address newImplementation) internal override onlyRole(UPGRADER_ROLE) {}

    function _hashTypedDataV4(bytes32 structHash)
        internal
        view
        override(EIP712Upgradeable, EIP3009Upgradeable)
        returns (bytes32)
    {
        return super._hashTypedDataV4(structHash);
    }

    function _transferWithAuthorization(address from, address to, uint256 value) internal override {
        _transfer(from, to, value);
    }
}
