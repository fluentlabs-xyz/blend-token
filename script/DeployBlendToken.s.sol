// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";

import {BlendToken} from "../src/BlendToken.sol";

/// @notice Deploys the BLEND token using env vars for configuration.
/// @dev Required env vars: TOKEN_NAME, TOKEN_SYMBOL, TOKEN_CAP, TOKEN_INITIAL_SUPPLY, TOKEN_INITIAL_RECIPIENT.
contract DeployBlendToken is Script {
    function run() external returns (BlendToken token) {
        string memory name = "BLEND";
        string memory symbol = "BLEND";
        uint256 cap = 1_000_000;
        uint256 initialSupply = 2_000_000;
        address initialRecipient = 0x33a831e42B24D19bf57dF73682B9a3780A0435BA;

        vm.startBroadcast();
        token = new BlendToken(name, symbol, cap, initialSupply, initialRecipient);
        vm.stopBroadcast();
    }
}
