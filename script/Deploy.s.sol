// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";

import {BlendToken} from "../src/BlendToken.sol";

/// @notice Deploys the BLEND token using a cap provided via the BLEND_CAP env var.
contract Deploy is Script {
    function run() external returns (BlendToken token) {
        uint256 cap = vm.envUint("BLEND_CAP");

        vm.startBroadcast();
        token = new BlendToken(cap);
        vm.stopBroadcast();
    }
}
