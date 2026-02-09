// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {Upgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";

import {BlendToken} from "../src/BlendToken.sol";

/// @notice Deploys the Fluent (BLEND) token as a UUPS proxy.
contract DeployBlendToken is Script {
    function run() external returns (address proxy, address implementation) {
        string memory name = "Fluent";
        string memory symbol = "BLEND";
        uint256 cap = 1_000_000e18;
        uint256 initialSupply = 0;
        address initialRecipient = address(0);
        address admin = msg.sender;

        vm.startBroadcast();

        proxy = Upgrades.deployUUPSProxy(
            "BlendToken.sol:BlendToken",
            abi.encodeCall(BlendToken.initialize, (name, symbol, cap, initialSupply, initialRecipient, admin))
        );

        implementation = Upgrades.getImplementationAddress(proxy);

        console.log("Proxy deployed at:", proxy);
        console.log("Implementation deployed at:", implementation);

        vm.stopBroadcast();
    }
}
