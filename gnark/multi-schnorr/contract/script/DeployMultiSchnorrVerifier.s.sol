// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {MultischnorrVerifier} from "../src/MultischnorrVerifier.sol";

contract DeployMultischnorr is Script {
    function run(uint256 threshold, uint256 merkleRoot) external {
        vm.startBroadcast();
        address owner = tx.origin;
        MultischnorrVerifier verifier = new MultischnorrVerifier(
            threshold,
            merkleRoot,
            owner
        );
        vm.stopBroadcast();

        console2.log("MultischnorrVerifier deployed at:", address(verifier));
        console2.log("owner:", owner);
    }
}
