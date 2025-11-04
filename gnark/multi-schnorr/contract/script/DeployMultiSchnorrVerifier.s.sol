// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {MultiSchnorrVerifier} from "../src/MultiSchnorrVerifier.sol";
import {Verifier} from "../src/Verifier.sol";

contract DeployMultischnorr is Script {
    function run(uint256 threshold, uint256 merkleRoot) external {
        vm.startBroadcast();
        address owner = tx.origin;
        Verifier ver = new Verifier();
        MultiSchnorrVerifier verifier = new MultiSchnorrVerifier(
            ver,
            threshold,
            merkleRoot,
            owner
        );
        vm.stopBroadcast();

        console2.log("Verifier deployed at:", address(ver));
        console2.log("MultischnorrVerifier deployed at:", address(verifier));
        console2.log("owner:", owner);
    }
}
