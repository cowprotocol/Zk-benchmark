// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {CombAuctionVerifier} from "../src/CombAuctionVerifier.sol";
import {Verifier} from "../src/Verifier.sol";

contract DeployCombAuctionVerifier is Script {
    function run() external {
        vm.startBroadcast();
        address owner = tx.origin;
        Verifier ver = new Verifier();
        CombAuctionVerifier verifier = new CombAuctionVerifier(ver, owner);
        vm.stopBroadcast();

        console2.log("Verifier deployed at:", address(ver));
        console2.log("CombAuctionVerifier deployed at:", address(verifier));
        console2.log("owner:", owner);
    }
}
