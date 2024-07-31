// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import {Script, console2} from "forge-std/Script.sol";
import {P256Verifier} from "../src/P256Verifier.sol";

/**
 * Deployes P256Verifier at a deterministic CREATE2 address.
 * Combined with fixed compiler settings, this is a reproducible address that
 * can be used as a progressive precompile.
 */
contract DeployScript is Script {
    function setUp() public {}

    function run() public {
        vm.broadcast();
        new P256Verifier{salt: 0}();
    }

    // Disable coverage for this file
    function test() public view {}
}
