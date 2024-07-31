// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Test, console2} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {P256Verifier} from "../src/P256Verifier.sol";
import {FCL_Elliptic_ZZ} from "./external/FCL_elliptic.sol";

using stdJson for string;

// Wrapper for https://github.com/rdubois-crypto/FreshCryptoLib/blob/master/solidity/src/FCL_elliptic.sol to support the same contract call format
// as our contract for benchmarking.
contract FCLWrapperEIP7212 {
    /**
     * Precompiles don't use a function signature. The first byte of callldata
     * is the first byte of an input argument. In this case:
     *
     * input[  0: 32] = signed data hash
     * input[ 32: 64] = signature r
     * input[ 64: 96] = signature s
     * input[ 96:128] = public key x
     * input[128:160] = public key y
     *
     * result[ 0: 32] = 0x00..00 (invalid) or 0x00..01 (valid)
     *
     * For details, see https://eips.ethereum.org/EIPS/eip-7212
     */
    fallback(bytes calldata input) external returns (bytes memory) {
        if (input.length != 160) {
            return abi.encodePacked(uint256(0));
        }

        bytes32 hash = bytes32(input[0:32]);
        uint256 r = uint256(bytes32(input[32:64]));
        uint256 s = uint256(bytes32(input[64:96]));
        uint256 x = uint256(bytes32(input[96:128]));
        uint256 y = uint256(bytes32(input[128:160]));

        uint256[2] memory rs = [r, s];
        uint256[2] memory xy = [x, y];

        uint256 ret = FCL_Elliptic_ZZ.ecdsa_verify(hash, rs, xy) ? 1 : 0;

        return abi.encodePacked(ret);
    }

    // Exclude from forge coverage
    function test() public {}
}

contract GasBenchmarkTest is Test {
    P256Verifier public our_verifier;
    FCLWrapperEIP7212 public fcl_verifier;

    function setUp() public {
        our_verifier = new P256Verifier();
        fcl_verifier = new FCLWrapperEIP7212();
    }

    /** Checks a single test vector: signature rs, pubkey Q = (x,y). */
    function evaluate(
        address verifier_addr,
        bytes32 hash,
        uint256 r,
        uint256 s,
        uint256 x,
        uint256 y
    ) private returns (bool valid, uint gasUsed) {
        bytes memory input = abi.encodePacked(hash, r, s, x, y);

        uint gasBefore = gasleft();
        (bool success, bytes memory res) = verifier_addr.staticcall(input);
        gasUsed = gasBefore - gasleft();

        assertEq(success, true, "call failed");
        assertEq(res.length, 32, "invalid result length");
        uint256 result = abi.decode(res, (uint256));
        assertTrue(result == 1 || result == 0, "invalid result");

        return (result == 1, gasUsed);
    }

    uint256[] our_gasUsed;
    uint256[] fcl_gasUsed;

    function logSummaryStatistics(
        uint256[] storage gasUsed,
        string memory tag
    ) internal view {
        uint256 avg = 0;
        uint256 min = 2 ** 256 - 1;
        uint256 max = 0;
        for (uint256 i = 0; i < gasUsed.length; i++) {
            avg += gasUsed[i];
            if (gasUsed[i] < min) {
                min = gasUsed[i];
            }
            if (gasUsed[i] > max) {
                max = gasUsed[i];
            }
        }
        avg /= gasUsed.length;
        console2.log(tag, " avg: ", avg);
        console2.log(tag, " min: ", min);
        console2.log(tag, " max: ", max);
        console2.log("\n");
    }

    // Benchmark gas usage for a set of test vectors, run on both our verifier
    // and the FCL verifier, and log summary statistics for each.
    function benchmarkGasUsage(string memory file) internal {
        our_gasUsed = new uint256[](0);
        fcl_gasUsed = new uint256[](0);

        while (true) {
            string memory vector = vm.readLine(file);
            if (bytes(vector).length == 0) {
                break;
            }

            uint256 x = uint256(vector.readBytes32(".x"));
            uint256 y = uint256(vector.readBytes32(".y"));
            uint256 r = uint256(vector.readBytes32(".r"));
            uint256 s = uint256(vector.readBytes32(".s"));
            bytes32 hash = vector.readBytes32(".hash");

            (bool our_result, uint256 our_gasUsed_test) = evaluate(
                address(our_verifier),
                hash,
                r,
                s,
                x,
                y
            );
            (bool fcl_result, uint256 fcl_gasUsed_test) = evaluate(
                address(fcl_verifier),
                hash,
                r,
                s,
                x,
                y
            );

            assertEq(our_result, fcl_result, "results don't match");

            our_gasUsed.push(our_gasUsed_test);
            fcl_gasUsed.push(fcl_gasUsed_test);
        }

        logSummaryStatistics(our_gasUsed, "Our verifier gas usage");
        logSummaryStatistics(fcl_gasUsed, "FCL verifier gas usage");
    }

    // Benchmark gas usage for the Wycheproof test vectors.
    // These include edge cases and invalid signatures, so are
    // less representative of real-world usage.
    function testBenchmarkWycheProofGasUsage() public {
        benchmarkGasUsage("./test-vectors/vectors_wycheproof.jsonl");
    }

    // Benchmark gas usage for a set of randomly generated test vectors.
    // These are more representative of real-world usage.
    function testBenchmarkRandomGasUsage() public {
        benchmarkGasUsage("./test-vectors/vectors_random_valid.jsonl");
    }

    // Exclude from forge coverage
    function test() public {}
}
