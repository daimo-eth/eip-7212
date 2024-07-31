// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Test, console2} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {Base64URL} from "../../src/utils/Base64URL.sol";
import "openzeppelin-contracts/contracts/utils/Base64.sol";

using stdJson for string;

contract Base64URLTest is Test {
    function testSimple() public {
        bytes memory data = "hello world";
        string memory b64 = Base64.encode(data);
        string memory b64url = Base64URL.encode(data);
        assertEq(b64, "aGVsbG8gd29ybGQ=");
        assertEq(b64url, "aGVsbG8gd29ybGQ");
    }

    function testScureVectors() public {
        string memory file = "./test-vectors/vectors_scure_base64url.jsonl";
        while (true) {
            string memory vector = vm.readLine(file);
            if (bytes(vector).length == 0) {
                break;
            }

            bytes memory data = vector.readBytes(".data");
            string memory expected = vector.readString(".base64url");
            string memory computed = Base64URL.encode(data);

            assertEq(computed, expected);
        }
    }

    function testEdgeCases() public {
        bytes memory data = "";
        string memory b64url = Base64URL.encode(data);
        assertEq(b64url, "");
    }
}
