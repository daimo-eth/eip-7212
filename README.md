## `P256Verifier` Solidity contract

> **This is currently the only audited, open source P256 verifier.** It's not quite the lowest-gas implementation, but it's close.
> Our implementation uses no `unsafe` or assembly to maximize simplicity and security.

Verifying a signature costs about 330k gas. Pure function, no precomputation.

This contract matches the [EIP-7212 precompile spec](https://eips.ethereum.org/EIPS/eip-7212).

**It exists at a deterministic CREATE2 address: `0xc2b78104907F722DABAc4C69f826a522B2754De4`. You can use it on any EVM chain.** So far, we've deployed it on Ethereum L1, OP Mainnet, Base, Arbitrum and others. You can deploy to any EVM chain using `forge script`.

The secp256r1 elliptic curve, aka P256, is used by security keys like Yubikey, Apple's Secure Enclave, the Android Keystore, and WebAuthn, aka passkeys. P256 verification enables secure hardware-based signing keys, great UX and passkey backup.

Our implementation was inspired by [Renaud Dubois/Ledger's FCL library](https://github.com/rdubois-crypto/FreshCryptoLib) and [blst](https://github.com/supranational/blst).

## Usage

**Address `0xc2b78104907F722DABAc4C69f826a522B2754De4`**

Available on any chain. If missing, see `deploy.sh`.

Install with:

- `forge install daimo-eth/p256-verifier`
- add `p256-verifier/=lib/p256-verifier/src/` to remappings.txt

```solidity
import "p256-verifier/P256.sol";

bytes32 hash; // message hash
uint256 r, s; // signature
uint256 x, y; // public key

bool valid = P256.verifySignature(hash, r, s, x, y);
```

Alternately, calling `P256.verifySignatureAllowMalleability` ignores
malleability of signatures, matching the behavior specified by the NIST standard
exactly.

You can also verify WebAuthn/Passkey signatures using the [`WebAuthn.sol`](./src/WebAuthn.sol) library contract.

## Audits

- [Veridise audit 2023 Oct: P256Verifier](./audits/2023-10-veridise.pdf)
- [Veridise audit 2023 Nov: WebAuthn](./audits/2023-11-veridise-webauthn.pdf)

## Development

Run `foundryup` to ensure you have the latest foundry. Then,

```
git clone --recurse-submodules git@github.com:daimo-eth/p256-verifier
cd p256-verifier
forge test --via-ir -vv
```

This runs test input and output handling as well as all applicable Wycheproof
test vectors, covering a range of edge cases.

<details>
<summary>Code coverage</summary>
Install the recommended VSCode extension to view line-by-line test coverage.
To regenerate coverage:

```
forge coverage --ir-minimum --report lcov
```

</details>

<details>
<summary>Test vectors</summary>

To regenerate test vectors:

```
cd test-vectors
npm i

# Download, extract, clean test vectors
# This regenerates ../test/vectors.jsonl
npm start

# Validate that all vectors produce expected results with SubtleCrypto and noble library implementation
npm test

# Validate that all vectors also work with EIP-7212
# Test the fallback contract...
cd ..
forge test --via-ir -vv

# In future, execution spec and clients can test against the same clean vectors
```

</details>
