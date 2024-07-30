// SPDX-License-Identifier: MIT
// Force a specific Solidity version for reproducibility.
pragma solidity 0.8.21;

/**
 * @dev This contract verifies P256 (secp256r1) signatures. It matches the exact
 * interface specified in the EIP-7212 precompile, allowing it to be used as a
 * fallback. It's based on Ledger's optimized implementation:
 * https://github.com/rdubois-crypto/FreshCryptoLib/tree/master/solidity
 * @custom:security-contact security@daimo.com
 */
contract P256Verifier {
    /**
     * @dev Precompiles don't use a function signature. The first byte of
     * calldata is the first byte of an input argument. In this case:
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

        uint256 ret = ecdsa_verify(hash, r, s, [x, y]) ? 1 : 0;

        return abi.encodePacked(ret);
    }

    // Parameters for the sec256r1 (P256) elliptic curve
    // Curve prime field modulus
    uint256 constant p =
        0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF;
    // Short weierstrass first coefficient
    uint256 constant a = // The assumption a == -3 (mod p) is used throughout the codebase
        0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC;
    // Short weierstrass second coefficient
    uint256 constant b =
        0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B;
    // Generating point affine coordinates
    uint256 constant GX =
        0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296;
    uint256 constant GY =
        0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5;
    // Curve order (number of points)
    uint256 constant n =
        0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
    // -2 mod p constant, used to speed up inversion and doubling (avoid negation)
    uint256 constant minus_2modp =
        0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFD;
    // -2 mod n constant, used to speed up inversion
    uint256 constant minus_2modn =
        0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254F;

    /**
     * @dev ECDSA verification given signature and public key.
     */
    function ecdsa_verify(
        bytes32 message_hash,
        uint256 r,
        uint256 s,
        uint256[2] memory pubKey
    ) private view returns (bool) {
        // Check r and s are in the scalar field
        if (r == 0 || r >= n || s == 0 || s >= n) {
            return false;
        }

        if (!ecAff_isValidPubkey(pubKey[0], pubKey[1])) {
            return false;
        }

        uint256 sInv = nModInv(s);

        uint256 scalar_u = mulmod(uint256(message_hash), sInv, n); // (h * s^-1) in scalar field
        uint256 scalar_v = mulmod(r, sInv, n); // (r * s^-1) in scalar field

        uint256 r_x = ecZZ_mulmuladd(
            pubKey[0],
            pubKey[1],
            scalar_u,
            scalar_v
        );
        return r_x % n == r;
    }

    /**
     * @dev Check if a point in affine coordinates is on the curve
     * Reject 0 point at infinity.
     */
    function ecAff_isValidPubkey(
        uint256 x,
        uint256 y
    ) internal pure returns (bool) {
        if (x >= p || y >= p || (x == 0 && y == 0)) {
            return false;
        }

        return ecAff_satisfiesCurveEqn(x, y);
    }

    function ecAff_satisfiesCurveEqn(
        uint256 x,
        uint256 y
    ) internal pure returns (bool) {
        uint256 LHS = mulmod(y, y, p); // y^2
        uint256 RHS = addmod(mulmod(mulmod(x, x, p), x, p), mulmod(a, x, p), p); // x^3 + a x
        RHS = addmod(RHS, b, p); // x^3 + a*x + b

        return LHS == RHS;
    }

    /**
     * @dev Computation of uG + vQ using Strauss-Shamir's trick, G basepoint, Q public key
     * returns tuple of (x coordinate of uG + vQ, boolean that is false if internal precompile staticcall fail)
     * Strauss-Shamir is described well in https://stackoverflow.com/a/50994362
     */
    function ecZZ_mulmuladd(
        uint256 QX,
        uint256 QY, // affine rep for input point Q
        uint256 scalar_u,
        uint256 scalar_v
    ) internal view returns (uint256 X) {
        uint256 zz = 1;
        uint256 zzz = 1;
        uint256 Y;
        uint256 HX;
        uint256 HY;

        if (scalar_u == 0 && scalar_v == 0) return 0;

        // H = g + Q
        (HX, HY) = ecAff_add(GX, GY, QX, QY);

        int256 index = 255;
        uint256 bitpair;

        // Find the first bit index that's active in either scalar_u or scalar_v.
        while(index >= 0) {
            bitpair = compute_bitpair(uint256(index), scalar_u, scalar_v);
            index--;
            if (bitpair != 0) break;
        }

        // initialise (X, Y) depending on the first active bitpair.
        // invariant(bitpair != 0); // bitpair == 0 is only possible if u and v are 0.
        
        if (bitpair == 1) {
            (X, Y) = (GX, GY);
        } else if (bitpair == 2) {
            (X, Y) = (QX, QY);
        } else if (bitpair == 3) {
            (X, Y) = (HX, HY);
        }

        uint256 TX;
        uint256 TY;
        while(index >= 0) {
            (X, Y, zz, zzz) = ecZZ_double_zz(X, Y, zz, zzz);

            bitpair = compute_bitpair(uint256(index), scalar_u, scalar_v);
            index--;

            if (bitpair == 0) {
                continue;
            } else if (bitpair == 1) {
                (TX, TY) = (GX, GY);
            } else if (bitpair == 2) {
                (TX, TY) = (QX, QY);
            } else {
                (TX, TY) = (HX, HY);
            }

            (X, Y, zz, zzz) = ecZZ_dadd_affine(X, Y, zz, zzz, TX, TY);
        }

        uint256 zzInv = pModInv(zz); // If zz = 0, zzInv = 0.
        X = mulmod(X, zzInv, p); // X/zz
    }

    /**
     * @dev Compute the bits at `index` of u and v and return
     * them as 2 bit concatenation. The bit at index 0 is on 
     * if the `index`th bit of scalar_u is on and the bit at
     * index 1 is on if the `index`th bit of scalar_v is on.
     * Examples:
     * - compute_bitpair(0, 1, 1) == 3
     * - compute_bitpair(0, 1, 0) == 1
     * - compute_bitpair(0, 0, 1) == 2
     */
    function compute_bitpair(uint256 index, uint256 scalar_u, uint256 scalar_v) internal pure returns (uint256 ret) {
        ret = (((scalar_v >> index) & 1) << 1) + ((scalar_u >> index) & 1);
    }

    /**
     * @dev Add two elliptic curve points in affine coordinates
     * Assumes points are on the EC
     */
    function ecAff_add(
        uint256 x1,
        uint256 y1,
        uint256 x2,
        uint256 y2
    ) internal view returns (uint256, uint256) {
        // invariant(ecAff_IsZero(x1, y1) || ecAff_isOnCurve(x1, y1));
        // invariant(ecAff_IsZero(x2, y2) || ecAff_isOnCurve(x2, y2));

        uint256 zz1;
        uint256 zzz1;

        if (ecAff_IsInf(x1, y1)) return (x2, y2);
        if (ecAff_IsInf(x2, y2)) return (x1, y1);

        (x1, y1, zz1, zzz1) = ecZZ_dadd_affine(x1, y1, 1, 1, x2, y2);

        return ecZZ_SetAff(x1, y1, zz1, zzz1);
    }

    /**
     * @dev Check if a point is the infinity point in affine rep.
     * Assumes point is on the EC or is the point at infinity.
     */
    function ecAff_IsInf(
        uint256 x,
        uint256 y
    ) internal pure returns (bool flag) {
        // invariant((x == 0 && y == 0) || ecAff_isOnCurve(x, y));

        return (x == 0 && y == 0);
    }

    /**
     * @dev Check if a point is the infinity point in ZZ rep.
     * Assumes point is on the EC or is the point at infinity.
     */
    function ecZZ_IsInf(
        uint256 zz,
        uint256 zzz
    ) internal pure returns (bool flag) {
        // invariant((zz == 0 && zzz == 0) || ecAff_isOnCurve(x, y) for affine 
        // form of the point)

        return (zz == 0 && zzz == 0);
    }

    /**
     * @dev Add a ZZ point to an affine point and return as ZZ rep
     * Uses madd-2008-s and mdbl-2008-s internally
     * https://hyperelliptic.org/EFD/g1p/auto-shortw-xyzz-3.html#addition-madd-2008-s
     * Matches https://github.com/supranational/blst/blob/9c87d4a09d6648e933c818118a4418349804ce7f/src/ec_ops.h#L705 closely
     * Handles points at infinity gracefully
     */
    function ecZZ_dadd_affine(
        uint256 x1,
        uint256 y1,
        uint256 zz1,
        uint256 zzz1,
        uint256 x2,
        uint256 y2
    ) internal pure returns (uint256 x3, uint256 y3, uint256 zz3, uint256 zzz3) {
        if (ecAff_IsInf(x2, y2)) { // (X2, Y2) is point at infinity
            if (ecZZ_IsInf(zz1, zzz1)) return ecZZ_PointAtInf();
            return (x1, y1, zz1, zzz1);
        } else if (ecZZ_IsInf(zz1, zzz1)) { // (X1, Y1) is point at infinity
            return (x2, y2, 1, 1);
        }

        uint256 comp_R = addmod(mulmod(y2, zzz1, p), p - y1, p); // R = S2 - y1 = y2*zzz1 - y1
        uint256 comp_P = addmod(mulmod(x2, zz1, p), p - x1, p); // P = U2 - x1 = x2*zz1 - x1

        if (comp_P != 0) { // X1 != X2
            // invariant(x1 != x2);
            uint256 comp_PP = mulmod(comp_P, comp_P, p); // PP = P^2
            uint256 comp_PPP = mulmod(comp_PP, comp_P, p); // PPP = P*PP
            zz3 = mulmod(zz1, comp_PP, p); //// ZZ3 = ZZ1*PP
            zzz3 = mulmod(zzz1, comp_PPP, p); //// ZZZ3 = ZZZ1*PPP
            uint256 comp_Q = mulmod(x1, comp_PP, p); // Q = X1*PP
            x3 = addmod(
                addmod(mulmod(comp_R, comp_R, p), p - comp_PPP, p), // (R^2) + (-PPP)
                mulmod(minus_2modp, comp_Q, p), // (-2)*(Q)
                p
            ); // R^2 - PPP - 2*Q
            y3 = addmod(
                mulmod(addmod(comp_Q, p - x3, p), comp_R, p), //(Q+(-x3))*R
                mulmod(p - y1, comp_PPP, p), // (-y1)*PPP
                p
            ); // R*(Q-x3) - y1*PPP
        } else if (comp_R == 0) { // X1 == X2 and Y1 == Y2
            // invariant(x1 == x2 && y1 == y2);

            // Must be affine because (X2, Y2) is affine.
            (x3, y3, zz3, zzz3) = ecZZ_double_affine(x2, y2);
        } else { // X1 == X2 and Y1 == -Y2
            // invariant(x1 == x2 && y1 == p - y2);
            (x3, y3, zz3, zzz3) = ecZZ_PointAtInf();
        }

        return (x3, y3, zz3, zzz3);
    }

    /**
     * @dev Double a ZZ point 
     * Uses http://hyperelliptic.org/EFD/g1p/auto-shortw-xyzz.html#doubling-dbl-2008-s-1
     * Handles point at infinity gracefully
     */
    function ecZZ_double_zz(uint256 x1,
        uint256 y1, uint256 zz1, uint256 zzz1) internal pure returns (uint256 x3, uint256 y3, uint256 zz3, uint256 zzz3) {
        if (ecZZ_IsInf(zz1, zzz1)) return ecZZ_PointAtInf();
    
        uint256 comp_U = mulmod(2, y1, p); // U = 2*Y1
        uint256 comp_V = mulmod(comp_U, comp_U, p); // V = U^2
        uint256 comp_W = mulmod(comp_U, comp_V, p); // W = U*V
        uint256 comp_S = mulmod(x1, comp_V, p); // S = X1*V
        uint256 comp_M = addmod(mulmod(3, mulmod(x1, x1, p), p), mulmod(a, mulmod(zz1, zz1, p), p), p); //M = 3*(X1)^2 + a*(zz1)^2
        
        x3 = addmod(mulmod(comp_M, comp_M, p), mulmod(minus_2modp, comp_S, p), p); // M^2 + (-2)*S
        y3 = addmod(mulmod(comp_M, addmod(comp_S, p - x3, p), p), mulmod(p - comp_W, y1, p), p); // M*(S+(-X3)) + (-W)*Y1
        zz3 = mulmod(comp_V, zz1, p); // V*ZZ1
        zzz3 = mulmod(comp_W, zzz1, p); // W*ZZZ1
    }

    /**
     * @dev Double an affine point and return as a ZZ point 
     * Uses http://hyperelliptic.org/EFD/g1p/auto-shortw-xyzz.html#doubling-mdbl-2008-s-1
     * Handles point at infinity gracefully
     */
    function ecZZ_double_affine(uint256 x1,
        uint256 y1) internal pure returns (uint256 x3, uint256 y3, uint256 zz3, uint256 zzz3) {
        if (ecAff_IsInf(x1, y1)) return ecZZ_PointAtInf();

        uint256 comp_U = mulmod(2, y1, p); // U = 2*Y1
        zz3 = mulmod(comp_U, comp_U, p); // V = U^2 = zz3
        zzz3 = mulmod(comp_U, zz3, p); // W = U*V = zzz3
        uint256 comp_S = mulmod(x1, zz3, p); // S = X1*V
        uint256 comp_M = addmod(mulmod(3, mulmod(x1, x1, p), p), a, p); // M = 3*(X1)^2 + a
        
        x3 = addmod(mulmod(comp_M, comp_M, p), mulmod(minus_2modp, comp_S, p), p); // M^2 + (-2)*S
        y3 = addmod(mulmod(comp_M, addmod(comp_S, p - x3, p), p), mulmod(p - zzz3, y1, p), p); // M*(S+(-X3)) + (-W)*Y1
    }

    /**
     * @dev Convert from ZZ rep to affine rep
     * Assumes (zz)^(3/2) == zzz (i.e. zz == z^2 and zzz == z^3)
     * See https://hyperelliptic.org/EFD/g1p/auto-shortw-xyzz-3.html
     */
    function ecZZ_SetAff(
        uint256 x,
        uint256 y,
        uint256 zz,
        uint256 zzz
    ) internal view returns (uint256 x1, uint256 y1) {
        if(ecZZ_IsInf(zz, zzz)) {
            (x1, y1) = ecAffine_PointAtInf();
            return (x1, y1);
        }

        uint256 zzzInv = pModInv(zzz); // 1 / zzz
        uint256 zInv = mulmod(zz, zzzInv, p); // 1 / z
        uint256 zzInv = mulmod(zInv, zInv, p); // 1 / zz

        // invariant(mulmod(FCL_pModInv(zInv), FCL_pModInv(zInv), p) == zz)
        // invariant(mulmod(mulmod(FCL_pModInv(zInv), FCL_pModInv(zInv), p), FCL_pModInv(zInv), p) == zzz)

        x1 = mulmod(x, zzInv, p); // X / zz
        y1 = mulmod(y, zzzInv, p); // y = Y / zzz
    }

    /**
     * @dev Point at infinity in ZZ rep
     */
    function ecZZ_PointAtInf() internal pure returns (uint256, uint256, uint256, uint256) {
        return (0, 0, 0, 0);
    }

    /**
     * @dev Point at infinity in affine rep
     */
    function ecAffine_PointAtInf() internal pure returns (uint256, uint256) {
        return (0, 0);
    }

    /**
     * @dev u^-1 mod n
     */
    function nModInv(uint256 u) internal view returns (uint256) {
        return modInv(u, n, minus_2modn);
    }

    /**
     * @dev u^-1 mod p
     */
    function pModInv(uint256 u) internal view returns (uint256) {
        return modInv(u, p, minus_2modp);
    }

    /**
     * @dev u^-1 mod f = u^(phi(f) - 1) mod f = u^(f-2) mod f for prime f
     * by Fermat's little theorem, compute u^(f-2) mod f using modexp precompile
     * Assume f != 0. If u is 0, then u^-1 mod f is undefined mathematically, 
     * but this function returns 0.
     */
    function modInv(uint256 u, uint256 f, uint256 minus_2modf) internal view returns (uint256 result) {
        // invariant(f != 0);
        // invariant(f prime);

        // This seems like a relatively standard way to use this precompile:
        // https://github.com/OpenZeppelin/openzeppelin-contracts/pull/3298/files#diff-489d4519a087ca2c75be3315b673587abeca3b302f807643e97efa7de8cb35a5R427

        (bool success, bytes memory ret) = (address(0x05).staticcall(abi.encode(32, 32, 32, u, minus_2modf, f)));
        assert(success); // precompile should never fail on regular EVM environments
        result = abi.decode(ret, (uint256));
    }
}
