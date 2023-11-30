// SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/Strings.sol";
import "./utils/ec-solidity.sol";

contract RingSigVerifier {
    // Curve parameters
    uint256 constant aa = 0;
    uint256 constant bb = 7;

    // Field size
    uint256 constant pp =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

    // Base point (generator) G
    uint256 constant Gx =
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 constant Gy =
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

    // Order of G
    uint256 constant nn =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    constructor() {}

    function verifyRingSignature(
        uint256 message, // keccack256 hash
        uint256[] memory ring, // ring of public keys [pkX1, pkY1, pkX2, pkY2, ..., pkXn, pkYn]
        uint256[] memory responses,
        uint256 c // signature seed
    ) public pure returns (bool) {
        
        // check if ring.length is even
        require(
            ring.length > 1 && ring.length % 2 == 0,
            "Ring length must be even and greater than 1"
        );

        // check if responses.length = ring.length / 2
        require(
            responses.length == ring.length / 2,
            "Responses length must be equal to ring length / 2"
        );

        // compute c1'
        uint256 cp = computeC1(message, responses[0], c, ring[0], ring[1]);

        // compute c2', c3', ..., cn
        for (uint256 i = 1; i < responses.length; i++) {
            cp = computeC(responses[i], cp, ring[2 * i], ring[2 * i + 1]);
        }

        // check if c0' == c0
        return (c == cp);
    }

    function computeC(
        uint256 response,
        uint256 previousC,
        uint256 xpreviousPubKey,
        uint256 ypreviousPubKey
    ) internal pure returns (uint256) {
        require(
            EllipticCurve.isOnCurve(
                xpreviousPubKey,
                ypreviousPubKey,
                aa,
                bb,
                pp
            ),
            "previousPubKey is not on curve"
        );

        // compute rG + previousPubKey * c by tweaking ecRecover
        address computedPubKey = sbmul_add_smul(
            response,
            xpreviousPubKey,
            ypreviousPubKey,
            previousC
        );

        // message + (rG + previousPubKey * c)
        bytes memory data = abi.encodePacked(
            // Strings.toString(uint256(uint160(computedPubKey)))
            computedPubKey
        );

        return modulo(uint256(keccak256(data)), nn);
    }

    function computeC1(
        uint256 message,
        uint256 response,
        uint256 previousC,
        uint256 xPreviousPubKey,
        uint256 yPreviousPubKey
    ) internal pure returns (uint256) {
        require(
            EllipticCurve.isOnCurve(
                xPreviousPubKey,
                yPreviousPubKey,
                aa,
                bb,
                pp
            ),
            "previousPubKey is not on curve"
        );

        // compute rG + previousPubKey * c by tweaking ecRecover
        address computedPubKey = sbmul_add_smul(
            response,
            xPreviousPubKey,
            yPreviousPubKey,
            previousC
        );

        // message + (rG + previousPubKey * c)
        bytes memory data = abi.encodePacked(
            // Strings.toString(message),
            // Strings.toString(uint256(uint160(computedPubKey))) // same as ts
            message,
            computedPubKey
        );

        return modulo(uint256(keccak256(data)), nn);
    }

    // compute a * G + b * (x, y) by tweaking ecRecover
    function sbmul_add_smul(
        uint256 response, // response
        uint256 x, // previousPubKey.x
        uint256 y, // previousPubKey.y
        uint256 challenge // previousC
    ) internal pure returns (address) {
        uint256 N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141; // order of G (= secp256k1.N)

        response = mulmod((N - response) % N, x, N);

        return
            ecrecover(
                bytes32(response), // 'msghash'
                y % 2 != 0 ? 28 : 27, // v
                bytes32(x), // r
                bytes32(mulmod(challenge, x, N))
            ); // s
    }

    function modulo(
        uint256 value,
        uint256 mod
    ) internal pure returns (uint256) {
        uint256 result = value % mod;
        if (result < 0) {
            result += mod;
        }
        return result;
    }
}
