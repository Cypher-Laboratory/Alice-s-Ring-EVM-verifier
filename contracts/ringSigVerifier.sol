// SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.20;

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

    /**
     * @dev Verifies a non-linkable ring signature generated with the evmCompatibilty parameters
     *
     * @param message - keccack256 message hash
     * @param ring - ring of public keys [pkX0, pkY0, pkX1, pkY1, ..., pkXn, pkYn]
     * @param responses - ring of responses [r0, r1, ..., rn]
     * @param c - signature seed
     *
     * @return true if the signature is valid, false otherwise
     */
    function verifyRingSignature(
        uint256 message,
        uint256[] memory ring,
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

        // compute c1' (message is added to the hash)
        uint256 cp = computeC1(message, responses[0], c, ring[0], ring[1]);

        // compute c2', c3', ..., cn', c0'
        for (uint256 i = 1; i < responses.length; i++) {
            cp = computeC(responses[i], cp, ring[2 * i], ring[2 * i + 1]);
        }

        // check if c0' == c0
        return (c == cp);
    }

    /**
     * @dev Computes a ci value (i != 1)
     *
     * @param response - previous response
     * @param previousC - previous c value
     * @param xpreviousPubKey - previous public key x coordinate
     * @param ypreviousPubKey - previous public key y coordinate
     *
     * @return ci value
     */
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

        // compute [rG + previousPubKey * c] by tweaking ecRecover
        address computedPubKey = sbmul_add_smul(
            response,
            xpreviousPubKey,
            ypreviousPubKey,
            previousC
        );

        // keccack256(message, [rG + previousPubKey * c])
        bytes memory data = abi.encodePacked(
            uint256(uint160(computedPubKey))
        );

        return modulo(uint256(keccak256(data)), nn);
    }

    /**
     * @dev Computes the c1 value
     *
     * @param message - keccack256 message hash
     * @param response - response[0]
     * @param previousC - previous c value
     * @param xPreviousPubKey - previous public key x coordinate
     * @param yPreviousPubKey - previous public key y coordinate
     * 
     * @return c1 value
     */
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

        // compute [rG + previousPubKey * c] by tweaking ecRecover
        address computedPubKey = sbmul_add_smul(
            response,
            xPreviousPubKey,
            yPreviousPubKey,
            previousC
        );

        // keccack256(message, [rG + previousPubKey * c])
        bytes memory data = abi.encodePacked(
            message,
            uint256(uint160(computedPubKey))
        );

        return modulo(uint256(keccak256(data)), nn);
    }

    /**
     * @dev Computs response * G + challenge * (x, y) by tweaking ecRecover (response and challenge are scalars)
     * 
     * @param response - response value
     * @param x - previousPubKey.x
     * @param y - previousPubKey.y
     * @param challenge - previousC value
     * 
     * @return computedPubKey - the ethereum address derived from the point [response * G + challenge * (x, y)]
     */
    function sbmul_add_smul(
        uint256 response,
        uint256 x,
        uint256 y, 
        uint256 challenge 
    ) internal pure returns (address) {
        uint256 N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141; // order of G (= secp256k1.N)

        response = mulmod((N - response) % N, x, N);

        return
            ecrecover(
                bytes32(response), // 'msghash'
                y % 2 != 0 ? 28 : 27, // v
                bytes32(x), // r
                bytes32(mulmod(challenge, x, N)) // s
            );
    }

    /**
     * @dev Computes (value * mod) % mod
     * 
     * @param value - value to be modulated
     * @param mod - mod value
     * 
     * @return result - the result of the modular operation
     */
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
