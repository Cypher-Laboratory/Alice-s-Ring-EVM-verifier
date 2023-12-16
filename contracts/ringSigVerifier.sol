// SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.20;

contract RingSigVerifier {
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

    /* ----------------------NON-LINKABLE---------------------- */
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
        if (ring.length == 0 && ring.length % 2 != 0) {
            revert("Ring length must be even and greater than 1");
        }

        // check if responses.length = ring.length / 2
        if (responses.length != ring.length / 2) {
            revert("Responses length must be equal to ring length / 2");
        }

        // compute c1' (message is added to the hash)
        uint256 cp = computeC1(message, responses[0], c, ring[0], ring[1]);

        uint256 j = 2;

        // compute c2', c3', ..., cn', c0'
        for (uint256 i = 1; i < responses.length; ) {
            cp = computeC(responses[i], cp, ring[j], ring[j + 1]);

            unchecked {
                j += 2;
                i++;
            }
        }

        // check if c0' == c0
        return (c == cp);
    }

    /**
     * @dev Computes a ci value (i != 1)
     *
     * @param response - previous response
     * @param previousC - previous c value
     * @param xPreviousPubKey - previous public key x coordinate
     * @param yPreviousPubKey - previous public key y coordinate
     *
     * @return ci value
     */
    function computeC(
        uint256 response,
        uint256 previousC,
        uint256 xPreviousPubKey,
        uint256 yPreviousPubKey
    ) internal pure returns (uint256) {
        // check if [ring[0], ring[1]] is on the curve
        isOnSECP25K1(xPreviousPubKey, yPreviousPubKey);

        // compute [rG + previousPubKey * c] by tweaking ecRecover
        address computedPubKey = sbmul_add_smul(
            response,
            xPreviousPubKey,
            yPreviousPubKey,
            previousC
        );

        // keccack256(message, [rG + previousPubKey * c])
        return
            uint256(keccak256(abi.encode(uint256(uint160(computedPubKey))))) %
            nn;
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
        // check if [ring[0], ring[1]] is on the curve
        isOnSECP25K1(xPreviousPubKey, yPreviousPubKey);

        // compute [rG + previousPubKey * c] by tweaking ecRecover
        address computedPubKey = sbmul_add_smul(
            response,
            xPreviousPubKey,
            yPreviousPubKey,
            previousC
        );

        return
            uint256(
                // keccack256(message, [rG + previousPubKey * c])
                keccak256(abi.encode(message, uint256(uint160(computedPubKey))))
            ) % nn;
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

    /**
     * @dev Checks if a point is on the secp256k1 curve
     *
     * Revert if the point is not on the curve
     *
     * @param x - point x coordinate
     * @param y - point y coordinate
     */
    function isOnSECP25K1(uint256 x, uint256 y) internal pure {
        if (
            mulmod(y, y, pp) != addmod(mulmod(x, mulmod(x, x, pp), pp), 7, pp)
        ) {
            revert("Point is not on curve");
        }
    }

    /* ----------------------LINKABLE---------------------- */

    /**
     * @dev Verifies a linkable ring signature generated with the evmCompatibilty parameters
     *
     * for each ring address:
     * - linkability witness = [ numberAddedToHash, cubeRoot for icart, ecHash*r.x, ecHash*r.y, keyImage*c.x, keyImage*c.y ]
     *
     * @param message - keccack256 message hash
     * @param ring - ring of public keys [pkX0, pkY0, pkX1, pkY1, ..., pkXn, pkYn]
     * @param responses - ring of responses [r0, r1, ..., rn]
     * @param c - signature seed
     * @param link - link value
     * @param signerKeyImage - signer key image
     * @param linkabilityWitnesses - linkability witnesses (length = 2 * ring length)
     *
     * @return true if the signature is valid, false otherwise
     */
    function verifyLinkableRingSignature(
        uint256 message,
        uint256[] memory ring,
        uint256[] memory responses,
        uint256 c, // signature seed
        uint256 link,
        uint256[2] memory signerKeyImage, // point on secp256k1
        uint256[] memory linkabilityWitnesses // ri*Hp(Ki) and ci*KeyImage (points on secp256k1), compared to the computed one here
    ) public pure returns (bool) {
        // check if ring.length is even
        if (ring.length == 0 && ring.length % 2 != 0) {
            revert("Ring length must be even and greater than 1");
        }

        // check if responses.length = ring.length / 2
        if (responses.length != ring.length / 2) {
            revert("Responses length must be equal to ring length / 2");
        }

        if (linkabilityWitnesses.length != 5 * responses.length) {
            // 5 witnesses per ring address
            revert(
                "Linkability witnesses length must be equal to reponses length * 5"
            );
        }

        // check if signerKeyImage is on the curve
        isOnSECP25K1(signerKeyImage[0], signerKeyImage[1]);

        // compute c1' (message is added to the hash)
        uint256 cp = computeLinkableC1(
            message,
            responses[0],
            c,
            ring[0],
            ring[1],
            link,
            signerKeyImage,
            [
                linkabilityWitnesses[0],
                linkabilityWitnesses[1],
                linkabilityWitnesses[2],
                linkabilityWitnesses[3],
                linkabilityWitnesses[4],
                linkabilityWitnesses[5]
            ]
        );

        uint256 j = 2;

        // compute c2', c3', ..., cn', c0'
        for (uint256 i = 1; i < responses.length; ) {
            // cp = computeLinkableC(responses[i], cp, ring[j], ring[j + 1]);

            unchecked {
                j += 2;
                i++;
            }
        }

        // check if c0' == c0
        return (c == cp);
    }

    /**
     * @dev Computes a ci value (i != 1) for a linkable ring signature
     *
     * A linkability witness is constructed as follows:
     * [ numberAddedToHash, cubeRoot for icart,  ecHash*r.x, ecHash*r.y,  keyImage*c.x, keyImage*c.y ]
     *
     * @param response - previous response
     * @param previousC - previous c value
     * @param xPreviousPubKey - previous public key x coordinate
     * @param yPreviousPubKey - previous public key y coordinate
     * @param linkabilityFlag - linkability flag
     * @param signerKeyImage - signer key image
     * @param linkabilityWitness - linkability witness
     *
     * @return c1 value
     */
    function computeLinkableC(
        uint256 response,
        uint256 previousC,
        uint256 xPreviousPubKey,
        uint256 yPreviousPubKey,
        uint256 linkabilityFlag,
        uint256[2] memory signerKeyImage,
        uint256[5] memory linkabilityWitness
    ) internal pure returns (uint256) {
        // check if [ring[0], ring[1]] is on the curve
        isOnSECP25K1(xPreviousPubKey, yPreviousPubKey);

        // compute [rG + previousPubKey * c] by tweaking ecRecover
        address computedPubKey = sbmul_add_smul(
            response,
            xPreviousPubKey,
            yPreviousPubKey,
            previousC
        );

        // compute linkability part
        // ri*Hp(Ki)
        // the first 2 witnesses are Hp(Ki).x and Hp(Ki).y
        uint256[2] memory image = ecHash(
            uint256(
                keccak256(
                    abi.encode(
                        xPreviousPubKey,
                        yPreviousPubKey,
                        linkabilityFlag
                    )
                )
            ), // data to map to a point on the curve
            linkabilityWitness[0], // added number to the hash to get a valid point on the curve
            linkabilityWitness[1] // square root of the hash (used as witness)
        );

        address rTimesEcHash = sbmul_add_smul(
            uint256(0),
            image[0],
            image[1],
            response
        );

        // verify if rTimesEcHash corresponds to the witness
        if (
            rTimesEcHash !=
            pointsToAddress([linkabilityWitness[1], linkabilityWitness[2]])
        ) {
            revert("Linkability witness is not valid");
        }

        // ci*KeyImage
        // the last 2 witnesses are KeyImage.x and KeyImage.y
        address cTimesKeyImage = sbmul_add_smul(
            uint256(0),
            signerKeyImage[0],
            signerKeyImage[1],
            previousC
        );

        // verify if cTimesKeyImage corresponds to the witness
        if (
            cTimesKeyImage !=
            pointsToAddress([linkabilityWitness[3], linkabilityWitness[4]])
        ) {
            revert("Linkability witness is not valid");
        }

        // compute cTimesKeyImage + rTimesEcHash
        uint256[2] memory link = [uint256(0), 1];

        return
            uint256(
                // keccack256(message, [rG + previousPubKey * c], [ri*Hp(Ki) + ci*KeyImage], link)
                keccak256(
                    abi.encode(
                        // base
                        uint256(uint160(computedPubKey)),
                        // linkability part
                        link[0],
                        link[1]
                    )
                )
            ) % nn;
    }

    /**
     * @dev Computes a ci value (i != 1) for a linkable ring signature
     *
     * A linkability witness is constructed as follows:
     * [ numberAddedToHash, ecHash*r.x, ecHash*r.y,  keyImage*c.x, keyImage*c.y ]
     *
     * @param message - keccack256 message hash
     * @param response - previous response
     * @param previousC - previous c value
     * @param xPreviousPubKey - previous public key x coordinate
     * @param yPreviousPubKey - previous public key y coordinate
     * @param linkabilityFlag - linkability flag
     * @param signerKeyImage - signer key image
     * @param linkabilityWitness - linkability witness
     *
     * @return c1 value
     */
    function computeLinkableC1(
        uint256 message,
        uint256 response,
        uint256 previousC,
        uint256 xPreviousPubKey,
        uint256 yPreviousPubKey,
        uint256 linkabilityFlag,
        uint256[2] memory signerKeyImage,
        uint256[6] memory linkabilityWitness
    ) internal pure returns (uint256) {
        // check if [ring[0], ring[1]] is on the curve
        isOnSECP25K1(xPreviousPubKey, yPreviousPubKey);

        // compute [rG + previousPubKey * c] by tweaking ecRecover
        address computedPubKey = sbmul_add_smul(
            response,
            xPreviousPubKey,
            yPreviousPubKey,
            previousC
        );

        // compute linkability part
        // ri*Hp(Ki)
        // the first 2 witnesses are Hp(Ki).x and Hp(Ki).y
        uint256[2] memory image = ecHash(
            uint256(
                keccak256(
                    abi.encode(
                        xPreviousPubKey,
                        yPreviousPubKey,
                        linkabilityFlag
                    )
                )
            ), // data to map to a point on the curve
            linkabilityWitness[0], // added number to the hash to get a valid point on the curve
            linkabilityWitness[1] // square root of the hash (used as witness)
        );

        address rTimesEcHash = sbmul_add_smul(
            uint256(0),
            image[0],
            image[1],
            response
        );

        // verify if rTimesEcHash corresponds to the witness
        if (
            rTimesEcHash !=
            pointsToAddress([linkabilityWitness[2], linkabilityWitness[3]])
        ) {
            revert("Linkability witness is not valid");
        }

        // ci*KeyImage
        // the last 2 witnesses are KeyImage.x and KeyImage.y
        address cTimesKeyImage = sbmul_add_smul(
            uint256(0),
            signerKeyImage[0],
            signerKeyImage[1],
            previousC
        );

        // verify if cTimesKeyImage corresponds to the witness
        if (
            cTimesKeyImage !=
            pointsToAddress([linkabilityWitness[4], linkabilityWitness[5]])
        ) {
            revert("Linkability witness is not valid");
        }

        // compute cTimesKeyImage + rTimesEcHash
        uint256[2] memory link = [uint256(0), 1];

        return
            uint256(
                // keccack256(message, [rG + previousPubKey * c], [ri*Hp(Ki) + ci*KeyImage], link)
                keccak256(
                    abi.encode(
                        // base
                        message,
                        uint256(uint160(computedPubKey)),
                        // linkability part
                        link[0],
                        link[1]
                    )
                )
            ) % nn;
    }

    /**
     * @dev maps a message hash to a point on the secp256k1 curve using icart's method
     *
     * @param msghash - keccak256 hash of the message
     * @param addedNumber - number added to the hash to get a valid point on the curve
     * @param cubeRoot - square root of the hash (used as witness)
     *
     * @return [x,y] - point representation of the data on the secp256k1 curve
     */
    function ecHash(
        uint256 msghash,
        uint256 addedNumber,
        uint256 cubeRoot
    ) internal pure returns (uint256[2] memory) {
        // secp256k1 params : a = 0, b = 7
        uint256 u = msghash + addedNumber;
        uint256 uCube = powmod(u, 3);

        if (
            powmod(cubeRoot, 3) !=
            addmod(
                addmod(powmod(uCube * invmod(6), 2), pp - 7, pp),
                pp - mulmod(powmod(u, 6), invmod(27), pp),
                pp
            )
        ) {
            revert("Cube root witness is not valid");
        }

        uint256 x = cubeRoot + powmod(u, 2) * invmod(3);
        uint256 y = addmod(mulmod(x, u, pp), pp - uCube * invmod(6), pp);

        return [x, y];
    }

    /* ----------------------ECRECOVER-TWEAK---------------------- */

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
        uint256 response, // if = 0, then it's a smul
        uint256 x,
        uint256 y,
        uint256 challenge
    ) internal pure returns (address) {
        response = mulmod((nn - response) % nn, x, nn);

        return
            ecrecover(
                bytes32(response), // 'msghash'
                y % 2 != 0 ? 28 : 27, // v
                bytes32(x), // r
                bytes32(mulmod(challenge, x, nn)) // s
            );
    }

    /* ----------------------UTILS---------------------- */

    /**
     * @dev convert a point from SECP256k1 to an ethereum address
     * @param point the point to convert -> [x,y]
     *
     * @return address - the ethereum address
     */
    function pointsToAddress(
        uint256[2] memory point
    ) public pure returns (address) {
        bytes32 x = bytes32(point[0]);
        bytes32 y = bytes32(point[1]);
        return address(uint160(uint256(keccak256(abi.encodePacked(x, y)))));
    }

    /**
     * @dev Computes (base^exponent) % modulus
     *
     * @param base - The base
     * @param exponent - The exponent
     *
     * @return - The result of (base^exponent) % modulus
     */
    function powmod(
        uint256 base,
        uint256 exponent
    ) internal pure returns (uint256) {
        uint256 result = 1;
        base = base % pp;
        while (exponent > 0) {
            if (exponent % 2 == 1) {
                result = (result * base) % pp;
            }
            exponent = exponent / 2;
            base = (base * base) % pp;
        }
        return result;
    }

    /**
     * @dev Returns the modular multiplicative inverse of a number.
     *
     * @param a - The number to find the inverse of
     *
     * @return - The modular multiplicative inverse of a
     */
    function invmod(uint256 a) internal pure returns (uint256) {
        return powmod(a, pp - 2);
    }
}
