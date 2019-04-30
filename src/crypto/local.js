/**
 * This implements a 2HashDH-based token scheme using the SJCL ecc package.
 *
 * @author: George Tankersley
 * @author: Alex Davidson
 */

/* global sjcl */
/* exported sec1Encode */
/* exported sec1EncodeToBase64 */
/* exported sec1DecodeFromBase64 */
/* exported sec1DecodeFromBytes */
/* exported newRandomPoint */
/* exported blindPoint, unblindPoint */
/* exported verifyProof */
/* exported initECSettings */
/* exported getCurvePoints */
/* exported getBigNumFromBytes */
/* exported getActiveECSettings */
"use strict";

const BATCH_PROOF_PREFIX = "batch-proof=";
const MASK = ["0xff", "0x1", "0x3", "0x7", "0xf", "0x1f", "0x3f", "0x7f"];

const DIGEST_INEQUALITY_ERR = "[privacy-pass]: Recomputed digest does not equal received digest";
const PARSE_ERR = "[privacy-pass]: Error parsing proof";

// Globals for keeping track of EC curve settings
let CURVE;
let CURVE_H2C_HASH;
let CURVE_H2C_METHOD;

/**
 * Sets the curve parameters for the current session based on the contents of
 * activeConfig.h2c-params
 * @param {JSON} h2cParams
 */
function initECSettings(h2cParams) {
    const curveStr = h2cParams.curve;
    const hashStr = h2cParams.hash;
    const methodStr = h2cParams.method;
    switch (curveStr) {
        case "p256":
            if (methodStr != "swu" && methodStr != "increment") {
                throw new Error("[privacy-pass]: Incompatible h2c method: '" + methodStr + "', for curve " + curveStr);
            } else if (hashStr != "sha256") {
                throw new Error("[privacy-pass]: Incompatible h2c hash: '" + hashStr + "', for curve " + curveStr);
            }
            CURVE = sjcl.ecc.curves.c256;
            CURVE_H2C_HASH = sjcl.hash.sha256;
            CURVE_H2C_METHOD = methodStr;
            break;
        default:
            throw new Error("[privacy-pass]: Incompatible curve chosen: " + curveStr);
    }
}

/**
 * Returns the active configuration for the elliptic curve setting
 * @return {Object} Object containing the active curve and h2c configuration
 */
function getActiveECSettings() {
    return {curve: CURVE, hash: CURVE_H2C_HASH, method: CURVE_H2C_METHOD};
}

/**
 * Multiplies the point P with the scalar k and outputs kP
 * @param {sjcl.bn} k scalar
 * @param {sjcl.ecc.point} P curve point
 * @return {sjcl.ecc.point}
 */
function _scalarMult(k, P) {
    const Q = P.mult(k);
    return Q;
}

/**
 * Samples a random scalar and uses it to blind the point P
 * @param {sjcl.ecc.point} P curve point
 * @return {sjcl.ecc.point}
 */
function blindPoint(P) {
    const bF = sjcl.bn.random(CURVE.r, 10);
    const bP = _scalarMult(bF, P);
    return {point: bP, blind: bF};
}


/**
 * unblindPoint takes an assumed-to-be blinded point Q and an accompanying
 * blinding scalar b, then returns the point (1/b)*Q.
 * @param {sjcl.bn} b scalar blinding factor
 * @param {sjcl.ecc.point} Q curve point
 * @return {sjcl.ecc.point}
 */
function unblindPoint(b, Q) {
    const binv = b.inverseMod(CURVE.r);
    return _scalarMult(binv, Q);
}

/**
 * Creates a new random point on the curve by sampling random bytes and then
 * hashing to the chosen curve.
 * @return {sjcl.ecc.point}
 */
function newRandomPoint() {
    const byteLength = 32;
    const wordLength = byteLength / 4; // SJCL 4 bytes to a word
    const random = sjcl.random.randomWords(wordLength, 10); // TODO Use webcrypto instead.

    // Choose hash-to-curve method
    const point = h2Curve(random, getActiveECSettings());

    let t;
    if (point) {
        t = {data: sjcl.codec.bytes.fromBits(random), point: point};
    }
    return t;
}

/**
 * Encodes a curve point as bytes in SEC1 uncompressed format
 * @param {sjcl.ecc.point} P
 * @param {bool} compressed
 * @return {sjcl.codec.bytes}
 */
function sec1Encode(P, compressed) {
    let out = [];
    if (!compressed) {
        const xyBytes = sjcl.codec.bytes.fromBits(P.toBits());
        out = [0x04].concat(xyBytes);
    } else {
        const xBytes = sjcl.codec.bytes.fromBits(P.x.toBits());
        const y = P.y.normalize();
        const sign = y.limbs[0] & 1 ? 0x03 : 0x02;
        out = [sign].concat(xBytes);
    }
    return out;
}

/**
 * Encodes a curve point into bits for using as input to hash functions etc
 * @param {sjcl.ecc.point} point curve point
 * @param {bool} compressed flag indicating whether points have been compressed
 * @return {sjcl.bitArray}
 */
function sec1EncodeToBits(point, compressed) {
    return sjcl.codec.bytes.toBits(sec1Encode(point, compressed));
}

/**
 * Encodes a point into a base 64 string
 * @param {sjcl.ecc.point} point
 * @param {bool} compressed
 * @return {string}
 */
function sec1EncodeToBase64(point, compressed) {
    return sjcl.codec.base64.fromBits(sec1EncodeToBits(point, compressed));
}

/**
 * Decodes a base64-encoded string into a curve point
 * @param {string} p a base64-encoded, uncompressed curve point
 * @return {sjcl.ecc.point}
 */
function sec1DecodeFromBase64(p) {
    const sec1Bits = sjcl.codec.base64.toBits(p);
    const sec1Bytes = sjcl.codec.bytes.fromBits(sec1Bits);
    return sec1DecodeFromBytes(sec1Bytes);
}

/**
 * Decodes (SEC1) curve point bytes into a valid curve point
 * @param {sjcl.codec.bytes} sec1Bytes bytes of an uncompressed curve point
 * @return {sjcl.ecc.point}
 */
function sec1DecodeFromBytes(sec1Bytes) {
    let P;
    switch (sec1Bytes[0]) {
        case 0x02:
        case 0x03:
            P = decompressPoint(sec1Bytes);
            break;
        case 0x04:
            P = CURVE.fromBits(sjcl.codec.bytes.toBits(sec1Bytes.slice(1)));
            break;
        default:
            throw new Error("[privacy-pass]: attempted sec1 point decoding with incorrect tag: " + sec1Bytes[0]);
    }
    return P;
}

/**
 * Attempts to decompress a curve point in SEC1 encoded format. Returns null if
 * the point is invalid
 * @param {sjcl.codec.bytes} bytes bytes of a compressed curve point (SEC1)
 * @return {sjcl.ecc.point} may be null if compressed bytes are not valid
 */
function decompressPoint(bytes) {
    const yTag = bytes[0];
    const expLength = CURVE.r.bitLength()/8+1; // bitLength rounds up
    if (yTag != 2 && yTag != 3) {
        throw new Error("[privacy-pass]: compressed point is invalid, bytes[0] = " + yTag);
    } else if (bytes.length !== expLength) {
        throw new Error(`[privacy-pass]: compressed point is too long, actual = ${bytes.length}, expected = ${expLength}`);
    }
    const xBytes = bytes.slice(1);
    const x = CURVE.field.fromBits(sjcl.codec.bytes.toBits(xBytes)).normalize();
    const sign = yTag & 1;

    // y^2 = x^3 - 3x + b (mod p)
    let rh = x.power(3);
    const threeTimesX = x.mul(CURVE.a);
    rh = rh.add(threeTimesX).add(CURVE.b).mod(CURVE.field.modulus); // mod() normalizes

    // modsqrt(z) for p = 3 mod 4 is z^(p+1/4)
    const sqrt = CURVE.field.modulus.add(1).normalize().halveM().halveM();
    let y = new CURVE.field(rh.powermod(sqrt, CURVE.field.modulus));

    const parity = y.limbs[0] & 1;
    if (parity != sign) {
        y = CURVE.field.modulus.sub(y).normalize();
    }

    const point = new sjcl.ecc.point(CURVE, x, y);
    if (!point.isValid()) {
        // we return null here rather than an error as we iterate over this
        // method during hash-and-inc
        return null;
    }
    return point;
}

/**
 * Decodes the received curve points
 * @param {Array<string>} signatures An array of base64-encoded signed points
 * @return {Object} object containing array of curve points and compression flag
 */
function getCurvePoints(signatures) {
    const compression = {on: false, set: false};
    const sigBytes = [];
    signatures.forEach(function(signature) {
        const buf = sjcl.codec.bytes.fromBits(sjcl.codec.base64.toBits(signature));
        let setting = false;
        switch (buf[0]) {
            case 2:
            case 3:
                setting = true;
                break;
            case 4:
                // do nothing
                break;
            default:
                throw new Error(`[privacy-pass]: point, ${buf}, is not encoded correctly`);
        }
        if (!validResponseCompression(compression, setting)) {
            throw new Error("[privacy-pass]: inconsistent point compression in server response");
        }
        sigBytes.push(buf);
    });

    const usablePoints = [];
    sigBytes.forEach(function(buf) {
        const usablePoint = sec1DecodeFromBytes(buf);
        if (usablePoint == null) {
            throw new Error("[privacy-pass]: unable to decode point: " + buf);
        }
        usablePoints.push(usablePoint);
    });
    return {points: usablePoints, compressed: compression.on};
}

/**
 * Checks that the signed points from the IssueResponse have consistent
 * compression
 * @param {Object} compression compression object to be checked for consistency
 * @param {bool} setting new setting based on point data
 * @return {bool}
 */
function validResponseCompression(compression, setting) {
    if (!compression.set) {
        compression.on = setting;
        compression.set = true;
    } else if (compression.on !== setting) {
        return false;
    }
    return true;
}

/**
 * DLEQ proof verification logic
 */

/**
 * Verify the DLEQ proof object using the information provided
 * @param {string} proofObj base64-encoded batched DLEQ proof object
 * @param {Object} tokens array of token objects containing blinded curve points
 * @param {Array<sjcl.ecc.point>} signatures an array of signed points
 * @param {Object} commitments JSON object containing encoded curve points
 * @param {string} prngName name of the PRNG used for verifying proof
 * @return {boolean}
 */
function verifyProof(proofObj, tokens, signatures, commitments, prngName) {
    const bp = getMarshaledBatchProof(proofObj);
    const dleq = retrieveProof(bp);
    if (!dleq) {
        // Error has probably occurred
        return false;
    }
    if (tokens.length !== signatures.points.length) {
        return false;
    }
    const pointG = sec1DecodeFromBase64(commitments.G);
    const pointH = sec1DecodeFromBase64(commitments.H);

    // Recompute A and B for proof verification
    const cH = _scalarMult(dleq.C, pointH);
    const rG = _scalarMult(dleq.R, pointG);
    const A = cH.toJac().add(rG).toAffine();

    const composites = recomputeComposites(tokens, signatures, pointG, pointH, prngName);
    const cZ = _scalarMult(dleq.C, composites.Z);
    const rM = _scalarMult(dleq.R, composites.M);
    const B = cZ.toJac().add(rM).toAffine();

    // Recalculate C' and check if C =?= C'
    const h = new CURVE_H2C_HASH(); // use the h2c hash for convenience
    h.update(sec1EncodeToBits(pointG, signatures.compressed));
    h.update(sec1EncodeToBits(pointH, signatures.compressed));
    h.update(sec1EncodeToBits(composites.M, signatures.compressed));
    h.update(sec1EncodeToBits(composites.Z, signatures.compressed));
    h.update(sec1EncodeToBits(A, signatures.compressed));
    h.update(sec1EncodeToBits(B, signatures.compressed));
    const digestBits = h.finalize();
    const receivedDigestBits = dleq.C.toBits();
    if (!sjcl.bitArray.equal(digestBits, receivedDigestBits)) {
        console.error(DIGEST_INEQUALITY_ERR);
        console.error("Computed digest: " + digestBits.toString());
        console.error("Received digest: " + receivedDigestBits.toString());
        return false;
    }
    return true;
}

/**
 * Recompute the composite M and Z values for verifying DLEQ
 * @param {Array<Object>} tokens array of token objects containing blinded curve points
 * @param {Object} signatures contains array of signed curve points and compression flag
 * @param {sjcl.ecc.point} pointG curve point
 * @param {sjcl.ecc.point} pointH curve point
 * @param {string} prngName name of PRNG used to verify proof
 * @return {Object} Object containing composite points M and Z
 */
function recomputeComposites(tokens, signatures, pointG, pointH, prngName) {
    const seed = computeSeed(tokens, signatures, pointG, pointH);
    let cM = new sjcl.ecc.pointJac(CURVE); // can only add points in jacobian representation
    let cZ = new sjcl.ecc.pointJac(CURVE);
    const prng = {name: prngName};
    switch (prng.name) {
        case "shake":
            prng.func = createShake256();
            prng.func.update(seed, "hex");
            break;
        case "hkdf":
            prng.func = evaluateHkdf;
            break;
        default:
            throw new Error(`Server specified PRNG is not compatible: ${prng.name}`);
    }
    let iter = -1;
    for (let i=0; i<tokens.length; i++) {
        iter++;
        const ci = computePRNGScalar(prng, seed, (new sjcl.bn(iter)).toBits());
        // Moved this check out of computePRNGScalar to here
        if (ci.greaterEquals(CURVE.r)) {
            i--;
            continue;
        }
        const cMi = _scalarMult(ci, tokens[i].point);
        const cZi = _scalarMult(ci, signatures.points[i]);
        cM = cM.add(cMi);
        cZ = cZ.add(cZi);
    }
    return {M: cM.toAffine(), Z: cZ.toAffine()};
}

/**
 * Computes an output of a PRNG (using the seed if it is HKDF) as a sjcl bn
 * object
 * @param {Object} prng PRNG object for generating output
 * @param {string} seed hex-encoded seed
 * @param {sjcl.bitArray} salt optional salt for each PRNG eval
 * @return {sjcl.bn} PRNG output as scalar value
 */
function computePRNGScalar(prng, seed, salt) {
    const bitLen = CURVE.r.bitLength();
    const mask = MASK[bitLen % 8];
    let out;
    switch (prng.name) {
        case "shake":
            out = prng.func.squeeze(32, "hex");
            break;
        case "hkdf":
            out = sjcl.codec.hex.fromBits(prng.func(sjcl.codec.hex.toBits(seed), bitLen/8, sjcl.codec.utf8String.toBits("DLEQ_PROOF"), salt, CURVE_H2C_HASH));
            break;
        default:
            throw new Error(`Server specified PRNG is not compatible: ${prng.name}`);
    }
    // Masking is not strictly necessary for p256 but better to be completely
    // compatible in case that the curve changes
    const h = parseInt(out.substr(0, 2), 16);
    const mh = sjcl.codec.hex.fromBits(sjcl.codec.bytes.toBits([h & mask]));
    out = mh + out.substr(2);
    const nOut = getBigNumFromHex(out);
    return nOut;
}

/**
 * Computes a seed for the PRNG for verifying batch DLEQ proofs
 * @param {Object} chkM array of token objects containing blinded curve points
 * @param {sjcl.ecc.point[]} chkZ array of signed curve points
 * @param {sjcl.ecc.point} pointG curve point
 * @param {sjcl.ecc.point} pointH curve point
 * @return {string} hex-encoded PRNG seed
 */
function computeSeed(chkM, chkZ, pointG, pointH) {
    const compressed = chkZ.compressed;
    const h = new CURVE_H2C_HASH(); // we use the h2c hash for convenience
    h.update(sec1EncodeToBits(pointG, compressed));
    h.update(sec1EncodeToBits(pointH, compressed));
    for (let i=0; i<chkM.length; i++) {
        h.update(sec1EncodeToBits(chkM[i].point, compressed));
        h.update(sec1EncodeToBits(chkZ.points[i], compressed));
    }
    return sjcl.codec.hex.fromBits(h.finalize());
}

/**
 * hkdf - The HMAC-based Key Derivation Function
 * based on https://github.com/mozilla/node-hkdf
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * @param {bitArray} ikm Initial keying material
 * @param {integer} length Length of the derived key in bytes
 * @param {bitArray} info Key derivation data
 * @param {bitArray} salt Salt
 * @param {sjcl.hash} hash hash function
 * @return {bitArray}
 */
function evaluateHkdf(ikm, length, info, salt, hash) {
    const mac = new sjcl.misc.hmac(salt, hash);
    mac.update(ikm);
    const prk = mac.digest();

    const hashLength = Math.ceil(sjcl.bitArray.bitLength(prk)/8);
    const numBlocks = Math.ceil(length / hashLength);
    if (numBlocks > 255) {
        throw new Error(`[privacy-pass]: HKDF error, number of proposed iterations too large: ${numBlocks}`);
    }

    let prev = sjcl.codec.hex.toBits("");
    let output = "";
    for (let i = 0; i < numBlocks; i++) {
        const hmac = new sjcl.misc.hmac(prk, hash);
        const input = sjcl.bitArray.concat(
            sjcl.bitArray.concat(prev, info),
            sjcl.codec.utf8String.toBits((String.fromCharCode(i + 1)))
        );
        hmac.update(input);
        prev = hmac.digest();
        output += sjcl.codec.hex.fromBits(prev);
    }
    return sjcl.bitArray.clamp(sjcl.codec.hex.toBits(output), length * 8);
}

/**
 * Returns a decoded DLEQ proof as an object that can be verified
 * @param {Object} bp batch proof as encoded JSON
 * @return {Object} DLEQ proof object
 */
function retrieveProof(bp) {
    let dleqProof;
    try {
        dleqProof = parseDleqProof(atob(bp.P));
    } catch (e) {
        console.error(`${PARSE_ERR}: ${e}`);
        return;
    }
    return dleqProof;
}

/**
 * Decode proof string and remove prefix
 * @param {string} proof base64-encoded batched DLEQ proof
 * @return {Object} JSON batched DLEQ proof
 */
function getMarshaledBatchProof(proof) {
    let proofStr = atob(proof);
    if (proofStr.indexOf(BATCH_PROOF_PREFIX) === 0) {
        proofStr = proofStr.substring(BATCH_PROOF_PREFIX.length);
    }
    return JSON.parse(proofStr);
}

/**
 * Decode the proof that is sent into an Object
 * @param {string} proofStr proof JSON as string
 * @return {Object}
 */
function parseDleqProof(proofStr) {
    const dleqProofM = JSON.parse(proofStr);
    const dleqProof = {};
    dleqProof.R = getBigNumFromB64(dleqProofM.R);
    dleqProof.C = getBigNumFromB64(dleqProofM.C);
    return dleqProof;
}

/**
 * Return a bignum from a base64-encoded string
 * @param {string} b64Str
 * @return {sjcl.bn}
 */
function getBigNumFromB64(b64Str) {
    const bits = sjcl.codec.base64.toBits(b64Str);
    return sjcl.bn.fromBits(bits);
}

/**
 * Return a big number from an array of bytes
 * @param {sjcl.codec.bytes} bytes
 * @return {sjcl.bn}
 */
function getBigNumFromBytes(bytes) {
    const bits = sjcl.codec.bytes.toBits(bytes);
    return sjcl.bn.fromBits(bits);
}

/**
 * Return a big number from hex-encoded string
 * @param {string} hex hex-encoded string
 * @return {sjcl.bn}
 */
function getBigNumFromHex(hex) {
    return sjcl.bn.fromBits(sjcl.codec.hex.toBits(hex));
}
