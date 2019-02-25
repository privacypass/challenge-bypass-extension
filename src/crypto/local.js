/**
 * This implements a 2HashDH-based token scheme using the SJCL ecc package.
 *
 * @author: George Tankersley
 * @author: Alex Davidson
 */

/*global sjcl*/
/* exported compressPoint */
/* exported decompressPoint */
/* exported sec1EncodePoint */
/* exported decodeStorablePoint */
/* exported encodeStorablePoint */
/* exported newRandomPoint */
/* exported blindPoint, unblindPoint */
/* exported verifyProof */
/* exported initECSettings */
/* exported getCurvePoints */
/* exported getBigNumFromBytes */
"use strict";

const BATCH_PROOF_PREFIX = "batch-proof=";
const UNCOMPRESSED_POINT_PREFIX = "04";
const MASK = ["0xff", "0x1", "0x3", "0x7", "0xf", "0x1f", "0x3f", "0x7f"];

const DIGEST_INEQUALITY_ERR = "[privacy-pass]: Recomputed digest does not equal received digest";
const PARSE_ERR = "[privacy-pass]: Error parsing proof";

// Globals for keeping track of EC curve settings
let CURVE;
let CURVE_H2C_HASH;
let CURVE_H2C_METHOD;

/**
 * Sets the curve parameters for the current session based on the contents of
 * ACTIVE_CONFIG.h2c-params
 * @param {JSON} h2cParams
 */
function initECSettings(h2cParams) {
    let curveStr = h2cParams.curve;
    let hashStr = h2cParams.hash;
    let methodStr = h2cParams.method;
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

// Returns the active configuration for the elliptic curve setting
function getActiveECSettings() {
    return { curve: CURVE, hash: CURVE_H2C_HASH, method: CURVE_H2C_METHOD };
}

// Performs the scalar multiplication k*P
//
// Inputs:
//  k: bigInt scalar (not field element or bits!)
//  P: sjcl Point
// Returns:
//  sjcl Point
function _scalarMult(k, P) {
    const Q = P.mult(k);
    return Q;
}

// blindPoint generates a random scalar blinding factor, multiplies the
// supplied point by it, and returns both values.
function blindPoint(P) {
    const bF = sjcl.bn.random(CURVE.r, 10);
    const bP = _scalarMult(bF, P);
    return { point: bP, blind: bF };
}

// unblindPoint takes an assumed-to-be blinded point Q and an accompanying
// blinding scalar b, then returns the point (1/b)*Q.
//
// inputs:
//  b: bigint scalar (not field element or bits!)
//  q: sjcl point
// returns:
//  sjcl point
function unblindPoint(b, Q) {
    const binv = b.inverseMod(CURVE.r);
    return _scalarMult(binv, Q);
}

// Creates a new random point on the curve by sampling random bytes and then
// hashing to the chosen curve.
function newRandomPoint() {
    const byteLength = 32;
    const wordLength = byteLength / 4; // SJCL 4 bytes to a word
    const random = sjcl.random.randomWords(wordLength, 10); // TODO Use webcrypto instead.

    // Choose hash-to-curve method
    let point = h2Curve(random, getActiveECSettings());

    let t;
    if (point) {
        t = { data: sjcl.codec.bytes.fromBits(random), point: point};
    }
    return t;
}

// Compresses a point according to SEC1.
// input: point
// output: base64-encoded bytes
function compressPoint(p) {
    const xBytes = sjcl.codec.bytes.fromBits(p.x.toBits());
    const sign = p.y.limbs[0] & 1 ? 0x03 : 0x02;
    const taggedBytes = [sign].concat(xBytes);
    return sjcl.codec.base64.fromBits(sjcl.codec.bytes.toBits(taggedBytes));
}

// Attempts to decompress the bytes into a curve point following SEC1 and
// assuming it's a Weierstrass curve with a = -3 and p = 3 mod 4 (true for the
// main three NIST curves).
// input: bits of an x coordinate, the even/odd tag
// output: point
function decompressPoint(bytes) {
    const yTag = bytes[0];
    const xBytes = bytes.slice(1);

    const x = CURVE.field.fromBits(sjcl.codec.bytes.toBits(xBytes)).normalize();
    const sign = yTag & 1;

    // y^2 = x^3 - 3x + b (mod p)
    let rh = x.power(3);
    let threeTimesX = x.mul(CURVE.a);
    rh = rh.add(threeTimesX).add(CURVE.b).mod(CURVE.field.modulus); // mod() normalizes

    // modsqrt(z) for p = 3 mod 4 is z^(p+1/4)
    const sqrt = CURVE.field.modulus.add(1).normalize().halveM().halveM();
    let y = new CURVE.field(rh.powermod(sqrt, CURVE.field.modulus));

    let parity = y.limbs[0] & 1;
    if (parity != sign) {
        y = CURVE.field.modulus.sub(y).normalize();
    }

    let point = new sjcl.ecc.point(CURVE, x, y);
    if (!point.isValid()) {
        console.error("point is invalid, x: " + x + ", y: " + y);
        return null;
    }
    return point;
}

// This has to match Go's elliptic.Marshal, which follows SEC1 2.3.3 for
// uncompressed points.  SJCL's native point encoding is a concatenation of the
// x and y coordinates, so it's *almost* SEC1 but lacks the tag for
// uncompressed point encoding.
//
// Inputs:
//  P: sjcl Point
// Returns:
//  bytes
function sec1EncodePoint(P) {
    const pointBits = P.toBits();
    const xyBytes = sjcl.codec.bytes.fromBits(pointBits);
    return [0x04].concat(xyBytes);
}

// input: base64-encoded bytes
// output: point
function sec1DecodePoint(p) {
    const sec1Bits = sjcl.codec.base64.toBits(p);
    const sec1Bytes = sjcl.codec.bytes.fromBits(sec1Bits);
    return sec1DecodePointFromBytes(sec1Bytes);
}

// Decode point when it is in byte format rather than base64
function sec1DecodePointFromBytes(sec1Bytes) {
    if (sec1Bytes[0] != 0x04) {
        throw new Error("[privacy-pass]: attempted sec1 point decoding with incorrect tag: " + sec1Bytes);
    }
    const coordinates = sec1Bytes.slice(1); // remove "uncompressed" tag
    const pointBits = sjcl.codec.bytes.toBits(coordinates);
    return CURVE.fromBits(pointBits);
}

// Marshals a point in an SJCL-internal format that can be used with
// JSON.stringify for localStorage.
//
// input: point
// output: base64 string
function encodeStorablePoint(p) {
    const bits = p.toBits();
    return sjcl.codec.base64.fromBits(bits);
}

// Renders a point from SJCL-internal base64.
//
// input: base64 string
// ouput: point
function decodeStorablePoint(s) {
    const bits = sjcl.codec.base64.toBits(s);
    return CURVE.fromBits(bits);
}

/**
 * Decodes the received curve points
 * @param signatures encoded signed points
 */
function getCurvePoints(signatures) {
    let usablePoints = [];
    signatures.forEach(function(signature) {
        let usablePoint = sec1DecodePoint(signature);
        if (usablePoint == null) {
            throw new Error("[privacy-pass]: unable to decode point " + signature + " in " + JSON.stringify(signatures));
        }
        usablePoints.push(usablePoint);
    });
    return usablePoints;
}

/**
 * DLEQ proof verification logic
 */

// Verifies the DLEQ proof that is returned when tokens are signed
//
// input: marshaled JSON DLEQ proof
// output: bool
function verifyProof(proofObj, tokens, signatures, commitments) {
    let bp = getMarshaledBatchProof(proofObj);
    const dleq = retrieveProof(bp);
    if (!dleq) {
        // Error has probably occurred
        return false;
    }
    const chkM = tokens;
    const chkZ = signatures;
    if (chkM.length !== chkZ.length) {
        return false;
    }
    const pointG = sec1DecodePoint(commitments.G);
    const pointH = sec1DecodePoint(commitments.H);

    // Recompute A and B for proof verification
    let cH = _scalarMult(dleq.C, pointH);
    let rG = _scalarMult(dleq.R, pointG);
    const A = cH.toJac().add(rG).toAffine();

    let composites = recomputeComposites(chkM, chkZ, pointG, pointH);
    let cZ = _scalarMult(dleq.C, composites.Z);
    let rM = _scalarMult(dleq.R, composites.M);
    const B = cZ.toJac().add(rM).toAffine();

    // Recalculate C' and check if C =?= C'
    let h = new sjcl.hash.sha256();
    h.update(sjcl.codec.bytes.toBits(sec1EncodePoint(pointG)));
    h.update(sjcl.codec.bytes.toBits(sec1EncodePoint(pointH)));
    h.update(sjcl.codec.bytes.toBits(sec1EncodePoint(composites.M)));
    h.update(sjcl.codec.bytes.toBits(sec1EncodePoint(composites.Z)));
    h.update(sjcl.codec.bytes.toBits(sec1EncodePoint(A)));
    h.update(sjcl.codec.bytes.toBits(sec1EncodePoint(B)));
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

// Recompute the composite M and Z values for verifying DLEQ
function recomputeComposites(chkM, chkZ, pointG, pointH) {
    let seed = getSeedPRNG(chkM, chkZ, pointG, pointH);
    let shake = createShake256();
    shake.update(seed, "hex");
    let cM;
    let cZ;
    for (let i=0; i<chkM.length; i++) {
        let ci = getShakeScalar(shake);
        let cMi = _scalarMult(ci, chkM[i].point);
        let cZi = _scalarMult(ci, chkZ[i]);
        if (cM === undefined || cZ === undefined) {
            cM = cMi;
            cZ = cZi;
        } else {
            cM = cM.toJac().add(cMi).toAffine();
            cZ = cZ.toJac().add(cZi).toAffine();
        }
    }

    return {M: cM, Z: cZ};
}

// Squeeze a seeded shake for output
function getShakeScalar(shake) {
    const curveOrder = CURVE.r;
    const bitLen = sjcl.bitArray.bitLength(curveOrder.toBits());
    const mask = MASK[bitLen % 8];
    let rnd;

    while(!rnd) {
        let out = shake.squeeze(32, "hex");
        // Masking is not strictly necessary for p256 but better to be completely
        // compatible in case that the curve changes
        let h = "0x" + out.substr(0,2);
        let mh = sjcl.codec.hex.fromBits(sjcl.codec.bytes.toBits([h & mask]));
        out = mh + out.substr(2);
        let nOut = getBigNumFromHex(out);
        // Reject samples outside of correct range
        if (nOut.greaterEquals(curveOrder)) {
            continue;
        }
        rnd = nOut;
    }
    return rnd
}

function getSeedPRNG(chkM, chkZ, pointG, pointH) {
    let sha256 = new sjcl.hash.sha256();
    sha256.update(encodePointForPRNG(pointG));
    sha256.update(encodePointForPRNG(pointH));
    for (let i=0; i<chkM.length; i++) {
        sha256.update(encodePointForPRNG(chkM[i].point));
        sha256.update(encodePointForPRNG(chkZ[i]));
    }
    return sjcl.codec.hex.fromBits(sha256.finalize());
}

// Returns a decoded batch proof as a map
function retrieveProof(bp) {
    let dleqProof;
    try {
        dleqProof = parseDleqProof(atob(bp.P));
    } catch(e) {
        console.error(PARSE_ERR);
        return;
    }
    return dleqProof;
}

// Decode proof string and remove prefix
function getMarshaledBatchProof(proof) {
    let proofStr = atob(proof);
    if (proofStr.indexOf(BATCH_PROOF_PREFIX) === 0) {
        proofStr = proofStr.substring(BATCH_PROOF_PREFIX.length);
    }
    return JSON.parse(proofStr);
}

// Decode the proof that is sent into a map
//
// input: Marshaled proof string
// output: DLEQ proof
function parseDleqProof(proofStr) {
    const dleqProofM = JSON.parse(proofStr);
    let dleqProof = new Map();
    dleqProof.R = getBigNumFromB64(dleqProofM.R);
    dleqProof.C = getBigNumFromB64(dleqProofM.C);
    return dleqProof;
}

// Return a bignum from a base-64 encoded string
function getBigNumFromB64(b64Str) {
    let bits = sjcl.codec.base64.toBits(b64Str);
    return sjcl.bn.fromBits(bits);
}

// Return a big number from an array of bytes
function getBigNumFromBytes(bytes) {
    let bits = sjcl.codec.bytes.toBits(bytes);
    return sjcl.bn.fromBits(bits);
}

// Return a bignum from a hex string
function getBigNumFromHex(hex) {
    return sjcl.bn.fromBits(sjcl.codec.hex.toBits(hex));
}

// PRNG encode point
function encodePointForPRNG(point) {
    let hex = sjcl.codec.hex.fromBits(point.toBits());
    let newHex = UNCOMPRESSED_POINT_PREFIX + hex;
    return sjcl.codec.hex.toBits(newHex);
}