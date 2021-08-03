/**
 * This implements a 2HashDH-based token scheme using the SJCL ecc package.
 *
 * @author: George Tankersley
 * @author: Alex Davidson
 */

const sjcl = require('sjcl');
require('asn1-parser');

let PEM;
let ASN1;
if (typeof window !== "undefined") {
    PEM = window.PEM;
    ASN1 = window.ASN1;
}

let shake256 = () => {
    return createShake256();
};

const BATCH_PROOF_PREFIX = "batch-proof=";
const MASK = ["0xff", "0x1", "0x3", "0x7", "0xf", "0x1f", "0x3f", "0x7f"];

const DIGEST_INEQUALITY_ERR = "[privacy-pass]: Recomputed digest does not equal received digest";
const PARSE_ERR = "[privacy-pass]: Error parsing proof";

// Globals for keeping track of EC curve settings
let CURVE;
let CURVE_H2C_HASH;
let CURVE_H2C_METHOD;
let CURVE_H2C_LABEL;

// 1.2.840.10045.3.1.7 point generation seed
const INC_H2C_LABEL = sjcl.codec.hex.toBits("312e322e3834302e31303034352e332e312e3720706f696e742067656e65726174696f6e2073656564");
const SSWU_H2C_LABEL = "H2C-P256-SHA256-SSWU-";

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
            CURVE_H2C_LABEL = methodStr === "increment" ? INC_H2C_LABEL : SSWU_H2C_LABEL;
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
    return {curve: CURVE, hash: CURVE_H2C_HASH, method: CURVE_H2C_METHOD, label: CURVE_H2C_LABEL};
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
    const random = crypto.getRandomValues(new Int32Array(8)); // TODO Use webcrypto instead.

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
    const expLength = CURVE.r.bitLength() / 8 + 1; // bitLength rounds up
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

// Commitments verification

/**
 * Parse a PEM-encoded signature.
 * @param {string} pemSignature - A signature in PEM format.
 * @return {sjcl.bitArray} a signature object for sjcl library.
 */
function parseSignaturefromPEM(pemSignature) {
    try {
        const bytes = PEM.parseBlock(pemSignature);
        const json = ASN1.parse(bytes.der);
        const r = sjcl.codec.bytes.toBits(json.children[0].value);
        const s = sjcl.codec.bytes.toBits(json.children[1].value);
        return sjcl.bitArray.concat(r, s);
    } catch (e) {
        throw new Error(
            "[privacy-pass]: Failed on parsing commitment signature. " + e.message,
        );
    }
}

/**
 * Parse a PEM-encoded public key.
 * @param {string} pemPublicKey - A public key in PEM format.
 * @return {sjcl.ecc.ecdsa.publicKey} a public key for sjcl library.
 */
function parsePublicKeyfromPEM(pemPublicKey) {
    try {
        let bytes = PEM.parseBlock(pemPublicKey);
        let json = ASN1.parse(bytes.der);
        let xy = json.children[1].value;
        const point = sec1DecodeFromBytes(xy);
        return new sjcl.ecc.ecdsa.publicKey(CURVE, point);
    } catch (e) {
        throw new Error(
            "[privacy-pass]: Failed on parsing public key. " + e.message,
        );
    }
}

/**
 * Verify the signature of the retrieved configuration portion.
 * @param {Number} cfgId - ID of configuration being used.
 * @param {json} config - commitments to verify
 * @return {boolean} True, if the commitment has valid signature and is not
 *                   expired; otherwise, throws an exception.
 */
function verifyConfiguration(publicKey, config, signature) {
    const sig = parseSignaturefromPEM(signature);
    const msg = JSON.stringify(config);
    const pk = parsePublicKeyfromPEM(publicKey);
    const hmsg = sjcl.hash.sha256.hash(msg);
    try {
        return pk.verify(hmsg, sig);
    } catch (error) {
        throw new Error("[privacy-pass]: Invalid configuration verification.");
    }
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
            prng.func = shake256();
            prng.func.update(seed, "hex");
            break;
        case "hkdf":
            prng.func = evaluateHkdf;
            break;
        default:
            throw new Error(`Server specified PRNG is not compatible: ${prng.name}`);
    }
    let iter = -1;
    for (let i = 0; i < tokens.length; i++) {
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
            out = sjcl.codec.hex.fromBits(prng.func(sjcl.codec.hex.toBits(seed), bitLen / 8, sjcl.codec.utf8String.toBits("DLEQ_PROOF"), salt, CURVE_H2C_HASH));
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
    for (let i = 0; i < chkM.length; i++) {
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

    const hashLength = Math.ceil(sjcl.bitArray.bitLength(prk) / 8);
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
            sjcl.codec.utf8String.toBits((String.fromCharCode(i + 1))),
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

const p256Curve = sjcl.ecc.curves.c256;
const precomputedP256 = {
    // a=-3, but must be reduced mod p for P256; otherwise,
    // inverseMod function loops forever.
    A: p256Curve.a.fullReduce(),
    B: p256Curve.b,
    baseField: p256Curve.field,
    c1: p256Curve.b.mul(-1).mul(p256Curve.a.inverseMod(p256Curve.field.modulus)),
    c2: p256Curve.field.modulus.sub(1).cnormalize().halveM(),
    sqrt: p256Curve.field.modulus.add(1).cnormalize().halveM().halveM(),
};

/**
 * Converts the number x into a byte array of length n
 * @param {Number} x
 * @param {Number} n
 * @return {sjcl.codec.bytes}
 */
function i2osp(x, n) {
    const bytes = [];
    for (let i = n - 1; i > -1; i--) {
        bytes[i] = x & 0xff;
        x = x >> 8;
    }

    if (x > 0) {
        throw new Error(`[privacy-pass]: number to convert (${x}) is too long for ${n} bytes.`);
    }
    return bytes;
}

/**
 * hashes bits to the base field (as described in
 * draft-irtf-cfrg-hash-to-curve)
 * @param {sjcl.bitArray} x bits of element to be translated
 * @param {sjcl.ecc.curve} curve elliptic curve
 * @param {sjcl.hash} hash hash function object
 * @param {string} label context label for domain separation
 * @return {int} integer in the base field of curve
 */
function h2Base(x, curve, hash, label) {
    const dataLen = sjcl.codec.bytes.fromBits(x).length;
    const h = new hash();
    h.update("h2b");
    h.update(label);
    h.update(sjcl.codec.bytes.toBits(i2osp(dataLen, 4)));
    h.update(x);
    const t = h.finalize();
    const y = curve.field.fromBits(t).cnormalize();
    return y;
}

/**
 * hashes bits to the chosen elliptic curve
 * @param {sjcl.bitArray} alpha bits to be encoded onto curve
 * @param {Object} ecSettings the curve settings being used by the extension
 * @return {sjcl.ecc.point} point on curve
 */
function h2Curve(alpha, ecSettings) {
    let point;
    switch (ecSettings.method) {
        case "swu":
            point = simplifiedSWU(alpha, ecSettings.curve, ecSettings.hash, ecSettings.label);
            break;
        case "increment":
            point = hashAndInc(alpha, ecSettings.hash, ecSettings.label);
            break;
        default:
            throw new Error("[privacy-pass]: Incompatible curve chosen for hashing, SJCL chosen curve: " + sjcl.ecc.curveName(ecSettings.curve));
    }
    return point;
}

/**
 * hashes bits onto affine curve point using simplified SWU encoding algorithm
 * Not constant-time due to conditional check
 * @param {sjcl.bitArray} alpha bits to be encoded
 * @param {sjcl.ecc.curve} activeCurve elliptic curve
 * @param {sjcl.hash} hash hash function for hashing bytes to base field
 * @param {String} label
 * @return {sjcl.ecc.point} curve point
 */
function simplifiedSWU(alpha, activeCurve, hash, label) {
    const params = getCurveParams(activeCurve);
    const u = h2Base(alpha, activeCurve, hash, label);
    const {X, Y} = computeSWUCoordinates(u, params);
    const point = new sjcl.ecc.point(activeCurve, X, Y);
    if (!point.isValid()) {
        throw new Error(`[privacy-pass]: Generated point is not on curve, X: ${X}, Y: ${Y}`);
    }
    return point;
}

/**
 * Compute (X,Y) coordinates from integer u
 * Operations taken from draft-irtf-cfrg-hash-to-curve.txt at commit
 * cea8485220812a5d371deda25b5eca96bd7e6c0e
 * @param {sjcl.bn} u integer to map
 * @param {Object} params curve parameters
 * @return {Object} curve coordinates
 */
function computeSWUCoordinates(u, params) {
    const {A, B, baseField, c1, c2, sqrt} = params;
    const p = baseField.modulus;
    const t1 = u.square().mul(-1); // steps 2-3
    const t2 = t1.square(); // step 4
    let x1 = t2.add(t1); // step 5
    x1 = x1.inverse(); // step 6
    x1 = x1.add(1); // step 7
    x1 = x1.mul(c1); // step 8

    let gx1 = x1.square().mod(p); // steps 9-12
    gx1 = gx1.add(A);
    gx1 = gx1.mul(x1);
    gx1 = gx1.add(B);
    gx1 = gx1.mod(p);

    const x2 = t1.mul(x1); // step 13
    let gx2 = x2.square().mod(p); // step 14-17
    gx2 = gx2.add(A);
    gx2 = gx2.mul(x2);
    gx2 = gx2.add(B);
    gx2 = gx2.mod(p);

    const e = new baseField(gx1.powermod(c2, p)).equals(new sjcl.bn(1)); // step 18
    const X = cmov(x2, x1, e, baseField); // step 19
    const gx = cmov(gx2, gx1, e, baseField); // step 20
    let y1 = gx.powermod(sqrt, p); // step 21
    // choose the positive (the smallest) root
    const r = c2.greaterEquals(y1);
    let y2 = y1.mul(-1).mod(p);
    const Y = cmov(y2, y1, r, baseField);
    return {X: X, Y: Y};
}

/**
 * Return the parameters for the active curve
 * @param {sjcl.ecc.curve} curve elliptic curve
 * @return {p;A;B}
 */
function getCurveParams(curve) {
    let curveParams;
    switch (sjcl.ecc.curveName(curve)) {
        case "c256":
            curveParams = precomputedP256;
            break;
        default:
            throw new Error("[privacy-pass]: Incompatible curve chosen for H2C: " + sjcl.ecc.curveName(curve));
    }
    return curveParams;
}

/**
 * DEPRECATED: Method for hashing to curve based on the principal of attempting
 * to hash the bytes multiple times and recover a curve point. Has non-negligble
 * probailistic failure conditions.
 * @param {sjcl.bitArray} seed
 * @param {sjcl.hash} hash hash function for hashing bytes to base field
 * @param {sjcl.bitArray} label
 * @return {sjcl.ecc.point} returns a curve point on the active curve
 */
function hashAndInc(seed, hash, label) {
    const h = new hash();

    // Need to match the Go curve hash, so we decode the exact bytes of the
    // string "1.2.840.100045.3.1.7 point generation seed" instead of relying
    // on the utf8 codec that didn't match.
    const separator = label;

    h.update(separator);

    let i = 0;
    // Increased increments to decrease chance of failure
    for (i = 0; i < 20; i++) {
        // little endian uint32
        const ctr = new Uint8Array(4);
        // typecast hack: number -> Uint32, bitwise Uint8
        ctr[0] = (i >>> 0) & 0xFF;
        const ctrBits = sjcl.codec.bytes.toBits(ctr);

        // H(s||ctr)
        h.update(seed);
        h.update(ctrBits);

        const digestBits = h.finalize();
        const bytes = sjcl.codec.bytes.fromBits(digestBits);

        // attempt to decompress a point with a valid tag (don't need to try
        // 0x03 because this is just the negative version)
        // curve choice is implicit based on active curve parameters
        const point = sec1DecodeFromBytes([2].concat(bytes));
        if (point !== null) {
            return point;
        }

        seed = digestBits;
        h.reset();
    }

    throw new Error("Unable to construct point using hash and increment");
}

/**
 * Conditional move selects x or y depending on the bit input.
 * @param {sjcl.bn} x is a big number
 * @param {sjcl.bn} y is a big number
 * @param {boolean} b is a bit
 * @param {sjcl.bn} field is the prime field used.
 * @return {sjcl.bn} returns x is b=0, otherwise return y.
 */
function cmov(x, y, b, field) {
    let z = new field();
    const m = z.radixMask;
    const m0 = m & (m + b);
    const m1 = m & (m + (!b));
    x.fullReduce();
    y.fullReduce();
    for (let i = Math.max(x.limbs.length, y.limbs.length) - 1; i >= 0; i--) {
        z.limbs.unshift((x.getLimb(i) & m0) ^ (y.getLimb(i) & m1));
    }
    return z.mod(field.modulus);
}

function newBigNum(s) {
    return new sjcl.bn(s);
}

/**
 * Derives the shared key used for redemption MACs
 * @param {sjcl.ecc.point} N Signed curve point associated with token
 * @param {Object} token client-generated token data
 * @return {sjcl.codec.bytes} bytes of derived key
 */
function deriveKey(N, token) {
    // the exact bits of the string "hash_derive_key"
    const tagBits = sjcl.codec.hex.toBits("686173685f6465726976655f6b6579");
    const hash = getActiveECSettings().hash;
    const h = new sjcl.misc.hmac(tagBits, hash);

    // Always compute derived key using uncompressed point bytes
    const encodedPoint = sec1Encode(N, false);
    const tokenBits = sjcl.codec.bytes.toBits(token);
    const pointBits = sjcl.codec.bytes.toBits(encodedPoint);

    h.update(tokenBits);
    h.update(pointBits);

    const keyBytes = sjcl.codec.bytes.fromBits(h.digest());
    return keyBytes;
}

function getBytesFromString(str) {
    const bits = sjcl.codec.utf8String.toBits(str);
    const bytes = sjcl.codec.bytes.fromBits(bits);
    return bytes;
}

function getBase64FromBytes(bytes) {
    const bits = sjcl.codec.bytes.toBits(bytes);
    const encoded = sjcl.codec.base64.fromBits(bits);
    return encoded;
}

function getBase64FromString(str) {
    const bits = sjcl.codec.utf8String.toBits(str);
    const encoded = sjcl.codec.base64.fromBits(bits);
    return encoded;
}

function createRequestBinding(key, data) {
    // the exact bits of the string "hash_request_binding"
    const tagBits = sjcl.codec.utf8String.toBits("hash_request_binding");
    const keyBits = sjcl.codec.bytes.toBits(key);
    const hash = getActiveECSettings().hash;

    const h = new sjcl.misc.hmac(keyBits, hash);
    h.update(tagBits);

    let dataBits = null;
    for (let i = 0; i < data.length; i++) {
        dataBits = sjcl.codec.bytes.toBits(data[i]);
        h.update(dataBits);
    }

    return sjcl.codec.base64.fromBits(h.digest());
}

module.exports = {
    blindPoint,
    deriveKey,
    createRequestBinding,
    getActiveECSettings,
    getBigNumFromBytes,
    getBase64FromBytes,
    getBase64FromString,
    getBytesFromString,
    getCurvePoints,
    initECSettings,
    newBigNum,
    newRandomPoint,
    sec1DecodeFromBase64,
    sec1DecodeFromBytes,
    sec1Encode,
    sec1EncodeToBase64,
    shake256,
    unblindPoint,
    verifyConfiguration,
    verifyProof,
};
