/**
 * Implements the methods of hashing to elliptic curves
 * that are described in draft-irtf-cfrg-hash-to-curve
 * @author Alex Davidson
 * Note: The SWU algorithm is constant-time except for the conditional checks in
 * the final two lines. The implementation follows a regular execution pattern.
 */

/* global sjcl */
/* exported h2Curve */

let H2C_SEED = sjcl.codec.hex.toBits("312e322e3834302e31303034352e332e312e3720706f696e742067656e65726174696f6e2073656564");
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
    for (let i=n-1; i>-1; i--) {
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
 * @param {literal} ecSettings the curve settings being used by the extension
 * @return {sjcl.ecc.point} point on curve
 */
function h2Curve(alpha, ecSettings) {
    let point;
    switch (ecSettings.method) {
        case "swu":
            point = simplifiedSWU(alpha, ecSettings.curve, ecSettings.hash);
            break;
        case "increment":
            point = hashAndInc(alpha, ecSettings.hash);
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
 * @return {sjcl.ecc.point} curve point
 */
function simplifiedSWU(alpha, activeCurve, hash) {
    const params = getCurveParams(activeCurve);
    const u = h2Base(alpha, activeCurve, hash, H2C_SEED);
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
    const t1 = u.square().mul(-1); // step 2
    const t2 = t1.square(); // step 3
    let x1 = t2.add(t1); // step 4
    x1 = x1.inverse(); // step 5
    x1 = x1.add(1); // step 6
    x1 = x1.mul(c1); // step 7

    let gx1 = x1.square().mod(p); // step 8
    gx1 = gx1.add(A); // step 9
    gx1 = gx1.mul(x1); // step 10
    gx1 = gx1.add(B); // step 11
    gx1 = gx1.mod(p);

    const x2 = t1.mul(x1); // step 12
    let gx2 = x2.square().mod(p); // step 13
    gx2 = gx2.add(A); // step 14
    gx2 = gx2.mul(x2); // step 15
    gx2 = gx2.add(B); // step 16
    gx2 = gx2.mod(p);

    const e = new baseField(gx1.montpowermod(c2, p)).equals(new sjcl.bn(1)); // step 17
    let X = x1; // step 18
    let gx = gx1;
    if (!e) {
        X = x2; // step 19
        gx = gx2;
    }
    X = X.mod(p);
    const Y = gx.montpowermod(sqrt, p); // step 21

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
 * @param {sjcl.codec.bitArray} seed
 * @param {sjcl.hash} hash hash function for hashing bytes to base field
 * @return {sjcl.ecc.point} returns a curve point on the active curve
 */
function hashAndInc(seed, hash) {
    const h = new hash();

    // Need to match the Go curve hash, so we decode the exact bytes of the
    // string "1.2.840.100045.3.1.7 point generation seed" instead of relying
    // on the utf8 codec that didn't match.
    const separator = H2C_SEED;

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
