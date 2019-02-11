/**
 * Implements the methods of hashing to elliptic curves
 * that are described in draft-irtf-cfrg-hash-to-curve
 * @author Alex Davidson
 * Note: The SWU algorithm is constant-time except for the conditional checks in
 * the final two lines. The implementation follows a regular execution pattern.
 */

/* global sjcl */
/* exported h2Curve */

const SWU_POINT_REPRESENTATION = 0; // 0 = affine, 1 = jacobian
const H2C_SEED = sjcl.codec.hex.toBits("312e322e3834302e31303034352e332e312e3720706f696e742067656e65726174696f6e2073656564");

/**
 * hashes bits to the base field (as described in
 * draft-irtf-cfrg-hash-to-curve)
 * @param {sjcl.bitArray} x bits of element to be translated
 * @param {sjcl.ecc.curve} curve elliptic curve
 * @param {string} label context label for domain separation
 * @return {int} integer in the base field of curve
 */
function h2Base(x, curve, hash, label) {
  const h = new hash();
  h.update(label);
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
      point = simplifiedSWU(alpha, ecSettings.curve, ecSettings.hash, SWU_POINT_REPRESENTATION);
      break;
    case "increment":
      point = hashAndInc(alpha, ecSettings.curve, ecSettings.hash);
      break;
    default:
      throw new Error("[privacy-pass]: Incompatible curve chosen for hashing, SJCL chosen curve: " + sjcl.ecc.curveName(ecSettings.curve));
  }
  return point;
}

/**
 * hashes bits onto affine P256 point using simplified SWU encoding algorithm
 * @param {sjcl.bitArray} alpha bits to be encoded
 * @param {sjcl.ecc.curve} activeCurve elliptic curve
 * @param {sjcl.hash} hash hash function for hashing bytes to base field
 * @param {int} mode 0 = affine, 1 = projective
 * @return {sjcl.ecc.point} point on P256
 */
function simplifiedSWU(alpha, activeCurve, hash, mode) {
  const params = getCurveParams(activeCurve);
  const t = h2Base(alpha, activeCurve, hash, H2C_SEED);

  let point;
  switch (mode) {
    case 0:
      point = affineSWUP256(activeCurve, params.baseField, params.A, params.B, t);
      break;
    case 1:
      point = jacobianSWUP256(activeCurve, params.baseField, params.A, params.B, t);
      break;
    default:
      throw new Error("[privacy-pass]: Incompatible mode type chosen for SWU");
  }

  if (!point.isValid()) {
    throw new Error("[privacy-pass]: Generated point is not on curve");
  }

  return point;
}

/**
 * Converts field elements into an affine pair of coordinates on P256
 * This is an optimised version of the algorithm found here:
 * https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-02#section-5.2.3
 * @param {sjcl.ecc.curve} activeCurve elliptic curve
 * @param {sjcl.ecc.curve.field} FFp base field for curve
 * @param {sjcl.bn} A Weierstrass coefficient for P256 curve
 * @param {sjcl.bn} B Weierstrass coefficient for P256 curve
 * @param {sjcl.bn} t FF_p field element
 * @return {sjcl.ecc.point} point on P256
 */
function affineSWUP256(activeCurve, FFp, A, B, t) {
  // step 1
  let u = t.square();
  u = u.mul(-1);

  // step 2
  let t0 = u.square().add(u);

  // step 3
  t0 = t0.inverseMod(FFp.modulus);

  // step 4
  t0 = t0.add(1);
  const invA = A.inverseMod(FFp.modulus);
  const minusBinvA = B.mul(invA).mul(-1);
  let X = new FFp(minusBinvA.mul(t0));

  // steps 5-8
  const g = X.mul(X.square().add(A)).add(B);

  // step 9
  const expo = FFp.modulus.add(1).cnormalize().halveM().halveM();
  let Y = new FFp(g.power(expo));

  // step 10
  const d0 = Y.square();

  // steps 11 - 14
  const b = g.equals(d0);
  const uX = u.mul(X);
  const t3Y = t.power(3).mul(Y); // p+1/4 is even for P256
  X = b ? X : uX;
  Y = b ? Y : t3Y;

  // step 15
  return new sjcl.ecc.point(activeCurve, X, Y);
}

/**
 * Converts field elements into jacobian coordinates on P256 (this is not
 * currently contained in the IETF draft but should be available soon)
 * @param {sjcl.ecc.curve} activeCurve elliptic curve
 * @param {sjcl.ecc.curve.field} FFp base field for curve
 * @param {sjcl.bn} A Weierstrass coefficient for P256 curve
 * @param {sjcl.bn} B (see above)
 * @param {sjcl.bn} t FF_p field element
 * @return {sjcl.ecc.pointJac} Jacobian coordinates of a curve point
 */
function jacobianSWUP256(activeCurve, FFp, A, B, t) {
  // calculate X/Z
  let u = t.square();
  u = u.mul(-1);
  let Z = new FFp(u.square().add(u));
  let X = new FFp(B.mul(Z.add(1)));
  Z = A.mul(Z).mul(-1);

  // calculate g0/g1
  const t0 = X.square();
  const t1 = Z.square();
  const g1 = t1.mul(Z);
  const t2 = g1.mul(B);
  let g0 = t1.mul(A);
  g0 = g0.add(t0);
  g0 = g0.mul(X);
  g0 = g0.add(t2);

  // calculate Y = \sqrt(g0/g1)
  let d0 = g0.mul(g1);
  const d1 = g1.square();
  const d2 = d0.mul(d1);
  let Y = new FFp(d2);
  Y = Y.power(FFp.modulus.sub(3).cnormalize().halveM().halveM());
  Y = Y.mul(d0);
  d0 = Y.square().mul(g1);

  // Verify value of Y^2
  const b = d0.equals(new FFp(g0)); // need this FFp for check
  const uX = u.mul(X);
  const tuY = t.mul(u).mul(Y); // (p+1)/4 is always even for P256
  X = b ? X : uX;
  Y = b ? Y : tuY;

  // Jac coordinates
  X = X.mul(Z);
  Y = g1.mul(Y);

  // Curve point
  return new sjcl.ecc.pointJac(activeCurve, X, Y, Z);
}

/**
 * Return the parameters for the active curve
 * @param {sjcl.ecc.curve} curve elliptic curve
 * @return {p;A;B}
 */
function getCurveParams(curve) {
  if (sjcl.ecc.curveName(curve) !== "c256") {
    throw new Error("[privacy-pass]: Incompatible curve chosen for H2C: " + sjcl.ecc.curveName(curve));
  }

  const FFp = curve.field;
  const a = curve.a;
  // a=-3, but must be reduced mod p; otherwise,
  // inverseMod function loops forever.
  a.fullReduce();
  const b = curve.b;
  return {baseField: FFp, A: a, B: b};
}

/**
 * DEPRECATED: Method for hashing to curve based on the principal of attempting
 * to hash the bytes multiple times and recover a curve point. Has non-negligble
 * probailistic failure conditions.
 * @param {sjcl.codec.bitArray} seed
 * @param {sjcl.ecc.curve} curve elliptic curve
 * @param {sjcl.hash} hash hash function for hashing bytes to base field
 */
function hashAndInc(seed, curve, hash) {
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
    let ctr = new Uint8Array(4);
    // typecast hack: number -> Uint32, bitwise Uint8
    ctr[0] = (i >>> 0) & 0xFF;
    let ctrBits = sjcl.codec.bytes.toBits(ctr);

    // H(s||ctr)
    h.update(seed);
    h.update(ctrBits);

    const digestBits = h.finalize();

    let point = decompressPoint(digestBits, curve, 0x02);
    if (point !== null) {
      return point;
    }

    point = decompressPoint(digestBits, curve, 0x03);
    if (point !== null) {
      return point;
    }

    seed = digestBits;
    h.reset();
  }

  return null;
}