/**
 * Implements the methods of hashing to elliptic curves
 * that are described in draft-irtf-cfrg-hash-to-curve
 * @author Alex Davidson
 * TODO: make constant-time
 */

 /* global sjcl */
 /* exported h2Curve */

// compatible curves
const p256 = sjcl.ecc.curves.c256;
const FFp = p256.field;

/**
 * hashes bits to the base field (as described in
 * draft-irtf-cfrg-hash-to-curve)
 * @param {sjcl.bitArray} x bits of element to be translated
 * @param {sjcl.ecc.curve} curve elliptic curve
 * @param {string} label context label for domain separation
 * @return {int} integer in the base field of curve
 */
function h2Base(x, curve, label) {
  const curveName = sjcl.ecc.curveName(curve);
  const h = getHash(curveName);
  h.update("h2c");
  h.update(label);
  h.update(x);
  const t = h.finalize();
  const y = curve.field.fromBits(t).cnormalize();
  return y;
}

/**
 * hashes bits to the chosen elliptic curve
 * @param {sjcl.bitArray} alpha bits to be encoded onto curve
 * @param {sjcl.ecc.curve} curve elliptic curve
 * @param {int} mode indicates which algorithm mode should be used (if any)
 * @return {sjcl.ecc.point} point on curve
 */
function h2Curve(alpha, curve, mode) {
  const curveName = sjcl.ecc.curveName(curve);
  let point;
  switch (curveName) {
    case "c256":
      point = simplifiedSWU(alpha, mode);
      break;
    default:
      throw new Error("[privacy-pass]: Incompatible curve chosen for hashing: " + curveName);
  }
  return point;
}

/**
 * hashes bits onto affine P256 point using simplified SWU encoding algorithm
 * @param {sjcl.bitArray} alpha bits to be encoded
 * @param {int} mode 0 = affine, 1 = projective
 * @return {sjcl.ecc.point} point on P256
 */
function simplifiedSWU(alpha, mode) {
  const params = getP256Params();
  const p = params.p;
  const A = params.A;
  const B = params.B;
  const t = h2Base(alpha, p256, "p256_hashing");

  let point;
  switch (mode) {
    case 0:
      point = affineSWUP256(p, A, B, t);
      break;
    case 1:
      point = jacobianSWUP256(p, A, B, t);
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
 * @param {sjcl.curve.field.modulus} p curve modulus
 * @param {sjcl.bn} A Weierstrass coefficient for P256 curve
 * @param {sjcl.bn} B Weierstrass coefficient for P256 curve
 * @param {sjcl.bn} t FF_p field element
 * @return {sjcl.ecc.point} point on P256
 */
function affineSWUP256(p, A, B, t) {
  // step 1
  let u = t.square();
  u = u.mul(-1);

  // step 2
  let t0 = u.square().add(u);

  // step 3
  t0 = t0.inverseMod(p);

  // step 4
  t0 = t0.add(1);
  const invA = A.inverseMod(p);
  const minusBinvA = B.mul(invA).mul(-1);
  let X = new FFp(minusBinvA.mul(t0));

  // steps 5-8
  const g = X.mul(X.square().add(A)).add(B);

  // step 9
  const expo = p.add(1).cnormalize().halveM().halveM();
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
  return new sjcl.ecc.point(p256, X, Y);
}

/**
 * Converts field elements into jacobian coordinates on P256 (this is not
 * currently contained in the IETF draft but should be available soon)
 * @param {sjcl.curve.field.modulus} p curve modulus
 * @param {sjcl.bn} A Weierstrass coefficient for P256 curve
 * @param {sjcl.bn} B (see above)
 * @param {sjcl.bn} t FF_p field element
 * @return {sjcl.ecc.pointJac} Jacobian coordinates of a curve point
 */
function jacobianSWUP256(p, A, B, t) {
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
  Y = Y.power(p.sub(3).cnormalize().halveM().halveM());
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
  return new sjcl.ecc.pointJac(p256, X, Y, Z);
}

/**
 * returns the chosen hash function for each compatible EC
 * @param {string} curveName name of EC
 * @return {sjcl.hash} a hash function
 */
function getHash(curveName) {
  let h;
  switch (curveName) {
    case "c256":
      h = new sjcl.hash.sha256();
      break;
    default:
      throw new Error("[privacy-pass]: Incompatible curve chosen: " + curveName);
  }
  return h;
}

/**
 * Return the parameters for the p256 curve
 * @return {p;A;B}
 */
function getP256Params() {
  const p = p256.field.modulus;
  const a = p256.a;
  // a=-3, but must be reduced mod p; otherwise,
  // inverseMod function loops forever.
  a.fullReduce();
  const b = p256.b;
  return {p: p, A: a, B: b};
}