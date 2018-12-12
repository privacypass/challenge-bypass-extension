/**
 * h2Curve test
 * @author Alex Davidson
 */

import rewire from "rewire";
const workflow = rewire("../addon/compiled/test_compiled.js");
const sjcl = workflow.__get__("sjcl");
const h2Curve = workflow.__get__('h2Curve');
const h2Base = workflow.__get__('h2Base');
const jacobianSWUP256 = workflow.__get__('jacobianSWUP256');
const getP256Params = workflow.__get__('getP256Params');

const p256 = sjcl.ecc.curves.c256;
const FFp = p256.field;

describe('hashing to p256', () => {
  const byteLength = 32;
  const wordLength = byteLength / 4;
  test('affine', () => {
    for (let i=0; i<10; i++) {
      const random = sjcl.random.randomWords(wordLength, 10);
      const rndBits = sjcl.codec.bytes.toBits(random);
      const runH2C = function run() {
        h2Curve(rndBits, p256, 0);
      };
      expect(runH2C).not.toThrowError();
    }
  });

  test('projective', () => {
    for (let i=0; i<10; i++) {
      const random = sjcl.random.randomWords(wordLength, 10);
      const rndBits = sjcl.codec.bytes.toBits(random);
      const runH2C = function run() {
        h2Curve(rndBits, p256, 1);
      };
      expect(runH2C).not.toThrowError();
    }
  });

  describe('point at infinity', () => {
    test('t=0', () => {
      const params = getInputParams(0);
      const pJac = jacobianSWUP256(params.p, params.A, params.B, params.t);
      expect(pJac.z.equals(new FFp(0))).toBeTruthy();
    });

    test('t=1', () => {
      const params = getInputParams(1);
      const pJac = jacobianSWUP256(params.p, params.A, params.B, params.t);
      expect(pJac.z.equals(new FFp(0))).toBeTruthy();
    });

    test('t=-1', () => {
      const params = getInputParams(-1);
      const pJac = jacobianSWUP256(params.p, params.A, params.B, params.t);
      expect(pJac.z.equals(new FFp(0))).toBeTruthy();
    });
  });
});

/**
 * Creates P256 curve parameters and a value in FF_p
 * @param {int} t optional value in FF_p
 * @return {p;A;B;t} P256 params and an element in FF_p
 */
function getInputParams(t) {
  const params = getP256Params();
  let eleFFp;
  if (!t && t != 0) {
    const byteLength = 32;
    const wordLength = byteLength / 4; // SJCL 4 bytes to a word
    const random = sjcl.random.randomWords(wordLength, 10);
    const rndBits = sjcl.codec.bytes.toBits(random);
    eleFFp = h2Base(rndBits, p256, 'p256_hashing');
  } else {
    eleFFp = new FFp(t);
  }

  return {p: params.p, A: params.A, B: params.B, t: eleFFp};
}
