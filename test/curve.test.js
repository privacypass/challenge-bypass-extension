/**
 * h2Curve test
 * @author Alex Davidson
 */

import rewire from "rewire";
const workflow = rewire("../addon/compiled/test_compiled.js");
const sjcl = workflow.__get__("sjcl");
const h2Curve = workflow.__get__('h2Curve');
const h2Base = workflow.__get__('h2Base');
const simplifiedSWU = workflow.__get__('simplifiedSWU');
const hashAndInc = workflow.__get__('hashAndInc');
const jacobianSWUP256 = workflow.__get__('jacobianSWUP256');
const ACTIVE_CONFIG = workflow.__get__('ACTIVE_CONFIG');
const setConfig = workflow.__get__('setConfig');
const getActiveECSettings = workflow.__get__('getActiveECSettings');
const initECSettings = workflow.__get__('initECSettings');
const getCurveParams = workflow.__get__('getCurveParams');
const newRandomPoint = workflow.__get__('newRandomPoint');
const compressPoint = workflow.__get__('compressPoint');
const decompressPoint = workflow.__get__('decompressPoint');

/**
 * Mocking
 */
let getMock = jest.fn();
let updateIconMock = jest.fn();
let clearCachedCommitmentsMock = jest.fn();
workflow.__set__("get", getMock);
workflow.__set__("updateIcon", updateIconMock);
workflow.__set__("clearCachedCommitments", clearCachedCommitmentsMock);
workflow.__set__("console", { error: jest.fn() });

/**
 * Configuration
 */
let curve;
let hash;
let activeCurveParams;
beforeEach(() => {
  setConfig(1);
  let settings = getActiveECSettings();
  curve = settings.curve;
  hash = settings.hash;
  activeCurveParams = ACTIVE_CONFIG["h2c-params"];
});

describe('check curve initialisation', () => {
  test('check with current config', () => {
    function run() {
      return initECSettings(activeCurveParams);
    }
    expect(run).not.toThrowError();
  });

  test('check with swu config', () => {
    activeCurveParams["method"] = "swu";
    function run() {
      return initECSettings(activeCurveParams);
    }
    expect(run).not.toThrowError();
  });

  test('with bad curve', () => {
    activeCurveParams["curve"] = "25519";
    function run() {
      return initECSettings(activeCurveParams);
    }
    expect(run).toThrowError();
  });

  test('with bad hash', () => {
    activeCurveParams["hash"] = "sha512";
    function run() {
      return initECSettings(activeCurveParams);
    }
    expect(run).toThrowError();
  });

  test('with bad method', () => {
    activeCurveParams["method"] = "elligator";
    function run() {
      return initECSettings(activeCurveParams);
    }
    expect(run).toThrowError();
  });
});

describe('check curve parameters are correct', () => {
  test('p256', () => {
    let curveP256 = sjcl.ecc.curves.c256;
    function run() {
      return getCurveParams(curve);
    }
    let cParams = run();
    expect(curveP256.field.modulus === cParams.baseField.modulus).toBeTruthy();
    expect(curveP256.a === cParams.A).toBeTruthy();
    expect(curveP256.b === cParams.B).toBeTruthy();
  });

  test('bad curve', () => {
    function run() {
      curve = sjcl.ecc.curves.c192;
      return getCurveParams(curve);
    }
    expect(run).toThrowError();
  });
});

describe('hashing to p256', () => {
  const byteLength = 32;
  const wordLength = byteLength / 4;
  test('affine', () => {
    for (let i=0; i<10; i++) {
      const random = sjcl.random.randomWords(wordLength, 10);
      const rndBits = sjcl.codec.bytes.toBits(random);
      const runH2C = function run() {
        simplifiedSWU(rndBits, curve, hash, 0);
      };
      expect(runH2C).not.toThrowError();
    }
  });

  test('jacobian', () => {
    for (let i=0; i<10; i++) {
      const random = sjcl.random.randomWords(wordLength, 10);
      const rndBits = sjcl.codec.bytes.toBits(random);
      const runH2C = function run() {
        simplifiedSWU(rndBits, curve, hash, 1);
      };
      expect(runH2C).not.toThrowError();
    }
  });

  test('hash-and-increment', () => {
    for (let i=0; i<10; i++) {
      const random = sjcl.random.randomWords(wordLength, 10);
      const rndBits = sjcl.codec.bytes.toBits(random);
      const runH2C = function run() {
        hashAndInc(rndBits, curve, hash);
      };
      expect(runH2C).not.toThrowError();
    }
  });

  test('h2c with increment settings', () => {
    for (let i=0; i<10; i++) {
      const random = sjcl.random.randomWords(wordLength, 10);
      const rndBits = sjcl.codec.bytes.toBits(random);
      const runH2C = function run() {
        h2Curve(rndBits, getActiveECSettings());
      };
      expect(runH2C).not.toThrowError();
    }
  });

  test('h2c with swu settings', () => {
    for (let i=0; i<10; i++) {
      const random = sjcl.random.randomWords(wordLength, 10);
      const rndBits = sjcl.codec.bytes.toBits(random);
      const runH2C = function run() {
        ACTIVE_CONFIG["method"] = "swu"
        h2Curve(rndBits, getActiveECSettings());
      };
      expect(runH2C).not.toThrowError();
    }
  }); 

  describe('point at infinity', () => {
    test('t=0', () => {
      const params = getInputParams(0);
      const pJac = jacobianSWUP256(curve, params.baseField, params.A, params.B, params.t);
      expect(pJac.z.equals(new params.baseField(0))).toBeTruthy();
    });

    test('t=1', () => {
      const params = getInputParams(1);
      const pJac = jacobianSWUP256(curve, params.baseField, params.A, params.B, params.t);
      expect(pJac.z.equals(new params.baseField(0))).toBeTruthy();
    });

    test('t=-1', () => {
      const params = getInputParams(-1);
      const pJac = jacobianSWUP256(curve, params.baseField, params.A, params.B, params.t);
      expect(pJac.z.equals(new params.baseField(0))).toBeTruthy();
    });
  });
});

describe('point compression/decompression', () => {
  test('random point', () => {
    let P = newRandomPoint().point;
    let b64 = compressPoint(P);
    let bytes = sjcl.codec.bytes.fromBits(sjcl.codec.base64.toBits(b64));
    let newP = decompressPoint(bytes, curve);
    expect(P.x.equals(newP.x)).toBeTruthy();
    expect(P.y.equals(newP.y)).toBeTruthy();
  });
});

/**
 * Creates P256 curve parameters and a value in FF_p
 * @param {int} t optional value in FF_p
 * @return {p;A;B;t} P256 params and an element in FF_p
 */
function getInputParams(t) {
  const params = getCurveParams(curve);
  let eleFFp;
  if (!t && t != 0) {
    const byteLength = 32;
    const wordLength = byteLength / 4; // SJCL 4 bytes to a word
    const random = sjcl.random.randomWords(wordLength, 10);
    const rndBits = sjcl.codec.bytes.toBits(random);
    eleFFp = h2Base(rndBits, p256, 'p256_hashing');
  } else {
    eleFFp = new params.baseField(t);
  }

  return {baseField: params.baseField, A: params.A, B: params.B, t: eleFFp};
}
