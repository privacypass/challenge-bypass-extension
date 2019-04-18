/**
 * h2Curve test
 * @author Alex Davidson
 */


const workflow = workflowSet();

const sjcl = workflow.__get__("sjcl");
const h2Curve = workflow.__get__("h2Curve");
const h2Base = workflow.__get__("h2Base");
const simplifiedSWU = workflow.__get__("simplifiedSWU");
const hashAndInc = workflow.__get__("hashAndInc");
const jacobianSWUP256 = workflow.__get__("jacobianSWUP256");
const activeConfig = workflow.__get__("activeConfig");
const setConfig = workflow.__get__("setConfig");
const getActiveECSettings = workflow.__get__("getActiveECSettings");
const initECSettings = workflow.__get__("initECSettings");
const getCurveParams = workflow.__get__("getCurveParams");
const newRandomPoint = workflow.__get__("newRandomPoint");
const sec1Encode = workflow.__get__("sec1Encode");
const sec1EncodeToBase64 = workflow.__get__("sec1EncodeToBase64");
const sec1DecodeFromBytes = workflow.__get__("sec1DecodeFromBytes");
const sec1DecodeFromBase64 = workflow.__get__("sec1DecodeFromBase64");

/**
 * Configuration
 */
let curve;
let hash;
let activeCurveParams;
beforeEach(() => {
    setConfig(1);
    const settings = getActiveECSettings();
    curve = settings.curve;
    hash = settings.hash;
    activeCurveParams = {curve: "p256", hash: "sha256", method: "increment"};
});

describe("check curve initialisation", () => {
    test("check with current config", () => {
        function run() {
            return initECSettings(activeCurveParams);
        }
        expect(run).not.toThrowError();
    });
    test("check with swu config", () => {
        activeCurveParams["method"] = "swu";
        function run() {
            return initECSettings(activeCurveParams);
        }
        expect(run).not.toThrowError();
    });
    test("with bad curve", () => {
        activeCurveParams["curve"] = "25519";
        function run() {
            return initECSettings(activeCurveParams);
        }
        expect(run).toThrowError();
    });
    test("with bad hash", () => {
        activeCurveParams["hash"] = "sha512";
        function run() {
            return initECSettings(activeCurveParams);
        }
        expect(run).toThrowError();
    });
    test("with bad method", () => {
        activeCurveParams["method"] = "elligator";
        function run() {
            return initECSettings(activeCurveParams);
        }
        expect(run).toThrowError();
    });
});

describe("check curve parameters are correct", () => {
    test("p256", () => {
        const curveP256 = sjcl.ecc.curves.c256;
        function run() {
            return getCurveParams(curve);
        }
        const cParams = run();
        expect(curveP256.field.modulus === cParams.baseField.modulus).toBeTruthy();
        expect(curveP256.a === cParams.A).toBeTruthy();
        expect(curveP256.b === cParams.B).toBeTruthy();
    });
    test("bad curve", () => {
        function run() {
            curve = sjcl.ecc.curves.c192;
            return getCurveParams(curve);
        }
        expect(run).toThrowError();
    });
});

describe("hashing to p256", () => {
    const byteLength = 32;
    const wordLength = byteLength / 4;
    test("affine", () => {
        for (let i = 0; i < 10; i++) {
            const random = sjcl.random.randomWords(wordLength, 10);
            const rndBits = sjcl.codec.bytes.toBits(random);
            const runH2C = function run() {
                simplifiedSWU(rndBits, curve, hash, 0);
            };
            expect(runH2C).not.toThrowError();
        }
    });
    test("jacobian", () => {
        for (let i = 0; i < 10; i++) {
            const random = sjcl.random.randomWords(wordLength, 10);
            const rndBits = sjcl.codec.bytes.toBits(random);
            const runH2C = function run() {
                simplifiedSWU(rndBits, curve, hash, 1);
            };
            expect(runH2C).not.toThrowError();
        }
    });
    test("hash-and-increment no errors", () => {
        for (let i = 0; i < 10; i++) {
            const random = sjcl.random.randomWords(wordLength, 10);
            const rndBits = sjcl.codec.bytes.toBits(random);
            const runH2C = function run() {
                hashAndInc(rndBits, hash);
            };
            expect(runH2C).not.toThrowError();
        }
    });
    test("h2c with increment settings", () => {
        for (let i = 0; i < 10; i++) {
            const random = sjcl.random.randomWords(wordLength, 10);
            const rndBits = sjcl.codec.bytes.toBits(random);
            const runH2C = function run() {
                h2Curve(rndBits, getActiveECSettings());
            };
            expect(runH2C).not.toThrowError();
        }
    });
    test("h2c with swu settings", () => {
        for (let i = 0; i < 10; i++) {
            const random = sjcl.random.randomWords(wordLength, 10);
            const rndBits = sjcl.codec.bytes.toBits(random);
            const runH2C = function run() {
                activeConfig()["method"] = "swu";
                h2Curve(rndBits, getActiveECSettings());
            };
            expect(runH2C).not.toThrowError();
        }
    });
    describe("point at infinity", () => {
        test("t=0", () => {
            const params = getInputParams(0);
            const pJac = jacobianSWUP256(curve, params.baseField, params.A, params.B, params.t);
            expect(pJac.z.equals(new params.baseField(0))).toBeTruthy();
        });

        test("t=1", () => {
            const params = getInputParams(1);
            const pJac = jacobianSWUP256(curve, params.baseField, params.A, params.B, params.t);
            expect(pJac.z.equals(new params.baseField(0))).toBeTruthy();
        });

        test("t=-1", () => {
            const params = getInputParams(-1);
            const pJac = jacobianSWUP256(curve, params.baseField, params.A, params.B, params.t);
            expect(pJac.z.equals(new params.baseField(0))).toBeTruthy();
        });
    });
});

describe("point encoding/decoding", () => {
    test("check bad tag fails for compressed encoding", () => {
        function run() {
            const P = newRandomPoint().point;
            const bytes = sec1Encode(P, true);
            bytes[0] = 4;
            return sec1DecodeFromBytes(bytes);
        }

        expect(run).toThrowError();
    });

    test("check bad tag fails for uncompressed encoding", () => {
        function run() {
            const P = newRandomPoint().point;
            const bytes = sec1Encode(P, false);
            bytes[0] = 3;
            return sec1DecodeFromBytes(bytes);
        }
        expect(run).toThrowError();
    });

    test("compressed random point (bytes)", () => {
        const P = newRandomPoint().point;
        const bytes = sec1Encode(P, true);
        const newP = sec1DecodeFromBytes(bytes);
        expect(P.x.equals(newP.x)).toBeTruthy();
        expect(P.y.equals(newP.y)).toBeTruthy();
    });

    test("compressed random point (base64)", () => {
        const P = newRandomPoint().point;
        const b64 = sec1EncodeToBase64(P, true);
        const newP = sec1DecodeFromBase64(b64);
        expect(P.x.equals(newP.x)).toBeTruthy();
        expect(P.y.equals(newP.y)).toBeTruthy();
    });

    test("uncompressed random point (bytes)", () => {
        const P = newRandomPoint().point;
        const bytes = sec1Encode(P, false);
        const newP = sec1DecodeFromBytes(bytes);
        expect(P.x.equals(newP.x)).toBeTruthy();
        expect(P.y.equals(newP.y)).toBeTruthy();
    });

    test("uncompressed random point (base64)", () => {
        const P = newRandomPoint().point;
        const b64 = sec1EncodeToBase64(P, false);
        const newP = sec1DecodeFromBase64(b64);
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
    if (!t && t !== 0) {
        const byteLength = 32;
        const wordLength = byteLength / 4; // SJCL 4 bytes to a word
        const random = sjcl.random.randomWords(wordLength, 10);
        const rndBits = sjcl.codec.bytes.toBits(random);
        eleFFp = h2Base(rndBits, curve, "p256_hashing");
    } else {
        eleFFp = new params.baseField(t);
    }

    return {baseField: params.baseField, A: params.A, B: params.B, t: eleFFp};
}
