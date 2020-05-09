/**
 * h2Curve test
 * @author Alex Davidson
 */


const workflow = workflowSet();

const sjcl = workflow.__get__("sjcl");
const h2Curve = workflow.__get__("h2Curve");
const h2Base = workflow.__get__("h2Base");
const simplifiedSWU = workflow.__get__("simplifiedSWU");
const computeSWUCoordinates = workflow.__get__("computeSWUCoordinates");
const hashAndInc = workflow.__get__("hashAndInc");
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
let label;
beforeEach(() => {
    setConfig(0);
    const settings = getActiveECSettings();
    curve = settings.curve;
    hash = settings.hash;
    label = settings.label;
    activeCurveParams = {curve: "p384", hash: "sha512", method: "swu"};
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
        activeCurveParams["hash"] = "sha256";
        function run() {
            return initECSettings(activeCurveParams);
        }
        expect(run).toThrowError();
    });
    
    test("with bad H2C method", () => {
        activeCurveParams["method"] = "increment";
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
    test("p384", () => {
        const curveP384 = sjcl.ecc.curves.c384;
        function run() {
            return getCurveParams(curve);
        }
        const cParams = run();
        expect(curveP384.field.modulus === cParams.baseField.modulus).toBeTruthy();
        expect(curveP384.a === cParams.A).toBeTruthy();
        expect(curveP384.b === cParams.B).toBeTruthy();
    });
    test("bad curve", () => {
        function run() {
            curve = sjcl.ecc.curves.c192;
            return getCurveParams(curve);
        }
        expect(run).toThrowError();
    });
});

// Test vectors taken from poc at
// https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve.git
// (tag: draft-irtf-cfrg-hash-to-curve-03)
// (commit: 8150855f1529290e783bbd903dd7e4aef29c9b57)


describe("hashing to p384", () => {
    const byteLength = 48;
    const wordLength = byteLength / 4;

    describe("affine test vectors", () => {
        let sets;
        beforeEach(() => {
            activeCurveParams["method"] = "swu";
            initECSettings(activeCurveParams);
            sets = getActiveECSettings();
        });
        const testVectors = [
            [],
            [0],
            [0xff],
            [0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x11, 0x22, 0x33, 0x44, 0x11, 0x22,
                0x33, 0x44, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x55, 0x66,
                0x77, 0x88, 0x55, 0x66, 0x77, 0x88, 0x55, 0x66, 0x77, 0x88],
        ];
        const expected = [
            {
                t: "53f46c6ae3188f49447f87374f909c0c473f09d59fc9bd62dbd2adf51375e63188d5f07e6133ef8125721a4fa9265f5e",
                X: "c2347960cf5b0fbec577c418a059368bf653ea9bb6170e86c53b9f009286c514a7cd0d7fbb5a66dcdb3929c98f4ff1ac",
                Y: "4e7c113ca3edacfc641577d8caf438ceefbb4f86c2f365fa12ac60112fc2307b520c8149c68303feea652ff6f0b496d3",
            },
            {
                t: "fbf18a436962b0e49f660f7dd5a662bf7437c4efef95e66749db54ce154889d6966f0a951f5b4c964d30ac62d0afa7ac",
                X: "7e68d2cfd879eca9f4722a15ba5b4eb2735569b94c984e1b3b16496da2e0a71537437588e3d1d14952a8074d915399eb",
                Y: "63d633d131d0847ca77f28e99d2ad20f78442e85ed989dc9e48f82f577cd4615f58311a98e71706432c3f2889295ba73",
            },
            {
                t: "ce159a22b10ca2b0bfd297e7c3925f989112154c173ee881cd771fcf86ac1ce170322221425ddd49b4c6e62d217b1031",
                X: "d077e9f856146df6e90b5e218f7ea4a0bf32fccf6739b1fbb4ed59c38d80c1f3e20b22fe50242f98f7478a518b803a86",
                Y: "2de8098254387248fc96d70961cc1d39e84eadb2e1fc06799034cc210f2339c0cb5648650081a9ac559327fb85f7bf95",
            },
            {
                t: "da595838c55f0ddaf8071c30fb425725b95e3fe3a20d8467b4cbbad00cb0d024ad90971c13a9122aebf947afc9d61415",
                X: "3b96bf8fbb288ca1af89228ae31c8eb067cf3e3db026b3ee68c5d3018e447dd223f82f94e6cecb9b75c184c565856f05",
                Y: "346115ac5698c8ecd9a596f160ff065e6943e1ea9c17a195b43c83cf6ab4bf4d1307391d426ad7440c5e95de1c43ca64",
            },
        ];
        for (let i = 0; i < testVectors.length; i++) {
            test(`i=${i}`, () => {
                const alpha = sjcl.codec.bytes.toBits(testVectors[i]);

                // check that h2base is consistent
                const t = h2Base(alpha, sets.curve, sets.hash, sets.label);
                expect(sjcl.codec.hex.fromBits(t.toBits())).toEqual(expected[i].t);

                // check that sswu in full is consistent
                const point = simplifiedSWU(alpha, sets.curve, sets.hash, sets.label);
                expect(sjcl.codec.hex.fromBits(point.x.toBits())).toEqual(expected[i].X);
                expect(sjcl.codec.hex.fromBits(point.y.toBits())).toEqual(expected[i].Y);
                expect(point.isValid()).toBeTruthy();
            });
        }
    });
    test("affine random", () => {
        for (let i = 0; i < 10; i++) {
            const random = sjcl.random.randomWords(wordLength, 10);
            const rndBits = sjcl.codec.bytes.toBits(random);
            const runH2C = function run() {
                const lbl = workflow.__get__("SSWU_H2C_LABEL_P384");
                simplifiedSWU(rndBits, curve, hash, lbl);
            };
            expect(runH2C).not.toThrowError();
        }
    });


    describe("exceptional cases", () => {
        const params = getCurveParams(sjcl.ecc.curves.c384);
        const testVectors = [
            {
                u: new params.baseField(0),
                X: "000000", // sjcl truncates the length of X
                Y: "3cf99ef04f51a5ea630ba3f9f960dd593a14c9be39fd2bd215d3b4b08aaaf86bbf927f2c46e52ab06fb742b8850e521e",
            },
            {
                u: new params.baseField(1),
                X: "199a4572b495b2b3cd25fe315ead464cf7f6213055d4ea4f544ea7d03aa42836bde34225d1f064cb9c7e125bb95bf1b0",
                Y: "6fe0457487694c4d19710d054d8e95a8889dffd38626f42b0caaed4ad6c84adc853f452a8a84cbed2d2f3446dc8d62b5",
            },
            {
                u: new params.baseField(-1),
                X: "199a4572b495b2b3cd25fe315ead464cf7f6213055d4ea4f544ea7d03aa42836bde34225d1f064cb9c7e125bb95bf1b0",
                Y: "6fe0457487694c4d19710d054d8e95a8889dffd38626f42b0caaed4ad6c84adc853f452a8a84cbed2d2f3446dc8d62b5",
            },
        ];
        testVectors.forEach((vector) => {
            test(`u=${vector.u}`, () => {
                const {X, Y} = computeSWUCoordinates(vector.u, params);
                expect(sjcl.codec.hex.fromBits(X.toBits())).toEqual(vector.X);
                expect(sjcl.codec.hex.fromBits(Y.toBits())).toEqual(vector.Y);
            });
        });
    });

    test("bad hash-and-increment", () => {
        for (let i = 0; i < 10; i++) {
            const random = sjcl.random.randomWords(wordLength, 10);
            const rndBits = sjcl.codec.bytes.toBits(random);
            const runH2C = function run() {
                hashAndInc(rndBits, hash, label);
            };
            expect(runH2C).toThrowError();
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
