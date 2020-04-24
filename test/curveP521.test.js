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
    activeCurveParams = {curve: "p521", hash: "sha512", method: "swu"};
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
    test("p521", () => {
        const curveP521 = sjcl.ecc.curves.c521;
        function run() {
            return getCurveParams(curve);
        }
        const cParams = run();
        expect(curveP521.field.modulus === cParams.baseField.modulus).toBeTruthy();
        expect(curveP521.a === cParams.A).toBeTruthy();
        expect(curveP521.b === cParams.B).toBeTruthy();
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


describe("hashing to p521", () => {
    const byteLength = 64;
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
                t: "000023aa13930e718b0482bb568d5345ca5eaf0a88266e091e53a399a350ffe1e70370aa5ab3434a4b8eb957a6cdb1eda270d63a7a7c0702a1a8737ff216a392f248",
                X: "00f3009572992148fb0330a00b8d90f0312204c56c99251e48d68415f778de554ccd95397920c5df56b8fdb73f652fde9eb69713d15bc3acf37eab4789471474bcbf",
                Y: "00aafe542358a362aef3e2087d18a09e68b1c6f1f0c7cc59d079f1c3e0992726ff3bfc384c301338b4f95ac57fb6e1b4f98e6a9663044078fe1aae862e7497265c16",
            },
            {
                t: "000035611bedc259213ba5905c48b2371bd36aef6fc05ef938c283065eff5fb90e6374a44227fc92067bd91f4b12a9290a45806e0ea45eae0044e02c138de459ea7f",
                X: "0006381ec39367dbf2668277aaa924c68c34759c68c50011f66d5a2b1b6f8e30bddf5a5ab5f34882bfb84f1d45bca8819df6e9caa2524f1d5c76b307098015312f2c",
                Y: "006871dd285028096a278902bffd68462419f87143b803d8e19375258bdef21a7a43e04608c85bc25cca53766dedbb32e6cec6252194a79cc2444fe1e5f564603bc9",
            },
            {
                t: "0000f254e3b20eab7df9f80aa49f7c78a55f3cd2d03cd45f7f0822b09178efe67e80fc04de25c711bd9ef14d5d14e7b8b952ceeaf86910ce0d9539d8007abe1bcb17",
                X: "0152059cfed17e165b4fed3d4801e27f5e5a37f7b7e38baab6e52aeb2f993da26dc90b552c48e128f5eddb7ec91caedd2bb8269bbbdd53b883c0cebc979d1f783d7d",
                Y: "00da3153edb5f1df2453410846a298fffae41f45eeeb6ef56e5e4791cd4cf49fba49d4c365d9f8185034ad70c5c880b4106b5de833d2808f7fe93f20da5390833e20",
            },
            {
                t: "0000c3183151e83905174a89b5f12862fbb6463bd421ea915b29c92c2a0e62f97ea27384c281654232ebe0bf5d7d3f728868af5c113b891f5488a935a9fd0c990b3b",
                X: "001a4794de39d045e0ffeddcbfe68031daf1297b7b1bb83836405c28b033e32454074272d6ce16eeac01077e8ba462e6cb96e5e6e3375b9edbaaa7b97ef2f7bf2c21",
                Y: "009306576bb05d5da82237b79d2bf5708f26a37792072a74da29226f48a55867e50bac2cb40af8d5bb5079f89411b6911997eabda27f974233371f0b4604f0a2aae6",
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
                const lbl = workflow.__get__("SSWU_H2C_LABEL_P521");
                simplifiedSWU(rndBits, curve, hash, lbl);
            };
            expect(runH2C).not.toThrowError();
        }
    });


    describe("exceptional cases", () => {
        const params = getCurveParams(sjcl.ecc.curves.c521);
        const testVectors = [
            {
                u: new params.baseField(0),
                X: "000000", // sjcl truncates the length of X
                Y: "d20ec9fea6b577c10d26ca1bb446f40b299e648b1ad508aad068896fee3f8e614bc63054d5772bf01a65d412e0bcaa8e965d2f5d332d7f39f846d440ae001f4f87",
            },
            {
                u: new params.baseField(1),
                X: "013a2395c234d0a121f579cc9f75187e3fb07461d9e1776ef8aec26e7ccf7b04fcb4e34cece4b12b242c4de46a6b96c4c052ee2eb57d40f143af5ae8f563dc3a95aa",
                Y: "ffd2fda3be9e4fadadcd97e3150ea648c023d14db5b2e63e3269738f1a0621c60db7c4a7b70bf1fa67c5330104ba2602d47f77eaeaf37b773c35a72dfc2f50edf9",
            },
            {
                u: new params.baseField(-1),
                X: "013a2395c234d0a121f579cc9f75187e3fb07461d9e1776ef8aec26e7ccf7b04fcb4e34cece4b12b242c4de46a6b96c4c052ee2eb57d40f143af5ae8f563dc3a95aa",
                Y: "ffd2fda3be9e4fadadcd97e3150ea648c023d14db5b2e63e3269738f1a0621c60db7c4a7b70bf1fa67c5330104ba2602d47f77eaeaf37b773c35a72dfc2f50edf9",
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
