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

// Test vectors taken from poc at
// https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve.git
// (tag: draft-irtf-cfrg-hash-to-curve-03)
// (commit: 8150855f1529290e783bbd903dd7e4aef29c9b57)
describe("hashing to p256", () => {
    const byteLength = 32;
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
                t: "f4bf932eec234a64399ba0f4aa4c07817bbf3d5e23b9efcf004631fb9d1ef60a",
                X: "0b05ff942eaf3c02a8d3d1bc1c3df582849dde7fef1e3030465605ca47be8695",
                Y: "35b74b59eed2eec5ddd2c98810f55db329acac55aecf735478e5c2c0d577f619",
            },
            {
                t: "928fd78ea9288b1849d9129a923a67ab925ba22fd8ab6d20ecfd1bbb27972ae5",
                X: "ebe93781c6da1f2e8c4f413ba513cc2e507b1cade03307cd11c6ce08427a2597",
                Y: "5fb12aa35a6336df78b5adcdabd264556b2c1150431c0849d99dac80b9f53271",
            },
            {
                t: "f12ed3708b3e0ad507b1d562b4236b3c00232140b61e1a8fdcc244a88d5f3b07",
                X: "d757d33753253ae290aa98071fd8ee5087617e8ce57542a5f4e1dcaddbd4cfed",
                Y: "110e75d49490243b2e836a9d8b6c2f27cf75fbdbc73155dc6b453611cad284f1",
            },
            {
                t: "7128b7ac4f9506e36831804ede26275e0b8f14491c45ca3eb172e179ebb5bb67",
                X: "d38c479f260c3cce0d3a0442fe3378fd7af61750984f3d30963a9e6a553f5777",
                Y: "51a3742c76246a7b293434b6133e3ee21db3c53eacd666be51c24ddf64694571",
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
                const lbl = workflow.__get__("SSWU_H2C_LABEL_P256");
                simplifiedSWU(rndBits, curve, hash, lbl);
            };
            expect(runH2C).not.toThrowError();
        }
    });

    describe("exceptional cases", () => {
        const params = getCurveParams(sjcl.ecc.curves.c256);
        const testVectors = [
            {
                u: new params.baseField(0),
                X: "000000", // sjcl truncates the length of X
                Y: "66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4",
            },
            {
                u: new params.baseField(1),
                X: "8c6898b71c972408c406c0e383227dc133a0fdc5bbe41a5896bb41409d648a91",
                Y: "022f57c5880ec13780670c6874cc9ccd7096fa95c841e7592bf4e95162aa89cd",
            },
            {
                u: new params.baseField(-1),
                X: "8c6898b71c972408c406c0e383227dc133a0fdc5bbe41a5896bb41409d648a91",
                Y: "022f57c5880ec13780670c6874cc9ccd7096fa95c841e7592bf4e95162aa89cd",
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

    test("hash-and-increment no errors", () => {
        for (let i = 0; i < 10; i++) {
            const random = sjcl.random.randomWords(wordLength, 10);
            const rndBits = sjcl.codec.bytes.toBits(random);
            const runH2C = function run() {
                hashAndInc(rndBits, hash, label);
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
