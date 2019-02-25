/**
* Integration tests for token generation and commitment functionality
* 
* @author: Alex Davidson
*/
import rewire from 'rewire';
var workflow = rewire('../addon/compiled/test_compiled.js');
const sjcl = workflow.__get__("sjcl");
const setConfig = workflow.__get__('setConfig');
const CreateBlindToken = workflow.__get__('CreateBlindToken');
const GenerateNewTokens = workflow.__get__('GenerateNewTokens');
const BuildRedeemHeader = workflow.__get__('BuildRedeemHeader');
const h2Curve = workflow.__get__('h2Curve');
const getActiveECSettings = workflow.__get__('getActiveECSettings');
const createRequestBinding = workflow.__get__('createRequestBinding');
const unblindPoint = workflow.__get__('unblindPoint');
const deriveKey = workflow.__get__('deriveKey');

// mocking for tests
import btoa from "btoa";
import atob from "atob";
let getMock = jest.fn();
let updateIconMock = jest.fn();
let clearCachedCommitmentsMock = jest.fn();
let consoleMock = {
    warn: jest.fn(),
    error: jest.fn()
};
workflow.__set__("get", getMock);
workflow.__set__("updateIcon", updateIconMock);
workflow.__set__("clearCachedCommitments", clearCachedCommitmentsMock);
workflow.__set__("console", consoleMock);
workflow.__set__("btoa", btoa);
workflow.__set__("atob", atob);

/**
* Configuration
*/
let CreateBlindTokenMock;
let curveSettings;
beforeEach(() => {
    setConfig(1);
    let count = 0;
    CreateBlindTokenMock = function() {
        let token;
        if (count != 1) {
            token = CreateBlindToken();
        }
        count++;
        return token;
    };
    curveSettings = getActiveECSettings();
});

/**
* Tests
*/
describe("check that null point errors are caught in token generation", () => {
    test("check that token generation happens correctly", () => {
        let tokens = GenerateNewTokens(3);
        expect(tokens.length == 3).toBeTruthy();
        let consoleNew = workflow.__get__("console");
        expect(consoleNew.warn).not.toBeCalled();
    });

    test("check that null tokens are caught and ignored", () => {
        workflow.__set__("CreateBlindToken", CreateBlindTokenMock);
        let tokens = GenerateNewTokens(3);
        expect(tokens.length == 2).toBeTruthy();
        let consoleNew = workflow.__get__("console");
        expect(consoleNew.warn).toBeCalled();
    });
});

describe("building of redemption headers", () => {
    const byteLength = 32;
    const wordLength = byteLength / 4;

    function testBuildHeader() {
        // Generate random bytes for token object
        const rnd1 = sjcl.random.randomWords(wordLength, 10);
        const rnd2 = sjcl.random.randomWords(wordLength, 10);
        const rnd2Bits = sjcl.codec.bytes.toBits(rnd2);
        // any old number...
        const blind = new curveSettings.curve.field(324323);
        const token = {data: rnd1, blind: blind, point: h2Curve(rnd2Bits, curveSettings)};

        // any host & path for request binding
        const host = "some_host";
        const path = "some_path";

        // construct and base-64 header value
        const encodedHeaderVal = BuildRedeemHeader(token, host, path);
        let decoded = atob(encodedHeaderVal);
        let json = JSON.parse(decoded);

        const type = json.type;
        const contents = json.contents;
        const chkBinding = reconstructRequestBinding(token.data, token.blind, token.point, host, path);
        expect(type === "Redeem").toBeTruthy();
        // check token data is correct
        expect(contents[0] == sjcl.codec.base64.fromBits(sjcl.codec.bytes.toBits(token.data))).toBeTruthy();
        // check request binding (hex is easiest way)
        expect(contents[1] === chkBinding).toBeTruthy();
        
        return contents;
    }

    test("header value is built correctly (SEND_H2C_PARAMS = false)", () => {
        workflow.__set__("SEND_H2C_PARAMS", false);
        const contents = testBuildHeader();
        // Test additional H2C parameters are omitted
        expect(contents.length === 2).toBeTruthy();
    });

    test("header value is built correctly (SEND_H2C_PARAMS = true)", () => {
        const contents = testBuildHeader();
        // Test additional H2C parameters are constructed correctly
        expect(contents.length === 3).toBeTruthy();
        let h2cParams = JSON.parse(atob(contents[2]));
        expect(h2cParams.curve === "p256").toBeTruthy();
        expect(h2cParams.hash === "sha256").toBeTruthy();
        expect(h2cParams.method === "increment").toBeTruthy();
    });
});

// For checking that BuildRedeemHeader is working correctly
function reconstructRequestBinding(data, blind, point, host, path) {
    const sharedPoint = unblindPoint(blind, point);
    const derivedKey = deriveKey(sharedPoint, data);
    const hostBytes = sjcl.codec.bytes.fromBits(sjcl.codec.utf8String.toBits(host));
    const pathBytes = sjcl.codec.bytes.fromBits(sjcl.codec.utf8String.toBits(path));
    return createRequestBinding(derivedKey, [hostBytes, pathBytes]);
}