/**
* Integrations tests for when headers are received by the extension
* 
* @author: Alex Davidson
*/
import rewire from "rewire";
var workflow = rewire("../addon/compiled/test_compiled.js");
var URL = window.URL;

/**
* Functions
*/
const EXAMPLE_HREF = "https://www.example.com";
const processHeaders = workflow.__get__('processHeaders');
const isBypassHeader = workflow.__get__('isBypassHeader');
const updateIconMock = jest.fn();
function getMock() {
    return 1;
}

/**
* Tests
* (Currently unable to test workflows that are dependent on cookies)
*/
describe("ensure that errors are handled properly", () => {
    const CHL_BYPASS_RESPONSE = "cf-chl-bypass-resp";
    const CHL_VERIFICATION_ERROR = "6";
    const CHL_CONNECTION_ERROR = "5";
    
    let url = new URL(EXAMPLE_HREF);
    test("connection error", () => {
        function processConnError() {
            let details = {
                responseHeaders: [{ name: CHL_BYPASS_RESPONSE, value: CHL_CONNECTION_ERROR }]
            }
            processHeaders(details, url);
        }
        expect(processConnError).toThrowError("error code: 5");
    });
    test("verification error", () => {
        function processConnError() {
            let details = {
                responseHeaders: [{ name: CHL_BYPASS_RESPONSE, value: CHL_VERIFICATION_ERROR }]
            }
            processHeaders(details, url);
        }
        expect(processConnError).toThrowError("error code: 6");
    });
});

describe("check bypass header is working", () => {
    const CHL_BYPASS_SUPPORT  = "cf-chl-bypass";
    let found;
    beforeEach(() => {
        found = false;
    });
    
    test("header is valid", () => {
        let header = { name: CHL_BYPASS_SUPPORT, value: "1" };
        found = isBypassHeader(header);
        expect(found).toBeTruthy();
    });
    test("header is invalid value", () => {
        let header = { name: CHL_BYPASS_SUPPORT, value: "0" };
        found = isBypassHeader(header);
        expect(found).toBeFalsy();
    });
    test("header is invalid name", () => {
        let header = { name: "Different-header-name", value: "1" };
        found = isBypassHeader(header);
        expect(found).toBeFalsy();
    });
});

describe("check redemption attempt conditions", () => {
    const CHL_BYPASS_SUPPORT  = "cf-chl-bypass";
    let url;
    let details;
    let header = {name: CHL_BYPASS_SUPPORT, value: "1"};
    // We have to set mock functions for testing
    setMockFunctions();
    beforeEach(() => {
        details = {
            statusCode: 403,
            responseHeaders: [header]
        };
        url = new URL("http://www.example.com");
    });
    
    test("check that redemption is not fired on CAPTCHA domain", () => {
        url = new URL("https://captcha.website");
        let fired = processHeaders(details, url);
        expect(fired).toBeFalsy();
    });
    
    test("redemption is attempted on general domains", () => {
        let fired = processHeaders(details, url);
        expect(fired).toBeTruthy;
        expect(updateIconMock).toBeCalledTimes(1);
    });
    
    test("not fired if status code != 403", () => {
        details.statusCode = 200;
        let fired = processHeaders(details, url);
        expect(fired).toBeFalsy();
    });
    
    test("if count is 0 update icon", () => {
        getMock = function() { return 0; };
        workflow.__set__("get", getMock);
        processHeaders(details, url);
        expect(updateIconMock).toBeCalledTimes(2);
    });
});

function setMockFunctions() {
    function attemptRedeemMock() {
        return true;
    }
    workflow.__set__("attemptRedeem", attemptRedeemMock);
    workflow.__set__("get", getMock);
    workflow.__set__("updateIcon", updateIconMock);
}