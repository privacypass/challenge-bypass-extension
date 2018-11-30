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
const setConfig = workflow.__get__('setConfig');
const updateIconMock = jest.fn();
const chkG = "BOidEuO9HSJsMZYE/Pfc5D+0ELn0bqhjEef2O0u+KAw3fPMHHXtVlEBvYjE5I/ONf9SyTFSkH3mLNHkS06Du6hQ=";
const chkH = "BHOPNAWXRi4r/NEptOiLOp8MSwcX0vHrVDRXv16Jnowc1eXXo5xFFKIOI6mUp8k9/eca5VY07dBhAe8QfR/FSRY=";
function getMock() {
    return 1;
}
beforeEach(() => {
    setConfig(1); // set the CF config
});

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
    let header;
    // We have to set mock functions for testing
    setMockFunctions();
    beforeEach(() => {
        header = {name: CHL_BYPASS_SUPPORT, value: "1"};
        details = {
            statusCode: 403,
            responseHeaders: [header]
        };
        url = new URL("http://www.example.com");
    });

    test("check that favicon urls are ignored", () => {
        url = new URL("https://captcha.website/favicon.ico");
        let fired = processHeaders(details, url);
        expect(fired).toBeFalsy();
        expect(updateIconMock).toBeCalledTimes(1);
    });
    
    test("check that redemption is not fired on CAPTCHA domain", () => {
        url = new URL("https://captcha.website");
        let fired = processHeaders(details, url);
        expect(fired).toBeFalsy();
    });
    
    test("redemption is attempted on general domains", () => {
        let fired = processHeaders(details, url);
        expect(fired).toBeTruthy;
        expect(updateIconMock).toBeCalledTimes(3);
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
        expect(updateIconMock).toBeCalledTimes(4);
    });

    describe("SPEND_IFRAME setting", () => {
        beforeEach(() => {
            getMock = function() { return 2; };
            workflow.__set__("get", getMock);
        });

        test("not set", () => {
            workflow.__set__("SPEND_IFRAME", false);
            let fired = processHeaders(details, url);
            expect(fired).toBeTruthy;
            expect(updateIconMock).toBeCalledTimes(3);
        });

        test("set and iframe", () => {
            workflow.__set__("SPEND_IFRAME", true);
            workflow.__set__("iframe", true);
            let fired = processHeaders(details, url);
            expect(fired).toBeTruthy;
            expect(updateIconMock).toBeCalledTimes(3);
        });

        test("set and not iframe", () => {
            workflow.__set__("SPEND_IFRAME", true);
            workflow.__set__("iframe", false);
            let fired = processHeaders(details, url);
            expect(fired).toBeTruthy;
            expect(updateIconMock).not.toBeCalled;
        });
    });

    describe("setting of readySign", () => {
        beforeEach(() => {
            getMock = function() { return 0; };
            workflow.__set__("get", getMock);
        });

        describe("signing enabled", () => {
            beforeEach(() => {
                workflow.__set__("DO_SIGN", true);
                workflow.__set__("readySign", false);
            });

            test("no tokens", () => {
                let fired = processHeaders(details, url);
                expect(fired).toBeFalsy();
                let readySign = workflow.__get__("readySign");
                expect(readySign).toBeTruthy();
                expect(updateIconMock).toBeCalledWith("!");
            });

            test("not activated", () => {
                header = { name: "Different-header-name", value: "1" };
                details.responseHeaders = [header];
                let fired = processHeaders(details, url);
                expect(fired).toBeFalsy();
                let readySign = workflow.__get__("readySign");
                expect(readySign).toBeFalsy();
            });

            test("tokens > 0", () => {
                getMock = function() { return 2; };
                workflow.__set__("get", getMock);
                let fired = processHeaders(details, url);
                expect(fired).toBeTruthy();
                let readySign = workflow.__get__("readySign");
                expect(readySign).toBeFalsy();
            });

            test("tokens > 0 but captcha.website", () => {
                url = new URL("https://captcha.website");
                getMock = function() { return 2; };
                workflow.__set__("get", getMock);
                let fired = processHeaders(details, url);
                expect(fired).toBeFalsy();
                let readySign = workflow.__get__("readySign");
                expect(readySign).toBeTruthy();
            });

            test("redemption off", () => {
                workflow.__set__("DO_REDEEM", false);
                let fired = processHeaders(details, url);
                expect(fired).toBeFalsy();
                let readySign = workflow.__get__("readySign");
                expect(readySign).toBeTruthy();
            });
        });

        describe("signing disabled", () => {
            beforeEach(() => {
                workflow.__set__("readySign", false);
                workflow.__set__("DO_SIGN", false);
            });
    
            test("signing is not activated", () => {
                header = { name: "Different-header-name", value: "1" };
                details.responseHeaders = [header];
                let fired = processHeaders(details, url);
                expect(fired).toBeFalsy();
                let readySign = workflow.__get__("readySign");
                expect(readySign).toBeFalsy();
            });
        });
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