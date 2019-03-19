/**
* Integrations tests for when headers are received by the extension
*
* @author: Alex Davidson
*/
import rewire from "rewire";
const workflow = rewire("../addon/compiled/test_compiled.js");
const URL = window.URL;

/**
* Functions
*/
const CACHED_COMMITMENTS_STRING = "cached-commitments";
const EXAMPLE_HREF = "https://www.example.com";
const processHeaders = workflow.__get__("processHeaders");
const isBypassHeader = workflow.__get__("isBypassHeader");
const setConfig = workflow.__get__("setConfig");
const updateIconMock = jest.fn();
function getMock() {
    return 1;
}
const setMock = jest.fn();
const clearCachedCommitmentsMock = function() {
    localStorage[CACHED_COMMITMENTS_STRING] = null;
};

/**
 * local storage set up
 */
const localStorage = new Map();
localStorage.clear = function() {
    localStorage.data = null;
};
beforeEach(() => {
    localStorage.data = "some_token";
    workflow.__set__("localStorage", localStorage);
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

    const url = new URL(EXAMPLE_HREF);
    test("connection error", () => {
        function processConnError() {
            const details = {
                responseHeaders: [{name: CHL_BYPASS_RESPONSE, value: CHL_CONNECTION_ERROR}],
            };
            processHeaders(details, url);
        }
        expect(processConnError).toThrowError("error code: 5");
        expect(localStorage.data).toBeTruthy();
    });
    test("verification error", () => {
        function processVerifyError() {
            const details = {
                responseHeaders: [{name: CHL_BYPASS_RESPONSE, value: CHL_VERIFICATION_ERROR}],
            };
            processHeaders(details, url);
        }
        expect(processVerifyError).toThrowError("error code: 6");
        expect(localStorage.data).toBeFalsy();
    });
});

describe("check bypass header is working", () => {
    const CHL_BYPASS_SUPPORT = "cf-chl-bypass";
    let found;
    beforeEach(() => {
        found = false;
    });

    test("header is valid", () => {
        const header = {name: CHL_BYPASS_SUPPORT, value: "1"};
        found = isBypassHeader(header);
        expect(found).toBeTruthy();
    });
    test("header is invalid value", () => {
        const header = {name: CHL_BYPASS_SUPPORT, value: "0"};
        found = isBypassHeader(header);
        expect(found).toBeFalsy();
    });
    test("header is invalid name", () => {
        const header = {name: "Different-header-name", value: "1"};
        found = isBypassHeader(header);
        expect(found).toBeFalsy();
    });
    test("config is reset if ID changes", () => {
        workflow.__set__("CONFIG_ID", 2);
        const header = {name: CHL_BYPASS_SUPPORT, value: "1"};
        found = isBypassHeader(header);
        expect(found).toBeTruthy();
        expect(updateIconMock).toBeCalledTimes(2);
    });
    test("config is not reset if ID does not change", () => {
        const header = {name: CHL_BYPASS_SUPPORT, value: "1"};
        found = isBypassHeader(header);
        expect(found).toBeTruthy();
        expect(updateIconMock).toBeCalledTimes(1);
    });
});

describe("check redemption attempt conditions", () => {
    const CHL_BYPASS_SUPPORT = "cf-chl-bypass";
    let url;
    let details;
    let header;
    // We have to set mock functions for testing
    setMockFunctions();
    beforeEach(() => {
        header = {name: CHL_BYPASS_SUPPORT, value: "1"};
        details = {
            statusCode: 403,
            responseHeaders: [header],
        };
        url = new URL("http://www.example.com");
    });

    test("check that favicon urls are ignored", () => {
        url = new URL("https://captcha.website/favicon.ico");
        const fired = processHeaders(details, url);
        expect(fired).toBeFalsy();
        expect(updateIconMock).toBeCalledTimes(1);
    });

    test("check that redemption is not fired on CAPTCHA domain", () => {
        url = new URL("https://captcha.website");
        const fired = processHeaders(details, url);
        expect(fired).toBeFalsy();
    });

    test("redemption is attempted on general domains", () => {
        const fired = processHeaders(details, url);
        expect(fired).toBeTruthy;
        expect(updateIconMock).toBeCalledTimes(2);
    });

    test("not fired if status code != 403", () => {
        details.statusCode = 200;
        const fired = processHeaders(details, url);
        expect(fired).toBeFalsy();
    });

    test("if count is 0 update icon", () => {
        getMock = function() {
            return 0;
        };
        workflow.__set__("get", getMock);
        processHeaders(details, url);
        expect(updateIconMock).toBeCalledTimes(3);
    });

    describe("SPEND_IFRAME setting", () => {
        beforeEach(() => {
            getMock = function() {
                return 2;
            };
            workflow.__set__("get", getMock);
        });

        test("not set", () => {
            workflow.__set__("SPEND_IFRAME", false);
            const fired = processHeaders(details, url);
            expect(fired).toBeTruthy;
            expect(updateIconMock).toBeCalledTimes(2);
        });

        test("set and iframe", () => {
            workflow.__set__("SPEND_IFRAME", true);
            workflow.__set__("iframe", true);
            const fired = processHeaders(details, url);
            expect(fired).toBeTruthy;
            expect(updateIconMock).toBeCalledTimes(2);
        });

        test("set and not iframe", () => {
            workflow.__set__("SPEND_IFRAME", true);
            workflow.__set__("iframe", false);
            const fired = processHeaders(details, url);
            expect(fired).toBeTruthy;
            expect(updateIconMock).not.toBeCalled;
        });
    });

    describe("setting of readySign", () => {
        beforeEach(() => {
            getMock = function() {
                return 0;
            };
            workflow.__set__("get", getMock);
        });

        describe("signing enabled", () => {
            beforeEach(() => {
                workflow.__set__("DO_SIGN", true);
                workflow.__set__("readySign", false);
            });

            test("no tokens", () => {
                const fired = processHeaders(details, url);
                expect(fired).toBeFalsy();
                const readySign = workflow.__get__("readySign");
                expect(readySign).toBeTruthy();
                expect(updateIconMock).toBeCalledWith("!");
            });

            test("not activated", () => {
                header = {name: "Different-header-name", value: "1"};
                details.responseHeaders = [header];
                const fired = processHeaders(details, url);
                expect(fired).toBeFalsy();
                const readySign = workflow.__get__("readySign");
                expect(readySign).toBeFalsy();
            });

            test("tokens > 0", () => {
                getMock = function() {
                    return 2;
                };
                workflow.__set__("get", getMock);
                const fired = processHeaders(details, url);
                expect(fired).toBeTruthy();
                const readySign = workflow.__get__("readySign");
                expect(readySign).toBeFalsy();
            });

            test("tokens > 0 but captcha.website", () => {
                url = new URL("https://captcha.website");
                getMock = function() {
                    return 2;
                };
                workflow.__set__("get", getMock);
                const fired = processHeaders(details, url);
                expect(fired).toBeFalsy();
                const readySign = workflow.__get__("readySign");
                expect(readySign).toBeTruthy();
            });

            test("redemption off", () => {
                workflow.__set__("DO_REDEEM", false);
                const fired = processHeaders(details, url);
                expect(fired).toBeFalsy();
                const readySign = workflow.__get__("readySign");
                expect(readySign).toBeTruthy();
            });
        });

        describe("signing disabled", () => {
            beforeEach(() => {
                workflow.__set__("readySign", false);
                workflow.__set__("DO_SIGN", false);
            });

            test("signing is not activated", () => {
                header = {name: "Different-header-name", value: "1"};
                details.responseHeaders = [header];
                const fired = processHeaders(details, url);
                expect(fired).toBeFalsy();
                const readySign = workflow.__get__("readySign");
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
    workflow.__set__("set", setMock);
    workflow.__set__("clearCachedCommitments", clearCachedCommitmentsMock);
    workflow.__set__("updateIcon", updateIconMock);
}
