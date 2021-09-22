/**
 * Integrations tests for when headers are received by the extension
 *
 * @author: Alex Davidson
 * @author: Drazen Urch
 */

const workflow = workflowSet();

/**
 * Functions
 */
const CHL_BYPASS_SUPPORT = workflow.__get__("CHL_BYPASS_SUPPORT");
const CHL_BYPASS_RESPONSE = workflow.__get__("CHL_BYPASS_RESPONSE");
const chlVerificationError = workflow.__get__("chlVerificationError");
const chlConnectionError = workflow.__get__("chlConnectionError");
const chlBadRequestError = workflow.__get__("chlBadRequestError");
const chlUnknownError = workflow.__get__("chlUnknownError");
const spendStatusCode = workflow.__get__("spendStatusCode");
const isFaviconUrl = workflow.__get__("isFaviconUrl");
const PPConfigs = workflow.__get__("PPConfigs");
const LISTENER_URLS = workflow.__get__("LISTENER_URLS");
const EXAMPLE_HREF = "https://www.example.com";
const processHeaders = workflow.__get__("processHeaders");
const isBypassHeader = workflow.__get__("isBypassHeader");
const chlCaptchaDomain = workflow.__get__("chlCaptchaDomain");
const getReadyIssue = workflow.__get__("getReadyIssue");
const setReadyIssue = workflow.__get__("setReadyIssue");

const setNoTokens = (configId) => {
    setMock(bypassTokens(configId), "{}");
    setMock(bypassTokensCount(configId), 0);
};

/**
 * Tests
 * (Currently unable to test workflows that are dependent on cookies)
 */

describe.each(PPConfigs().filter((config) => config.id > 0).map((config) => [config.id]))("CONFIG_ID = %i", (configId) => {
    beforeEach(() => {
        clearLocalStorage();
        // Override global setting
        workflow.__set__("attemptRedeem", () => true);
        workflow.__set__("CONFIG_ID", configId);
        workflow.__set__("spendActionUrls", () => [LISTENER_URLS]);
        workflow.__set__("issueActionUrls", () => [LISTENER_URLS]);
        setMock(bypassTokens(configId), storedTokens);
        setMock(bypassTokensCount(configId), 2);
    });

    describe("ensure that errors are handled properly", () => {
        const url = new URL(EXAMPLE_HREF);
        const UNRECOGNISED_ERROR_CODE = 4;
        const errorTypes = {
            "connection": {
                code: chlConnectionError(),
                message: "[privacy-pass]: internal server connection error occurred",
            },
            "verification": {
                code: chlVerificationError(),
                message: `[privacy-pass]: token verification failed for ${url.href}`,
            },
            "bad-request": {
                code: chlBadRequestError(),
                message: "[privacy-pass]: server indicated a bad client request",
            },
            "unknown": {
                code: chlUnknownError(),
                message: "[privacy-pass]: unknown internal server error occurred",
            },
            "unrecognised": {
                code: UNRECOGNISED_ERROR_CODE,
                message: `[privacy-pass]: server sent unrecognised response code (${UNRECOGNISED_ERROR_CODE})`,
            },
        };

        const keys = Object.keys(errorTypes);
        keys.forEach((k) => {
            const error = errorTypes[k];
            test(`${error} error`, () => {
                localStorage.setItem("data", "some token");
                function processError() {
                    const details = {
                        responseHeaders: [{name: CHL_BYPASS_RESPONSE, value: error.code}],
                    };
                    processHeaders(details, url);
                }

                switch (error.code) {
                    case UNRECOGNISED_ERROR_CODE:
                        processError();
                        expect(consoleMock.warn).toBeCalledWith(error.message);
                        break;
                    case chlVerificationError():
                        expect(processError).toThrowError(error.message);
                        expect(localStorage.getItem("data")).toBeTruthy();
                        break;
                    default:
                        expect(processError).toThrowError(error.message);
                }
            });
        });
    });

    describe("check bypass header is working", () => {
        let found;
        beforeEach(() => {
            found = false;
        });

        test("header is valid", () => {
            const header = {name: CHL_BYPASS_SUPPORT, value: `${configId}`};
            found = isBypassHeader(header);
            expect(found > 0).toBeTruthy();
        });
        test("header is invalid value", () => {
            const header = {name: CHL_BYPASS_SUPPORT, value: "0"};
            found = isBypassHeader(header);
            expect(found).toEqual(-1);
        });
        test("header is invalid name", () => {
            const header = {name: "Different-header-name", value: `${configId}`};
            found = isBypassHeader(header);
            expect(found).toEqual(-1);
        });
        test("config is reset if ID changes", () => {
            const oldConfigId = configId == 1 ? 2 : 1;
            workflow.__with__({CONFIG_ID: oldConfigId, recentConfigChange: false})(() => {
                setMock(bypassTokensCount(oldConfigId), 10);
                const header = {name: CHL_BYPASS_SUPPORT, value: `${configId}`};
                const oldCount = getMock(bypassTokensCount(oldConfigId));
                found = isBypassHeader(header);
                expect(found).toBeTruthy();
                expect(oldCount === getMock(bypassTokensCount(configId))).toBeFalsy();
                expect(updateIconMock).toHaveBeenCalledTimes(1);
            });
        });
        test("config is not reset if ID does not change", () => {
            const oldConfigId = configId;
            workflow.__with__({CONFIG_ID: oldConfigId, recentConfigChange: false})(() => {
                setMock(bypassTokensCount(oldConfigId), 10);
                const header = {name: CHL_BYPASS_SUPPORT, value: `${configId}`};
                const oldCount = getMock(bypassTokensCount(oldConfigId));
                found = isBypassHeader(header);
                expect(found).toBeTruthy();
                expect(oldCount === getMock(bypassTokensCount(configId))).toBeTruthy();
                expect(updateIconMock).toHaveBeenCalledTimes(0);
            });
        });
    });

    describe("check redemption attempt conditions", () => {
        let url;
        let details;
        let header;
        beforeEach(() => {
            header = {name: CHL_BYPASS_SUPPORT, value: configId};
            details = {
                statusCode: spendStatusCode()[0],
                responseHeaders: [header],
            };
            url = new URL("http://www.example.com");
        });

        test("check that favicon urls are ignored", () => {
            url = new URL("https://example.com/favicon.ico");
            expect(isFaviconUrl(url.href)).toBeTruthy();
            const ret = processHeaders(details, url);
            expect(ret.attempted).toBeFalsy();
            expect(ret.xhr).toBeFalsy();
            expect(ret.favicon).toBeTruthy();
            expect(updateIconMock).toBeCalledTimes(0);
        });

        test("check that redemption is not fired on CAPTCHA domain", () => {
            url = new URL(`https://${chlCaptchaDomain()}`);
            const ret = processHeaders(details, url);
            expect(ret.attempted).toBeFalsy();
            expect(ret.xhr).toBeFalsy();
            expect(ret.favicon).toBeFalsy();
        });

        test("redemption is attempted on general domains", () => {
            const ret = processHeaders(details, url);
            expect(ret.attempted).toBeTruthy();
            expect(ret.xhr).toBeFalsy();
            expect(ret.favicon).toBeFalsy();
            expect(updateIconMock).toBeCalledTimes(1);
        });

        test("not fired if status code != spendStatusCode()[0]", () => {
            details.statusCode = 418;
            const ret = processHeaders(details, url);
            expect(ret.attempted).toBeFalsy();
            expect(ret.xhr).toBeFalsy();
            expect(ret.favicon).toBeFalsy();
        });

        test("if count is 0 update icon", () => {
            setNoTokens(configId);
            processHeaders(details, url);
            expect(updateIconMock).toBeCalledTimes(2);
        });

        describe("setting of readyIssue", () => {
            describe("signing enabled", () => {
                beforeEach(() => {
                    workflow.__set__("doSign", () => true);
                    setReadyIssue(configId, false);
                });

                test("no tokens", () => {
                    setNoTokens(configId);
                    const ret = processHeaders(details, url);
                    expect(ret.attempted).toBeFalsy();
                    expect(ret.xhr).toBeFalsy();
                    expect(ret.favicon).toBeFalsy();
                    expect(getReadyIssue(configId)).toBeTruthy();
                    expect(updateIconMock).toBeCalledWith("!");
                });

                test("not activated", () => {
                    header = {name: "Different-header-name", value: configId};
                    details.responseHeaders = [header];
                    const ret = processHeaders(details, url);
                    expect(ret.attempted).toBeFalsy();
                    expect(ret.xhr).toBeFalsy();
                    expect(ret.favicon).toBeFalsy();
                    expect(getReadyIssue(configId)).toBeFalsy();
                });

                test("tokens > 0", () => {
                    const ret = processHeaders(details, url);
                    expect(ret.attempted).toBeTruthy();
                    expect(ret.xhr).toBeFalsy();
                    expect(ret.favicon).toBeFalsy();
                    expect(getReadyIssue(configId)).toBeFalsy();
                });

                test("tokens > 0 but captcha.website", () => {
                    url = new URL(`https://${chlCaptchaDomain()}`);
                    const ret = processHeaders(details, url);
                    expect(ret.attempted).toBeFalsy();
                    expect(ret.xhr).toBeFalsy();
                    expect(ret.favicon).toBeFalsy();
                    expect(getReadyIssue(configId)).toBeTruthy();
                });

                test("redemption off", () => {
                    workflow.__with__({doRedeem: () => false})(() => {
                        const ret = processHeaders(details, url);
                        expect(ret.attempted).toBeFalsy();
                        expect(ret.xhr).toBeFalsy();
                        expect(ret.favicon).toBeFalsy();
                        expect(getReadyIssue(configId)).toBeTruthy();
                    });
                });
            });

            describe("signing disabled", () => {
                beforeEach(() => {
                    setReadyIssue(configId, false);
                });
                test("signing is not activated", () => {
                    workflow.__with__({doSign: () => false})(() => {
                        header = {name: "Different-header-name", value: configId};
                        details.responseHeaders = [header];
                        const ret = processHeaders(details, url);
                        expect(ret.attempted).toBeFalsy();
                        expect(ret.xhr).toBeFalsy();
                        expect(ret.favicon).toBeFalsy();
                        expect(getReadyIssue(configId)).toBeFalsy();
                    });
                });
            });
        });
    });
});

describe("xhr for empty response headers", () => {
    const details = {
        statusCode: 403,
    };
    const url = new URL("https://example.com");

    beforeEach(() => {
        setXHR(mockXHRDirectRequest, workflow);
        // empty response headers
        details.responseHeaders = [];
        // set config values (tests currently are CF specific)
        workflow.__set__("CONFIG_ID", 1);
        workflow.__set__("emptyRespHeaders", () => ["direct-request"]);
        workflow.__set__("spendStatusCode", () => [403]);
    });

    test("direct request is not used if direct-request isn't included in empty-resp-headers", () => {
        workflow.__set__("emptyRespHeaders", () => ["something-else"]);
        const ret = processHeaders(details, url);
        expect(ret.attempted).toBeFalsy();
        expect(ret.xhr).toBeFalsy();
        expect(ret.favicon).toBeFalsy();
    });

    test("direct request is not used if response headers are not empty", () => {
        const someHeader = {name: "some-name", value: "some-value"};
        details.responseHeaders = [someHeader];
        const ret = processHeaders(details, url);
        expect(ret.attempted).toBeFalsy();
        expect(ret.xhr).toBeFalsy();
        expect(ret.favicon).toBeFalsy();
    });

    test("direct request does nothing if xhr status code != specified value", () => {
        const ret = processHeaders(details, url);
        expect(ret.attempted).toBeFalsy();
        expect(ret.xhr).toBeTruthy();
        expect(ret.favicon).toBeFalsy();
        const xhr = ret.xhr;
        xhr.status = 200;
        xhr.setResponseHeader("cf-chl-bypass", 1);
        const b = xhr.onreadystatechange();
        expect(b).toBeFalsy();
        expect(xhr.abort).toBeCalled();
    });

    test("direct request does nothing if CHL_BYPASS_SUPPORT header not received", () => {
        const ret = processHeaders(details, url);
        expect(ret.attempted).toBeFalsy();
        expect(ret.xhr).toBeTruthy();
        expect(ret.favicon).toBeFalsy();
        const xhr = ret.xhr;
        xhr.status = 403;
        xhr.setResponseHeader("some-header", 1);
        const b = xhr.onreadystatechange();
        expect(b).toBeFalsy();
        expect(xhr.abort).toBeCalled();
    });

    test("direct request does nothing if CHL_BYPASS_SUPPORT header has wrong value", () => {
        const ret = processHeaders(details, url);
        expect(ret.attempted).toBeFalsy();
        expect(ret.xhr).toBeTruthy();
        expect(ret.favicon).toBeFalsy();
        const xhr = ret.xhr;
        xhr.status = 403;
        xhr.setResponseHeader(CHL_BYPASS_SUPPORT, 2);
        const b = xhr.onreadystatechange();
        expect(b).toBeFalsy();
        expect(xhr.abort).toBeCalled();
    });

    test("direct request results in possible spend if CHL_BYPASS_SUPPORT header received", () => {
        const ret = processHeaders(details, url);
        expect(ret.attempted).toBeFalsy();
        expect(ret.xhr).toBeTruthy();
        expect(ret.favicon).toBeFalsy();
        const xhr = ret.xhr;
        xhr.status = 403;
        xhr.setResponseHeader(CHL_BYPASS_SUPPORT, 1);
        const b = xhr.onreadystatechange();
        expect(b).toBeTruthy();
        expect(xhr.abort).toBeCalled();
    });
});
