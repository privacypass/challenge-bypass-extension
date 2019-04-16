/**

 * Integrations tests for when headers are received by the extension
 *
 * @author: Alex Davidson
 * @author: Drazen Urch
 */

import each from "jest-each";

const workflow = workflowSet();

/**
 * Functions
 */
const CHL_BYPASS_SUPPORT = workflow.__get__("CHL_BYPASS_SUPPORT");
const CHL_BYPASS_RESPONSE = workflow.__get__("CHL_BYPASS_RESPONSE");
const chlVerificationError = workflow.__get__("chlVerificationError");
const spendStatusCode = workflow.__get__("spendStatusCode");
const chlConnectionError = workflow.__get__("chlConnectionError");
const isFaviconUrl = workflow.__get__("isFaviconUrl");
const PPConfigs = workflow.__get__("PPConfigs");
const LISTENER_URLS = workflow.__get__("LISTENER_URLS");
const EXAMPLE_HREF = "https://www.example.com";
const processHeaders = workflow.__get__("processHeaders");
const isBypassHeader = workflow.__get__("isBypassHeader");
const chlCaptchaDomain = workflow.__get__("chlCaptchaDomain");

const setNoTokens = (configId) => {
    setMock(bypassTokens(configId), "{}");
    setMock(bypassTokensCount(configId), 0);
};
/**
 * Tests
 * (Currently unable to test workflows that are dependent on cookies)
 */

each(PPConfigs().filter((config) => config.id > 0).map((config) => [config.id]))
    .describe("CONFIG_ID = %i", (configId) => {
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
            test("connection error", () => {
                localStorage.setItem("data", "some token");

                function processConnError() {
                    const details = {
                        responseHeaders: [{name: CHL_BYPASS_RESPONSE, value: chlConnectionError()}],
                    };
                    processHeaders(details, url);
                }

                expect(processConnError).toThrowError(`error code: ${chlConnectionError()}`);
                expect(localStorage.getItem("data")).toBeTruthy();
            });
            test("verification error", () => {
                function processVerifyError() {
                    const details = {
                        responseHeaders: [{name: CHL_BYPASS_RESPONSE, value: chlVerificationError()}],
                    };
                    processHeaders(details, url);
                }

                expect(processVerifyError).toThrowError(`error code: ${chlVerificationError()}`);
                expect(localStorage.getItem("data")).toBeFalsy();
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
                expect(found).toBeTruthy();
            });
            test("header is invalid value", () => {
                const header = {name: CHL_BYPASS_SUPPORT, value: "0"};
                found = isBypassHeader(header);
                expect(found).toBeFalsy();
            });
            test("header is invalid name", () => {
                const header = {name: "Different-header-name", value: `${configId}`};
                found = isBypassHeader(header);
                expect(found).toBeFalsy();
            });
            test("config is reset if ID changes", () => {
                const oldConfigId = configId + 1;
                workflow.__with__({CONFIG_ID: oldConfigId})(() => {
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
                workflow.__with__({CONFIG_ID: oldConfigId})(() => {
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
                const fired = processHeaders(details, url);
                expect(fired).toBeFalsy();
                expect(updateIconMock).toBeCalledTimes(0);
            });

            test("check that redemption is not fired on CAPTCHA domain", () => {
                url = new URL(`https://${chlCaptchaDomain()}`);
                const fired = processHeaders(details, url);
                expect(fired).toBeFalsy();
            });

            test("redemption is attempted on general domains", () => {
                const fired = processHeaders(details, url);
                expect(fired).toBeTruthy;
                expect(updateIconMock).toBeCalledTimes(1);
            });

            test("not fired if status code != spendStatusCode()[0]", () => {
                details.statusCode = 418;
                const fired = processHeaders(details, url);
                expect(fired).toBeFalsy();
            });

            test("if count is 0 update icon", () => {
                setNoTokens(configId);
                processHeaders(details, url);
                expect(updateIconMock).toBeCalledTimes(2);
            });

            describe("setting of readySign", () => {
                describe("signing enabled", () => {
                    beforeEach(() => {
                        workflow.__set__("doSign", () => true);
                        workflow.__set__("readySign", false);
                    });

                    test("no tokens", () => {
                        setNoTokens(configId);
                        const fired = processHeaders(details, url);
                        expect(fired).toBeFalsy();
                        const readySign = workflow.__get__("readySign");
                        expect(readySign).toBeTruthy();
                        expect(updateIconMock).toBeCalledWith("!");
                    });

                    test("not activated", () => {
                        header = {name: "Different-header-name", value: configId};
                        details.responseHeaders = [header];
                        const fired = processHeaders(details, url);
                        expect(fired).toBeFalsy();
                        const readySign = workflow.__get__("readySign");
                        expect(readySign).toBeFalsy();
                    });

                    test("tokens > 0", () => {
                        const fired = processHeaders(details, url);
                        expect(fired).toBeTruthy();
                        const readySign = workflow.__get__("readySign");
                        expect(readySign).toBeFalsy();
                    });

                    test("tokens > 0 but captcha.website", () => {
                        url = new URL(`https://${chlCaptchaDomain()}`);
                        const fired = processHeaders(details, url);
                        expect(fired).toBeFalsy();
                        const readySign = workflow.__get__("readySign");
                        expect(readySign).toBeTruthy();
                    });

                    test("redemption off", () => {
                        workflow.__with__({doRedeem: () => false})(() => {
                            const fired = processHeaders(details, url);
                            expect(fired).toBeFalsy();
                            const readySign = workflow.__get__("readySign");
                            expect(readySign).toBeTruthy();
                        });
                    });
                });

                describe("signing disabled", () => {
                    test("signing is not activated", () => {
                        workflow.__with__({readySign: false, doSign: () => false})(() => {
                            header = {name: "Different-header-name", value: configId};
                            details.responseHeaders = [header];
                            const fired = processHeaders(details, url);
                            expect(workflow.__get__("readySign")).toBeFalsy();
                            expect(fired).toBeFalsy();
                        });
                    });
                });
            });
        });
    });
