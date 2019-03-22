/**

 * Integrations tests for when headers are received by the extension
 *
 * @author: Alex Davidson
 * @author: Drazen Urch
 */

import each from "jest-each"

let workflow = workflowSet();


/**
 * Functions
 */
const CHL_BYPASS_SUPPORT = workflow.__get__("CHL_BYPASS_SUPPORT");
const CHL_BYPASS_RESPONSE = workflow.__get__("CHL_BYPASS_RESPONSE");
const chlVerificationError = workflow.__get__("chlVerificationError")
const spendStatusCode = workflow.__get__("spendStatusCode")
const chlConnectionError = workflow.__get__("chlConnectionError")
const isFaviconUrl = workflow.__get__("isFaviconUrl")
const PPConfigs = workflow.__get__("PPConfigs");
const LISTENER_URLS = workflow.__get__("LISTENER_URLS");
const CACHED_COMMITMENTS_STRING = "cached-commitments";
const EXAMPLE_HREF = "https://www.example.com";
const processHeaders = workflow.__get__("processHeaders");
const isBypassHeader = workflow.__get__("isBypassHeader");
const setConfig = workflow.__get__("setConfig");
const chlCaptchaDomain = workflow.__get__("chlCaptchaDomain");

let config_id;

const setNoTokens = (config_id) => {
    setMock(bypassTokens(config_id), "{}");
    setMock(bypassTokensCount(config_id), 0);
}
/**
 * Tests
 * (Currently unable to test workflows that are dependent on cookies)
 */

each(PPConfigs().filter(config => config.id > 0).map(config => [config.id]))
    .describe("CONFIG_ID = %i", (config_id) => {
        beforeEach(() => {
            clearLocalStorage()
            // Override global setting
            workflow.__set__("attemptRedeem", () => true);
            workflow.__set__("CONFIG_ID", config_id);
            workflow.__set__("spendActionUrls", () => [LISTENER_URLS])
            workflow.__set__("issueActionUrls", () => [LISTENER_URLS])
            setMock(bypassTokens(config_id), storedTokens);
            setMock(bypassTokensCount(config_id), 2);
        });

        describe("ensure that errors are handled properly", () => {
            let url = new URL(EXAMPLE_HREF);
            test("connection error", () => {
                localStorage.setItem("data", "some token")

                function processConnError() {
                    const details = {
                        responseHeaders: [{name: CHL_BYPASS_RESPONSE, value: chlConnectionError()}]
                    }
                    processHeaders(details, url);
                }

                expect(processConnError).toThrowError(`error code: ${chlConnectionError()}`);
                expect(localStorage.getItem("data")).toBeTruthy();
            });
            test("verification error", () => {
                function processVerifyError() {
                    const details = {
                        responseHeaders: [{name: CHL_BYPASS_RESPONSE, value: chlVerificationError()}]
                    }
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
                let header = {name: CHL_BYPASS_SUPPORT, value: `${config_id}`};
                found = isBypassHeader(header);
                expect(found).toBeTruthy();
            });
            test("header is invalid value", () => {
                let header = {name: CHL_BYPASS_SUPPORT, value: "0"};
                found = isBypassHeader(header);
                expect(found).toBeFalsy();
            });
            test("header is invalid name", () => {
                let header = {name: "Different-header-name", value: `${config_id}`};
                found = isBypassHeader(header);
                expect(found).toBeFalsy();
            });
            test("config is reset if ID changes", () => {
                const old_config_id = config_id + 1;
                workflow.__with__({CONFIG_ID: old_config_id})(() => {
                    setMock(bypassTokensCount(old_config_id), 10);
                    let header = {name: CHL_BYPASS_SUPPORT, value: `${config_id}`};
                    let old_count = getMock(bypassTokensCount(old_config_id))
                    found = isBypassHeader(header);
                    expect(found).toBeTruthy();
                    expect(old_count === getMock(bypassTokensCount(config_id))).toBeFalsy()
                })

            });
            test("config is not reset if ID does not change", () => {
                const old_config_id = config_id;
                workflow.__with__({CONFIG_ID: old_config_id})(() => {
                    setMock(bypassTokensCount(old_config_id), 10);
                    let header = {name: CHL_BYPASS_SUPPORT, value: `${config_id}`};
                    let old_count = getMock(bypassTokensCount(old_config_id))
                    found = isBypassHeader(header);
                    expect(found).toBeTruthy();
                    expect(old_count === getMock(bypassTokensCount(config_id))).toBeTruthy()
                })
            });
        });
        describe("check redemption attempt conditions", () => {
            let url;
            let details;
            let header;
            beforeEach(() => {
                header = {name: CHL_BYPASS_SUPPORT, value: config_id};
                details = {
                    statusCode: spendStatusCode()[0],
                    responseHeaders: [header]
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
                setNoTokens(config_id)
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
                        setNoTokens(config_id)
                        const fired = processHeaders(details, url);
                        expect(fired).toBeFalsy();
                        const readySign = workflow.__get__("readySign");
                        expect(readySign).toBeTruthy();
                        expect(updateIconMock).toBeCalledWith("!");

                    });

                    test("not activated", () => {
                        header = {name: "Different-header-name", value: config_id};
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
                            header = {name: "Different-header-name", value: config_id};
                            details.responseHeaders = [header];
                            const fired = processHeaders(details, url);
                            expect(fired).toBeFalsy();
                        })
                    });
                });
            });
        });
    });
