/**
 * Integrations tests for when headers are sent by the browser
 *
 * @author: Alex Davidson
 */
import each from "jest-each";


let workflow = workflowSet();
/**
 * Functions/variables
 */
const resetVars = workflow.__get__("resetVars");
const resetSpendVars = workflow.__get__("resetSpendVars");
const PPConfigs = workflow.__get__("PPConfigs");
const setConfig = workflow.__get__("setConfig");
const LISTENER_URLS = workflow.__get__("LISTENER_URLS");
const EXAMPLE_HREF = "https://www.example.com";
const CACHED_COMMITMENTS_STRING = "cached-commitments";
const beforeSendHeaders = workflow.__get__("beforeSendHeaders");
const b64EncodedTokenNoH2CParams = "eyJ0eXBlIjoiUmVkZWVtIiwiY29udGVudHMiOlsiR0Q0NFpreC95VytoMnZsdElucWcyMTI2OWd5eStmRnNSYlZOako0TjJMZz0iLCI0d3RmMXcvWGh4aUpydWtJVnBTQ3Z5NjNYR3lnK1o3bm45citVSlFzSGY0PSJdfQ==";
const b64EncodedToken = "eyJ0eXBlIjoiUmVkZWVtIiwiY29udGVudHMiOlsiR0Q0NFpreC95VytoMnZsdElucWcyMTI2OWd5eStmRnNSYlZOako0TjJMZz0iLCI0d3RmMXcvWGh4aUpydWtJVnBTQ3Z5NjNYR3lnK1o3bm45citVSlFzSGY0PSIsImV5SmpkWEoyWlNJNkluQXlOVFlpTENKb1lYTm9Jam9pYzJoaE1qVTJJaXdpYldWMGFHOWtJam9pYVc1amNtVnRaVzUwSW4wPSJdfQ==";
let details;
let url;

each(PPConfigs().filter(config => config.id > 0).map(config => [config.id]))
    .describe("CONFIG_ID: %i", (config_id) => {
        beforeEach(() => {
            set(bypassTokens(config_id), storedTokens);
            set(bypassTokensCount(config_id), 2);

            details = {
                method: "GET",
                requestHeaders: [],
                requestId: "212",
                tabId: "101",
            };
            url = new URL(EXAMPLE_HREF);
            clearSpentTab()
            resetVars();
            resetSpendVars();
            workflow.__set__("CONFIG_ID", config_id);
            workflow.__set__("SPEND_ACTION_URLS", () => [LISTENER_URLS])
            // config["spend-action"]["urls"] = [LISTENER_URLS];
        });
        describe("redemptions are not attempted", () => {
            test("redemption is off", () => {
                workflow.__with__({DO_REDEEM: () => false})(() => {
                    let redeemHdrs = beforeSendHeaders(details, url);
                    expect(redeemHdrs.cancel).toBeFalsy();
                    expect(redeemHdrs.requestHeaders).toBeFalsy();
                });
            });
            test("spend flag not set", () => {
                expect(getSpendFlag(url.host)).toBeNull();
                let redeemHdrs = beforeSendHeaders(details, url);
                expect(redeemHdrs.cancel).toBeFalsy();
                expect(redeemHdrs.requestHeaders).toBeFalsy();
            });
            test("url is error page", () => {
                let newUrl = EXAMPLE_HREF + "/cdn-cgi/styles/";
                url = new URL(newUrl);
                setSpendFlag(url.host, true);
                const redeemHdrs = beforeSendHeaders(details, url);
                expect(redeemHdrs.cancel).toBeFalsy();
                expect(redeemHdrs.requestHeaders).toBeFalsy();
            });
            test("url is favicon", () => {
                let newUrl = EXAMPLE_HREF + "/favicon.ico";
                url = new URL(newUrl);
                setSpendFlag(url.host, true);
                const redeemHdrs = beforeSendHeaders(details, url);
                expect(redeemHdrs.cancel).toBeFalsy();
                expect(redeemHdrs.requestHeaders).toBeFalsy();
            });
            test("max spend has been reached", () => {

                setSpendFlag(url.host, true);
                setSpentHosts(url.host, 31);
                let redeemHdrs = beforeSendHeaders(details, url);
                expect(redeemHdrs.cancel).toBeFalsy();
                switch (config_id) {
                    case 1:
                        workflow.__with__({SPEND_MAX: () => 3})(() => {
                            expect(redeemHdrs.requestHeaders).toBeFalsy();
                        })
                        break
                    case 2:
                        // hCaptcha has no SPEND_MAX
                        expect(workflow.__get__("CONFIG_ID")).toBe(2);
                        expect(workflow.__get__("SPEND_MAX")()).toBe(0);
                        expect(redeemHdrs.requestHeaders).toBeTruthy();
                        break
                    default:
                        throw Error(`Unhandled config.id value => ${config_id}`)
                }
            });
            test("spend has been attempted for url", () => {
                setSpendFlag(url.host, true);
                setSpentHosts(url.host, 0);
                setSpentUrl(url.href, true);
                let redeemHdrs = beforeSendHeaders(details, url);
                expect(redeemHdrs.cancel).toBeFalsy();
                switch (config_id) {
                    case 1:
                        expect(redeemHdrs.requestHeaders).toBeFalsy();
                        break
                    case 2:
                        // hCaptcha will always spend on its URLS
                        expect(redeemHdrs.requestHeaders).toBeTruthy();
                        break
                    default:
                        throw Error(`Unhandled config.id value => ${config_id}`)
                }
            });
            test("redemption method is not reload", () => {
                workflow.__with__({REDEEM_METHOD: () => "invalid"})(() => {
                    setSpendFlag(url.host, true);
                    setSpentHosts(url.host, 0);
                    setSpentUrl(url.href, false);
                    let redeemHdrs = beforeSendHeaders(details, url);
                    expect(redeemHdrs.cancel).toBeFalsy();
                    expect(redeemHdrs.requestHeaders).toBeFalsy();
                });
            });
            test(`no token to spend`, () => {
                set(bypassTokensCount(config_id), 0);
                set(bypassTokens(config_id), "{}");
                setSpentUrl(url.href, false);
                setSpendFlag(url.host, true);
                const redeemHdrs = beforeSendHeaders(details, url);
                expect(redeemHdrs.cancel).toBeFalsy();
                expect(redeemHdrs.requestHeaders).toBeFalsy();
                expect(getSpendFlag(url.host)).toBeNull();
            });
        });
        describe("redemption attempted", () => {
            test(`redemption header added (SEND_H2C_PARAMS = false)`, () => {
                workflow.__with__({SEND_H2C_PARAMS: () => false})(() => {
                    setSpendFlag(url.host, true);
                    setSpentUrl(url.href, false);
                    let redeemHdrs = beforeSendHeaders(details, url);
                    let reqHeaders = redeemHdrs.requestHeaders;
                    expect(getSpendFlag(url.host)).toBeNull();
                    expect(getSpendId([details.requestId])).toBeTruthy();
                    expect(getSpentUrl(url.href)).toBeTruthy();
                    switch (config_id) {
                        case 1:
                            expect(getSpentTab([details.tabId]).includes(url.href)).toBeTruthy();
                            break
                        case 2:
                            expect(getSpentTab([details.tabId])).toBeUndefined();
                            break
                        default:
                            throw Error(`Unhandled config.id value => ${config_id}`)
                    }
                    expect(reqHeaders).toBeTruthy();
                    let headerName = workflow.__get__("HEADER_NAME")();
                    expect(reqHeaders[0].name === headerName).toBeTruthy();
                    expect(reqHeaders[0].value === b64EncodedTokenNoH2CParams).toBeTruthy();
                })
            });
            test(`redemption header added (SEND_H2C_PARAMS = true)`, () => {
                workflow.__with__({SEND_H2C_PARAMS: () => true})(() => {
                    setSpendFlag(url.host, true);
                    setSpentUrl(url.href, false);
                    let redeemHdrs = beforeSendHeaders(details, url);
                    let reqHeaders = redeemHdrs.requestHeaders;
                    expect(getSpendFlag(url.host)).toBeNull();
                    expect(getSpendId([details.requestId])).toBeTruthy();
                    expect(getSpentUrl([url.href])).toBeTruthy();
                    switch (config_id) {
                        case 1:
                            expect(getSpentTab([details.tabId]).includes(url.href)).toBeTruthy();
                            break
                        case 2:
                            expect(getSpentTab([details.tabId])).toBeUndefined();
                            break
                        default:
                            throw Error(`Unhandled config.id value => ${config_id}`)
                    }
                    expect(reqHeaders).toBeTruthy();
                    let headerName = workflow.__get__("HEADER_NAME")();
                    expect(reqHeaders[0].name === headerName).toBeTruthy();
                    expect(reqHeaders[0].value === b64EncodedToken).toBeTruthy();
                });
            });
        });
    })
