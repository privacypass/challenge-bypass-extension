/**
 * Integrations tests for when headers are sent by the browser
 *
 * @author: Alex Davidson
 * @author: Drazen Urch
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
            setMock(bypassTokens(config_id), storedTokens);
            setMock(bypassTokensCount(config_id), 2);

            details = {
                method: "GET",
                requestHeaders: [],
                requestId: "212",
                tabId: "101",
            };
            url = new URL(EXAMPLE_HREF);
            clearSpentTabMock()
            resetVars();
            resetSpendVars();
            workflow.__set__("CONFIG_ID", config_id);
            workflow.__set__("spendActionUrls", () => [LISTENER_URLS])
            // config["spend-action"]["urls"] = [LISTENER_URLS];
        });
        describe("redemptions are not attempted", () => {
            test("redemption is off", () => {
                workflow.__with__({doRedeem: () => false})(() => {
                    let redeemHdrs = beforeSendHeaders(details, url);
                    expect(redeemHdrs.cancel).toBeFalsy();
                    expect(redeemHdrs.requestHeaders).toBeFalsy();
                });
            });
            test("spend flag not set", () => {
                expect(getSpendFlagMock(url.host)).toBeNull();
                let redeemHdrs = beforeSendHeaders(details, url);
                expect(redeemHdrs.cancel).toBeFalsy();
                expect(redeemHdrs.requestHeaders).toBeFalsy();
            });
            test("url is error page", () => {
                let newUrl = EXAMPLE_HREF + "/cdn-cgi/styles/";
                url = new URL(newUrl);
                setSpendFlagMock(url.host, true);
                const redeemHdrs = beforeSendHeaders(details, url);
                expect(redeemHdrs.cancel).toBeFalsy();
                expect(redeemHdrs.requestHeaders).toBeFalsy();
            });
            test("url is favicon", () => {
                let newUrl = EXAMPLE_HREF + "/favicon.ico";
                url = new URL(newUrl);
                setSpendFlagMock(url.host, true);
                const redeemHdrs = beforeSendHeaders(details, url);
                expect(redeemHdrs.cancel).toBeFalsy();
                expect(redeemHdrs.requestHeaders).toBeFalsy();
            });
            test("max spend has been reached", () => {

                setSpendFlagMock(url.host, true);
                setSpentHostsMock(url.host, 31);
                let redeemHdrs = beforeSendHeaders(details, url);
                expect(redeemHdrs.cancel).toBeFalsy();
                switch (config_id) {
                    case 1:
                        workflow.__with__({spendMax: () => 3})(() => {
                            expect(redeemHdrs.requestHeaders).toBeFalsy();
                        })
                        break
                    case 2:
                        // hCaptcha has no spendMax
                        expect(workflow.__get__("CONFIG_ID")).toBe(2);
                        expect(workflow.__get__("spendMax")()).toBe(0);
                        expect(redeemHdrs.requestHeaders).toBeTruthy();
                        break
                    default:
                        throw Error(`Unhandled config.id value => ${config_id}`)
                }
            });
            test("spend has been attempted for url", () => {
                setSpendFlagMock(url.host, true);
                setSpentHostsMock(url.host, 0);
                setSpentUrlMock(url.href, true);
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
            test("redemption method is invalid", () => {
                workflow.__with__({redeemMethod: () => "invalid"})(() => {
                    setSpendFlagMock(url.host, true);
                    setSpentHostsMock(url.host, 0);
                    setSpentUrlMock(url.href, false);
                    let redeemHdrs = beforeSendHeaders(details, url);
                    expect(redeemHdrs.cancel).toBeFalsy();
                    expect(redeemHdrs.requestHeaders).toBeFalsy();
                });
            });
            test(`no token to spend`, () => {
                setMock(bypassTokensCount(config_id), 0);
                setMock(bypassTokens(config_id), "{}");
                setSpentUrlMock(url.href, false);
                setSpendFlagMock(url.host, true);
                const redeemHdrs = beforeSendHeaders(details, url);
                expect(redeemHdrs.cancel).toBeFalsy();
                expect(redeemHdrs.requestHeaders).toBeFalsy();
                expect(getSpendFlagMock(url.host)).toBeNull();
            });
        });
        describe("redemption attempted", () => {
            test(`redemption header added (SEND_H2C_PARAMS = false)`, () => {
                workflow.__with__({sendH2CParams: () => false})(() => {
                    setSpendFlagMock(url.host, true);
                    setSpentUrlMock(url.href, false);
                    let redeemHdrs = beforeSendHeaders(details, url);
                    let reqHeaders = redeemHdrs.requestHeaders;
                    expect(getSpendFlagMock(url.host)).toBeNull();
                    expect(getSpendIdMock([details.requestId])).toBeTruthy();
                    expect(getSpentUrlMock(url.href)).toBeTruthy();
                    switch (config_id) {
                        case 1:
                            expect(getSpentTabMock([details.tabId]).includes(url.href)).toBeTruthy();
                            break
                        case 2:
                            expect(getSpentTabMock([details.tabId])).toBeUndefined();
                            break
                        default:
                            throw Error(`Unhandled config.id value => ${config_id}`)
                    }
                    expect(reqHeaders).toBeTruthy();
                    let headerName = workflow.__get__("headerName")();
                    expect(reqHeaders[0].name === headerName).toBeTruthy();
                    expect(reqHeaders[0].value === b64EncodedTokenNoH2CParams).toBeTruthy();
                })
            });
            test(`redemption header added (SEND_H2C_PARAMS = true)`, () => {
                workflow.__with__({sendH2CParams: () => true})(() => {
                    setSpendFlagMock(url.host, true);
                    setSpentUrlMock(url.href, false);
                    let redeemHdrs = beforeSendHeaders(details, url);
                    let reqHeaders = redeemHdrs.requestHeaders;
                    expect(getSpendFlagMock(url.host)).toBeNull();
                    expect(getSpendIdMock([details.requestId])).toBeTruthy();
                    expect(getSpentUrlMock([url.href])).toBeTruthy();
                    switch (config_id) {
                        case 1:
                            expect(getSpentTabMock([details.tabId]).includes(url.href)).toBeTruthy();
                            break
                        case 2:
                            expect(getSpentTabMock([details.tabId])).toBeUndefined();
                            break
                        default:
                            throw Error(`Unhandled config.id value => ${config_id}`)
                    }
                    expect(reqHeaders).toBeTruthy();
                    let headerName = workflow.__get__("headerName")();
                    expect(reqHeaders[0].name === headerName).toBeTruthy();
                    expect(reqHeaders[0].value === b64EncodedToken).toBeTruthy();
                });
            });
        });
    })
