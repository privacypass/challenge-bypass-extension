/**
 * Integrations tests for when headers are sent by the browser
 *
 * @author: Alex Davidson
 * @author: Drazen Urch
 */
import each from "jest-each";


const workflow = workflowSet();
/**
 * Functions/variables
 */
const resetVars = workflow.__get__("resetVars");
const resetSpendVars = workflow.__get__("resetSpendVars");
const PPConfigs = workflow.__get__("PPConfigs");
const LISTENER_URLS = workflow.__get__("LISTENER_URLS");
const EXAMPLE_HREF = "https://www.example.com";
const beforeSendHeaders = workflow.__get__("beforeSendHeaders");
const b64EncodedTokenNoH2CParams = "eyJ0eXBlIjoiUmVkZWVtIiwiY29udGVudHMiOlsiR0Q0NFpreC95VytoMnZsdElucWcyMTI2OWd5eStmRnNSYlZOako0TjJMZz0iLCI0d3RmMXcvWGh4aUpydWtJVnBTQ3Z5NjNYR3lnK1o3bm45citVSlFzSGY0PSJdfQ==";
const b64EncodedToken = "eyJ0eXBlIjoiUmVkZWVtIiwiY29udGVudHMiOlsiR0Q0NFpreC95VytoMnZsdElucWcyMTI2OWd5eStmRnNSYlZOako0TjJMZz0iLCI0d3RmMXcvWGh4aUpydWtJVnBTQ3Z5NjNYR3lnK1o3bm45citVSlFzSGY0PSIsImV5SmpkWEoyWlNJNkluQXlOVFlpTENKb1lYTm9Jam9pYzJoaE1qVTJJaXdpYldWMGFHOWtJam9pYVc1amNtVnRaVzUwSW4wPSJdfQ==";
let details;
let url;

each(PPConfigs().filter((config) => config.id > 0).map((config) => [config.id]))
    .describe("CONFIG_ID: %i", (configId) => {
        beforeEach(() => {
            setMock(bypassTokens(configId), storedTokens);
            setMock(bypassTokensCount(configId), 2);

            details = {
                method: "GET",
                requestHeaders: [],
                requestId: "212",
                tabId: "101",
            };
            url = new URL(EXAMPLE_HREF);
            resetVars();
            resetSpendVars();
            workflow.__set__("CONFIG_ID", configId);
            workflow.__set__("spendActionUrls", () => [LISTENER_URLS]);
        });
        describe("redemptions are not attempted", () => {
            test("redemption is off", () => {
                workflow.__with__({doRedeem: () => false})(() => {
                    const redeemHdrs = beforeSendHeaders(details, url);
                    expect(redeemHdrs.cancel).toBeFalsy();
                    expect(redeemHdrs.requestHeaders).toBeFalsy();
                });
            });
            test("spend flag not set", () => {
                expect(getSpendFlagMock(url.host)).toBeNull();
                const redeemHdrs = beforeSendHeaders(details, url);
                expect(redeemHdrs.cancel).toBeFalsy();
                expect(redeemHdrs.requestHeaders).toBeFalsy();
            });
            test("url is error page", () => {
                const newUrl = EXAMPLE_HREF + "/cdn-cgi/styles/";
                url = new URL(newUrl);
                setSpendFlagMock(url.host, true);
                const redeemHdrs = beforeSendHeaders(details, url);
                expect(redeemHdrs.cancel).toBeFalsy();
                expect(redeemHdrs.requestHeaders).toBeFalsy();
            });
            test("url is favicon", () => {
                const newUrl = EXAMPLE_HREF + "/favicon.ico";
                url = new URL(newUrl);
                setSpendFlagMock(url.host, true);
                const redeemHdrs = beforeSendHeaders(details, url);
                expect(redeemHdrs.cancel).toBeFalsy();
                expect(redeemHdrs.requestHeaders).toBeFalsy();
            });
            test("max spend has been reached", () => {
                setSpendFlagMock(url.host, true);
                setSpentHostsMock(url.host, 31);
                const redeemHdrs = beforeSendHeaders(details, url);
                expect(redeemHdrs.cancel).toBeFalsy();
                switch (configId) {
                    case 1:
                        workflow.__with__({spendMax: () => 3})(() => {
                            expect(redeemHdrs.requestHeaders).toBeFalsy();
                        });
                        break;
                    case 2:
                        // hCaptcha has no spendMax
                        expect(workflow.__get__("spendMax")()).toBeUndefined();
                        expect(redeemHdrs.requestHeaders).toBeTruthy();
                        break;
                    default:
                        throw Error(`Unhandled config.id value => ${configId}`);
                }
            });
            test("spend has been attempted for url", () => {
                setSpendFlagMock(url.host, true);
                setSpentHostsMock(url.host, 0);
                setSpentUrlMock(url.href, true);
                const redeemHdrs = beforeSendHeaders(details, url);
                expect(redeemHdrs.cancel).toBeFalsy();
                switch (configId) {
                    case 1:
                        expect(redeemHdrs.requestHeaders).toBeFalsy();
                        break;
                    case 2:
                        // hCaptcha will always spend on its URLS
                        expect(redeemHdrs.requestHeaders).toBeTruthy();
                        break;
                    default:
                        throw Error(`Unhandled config.id value => ${configId}`);
                }
            });
            test("redemption method is invalid", () => {
                workflow.__with__({redeemMethod: () => "invalid"})(() => {
                    setSpendFlagMock(url.host, true);
                    setSpentHostsMock(url.host, 0);
                    setSpentUrlMock(url.href, false);
                    const redeemHdrs = beforeSendHeaders(details, url);
                    expect(redeemHdrs.cancel).toBeFalsy();
                    expect(redeemHdrs.requestHeaders).toBeFalsy();
                });
            });
            test(`no token to spend`, () => {
                setMock(bypassTokensCount(configId), 0);
                setMock(bypassTokens(configId), "{}");
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
                    const redeemHdrs = beforeSendHeaders(details, url);
                    const reqHeaders = redeemHdrs.requestHeaders;
                    expect(getSpendFlagMock(url.host)).toBeNull();
                    expect(getSpendIdMock([details.requestId])).toBeTruthy();
                    expect(getSpentUrlMock(url.href)).toBeTruthy();
                    expect(getSpentTabMock([details.tabId]).includes(url.href)).toBeTruthy();
                    expect(reqHeaders).toBeTruthy();
                    const headerName = workflow.__get__("headerName")();
                    expect(reqHeaders[0].name === headerName).toBeTruthy();
                    expect(reqHeaders[0].value === b64EncodedTokenNoH2CParams).toBeTruthy();
                });
            });
            test(`redemption header added (SEND_H2C_PARAMS = true)`, () => {
                workflow.__with__({sendH2CParams: () => true})(() => {
                    setSpendFlagMock(url.host, true);
                    setSpentUrlMock(url.href, false);
                    const redeemHdrs = beforeSendHeaders(details, url);
                    const reqHeaders = redeemHdrs.requestHeaders;
                    expect(getSpendFlagMock(url.host)).toBeNull();
                    expect(getSpendIdMock([details.requestId])).toBeTruthy();
                    expect(getSpentUrlMock([url.href])).toBeTruthy();
                    expect(getSpentTabMock([details.tabId]).includes(url.href)).toBeTruthy();
                    expect(reqHeaders).toBeTruthy();
                    const headerName = workflow.__get__("headerName")();
                    expect(reqHeaders[0].name === headerName).toBeTruthy();
                    expect(reqHeaders[0].value === b64EncodedToken).toBeTruthy();
                });
            });
        });
    });
