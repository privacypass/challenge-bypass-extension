/**
 * Integrations tests for when headers are sent by the browser
 *
 * @author: Alex Davidson
 */
import btoa from "btoa";
import atob from "atob";

import rewire from "rewire";
import each from "jest-each";

let workflow = rewire("../addon/compiled/test_compiled.js");

const localStorageMock = {
    getItem: key => JSON.parse(localStorageItems[key]),
    setItem: (key, value) => localStorageItems[key] = JSON.stringify(value),
    clear: () => localStorageItems = {},
    removeItem: (key) => localStorageItems[key] = undefined,
};

let localStorageItems = {};

const updateIconMock = jest.fn();

workflow.__set__("localStorage", localStorageMock);
workflow.__set__("localStorageItems", localStorageItems);
workflow.__set__("updateIcon", updateIconMock);
workflow.__set__("atob", atob);
workflow.__set__("btoa", btoa);
setXHR(mockXHRCommitments);

const setSpendFlag = (key, value) => set(key, value);
const getSpendFlag = (key) => get(key)

workflow.__set__("setSpendFlag", setSpendFlag);
workflow.__set__("getSpendFlag", getSpendFlag);

const get = (key) => JSON.parse(localStorage.getItem(key));
const set = (key, value) => localStorage.setItem(key, JSON.stringify(value));

workflow.__set__("get", get);
workflow.__set__("set", set);


const resetVars = workflow.__get__("resetVars");
const resetSpendVars = workflow.__get__("resetSpendVars");
let URL = window.URL;

/**
 * Functions/variables
 */
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


// let config = {"id": 1}

const bypassTokens = (config_id) => `bypass-tokens-${config_id}`;
const bypassTokensCount = (config_id) => `bypass-tokens-count-${config_id}`;

each(PPConfigs().filter(config => config.id > 0).map(config => [config.id]))
    .describe("CONFIG_ID: %i", (config_id) => {
        beforeEach(() => {
            let storedTokens = `[ { "data":[24,62,56,102,76,127,201,111,161,218,249,109,34,122,160,219,93,186,246,12,178,249,241,108,69,181,77,140,158,13,216,184],"point":"/MWxehOPdGROly7JRQxXp4G8WRzMHTqIjtc17kXrk6W4i2nIp3QRv3/1EVQAeJfmTvIwVUgJTMI3KhGQ4pSNTQ==","blind":"0x46af9794d53f040607a35ad297f92aef6a9879686279a12a0a478b2e0bde9089"},{"data":[131,120,153,53,158,58,11,155,160,109,247,176,176,153,14,161,150,120,43,180,188,37,35,75,52,219,177,16,24,101,241,159],"point":"sn4KWtjU+RL7aE53zp4wUdhok4UU9iZTAwQVVAmBoGA+XltG/E3V5xIKZ1fxDs0qhbFG1ujXajYUt831rQcCug==","blind":"0xd475b86c84c94586503f035911388dd702f056472a755e964cbbb3b58c76bd53" } ]`;
            // localStorage = {};

            const bypassTokens = (config_id) => `bypass-tokens-${config_id}`;

            set(bypassTokens(config_id), storedTokens);
            set(bypassTokensCount(config_id), 2);

            details = {
                method: "GET",
                requestHeaders: [],
                requestId: "212",
                tabId: "101",
            };
            url = new URL(EXAMPLE_HREF);
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
                    expect(getSpentUrl([url.href])).toBeTruthy();
                    switch (config_id) {
                        case 1:
                            expect(getSpentTab([details.tabId]) == url.href).toBeTruthy();
                            break
                        case 2:
                            expect(getSpentTab([details.tabId]) == url.href).toBeFalsy();
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
                            expect(getSpentTab([details.tabId]) == url.href).toBeTruthy();
                            break
                        case 2:
                            expect(getSpentTab([details.tabId]) == url.href).toBeFalsy();
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
    });

/* mock XHR implementations */
function mockXHR(_xhr) {
    _xhr.open = function(method, url) {
        _xhr.method = method;
        _xhr.url = url;
    };
    _xhr.requestHeaders = new Map();
    _xhr.getRequestHeader = function(name) {
        return _xhr.requestHeaders[name];
    };
    _xhr.setRequestHeader = function(name, value) {
        _xhr.requestHeaders[name] = value;
    };
    _xhr.overrideMimeType = jest.fn();
    _xhr.body;
    _xhr.send = function(str) {
        _xhr.body = str;
    };
    _xhr.onreadystatechange = function() {
    };
}

function mockXHRCommitments() {
    mockXHR(this);
}

function getSpentUrl(key) {
    const spentUrl = workflow.__get__("spentUrl");
    return spentUrl[key];
}

function getSpendId(key) {
    const spendId = workflow.__get__("spendId");
    return spendId[key];
}

function getSpentTab(key) {
    const spentTab = workflow.__get__("spentTab");
    return spentTab[key];
}

function setSpentUrl(key, value) {
    const spentUrl = new Map();
    spentUrl[key] = value;
    workflow.__set__("spentUrl", spentUrl);
}

function setSpentHosts(key, value) {
    const spentHosts = new Map();
    spentHosts[key] = value;
    workflow.__set__("spentHosts", spentHosts);
}

function setXHR(xhr) {
    workflow.__set__("XMLHttpRequest", xhr);
}
