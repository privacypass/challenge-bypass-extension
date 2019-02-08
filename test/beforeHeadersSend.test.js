/**
* Integrations tests for when headers are sent by the browser
* 
* @author: Alex Davidson
*/
import btoa from "btoa";
import atob from "atob";

import rewire from "rewire";
var workflow = rewire("../addon/compiled/test_compiled.js");
const resetVars = workflow.__get__("resetVars");
const resetSpendVars = workflow.__get__("resetSpendVars");
var URL = window.URL;

/**
* Functions/variables
*/
const EXAMPLE_HREF = "https://www.example.com";
const beforeSendHeaders = workflow.__get__('beforeSendHeaders');
const setConfig = workflow.__get__('setConfig');
const b64EncodedTokenNoH2CParams = "eyJ0eXBlIjoiUmVkZWVtIiwiY29udGVudHMiOltbMjQsNjIsNTYsMTAyLDc2LDEyNywyMDEsMTExLDE2MSwyMTgsMjQ5LDEwOSwzNCwxMjIsMTYwLDIxOSw5MywxODYsMjQ2LDEyLDE3OCwyNDksMjQxLDEwOCw2OSwxODEsNzcsMTQwLDE1OCwxMywyMTYsMTg0XSxbMjI3LDExLDk1LDIxNSwxNSwyMTUsMTM1LDI0LDEzNywxNzQsMjMzLDgsODYsMTQ4LDEzMCwxOTEsNDYsMTgzLDkyLDEwOCwxNjAsMjQ5LDE1OCwyMzEsMTU5LDIxOCwyNTQsODAsMTQ4LDQ0LDI5LDI1NF1dfQ==";
const b64EncodedToken = "eyJ0eXBlIjoiUmVkZWVtIiwiY29udGVudHMiOltbMjQsNjIsNTYsMTAyLDc2LDEyNywyMDEsMTExLDE2MSwyMTgsMjQ5LDEwOSwzNCwxMjIsMTYwLDIxOSw5MywxODYsMjQ2LDEyLDE3OCwyNDksMjQxLDEwOCw2OSwxODEsNzcsMTQwLDE1OCwxMywyMTYsMTg0XSxbMjI3LDExLDk1LDIxNSwxNSwyMTUsMTM1LDI0LDEzNywxNzQsMjMzLDgsODYsMTQ4LDEzMCwxOTEsNDYsMTgzLDkyLDEwOCwxNjAsMjQ5LDE1OCwyMzEsMTU5LDIxOCwyNTQsODAsMTQ4LDQ0LDI5LDI1NF0sWzEyMywzNCw5OSwxMTcsMTE0LDExOCwxMDEsMzQsNTgsMzQsMTEyLDUwLDUzLDU0LDM0LDQ0LDM0LDEwNCw5NywxMTUsMTA0LDM0LDU4LDM0LDExNSwxMDQsOTcsNTAsNTMsNTQsMzQsNDQsMzQsMTA5LDEwMSwxMTYsMTA0LDExMSwxMDAsMzQsNTgsMzQsMTA1LDExMCw5OSwxMTQsMTAxLDEwOSwxMDEsMTEwLDExNiwzNCwxMjVdXX0=";
let localStorage;
let details;
let url;
let getMock;
let setMock;
let getSpendFlag;
let setSpendFlag;
beforeEach(() => {
    let storedTokens = `[ { "data":[24,62,56,102,76,127,201,111,161,218,249,109,34,122,160,219,93,186,246,12,178,249,241,108,69,181,77,140,158,13,216,184],"point":"/MWxehOPdGROly7JRQxXp4G8WRzMHTqIjtc17kXrk6W4i2nIp3QRv3/1EVQAeJfmTvIwVUgJTMI3KhGQ4pSNTQ==","blind":"0x46af9794d53f040607a35ad297f92aef6a9879686279a12a0a478b2e0bde9089"},{"data":[131,120,153,53,158,58,11,155,160,109,247,176,176,153,14,161,150,120,43,180,188,37,35,75,52,219,177,16,24,101,241,159],"point":"sn4KWtjU+RL7aE53zp4wUdhok4UU9iZTAwQVVAmBoGA+XltG/E3V5xIKZ1fxDs0qhbFG1ujXajYUt831rQcCug==","blind":"0xd475b86c84c94586503f035911388dd702f056472a755e964cbbb3b58c76bd53" } ]`;
    localStorage = {
        "bypass-tokens-1": storedTokens,
        "bypass-tokens-count-1": 2
    }
    details = {
        method: "GET",
        requestHeaders: [],
        requestId: "212",
        tabId: "101"
    };
    url = new URL(EXAMPLE_HREF);
    setMockFunctions();
    setConfig(1); // set the CF config
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
    }
    _xhr.setRequestHeader = function(name, value) {
        _xhr.requestHeaders[name] = value;
    }
    _xhr.overrideMimeType = jest.fn();
    _xhr.body;
    _xhr.send = function(str) {
        _xhr.body = str;
    }
    _xhr.onreadystatechange = function() {};
}

function mockXHRCommitments() {
    mockXHR(this);
}

/**
* Tests
*/
describe("redemptions are not attempted", () => {
    test("redemption is off", () => {
        workflow.__set__("DO_REDEEM", false);
        let redeemHdrs = beforeSendHeaders(details, url);
        expect(redeemHdrs.cancel).toBeFalsy();
        expect(redeemHdrs.requestHeaders).toBeFalsy();
    });
    test("spend flag not set", () => {
        let redeemHdrs = beforeSendHeaders(details, url);
        expect(redeemHdrs.cancel).toBeFalsy();
        expect(redeemHdrs.requestHeaders).toBeFalsy();
    });
    test("url is error page", () => {
        let newUrl = EXAMPLE_HREF + "/cdn-cgi/styles/";
        url = new URL(newUrl);
        setSpendFlag(url.host, true);
        let redeemHdrs = beforeSendHeaders(details, url);
        expect(redeemHdrs.cancel).toBeFalsy();
        expect(redeemHdrs.requestHeaders).toBeFalsy();
    });
    test("url is favicon", () => {
        let newUrl = EXAMPLE_HREF + "/favicon.ico";
        url = new URL(newUrl);
        setSpendFlag(url.host, true);
        let redeemHdrs = beforeSendHeaders(details, url);
        expect(redeemHdrs.cancel).toBeFalsy();
        expect(redeemHdrs.requestHeaders).toBeFalsy();
    });
    test("max spend has been reached", () => {
        setSpendFlag(url.host, true);
        setSpentHosts(url.host, 31);
        let redeemHdrs = beforeSendHeaders(details, url);
        expect(redeemHdrs.cancel).toBeFalsy();
        expect(redeemHdrs.requestHeaders).toBeFalsy();
    });
    test("spend has been attempted for url", () => {
        setSpendFlag(url.host, true);
        setSpentHosts(url.host, 0);
        setSpentUrl(url.href, true);
        let redeemHdrs = beforeSendHeaders(details, url);
        expect(redeemHdrs.cancel).toBeFalsy();
        expect(redeemHdrs.requestHeaders).toBeFalsy();
    });
    test("redemption method is not reload", () => {
        setSpendFlag(url.host, true);
        setSpentHosts(url.host, 0);
        setSpentUrl(url.href, false);
        workflow.__set__("REDEEM_METHOD", "invalid");
        let redeemHdrs = beforeSendHeaders(details, url);
        expect(redeemHdrs.cancel).toBeFalsy();
        expect(redeemHdrs.requestHeaders).toBeFalsy();
    });
    test("no token to spend", () => {
        localStorage = {
            "cf-bypass-tokens": `{}`,
            "cf-token-count": 0
        };
        setSpentUrl(url.href, false);
        setSpendFlag(url.host, true);
        workflow.__set__("REDEEM_METHOD", "reload");
        let redeemHdrs = beforeSendHeaders(details, url);
        expect(redeemHdrs.cancel).toBeFalsy();
        expect(redeemHdrs.requestHeaders).toBeFalsy();
        expect(getSpendFlag(url.host)).toBeFalsy();
    });
});

describe("redemption attempted", () => {
    beforeEach(() => {
        resetVars();
        resetSpendVars();
    });

    test("redemption header added (SEND_H2C_PARAMS = false)", () => {
        setSpendFlag(url.host, true);
        setSpentUrl(url.href, false);
        workflow.__set__("REDEEM_METHOD", "reload");
        let redeemHdrs = beforeSendHeaders(details, url);
        let reqHeaders = redeemHdrs.requestHeaders;
        expect(getSpendFlag(url.host)).toBeFalsy();
        expect(getSpendId([details.requestId])).toBeTruthy();
        expect(getSpentUrl([url.href])).toBeTruthy();
        expect(getSpentTab([details.tabId]) == url.href).toBeTruthy();
        expect(reqHeaders).toBeTruthy();
        let headerName = workflow.__get__("HEADER_NAME");
        expect(reqHeaders[0].name == headerName).toBeTruthy();
        expect(reqHeaders[0].value == b64EncodedTokenNoH2CParams).toBeTruthy();
    });

    test("redemption header added (SEND_H2C_PARAMS = true)", () => {
        setSpendFlag(url.host, true);
        setSpentUrl(url.href, false);
        workflow.__set__("REDEEM_METHOD", "reload");
        workflow.__set__("SEND_H2C_PARAMS", true);
        let redeemHdrs = beforeSendHeaders(details, url);
        let reqHeaders = redeemHdrs.requestHeaders;
        expect(getSpendFlag(url.host)).toBeFalsy();
        expect(getSpendId([details.requestId])).toBeTruthy();
        expect(getSpentUrl([url.href])).toBeTruthy();
        expect(getSpentTab([details.tabId]) == url.href).toBeTruthy();
        expect(reqHeaders).toBeTruthy();
        let headerName = workflow.__get__("HEADER_NAME");
        expect(reqHeaders[0].name == headerName).toBeTruthy();
        expect(reqHeaders[0].value == b64EncodedToken).toBeTruthy();
    });
});

function setMockFunctions() {
    getMock = function(key) {
        return localStorage[key];
    }
    setMock = function(key, value) {
        localStorage[key] = value; 
    }
    getSpendFlag = function(key) {
        return getMock(key);
    }
    setSpendFlag = function(key, value) {
        setMock(key, value);
    }
    const updateIconMock = jest.fn();
    workflow.__set__("getSpendFlag", getSpendFlag);
    workflow.__set__("setSpendFlag", setSpendFlag);
    workflow.__set__("updateIcon", updateIconMock);
    workflow.__set__("get", getMock);
    workflow.__set__("set", setMock);
    workflow.__set__("atob", atob);
    workflow.__set__("btoa", btoa);
    setXHR(mockXHRCommitments);
}

function getSpentUrl(key) {
    let spentUrl = workflow.__get__("spentUrl");
    return spentUrl[key];
}
function getSpendId(key) {
    let spendId = workflow.__get__("spendId");
    return spendId[key];
}
function getSpentTab(key) {
    let spentTab = workflow.__get__("spentTab");
    return spentTab[key];
}
function setSpentUrl(key, value) {
    let spentUrl = new Map();
    spentUrl[key] = value;
    workflow.__set__("spentUrl", spentUrl);
}
function setSpentHosts(key, value) {
    let spentHosts = new Map();
    spentHosts[key] = value;
    workflow.__set__("spentHosts", spentHosts);
}
function setXHR(xhr) {
    workflow.__set__("XMLHttpRequest", xhr);
}