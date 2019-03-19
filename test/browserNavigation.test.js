/**
* Integrations tests for processing redirections
*
* @author: Alex Davidson
*/
import rewire from "rewire";
const workflow = rewire("../addon/compiled/test_compiled.js");
const URL = window.URL;

/**
* Functions/variables
*/
const EXAMPLE_HREF = "example.com";
const HTTP = "http://";
const HTTP_WWW = "http://www.";
const HTTPS = "https://";
const HTTPS_WWW = "https://www.";
const ALTERN_HREF = "http://www.cloudflare.com";
const processRedirect = workflow.__get__("processRedirect");
const handleCompletion = workflow.__get__("handleCompletion");
const committedNavigation = workflow.__get__("committedNavigation");
let localStorage;
let details;
/* mock impls */
function getMock(key) {
    return localStorage[key];
}
function setMock(key, value) {
    localStorage[key] = value;
}
function getSpendFlag(key) {
    return getMock(key);
}
function setSpendFlag(key, value) {
    setMock(key, value);
}
const reloadBrowserTabMock = jest.fn();
const updateBrowserTabMock = jest.fn();
workflow.__set__("setSpendFlag", setSpendFlag);
workflow.__set__("reloadBrowserTab", reloadBrowserTabMock);
workflow.__set__("updateBrowserTab", updateBrowserTabMock);
beforeEach(() => {
    localStorage = {};
    details = {
        method: "GET",
        requestHeaders: [],
        requestId: "212",
        tabId: "101",
    };
});

describe("https redirects", () => {
    test("non-https redirect", () => {
        const oldUrl = new URL(HTTP + EXAMPLE_HREF);
        const newUrl = new URL(HTTP + ALTERN_HREF);
        processRedirect(details, oldUrl, newUrl);
        expect(getHttpsRedirect(newUrl.href)).toBeFalsy();
    });

    describe("valid redirects", () => {
        test("http www", () => {
            const oldUrl = new URL(HTTP + EXAMPLE_HREF);
            const newUrl = new URL(HTTP_WWW + EXAMPLE_HREF);
            processRedirect(details, oldUrl, newUrl);
            expect(getHttpsRedirect(newUrl.href)).toBeTruthy();
        });

        test("https", () => {
            const oldUrl = new URL(HTTP + EXAMPLE_HREF);
            const newUrl = new URL(HTTPS + EXAMPLE_HREF);
            processRedirect(details, oldUrl, newUrl);
            expect(getHttpsRedirect(newUrl.href)).toBeTruthy();
        });

        test("https www", () => {
            const oldUrl = new URL(HTTP + EXAMPLE_HREF);
            const newUrl = new URL(HTTPS_WWW + EXAMPLE_HREF);
            processRedirect(details, oldUrl, newUrl);
            expect(getHttpsRedirect(newUrl.href)).toBeTruthy();
        });
    });
});

describe("redemption", () => {
    test("no redemption if spendId not set", () => {
        const oldUrl = new URL(HTTP + EXAMPLE_HREF);
        const newUrl = new URL(HTTP + ALTERN_HREF);
        setSpendId(details.requestId, false);
        setRedirectCount(details.requestId, 0);
        processRedirect(details, oldUrl, newUrl);
        expect(getSpendFlag(newUrl.host)).toBeFalsy();
        expect(getRedirectCount(details.requestId) == 0).toBeTruthy();
    });

    test("no redemption if redirectCount above maximum", () => {
        const oldUrl = new URL(HTTP + EXAMPLE_HREF);
        const newUrl = new URL(HTTP + ALTERN_HREF);
        setSpendId(details.requestId, true);
        setRedirectCount(details.requestId, 5);
        processRedirect(details, oldUrl, newUrl);
        expect(getSpendFlag(newUrl.host)).toBeFalsy();
        expect(getRedirectCount(details.requestId) == 5).toBeTruthy();
    });

    test("reload is successful", () => {
        const oldUrl = new URL(HTTP + EXAMPLE_HREF);
        const newUrl = new URL(HTTP + ALTERN_HREF);
        setSpendId(details.requestId, true);
        setRedirectCount(details.requestId, 0);
        processRedirect(details, oldUrl, newUrl);
        expect(getSpendFlag(newUrl.host)).toBeTruthy();
        expect(getSpendId(details.requestId)).toBeFalsy();
        expect(getRedirectCount(details.requestId) == 1).toBeTruthy();
    });
});

describe("request completion", () => {
    test("reload if spendId set", () => {
        setSpendId(details.requestId, true);
        handleCompletion(details);
        expect(reloadBrowserTabMock).toBeCalledTimes(1);
        expect(getSpendId(details.requestId)).toBeFalsy();
    });

    test("do not reload if spendId not set", () => {
        setSpendId(details.requestId, false);
        handleCompletion(details);
        expect(reloadBrowserTabMock).not.toBeCalled();
        expect(getSpendId(details.requestId)).toBeFalsy();
    });
});

describe("committed navigation", () => {
    let url;
    beforeEach(() => {
        url = new URL(HTTPS+EXAMPLE_HREF);
        details = {
            tabId: "101",
        };
    });

    describe("ignored navigations", () => {
        test("auto_subframe", () => {
            details.transitionType = "auto_subframe";
            details.transitionQualifiers = [];
            committedNavigation(details, url);
            expect(getTarget(details.tabId) == url.href).toBeFalsy();
            expect(updateBrowserTabMock).not.toBeCalled();
        });

        test("bad transition type", () => {
            details.transitionType = "something_weird";
            details.transitionQualifiers = [false];
            setHttpsRedirect(url.href, false);
            committedNavigation(details, url);
            expect(getTarget(details.tabId) == url.href).toBeFalsy();
            expect(updateBrowserTabMock).not.toBeCalled();
        });

        test("server_redirect with bad type", () => {
            details.transitionType = "something_weird";
            details.transitionQualifiers = ["server_redirect"];
            setHttpsRedirect(url.href, false);
            committedNavigation(details, url);
            expect(getTarget(details.tabId) == url.href).toBeFalsy();
            expect(updateBrowserTabMock).not.toBeCalled();
        });

        test("server_redirect with good type", () => {
            details.transitionType = "typed";
            details.transitionQualifiers = ["server_redirect"];
            setHttpsRedirect(url.href, false);
            committedNavigation(details, url);
            expect(getTarget(details.tabId) == url.href).toBeFalsy();
            expect(updateBrowserTabMock).not.toBeCalled();
        });

        test("new tab", () => {
            details.transitionType = "typed";
            details.transitionQualifiers = ["fine"];
            url = new URL("about:privatebrowsing");
            setHttpsRedirect(url.href, false);
            committedNavigation(details, url);
            expect(getTarget(details.tabId) == url.href).toBeFalsy();
            expect(updateBrowserTabMock).not.toBeCalled();
        });
    });

    describe("no future reload set", () => {
        test("via https redirect", () => {
            details.transitionType = "typed";
            details.transitionQualifiers = ["server_redirect"];
            setHttpsRedirect(url.href, true);
            committedNavigation(details, url);
            expect(getHttpsRedirect(url.href)).toBeFalsy();
            expect(getTarget(details.tabId) == url.href).toBeTruthy();
            expect(updateBrowserTabMock).not.toBeCalled();
        });

        test("via good transition types", () => {
            details.transitionType = "typed";
            details.transitionQualifiers = ["fine"];
            setHttpsRedirect(url.href, false);
            committedNavigation(details, url);
            expect(getTarget(details.tabId) == url.href).toBeTruthy();
            expect(updateBrowserTabMock).not.toBeCalled();
        });
    });

    describe("update browser tab", () => {
        test("future reload is set", () => {
            details.transitionType = "typed";
            details.transitionQualifiers = ["fine"];
            setFutureReload(details.tabId, url.href);
            committedNavigation(details, url);
            expect(getTarget(details.tabId) == url.href).toBeTruthy();
            expect(updateBrowserTabMock).toBeCalled();
            expect(getFutureReload(details.tabId)).toBeFalsy();
        });
    });
});

function getTarget(key) {
    const target = workflow.__get__("target");
    return target[key];
}

function getFutureReload(key) {
    const futureReload = workflow.__get__("futureReload");
    return futureReload[key];
}

function setFutureReload(key, val) {
    const futureReload = new Map();
    futureReload[key] = val;
    workflow.__set__("futureReload", futureReload);
}

function getHttpsRedirect(key) {
    const httpsRedirect = workflow.__get__("httpsRedirect");
    return httpsRedirect[key];
}

function setHttpsRedirect(key, val) {
    const httpsRedirect = new Map();
    httpsRedirect[key] = val;
    workflow.__set__("httpsRedirect", httpsRedirect);
}

function getSpendId(key) {
    const spendId = workflow.__get__("spendId");
    return spendId[key];
}

function setSpendId(key, val) {
    const spendId = new Map();
    spendId[key] = val;
    workflow.__set__("spendId", spendId);
}

function getRedirectCount(key) {
    const redirectCount = workflow.__get__("redirectCount");
    return redirectCount[key];
}

function setRedirectCount(key, val) {
    const redirectCount = new Map();
    redirectCount[key] = val;
    workflow.__set__("redirectCount", redirectCount);
}
