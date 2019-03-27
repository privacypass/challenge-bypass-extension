/**
 * Integrations tests for processing redirections
 *
 * @author: Alex Davidson
 * @author Drazen Urch
 */

const workflow = workflowSet();

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

let details;
beforeEach(() => {
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
        expect(getHttpsRedirectMock(newUrl.href)).toBeFalsy();
    });

    describe("valid redirects", () => {
        test("http www", () => {
            const oldUrl = new URL(HTTP + EXAMPLE_HREF);
            const newUrl = new URL(HTTP_WWW + EXAMPLE_HREF);
            processRedirect(details, oldUrl, newUrl);
            expect(getHttpsRedirectMock(newUrl.href)).toBeTruthy();
        });

        test("https", () => {
            const oldUrl = new URL(HTTP + EXAMPLE_HREF);
            const newUrl = new URL(HTTPS + EXAMPLE_HREF);
            processRedirect(details, oldUrl, newUrl);
            expect(getHttpsRedirectMock(newUrl.href)).toBeTruthy();
        });

        test("https www", () => {
            const oldUrl = new URL(HTTP + EXAMPLE_HREF);
            const newUrl = new URL(HTTPS_WWW + EXAMPLE_HREF);
            processRedirect(details, oldUrl, newUrl);
            expect(getHttpsRedirectMock(newUrl.href)).toBeTruthy();
        });
    });
});

describe("redemption", () => {
    test("no redemption if spendId not set", () => {
        const oldUrl = new URL(HTTP + EXAMPLE_HREF);
        const newUrl = new URL(HTTP + ALTERN_HREF);
        setSpendIdMock(details.requestId, false);
        setRedirectCountMock(details.requestId, 0);
        processRedirect(details, oldUrl, newUrl);
        expect(getSpendFlagMock(newUrl.host)).toBeFalsy();
        expect(getRedirectCountMock(details.requestId) === 0).toBeTruthy();
    });

    test("no redemption if redirectCount above maximum", () => {
        const oldUrl = new URL(HTTP + EXAMPLE_HREF);
        const newUrl = new URL(HTTP + ALTERN_HREF);
        setSpendIdMock(details.requestId, true);
        setRedirectCountMock(details.requestId, 5);
        processRedirect(details, oldUrl, newUrl);
        expect(getSpendFlagMock(newUrl.host)).toBeFalsy();
        expect(getRedirectCountMock(details.requestId) === 5).toBeTruthy();
    });

    test("reload is successful", () => {
        const oldUrl = new URL(HTTP + EXAMPLE_HREF);
        const newUrl = new URL(HTTP + ALTERN_HREF);
        setSpendIdMock(details.requestId, true);
        setRedirectCountMock(details.requestId, 0);
        processRedirect(details, oldUrl, newUrl);
        expect(getSpendFlagMock(newUrl.host)).toBeTruthy();
        expect(getSpendIdMock(details.requestId)).toBeFalsy();
        expect(getRedirectCountMock(details.requestId) === 1).toBeTruthy();
    });
});

describe("request completion", () => {
    test("reload if spendId set", () => {
        setSpendIdMock(details.requestId, true);
        handleCompletion(details);
        expect(reloadBrowserTabMock).toBeCalledTimes(1);
        expect(getSpendIdMock(details.requestId)).toBeFalsy();
    });

    test("do not reload if spendId not set", () => {
        setSpendIdMock(details.requestId, false);
        handleCompletion(details);
        expect(reloadBrowserTabMock).not.toBeCalled();
        expect(getSpendIdMock(details.requestId)).toBeFalsy();
    });
});

describe("committed navigation", () => {
    let url;
    beforeEach(() => {
        url = new URL(HTTPS + EXAMPLE_HREF);
        details = {
            tabId: "101",
        };
    });

    describe("ignored navigations", () => {
        test("auto_subframe", () => {
            details.transitionType = "auto_subframe";
            details.transitionQualifiers = [];
            committedNavigation(details, url);
            expect(getTargetMock(details.tabId) === url.href).toBeFalsy();
            expect(updateBrowserTabMock).not.toBeCalled();
        });

        test("bad transition type", () => {
            details.transitionType = "something_weird";
            details.transitionQualifiers = [false];
            setHttpsRedirectMock(url.href, false);
            committedNavigation(details, url);
            expect(getTargetMock(details.tabId) === url.href).toBeFalsy();
            expect(updateBrowserTabMock).not.toBeCalled();
        });

        test("server_redirect with bad type", () => {
            details.transitionType = "something_weird";
            details.transitionQualifiers = ["server_redirect"];
            setHttpsRedirectMock(url.href, false);
            committedNavigation(details, url);
            expect(getTargetMock(details.tabId) === url.href).toBeFalsy();
            expect(updateBrowserTabMock).not.toBeCalled();
        });

        test("server_redirect with good type", () => {
            details.transitionType = "typed";
            details.transitionQualifiers = ["server_redirect"];
            setHttpsRedirectMock(url.href, false);
            committedNavigation(details, url);
            expect(getTargetMock(details.tabId) === url.href).toBeFalsy();
            expect(updateBrowserTabMock).not.toBeCalled();
        });

        test("new tab", () => {
            details.transitionType = "typed";
            details.transitionQualifiers = ["fine"];
            url = new URL("about:privatebrowsing");
            setHttpsRedirectMock(url.href, false);
            committedNavigation(details, url);
            expect(getTargetMock(details.tabId) === url.href).toBeFalsy();
            expect(updateBrowserTabMock).not.toBeCalled();
        });
    });

    describe("no future reload set", () => {
        test("via https redirect", () => {
            details.transitionType = "typed";
            details.transitionQualifiers = ["server_redirect"];
            setHttpsRedirectMock(url.href, true);
            committedNavigation(details, url);
            expect(getHttpsRedirectMock(url.href)).toBeFalsy();
            expect(getTargetMock(details.tabId) === url.href).toBeTruthy();
            expect(updateBrowserTabMock).not.toBeCalled();
        });

        test("via good transition types", () => {
            details.transitionType = "typed";
            details.transitionQualifiers = ["fine"];
            setHttpsRedirectMock(url.href, false);
            committedNavigation(details, url);
            expect(getTargetMock(details.tabId) === url.href).toBeTruthy();
            expect(updateBrowserTabMock).not.toBeCalled();
        });
    });

    describe("update browser tab", () => {
        test("future reload is set", () => {
            details.transitionType = "typed";
            details.transitionQualifiers = ["fine"];
            setFutureReloadMock(details.tabId, url.href);
            committedNavigation(details, url);
            expect(getTargetMock(details.tabId) === url.href).toBeTruthy();
            expect(getFutureReloadMock(details.tabId)).toBeFalsy();
            expect(updateBrowserTabMock).toBeCalled();
        });
    });
});
