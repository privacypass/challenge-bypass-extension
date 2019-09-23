/**
 * This background page handles the sending requests and dealing with responses.
 * Passes are exchanged with the server containing blinded tokens for bypassing CAPTCHAs.
 * Control flow is handled in the listeners. Cryptography uses SJCL.
 *
 * @author: George Tankersley
 * @author: Alex Davidson
 */

/* exported handleCompletion */
/* exported handleMessage */
/* exported processRedirect */
/* exported processHeaders */
/* exported beforeSendHeaders */
/* exported beforeRequest */
/* exported resetSpendVars */
/* exported committedNavigation */
/* exported cookiesChanged */
/* exported chlCaptchaDomain */
/* exported chlClearanceCookie */
/* exported redeemMethod */
/* exported reloadOnSign */
/* exported spentTab, timeSinceLastResp, futureReload, sentTokens */
/* exported dev */
/* exported commitmentsKey */
/* exported storageKeyTokens, storageKeyCount */
/* exported sendH2CParams, maxTokens, signResponseFMT, tokensPerRequest */
/* exported CONFIG_ID */
/* exported issueActionUrls */
/* exported LISTENER_URLS */
/* exported getTarget */
/* exported setFutureReload */
/* getConfigId */

"use strict";

const LISTENER_URLS = "<all_urls>";
// CF config is initialized by default
let CONFIG_ID = 1;
let getConfigId = () => CONFIG_ID;
let setConfigId = (val) => CONFIG_ID = val;

let checkConfigId = (configId) => PPConfigs().map((config) => config.id).includes(configId);

let STORAGE_STR = "bypass-tokens-";
let COUNT_STR = STORAGE_STR + "count-";
let activeConfig = () => PPConfigs()[getConfigId()];
let dev = () => activeConfig()["dev"];
let chlClearanceCookie = () => activeConfig()["cookies"]["clearance-cookie"];
let chlCaptchaDomain = () => activeConfig()["captcha-domain"]; // cookies have dots prepended
let chlVerificationError = () => activeConfig()["error-codes"]["connection-error"];
let chlConnectionError = () => activeConfig()["error-codes"]["verify-error"];
let commitmentsKey = () => activeConfig()["commitments"];
let spendMax = () => activeConfig()["max-spends"];
let maxTokens = () => activeConfig()["max-tokens"];
let doSign = () => activeConfig()["sign"];
let doRedeem = () => activeConfig()["redeem"];
let redeemMethod = () => activeConfig()["spend-action"]["redeem-method"];
let headerName = () => activeConfig()["spend-action"]["header-name"];
let headerHostName = () => activeConfig()["spend-action"]["header-host-name"];
let headerPathName = () => activeConfig()["spend-action"]["header-path-name"];
let spendActionUrls = () => activeConfig()["spend-action"]["urls"];
let spendStatusCode = () => activeConfig()["spending-restrictions"]["status-code"];
let maxRedirect = () => activeConfig()["spending-restrictions"]["max-redirects"];
let newTabs = () => activeConfig()["spending-restrictions"]["new-tabs"];
let badNav = () => activeConfig()["spending-restrictions"]["bad-navigation"];
let badTransition = () => activeConfig()["spending-restrictions"]["bad-transition"];
let validRedirects = () => activeConfig()["spending-restrictions"]["valid-redirects"];
let validTransitions = () => activeConfig()["spending-restrictions"]["valid-transitions"];
let varReset = () => activeConfig()["var-reset"];
let varResetMs = () => activeConfig()["var-reset-ms"];
let storageKeyTokens = () => STORAGE_STR + activeConfig()["id"];
let storageKeyCount = () => COUNT_STR + activeConfig()["id"];
let h2cParams = () => activeConfig()["h2c-params"];
let sendH2CParams = () => activeConfig()["send-h2c-params"];
let issueActionUrls = () => activeConfig()["issue-action"]["urls"];
let reloadOnSign = () => activeConfig()["issue-action"]["sign-reload"];
let signResponseFMT = () => activeConfig()["issue-action"]["sign-resp-format"];
let tokensPerRequest = () => activeConfig()["issue-action"]["tokens-per-request"];
let optEndpoints = () => activeConfig()["opt-endpoints"];
let emptyRespHeaders = () => activeConfig()["spend-action"]["empty-resp-headers"];

/* Config variables that are reset in setConfig() depending on the header value that is received (see config.js) */
initECSettings(h2cParams());

// Used for resetting variables below
let timeSinceLastResp = 0;

// Prevent too many redirections from exhausting tokens
let redirectCount = new Map();

// Set if a spend has occurred for a req id
let spendId = new Map();

// used for checking if we've already spent a token for this host to
// prevent token DoS attacks
let spentHosts = new Map();

// Used for tracking spends globally
let spentUrl = new Map();

// We want to monitor attempted spends to check if we should remove cookies
let httpsRedirect = new Map();

// Monitor whether we have already sent tokens for signing
let sentTokens = new Map();

// URL string for determining where tokens should be spent
let target = new Map();

// Used for firefox primarily
let futureReload = new Map();

// Tabs that a spend occurred in
let spentTab = new Map();

// Track whether we should try to initiate a signing request
let readySign = false;


let getSpentUrl = (key) => spentUrl[key];
let setSpentUrl = (key, value) => spentUrl[key] = value;

let getSpendId = (key) => spendId[key];
let setSpendId = (key, value) => spendId[key] = value;

let pushSpentTab = (key, value) => {
    if (!Array.isArray(spentTab[key])) {
        spentTab[key] = [];
    }
    spentTab[key].push(value);
};

let getSpentHosts = (key) => spentHosts[key];
let setSpentHosts = (key, value) => spentHosts[key] = value;

let getFutureReload = (key) => futureReload[key];
let setFutureReload = (key, value) => futureReload[key] = value;

let getTarget = (key) => target[key];
let setTarget = (key, value) => target[key] = value;

let getHttpsRedirect = (key) => httpsRedirect[key];
let setHttpsRedirect = (key, value) => httpsRedirect[key] = value;

let getRedirectCount = (key) => redirectCount[key];
let setRedirectCount = (key, value) => redirectCount[key] = value;
let incrRedirectCount = (key) => redirectCount[key] += 1;


/**
 * Functions used by event listeners (listeners.js)
 */

/**
 * Runs when a request is completed
 * @param {Object} details HTTP request details
 */
function handleCompletion(details) {
    timeSinceLastResp = Date.now();
    // If we had a spend and we're using "reload" method then reload the page
    if (getSpendId(details.requestId) && redeemMethod() === "reload") {
        reloadBrowserTab(details.tabId);
    }
    setSpendId(details.requestId, false);
}

/**
 * If a redirect occurs then we want to see if we had spent previously
 * If so then it is likely that we will want to spend on the redirect
 * @param {Object} details contains the HTTP redirect info
 * @param {URL} oldUrl URL object of previous navigation
 * @param {URL} newUrl URL object of current redirection
 */
function processRedirect(details, oldUrl, newUrl) {
    setHttpsRedirect(newUrl.href, validRedirect(oldUrl.href, newUrl.href));
    if (getRedirectCount(details.requestId) === undefined) {
        setRedirectCount(details.requestId, 0);
    }
    if (getSpendId(details.requestId) && getRedirectCount(details.requestId) < maxRedirect()) {
        setSpendFlag(newUrl.host, true);
        setSpendId(details.requestId, false);
        incrRedirectCount(details.requestId);
    }
}

/**
 * Checks if a redirect is valid using the VALID_REDIRECTS config option
 * @param {URL} oldUrl
 * @param {URL} redirectUrl
 * @return {boolean}
 */
function validRedirect(oldUrl, redirectUrl) {
    if (oldUrl.includes("http://")) {
        const urlStr = oldUrl.substring(7);
        const valids = validRedirects();
        for (let i = 0; i < valids.length; i++) {
            const newUrl = valids[i] + urlStr;
            if (newUrl === redirectUrl) {
                return true;
            }
        }
    }
    return false;
}

/**
 * Headers are received before document render. The blocking attributes allows
 * us to cancel requests instead of loading an unnecessary ReCaptcha widget.
 * @param {Object} details contains the HTTP response info
 * @param {URL} url request URL object
 * @return {boolean}
 */
function processHeaders(details, url) {
    const ret = {attempted: false, xhr: false, favicon: false};
    // We're not interested in running this logic for favicons
    if (isFaviconUrl(url.href)) {
        ret.favicon = true;
        return ret;
    }

    for (let i = 0; i < details.responseHeaders.length; i++) {
        const header = details.responseHeaders[i];
        if (header.name.toLowerCase() === CHL_BYPASS_RESPONSE) {
            if (header.value === chlVerificationError()
                || header.value === chlConnectionError()) {
                // If these errors occur then something bad is happening.
                // Either tokens are bad or some resource is calling the server
                // in a bad way
                if (header.value === chlVerificationError()) {
                    clearStorage();
                }
                throw new Error("[privacy-pass]: There may be a problem with the stored tokens. Redemption failed for: " + url.href + " with error code: " + header.value);
            }
        }

        // correct status code with the right header indicates a bypassable Cloudflare CAPTCHA
        if (isBypassHeader(header) && spendStatusCode().includes(details.statusCode)) {
            ret.attempted = decideRedeem(details, url);
            break;
        }
    }

    if (details.responseHeaders.length === 0
        && spendStatusCode().includes(details.statusCode)
        && emptyRespHeaders().includes("direct-request")) {
        // There is some weirdness with Chrome whereby some resources return empty
        // responseHeaders but where a spend *should* occur. If this happens then we
        // send a direct request to an endpoint that determines whether a CAPTCHA
        // page is shown via XHR.
        ret.xhr = tryRequestChallenge(details, url, ret);
    }

    return ret;
}

/**
 * Try a direct request against a challenge endpoint if the response headers are
 * empty. This fixes some strange behaviour with CF sites and Chrome.
 * @param {Object} details Original request details
 * @param {URL} url Origin URL
 * @return {boolean} indicates whether an XHR was launched
 */
function tryRequestChallenge(details, url) {
    const xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
        // We return a boolean for testing purposes
        let xhrRet = false;
        if (this.readyState === this.HEADERS_RECEIVED) {
            if (spendStatusCode().includes(xhr.status) && xhr.getResponseHeader(CHL_BYPASS_SUPPORT) === CONFIG_ID) {
                // don't return anything here because it is async
                decideRedeem(details, url);
                xhrRet = true;
            }
            xhr.abort();
        }
        return xhrRet;
    };
    const challengePath = optEndpoints().challenge || "";
    xhr.open("GET", url.origin + challengePath, true);
    xhr.send();
    return xhr;
}

/**
 * Decides whether to redeem a token for the given URL
 * @param {Object} details Response details
 * @param {URL} url URL object for possible redemption
 * @return {boolean}
 */
function decideRedeem(details, url) {
    let attempted = false;
    if (!spentUrl[url.href]) {
        const count = countStoredTokens();
        if (doRedeem()) {
            if (count > 0 && !url.host.includes(chlCaptchaDomain())) {
                attemptRedeem(url, details.tabId, target);
                attempted = true;
            } else if (count === 0) {
                // Update icon to show user that token may be spent here
                updateIcon("!");
            }
        }

        // If signing is permitted then we should note this
        if (!attempted && doSign()) {
            readySign = true;
        }
    }
    return attempted;
}

/**
 * If a spend flag is set then we alter the request and add a header
 * containing a valid BlindTokenRequest for redemption
 * @param {Object} request HTTP request details
 * @param {URL} url URL object of request
 * @return {Object} an object containing new headers for the request
 */
function beforeSendHeaders(request, url) {
    // Cancel if we don't have a token to spend
    const reqUrl = url.href;
    const host = url.host;

    if (doRedeem() && !isErrorPage(reqUrl) && !isFaviconUrl(reqUrl) && !checkMaxSpend(host) && getSpendFlag(host)) {
        // No reload method branch
        if (redeemMethod() === "no-reload") {
            // check that we're at an URL that can handle redeems
            const isRedeemUrl = spendActionUrls()
                .map((redeemUrl) => patternToRegExp(redeemUrl))
                .some((re) => reqUrl.match(re));

            setSpendFlag(host, null);

            if (countStoredTokens() > 0 && isRedeemUrl) {
                const tokenToSpend = GetTokenForSpend();
                if (tokenToSpend == null) {
                    return {cancel: false};
                }
                setSpendFlag(host, null);
                incrementSpentHost(host);

                const httpPath = request.method + " " + url.pathname;
                const redemptionString = BuildRedeemHeader(tokenToSpend, url.hostname, httpPath);
                const headers = request.requestHeaders;
                headers.push({name: headerName(), value: redemptionString});
                headers.push({name: headerHostName(), value: url.hostname});
                headers.push({name: headerPathName(), value: httpPath});
                setSpendId(request.requestId, true);
                setSpentUrl(reqUrl, true);
                pushSpentTab(request.tabId, url.href);
                return {requestHeaders: headers};
            }
        } else if (redeemMethod() === "reload" && !getSpentUrl(reqUrl)) {
            return getReloadHeaders(request, url);
        }
    }

    return {cancel: false};
}

/**
 * Creates redemption headers if the tab should be reloaded
 * @param {Object} request HTTP request details
 * @param {URL} url URL of the request
 * @return {Object} contains new header objects
 */
function getReloadHeaders(request, url) {
    const headers = request.requestHeaders;
    setSpendFlag(url.host, null);
    incrementSpentHost(url.host);
    setTarget(request.tabId, "");

    // Create a pass and reload to send it to the edge
    const tokenToSpend = GetTokenForSpend();
    if (tokenToSpend == null) {
        return {cancel: false};
    }

    const method = request.method;
    const httpPath = method + " " + url.pathname;
    const redemptionString = BuildRedeemHeader(tokenToSpend, url.hostname, httpPath);
    const newHeader = {name: headerName(), value: redemptionString};
    headers.push(newHeader);
    setSpendId(request.requestId, true);
    setSpentUrl(url.href, true);
    pushSpentTab(request.tabId, url.href);
    return {requestHeaders: headers};
}

/**
 * Filters requests before we've made a connection. If a challenge is observed
 * and we don't have available tokens to spend then it sends tokens to the
 * server.
 * @param {Object} details HTTP request details
 * @param {URL} url URL object of request
 * @return {Object} contains XHR details for sending tokens
 */
function beforeRequest(details, url) {
    if (!checkConfigId(getConfigId())) {
        throw new Error("Incorrect config ID specified");
    }

    // Clear vars if they haven't been used for a while
    if (varReset() && Date.now() - varResetMs() > timeSinceLastResp) {
        resetVars();
    }

    // Only sign tokens if config says so and the appropriate header was received previously
    if (!doSign() || !readySign) {
        return false;
    }

    // Different signing methods based on configs
    let xhrInfo;
    switch (getConfigId()) {
        case 1:
            xhrInfo = signReqCF(url);
            break;
        case 2:
            xhrInfo = signReqHC(url);
            break;
        default:
            throw new Error("Incorrect config ID specified");
    }

    // If this is null then signing is not appropriate
    if (xhrInfo === null) {
        return false;
    }
    readySign = false;

    // actually send the token signing request via xhr and return the xhr object
    const xhr = sendXhrSignReq(xhrInfo, url, details.tabId);
    return {xhr: xhr};
}

/**
 * Set the target URL for the spend and update the tab if necessary. When
 * navigation is committed we may want to reload.
 * @param {Object} details Navigation details
 * @param {URL} url URL of navigation
 */
function committedNavigation(details, url) {
    const redirect = details.transitionQualifiers[0];
    const tabId = details.tabId;
    if (!badNav().includes(details.transitionType)
        && (!checkBadTransition(url.href, redirect, details.transitionType))
        && !isNewTab(url.href)
    ) {
        const id = getTabId(tabId);
        setTarget(id, url.href);
        // If a reload was attempted but target hadn't been inited then reload now
        if (getFutureReload(id) === getTarget(id)) {
            setFutureReload(id, false);
            updateBrowserTab(id, getTarget(id));
        }
    }
}

/**
 * Handles messages from the plugin HTML that need BG page functionality
 * @param {Object} request HTTP request details
 * @param {Object} sender Used by the plugin to communicate with the BG page
 * @param {Function} sendResponse sends the response back to the plugin HTML
 */
function handleMessage(request, sender, sendResponse) {
    if (request.callback) {
        UpdateCallback = request.callback;
    } else if (request.tokLen) {
        sendResponse(countStoredTokens());
    } else if (request.clear) {
        clearStorage();
    }
}

/* Token storage functions */

/**
 * Increments the number of spends for a given host
 * @param {string} host String corresponding to host
 */
function incrementSpentHost(host) {
    let n = getSpentHosts(host);
    if (n === undefined) {
        n = 0;
    }
    setSpentHosts(host, n + 1);
}

/**
 * Checks whether the given host has not exceeded the max number of spends
 * @param {string} host
 * @return {boolean}
 */
function checkMaxSpend(host) {
    const n = getSpentHosts(host);
    if (n === undefined || n < spendMax() || spendMax() === undefined) {
        return false;
    }
    return true;
}

/**
 * Pops a token from storage for a redemption
 * @return {Object} token object
 */
function GetTokenForSpend() {
    let tokens = loadTokens();
    // prevent null checks
    if (tokens == null) {
        return null;
    }
    const tokenToSpend = tokens[0];
    tokens = tokens.slice(1);
    storeTokens(tokens);
    return tokenToSpend;
}


/**
 * Clears the stored tokens and other variables
 */
function clearStorage() {
    clear();
    resetVars();
    resetSpendVars();
    // Update icons
    updateIcon(0);
    UpdateCallback();
}

/* Utility functions */

/**
 * Indicates whether a bad state transition has occurred
 * @param {string} href href string of URL object
 * @param {string} type type of navigation
 * @param {string} transitionType type of state transition for navigation
 * @return {boolean}
 */
function checkBadTransition(href, type, transitionType) {
    if (getHttpsRedirect(href)) {
        setHttpsRedirect(href, false);
        return false;
    }
    const maybeGood = (validTransitions().includes(transitionType));
    if (!type && !maybeGood) {
        return true;
    }
    return badTransition().includes(type);
}

/**
 * Checks if the tab is deemed to be new or not
 * @param {string} url string href of URL object
 * @return {boolean}
 */
function isNewTab(url) {
    for (let i = 0; i < newTabs().length; i++) {
        if (url.includes(newTabs()[i])) {
            return true;
        }
    }
    return false;
}

/**
 * Reset variables
 */
function resetVars() {
    redirectCount = new Map();
    sentTokens = new Map();
    target = new Map();
    spendId = new Map();
    futureReload = new Map();
    spentHosts = new Map();
}

/**
 * Reset variables that are specifically used for restricting spending
 */
function resetSpendVars() {
    spentTab = new Map();
    spentUrl = new Map();
}

/**
 * Checks whether a header should activate the extension. The value dictates
 * whether to swap to a new configuration
 * @param {header} header
 * @return {boolean}
 */
function isBypassHeader(header) {
    const newConfigVal = parseInt(header.value);
    if (header.name.toLowerCase() === CHL_BYPASS_SUPPORT && newConfigVal !== 0) {
        if (checkConfigId(newConfigVal) && newConfigVal !== getConfigId()) {
            setConfig(newConfigVal);
        }
        return true;
    }
    return false;
}

/**
 * Changes the active configuration when the client receives a new configuration
 * value.
 * @param {int} val
 */
function setConfig(val) {
    setConfigId(val);
    initECSettings(h2cParams());
    clearCachedCommitments();
    countStoredTokens();
}
