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

"use strict";

const LISTENER_URLS = "<all_urls>";
// CF config is initialized by default
let CONFIG_ID = 1;
const getConfigId = () => CONFIG_ID;
const setConfigId = (val) => CONFIG_ID = val;

const STORAGE_STR = "bypass-tokens-";
const COUNT_STR = STORAGE_STR + "count-";
const activeConfig = () => PPConfigs()[getConfigId()];
const dev = () => activeConfig()["dev"];
const chlClearanceCookie = () => activeConfig()["cookies"]["clearance-cookie"];
const chlCaptchaDomain = () => activeConfig()["captcha-domain"]; // cookies have dots prepended
const chlVerificationError = () => activeConfig()["error-codes"]["connection-error"];
const chlConnectionError = () => activeConfig()["error-codes"]["verify-error"];
const commitmentsKey = () => activeConfig()["commitments"];
const spendMax = () => activeConfig()["max-spends"];
const maxTokens = () => activeConfig()["max-tokens"];
const doSign = () => activeConfig()["sign"];
const doRedeem = () => activeConfig()["redeem"];
const redeemMethod = () => activeConfig()["spend-action"]["redeem-method"];
const headerName = () => activeConfig()["spend-action"]["header-name"];
const headerHostName = () => activeConfig()["spend-action"]["header-host-name"];
const headerPathName = () => activeConfig()["spend-action"]["header-path-name"];
const spendActionUrls = () => activeConfig()["spend-action"]["urls"];
const spendStatusCode = () => activeConfig()["spending-restrictions"]["status-code"];
const maxRedirect = () => activeConfig()["spending-restrictions"]["max-redirects"];
const newTabs = () => activeConfig()["spending-restrictions"]["new-tabs"];
const badNav = () => activeConfig()["spending-restrictions"]["bad-navigation"];
const badTransition = () => activeConfig()["spending-restrictions"]["bad-transition"];
const validRedirects = () => activeConfig()["spending-restrictions"]["valid-redirects"];
const validTransitions = () => activeConfig()["spending-restrictions"]["valid-transitions"];
const varReset = () => activeConfig()["var-reset"];
const varResetMs = () => activeConfig()["var-reset-ms"];
const storageKeyTokens = () => STORAGE_STR + activeConfig()["id"];
const storageKeyCount = () => COUNT_STR + activeConfig()["id"];
const h2cParams = () => activeConfig()["h2c-params"];
const sendH2CParams = () => activeConfig()["send-h2c-params"];
const issueActionUrls = () => activeConfig()["issue-action"]["urls"];
const reloadOnSign = () => activeConfig()["issue-action"]["sign-reload"];
const signResponseFMT = () => activeConfig()["issue-action"]["sign-resp-format"];
const tokensPerRequest = () => activeConfig()["issue-action"]["tokens-per-request"];

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
const httpsRedirect = new Map();

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


const getSpentUrl = (key) => spentUrl[key];
const setSpentUrl = (key, value) => spentUrl[key] = value;

const getSpendId = (key) => spendId[key];
const setSpendId = (key, value) => spendId[key] = value;

const getSpentTab = (key) => spentTab[key];
const setSpentTab = (key, value) => spentTab[key] = value;
const pushSpentTab = (key, value) => {
    if (!Array.isArray(getSpentTab(key))) {
        setSpentTab(key, []);
    }
    spentTab[key].push(value);
};

const getSpentHosts = (key) => spentHosts[key];
const setSpentHosts = (key, value) => spentHosts[key] = value;

const getFutureReload = (key) => futureReload[key];
const setFutureReload = (key, value) => futureReload[key] = value;

const getTarget = (key) => target[key];
const setTarget = (key, value) => target[key] = value;

const getHttpsRedirect = (key) => httpsRedirect[key];
const setHttpsRedirect = (key, value) => httpsRedirect[key] = value;

const getRedirectCount = (key) => redirectCount[key];
const setRedirectCount = (key, value) => redirectCount[key] = value;
const incrRedirectCount = (key) => redirectCount[key] += 1;


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
    // We're not interested in running this logic for favicons
    if (isFaviconUrl(url.href)) {
        return false;
    }

    let activated = false;
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
            activated = true;
        }
    }

    // If we have tokens to spend, cancel the request and pass execution over to the token handler.
    let attempted = false;
    if (activated && !getSpentUrl(url.href)) {
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

            setSpendFlag(url.host, null);

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
    switch (CONFIG_ID) {
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
    if (getSpentHosts(host) === undefined) {
        setSpentHosts(host, 0);
    }
    setSpentHosts(host, getSpentHosts(host) + 1);
}

/**
 * Checks whether the given host has not exceeded the max number of spends
 * @param {string} host
 * @return {boolean}
 */
function checkMaxSpend(host) {
    if (getSpentHosts(host) === undefined || getSpentHosts(host) < spendMax() || spendMax() === undefined) {
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
        if (newConfigVal !== CONFIG_ID) {
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
