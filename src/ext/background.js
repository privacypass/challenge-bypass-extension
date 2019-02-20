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
/* exported CHL_CAPTCHA_DOMAIN */
/* exported CHL_CLEARANCE_COOKIE */
/* exported REDEEM_METHOD */
/* exported RELOAD_ON_SIGN */
/* exported spentTab, timeSinceLastResp, futureReload, sentTokens */
/* exported DEV */
/* exported COMMITMENTS_KEY */
/* exported STORAGE_KEY_TOKENS, STORAGE_KEY_COUNT */
/* exported SEND_H2C_PARAMS, MAX_TOKENS, SIGN_RESPONSE_FMT, TOKENS_PER_REQUEST */
"use strict";
/* Config variables that are reset in setConfig() depending on the header value that is received (see config.js) */
let CONFIG_ID = ACTIVE_CONFIG["id"];
let DEV = ACTIVE_CONFIG["dev"];
let CHL_CLEARANCE_COOKIE = ACTIVE_CONFIG["cookies"]["clearance-cookie"];
let CHL_CAPTCHA_DOMAIN = ACTIVE_CONFIG["captcha-domain"]; // cookies have dots prepended
let CHL_VERIFICATION_ERROR = ACTIVE_CONFIG["error-codes"]["connection-error"];
let CHL_CONNECTION_ERROR = ACTIVE_CONFIG["error-codes"]["verify-error"];
let COMMITMENTS_KEY = ACTIVE_CONFIG["commitments"];
let SPEND_MAX = ACTIVE_CONFIG["max-spends"];
let MAX_TOKENS = ACTIVE_CONFIG["max-tokens"];
let DO_SIGN = ACTIVE_CONFIG["sign"];
let DO_REDEEM = ACTIVE_CONFIG["redeem"];
let RELOAD_ON_SIGN = ACTIVE_CONFIG["sign-reload"];
let SIGN_RESPONSE_FMT = ACTIVE_CONFIG["sign-resp-format"];
let REDEEM_METHOD = ACTIVE_CONFIG["spend-action"]["redeem-method"];
let HEADER_NAME = ACTIVE_CONFIG["spend-action"]["header-name"];
let TOKENS_PER_REQUEST = ACTIVE_CONFIG["tokens-per-request"];
let SPEND_STATUS_CODE = ACTIVE_CONFIG["spending-restrictions"]["status-code"];
let MAX_REDIRECT = ACTIVE_CONFIG["spending-restrictions"]["max-redirects"];
let NEW_TABS = ACTIVE_CONFIG["spending-restrictions"]["new-tabs"];
let BAD_NAV = ACTIVE_CONFIG["spending-restrictions"]["bad-navigation"];
let BAD_TRANSITION = ACTIVE_CONFIG["spending-restrictions"]["bad-transition"];
let VALID_REDIRECTS = ACTIVE_CONFIG["spending-restrictions"]["valid-redirects"];
let VALID_TRANSITIONS = ACTIVE_CONFIG["spending-restrictions"]["valid-transitions"];
let VAR_RESET = ACTIVE_CONFIG["var-reset"];
let VAR_RESET_MS = ACTIVE_CONFIG["var-reset-ms"];
const STORAGE_STR = "bypass-tokens-";
const COUNT_STR = STORAGE_STR + "count-";
let STORAGE_KEY_TOKENS = STORAGE_STR + ACTIVE_CONFIG["id"];
let STORAGE_KEY_COUNT = COUNT_STR + ACTIVE_CONFIG["id"];
let H2C_PARAMS = ACTIVE_CONFIG["h2c-params"];
let SEND_H2C_PARAMS = ACTIVE_CONFIG["send-h2c-params"];
initECSettings(H2C_PARAMS);

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

/**
 * Functions used by event listeners (listeners.js)
 */

/**
  * Runs when a request is completed
  * @param details HTTP request details
  */
function handleCompletion(details) {
    timeSinceLastResp = Date.now();
    // If we had a spend then reload the page
    if (spendId[details.requestId]) {
        reloadBrowserTab(details.tabId);
    }
    spendId[details.requestId] = false;
}

/**
 * If a redirect occurs then we want to see if we had spent previously
 * If so then it is likely that we will want to spend on the redirect
 * @param details contains the HTTP redirect info
 * @param oldUrl URL object of previous navigation
 * @param newUrl URL object of current redirection
 */
function processRedirect(details, oldUrl, newUrl) {
    httpsRedirect[newUrl.href] = validRedirect(oldUrl.href, newUrl.href);
    if (redirectCount[details.requestId] === undefined) {
        redirectCount[details.requestId] = 0;
    }
    if (spendId[details.requestId] && redirectCount[details.requestId] < MAX_REDIRECT) {
        setSpendFlag(newUrl.host, true);
        spendId[details.requestId] = false;
        redirectCount[details.requestId] = redirectCount[details.requestId]+1;
    }
}
function validRedirect(oldUrl, redirectUrl) {
    if (oldUrl.includes("http://")) {
        let urlStr = oldUrl.substring(7);
        let valids = VALID_REDIRECTS;
        for (let i=0; i<valids.length; i++) {
            let newUrl = valids[i] + urlStr;
            if (newUrl == redirectUrl) {
                return true;
            }
        }
    }
    return false;
}

/**
 * Headers are received before document render. The blocking attributes allows
 * us to cancel requests instead of loading an unnecessary ReCaptcha widget.
 * @param details contains the HTTP response info
 * @param url request URL object
 */
function processHeaders(details, url) {
    // We're not interested in running this logic for favicons
    if (isFaviconUrl(url.href)) {
        return false;
    }

    let activated = false;
    for (var i = 0; i < details.responseHeaders.length; i++) {
        const header = details.responseHeaders[i];
        if (header.name.toLowerCase() == CHL_BYPASS_RESPONSE) {
            if (header.value == CHL_VERIFICATION_ERROR
                || header.value == CHL_CONNECTION_ERROR) {
                // If these errors occur then something bad is happening.
                // Either tokens are bad or some resource is calling the server
                // in a bad way
                if (header.value == CHL_VERIFICATION_ERROR) {
                    clearStorage();
                }
                throw new Error("[privacy-pass]: There may be a problem with the stored tokens. Redemption failed for: " + url.href + " with error code: " + header.value);
            }
        }

        // correct status code with the right header indicates a bypassable Cloudflare CAPTCHA
        if (isBypassHeader(header) && SPEND_STATUS_CODE.includes(details.statusCode)) {
            activated = true;
        }
    }

    // If we have tokens to spend, cancel the request and pass execution over to the token handler.
    let attempted = false;
    if (activated && !spentUrl[url.href]) {
        let count = countStoredTokens();
        if (DO_REDEEM) {
            if (count > 0 && !url.host.includes(CHL_CAPTCHA_DOMAIN)) {
                attemptRedeem(url, details.tabId, target);
                attempted = true;
            } else if (count == 0) {
                // Update icon to show user that token may be spent here
                updateIcon("!");
            }
        }

        // If signing is permitted then we should note this
        if (!attempted && DO_SIGN) {
            readySign = true;
        }
    }
    return attempted;
}

/**
 * If a spend flag is set then we alter the request and add a header
 * containing a valid BlindTokenRequest for redemption
 * @param request HTTP request details
 * @param url URL object of request
 */
function beforeSendHeaders(request, url) {
    // Cancel if we don't have a token to spend
    if (!DO_REDEEM || !getSpendFlag(url.host) || checkMaxSpend(url.host) || spentUrl[url.href] || isErrorPage(url.href) || isFaviconUrl(url.href) || REDEEM_METHOD != "reload") {
        return {cancel: false};
    }
    return getReloadHeaders(request, url);
}

// returns the new headers for the request
function getReloadHeaders(request, url) {
    let headers = request.requestHeaders;
    setSpendFlag(url.host, null);
    incrementSpentHost(url.host);
    target[request.tabId] = "";

    // Create a pass and reload to send it to the edge
    const tokenToSpend = GetTokenForSpend();
    if (tokenToSpend == null) {
        return { cancel: false };
    }

    const method = request.method;
    const http_path = method + " " + url.pathname;
    const redemptionString = BuildRedeemHeader(tokenToSpend, url.hostname, http_path);
    const newHeader = { name: HEADER_NAME, value: redemptionString };
    headers.push(newHeader);
    spendId[request.requestId] = true;
    spentUrl[url.href] = true;
    if (!spentTab[request.tabId]) {
        spentTab[request.tabId] = [];
    }
    spentTab[request.tabId].push(url.href);
    return { requestHeaders: headers };
}

/**
 * This function filters requests before we've made a connection. If we don't
 * have tokens, it asks for new ones when we solve a captcha.
 * @param details HTTP request details
 * @param url URL object of request
 */
function beforeRequest(details, url) {
    // Clear vars if they haven't been used for a while
    if (VAR_RESET && Date.now() - VAR_RESET_MS > timeSinceLastResp) {
        resetVars();
    }

    // Only sign tokens if config says so and the appropriate header was received previously
    if (!DO_SIGN || !readySign) {
        return false;
    }

    // Different signing methods based on configs
    let xhrInfo;
    switch (CONFIG_ID) {
    case 1:
        xhrInfo = signReqCF(url);
        break;
    default:
        throw new Error("Incorrect config ID specified");
    }

    // If this is null then signing is not appropriate
    if (xhrInfo == null) {
        return false;
    }
    readySign = false;

    // actually send the token signing request via xhr and return the xhr object
    let xhr = sendXhrSignReq(xhrInfo, url, details.tabId);
    return {xhr: xhr};
}

// Set the target URL for the spend and update the tab if necessary
/**
 * When navigation is committed we may want to reload.
 * @param details Navigation details
 * @param url url of navigation
 */
function committedNavigation(details, url) {
    let redirect = details.transitionQualifiers[0];
    let tabId = details.tabId;
    if (!BAD_NAV.includes(details.transitionType)
        && (!badTransition(url.href, redirect, details.transitionType))
        && !isNewTab(url.href)) {
        let id = getTabId(tabId);
        target[id] = url.href;
        // If a reload was attempted but target hadn't been inited then reload now
        if (futureReload[id] == target[id]) {
            futureReload[id] = false;
            updateBrowserTab(id, target[id]);
        }
    }
}

// Handle messages from popup
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
function incrementSpentHost(host) {
    if (spentHosts[host] === undefined) {
        spentHosts[host] = 0;
    }
    spentHosts[host] = spentHosts[host]+1;
}

function checkMaxSpend(host) {
    if (spentHosts[host] === undefined || spentHosts[host] < SPEND_MAX) {
        return false;
    }
    return true
}

// Pops a token from storage for a redemption
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



// Clears the stored tokens and other variables
function clearStorage() {
    clear();
    resetVars();
    resetSpendVars();
    // Update icons
    updateIcon(0);
    UpdateCallback();
}

/* Utility functions */

// Checks whether a transition is deemed to be bad to prevent loading subresources
// in address bar
function badTransition(href, type, transitionType) {
    if (httpsRedirect[href]) {
        httpsRedirect[href] = false;
        return false;
    }
    let maybeGood = (VALID_TRANSITIONS.includes(transitionType));
    if (!type && !maybeGood) {
        return true;
    }
    return BAD_TRANSITION.includes(type);
}

// Checks if the tab is deemed to be new or not
function isNewTab(url) {
    for (let i=0; i<NEW_TABS.length; i++) {
        if (url.includes(NEW_TABS[i])) {
            return true;
        }
    }
    return false;
}

// Reset variables
function resetVars() {
    redirectCount = new Map();
    sentTokens = new Map();
    target = new Map();
    spendId = new Map();
    futureReload = new Map();
    spentHosts = new Map();
}

// Reset variables that are used for restricting spending
function resetSpendVars() {
    spentTab = new Map();
    spentUrl = new Map();
}

/**
 * Checks whether a header should activate the extension. The value dictates
 * whether to swap to a new configuration
* @param {header} header
 */
function isBypassHeader(header) {
    let newConfigVal = parseInt(header.value);
    if (header.name.toLowerCase() == CHL_BYPASS_SUPPORT && newConfigVal !== 0) {
        if (newConfigVal != CONFIG_ID) {
            setConfig(newConfigVal);
        }
        return true
    }
    return false;
}

/**
 * CHanges the active configuration when the client receives a new configuration
 * value.
 * @param {int} val
 */
function setConfig(val) {
    ACTIVE_CONFIG = PPConfigs[val];
    CONFIG_ID = ACTIVE_CONFIG["id"];
    DEV = ACTIVE_CONFIG["dev"];
    CHL_CLEARANCE_COOKIE = ACTIVE_CONFIG["cookies"]["clearance-cookie"];
    CHL_CAPTCHA_DOMAIN = ACTIVE_CONFIG["captcha-domain"]; // cookies have dots prepended
    CHL_VERIFICATION_ERROR = ACTIVE_CONFIG["error-codes"]["connection-error"];
    CHL_CONNECTION_ERROR = ACTIVE_CONFIG["error-codes"]["verify-error"];
    COMMITMENTS_KEY = ACTIVE_CONFIG["commitments"];
    SPEND_MAX = ACTIVE_CONFIG["max-spends"];
    MAX_TOKENS = ACTIVE_CONFIG["max-tokens"];
    DO_SIGN = ACTIVE_CONFIG["sign"];
    DO_REDEEM = ACTIVE_CONFIG["redeem"];
    RELOAD_ON_SIGN = ACTIVE_CONFIG["sign-reload"];
    SIGN_RESPONSE_FMT = ACTIVE_CONFIG["sign-resp-format"];
    STORAGE_KEY_TOKENS = STORAGE_STR + ACTIVE_CONFIG["id"];
    STORAGE_KEY_COUNT = COUNT_STR + ACTIVE_CONFIG["id"];
    REDEEM_METHOD = ACTIVE_CONFIG["spend-action"]["redeem-method"];
    LISTENER_URLS = ACTIVE_CONFIG["spend-action"]["urls"];
    HEADER_NAME = ACTIVE_CONFIG["spend-action"]["header-name"];
    TOKENS_PER_REQUEST = ACTIVE_CONFIG["tokens-per-request"];
    SPEND_STATUS_CODE = ACTIVE_CONFIG["spending-restrictions"]["status-code"];
    CHECK_COOKIES = ACTIVE_CONFIG["cookies"]["check-cookies"];
    MAX_REDIRECT = ACTIVE_CONFIG["spending-restrictions"]["max-redirects"];
    NEW_TABS = ACTIVE_CONFIG["spending-restrictions"]["new-tabs"];
    BAD_NAV = ACTIVE_CONFIG["spending-restrictions"]["bad-navigation"];
    BAD_TRANSITION = ACTIVE_CONFIG["spending-restrictions"]["bad-transition"];
    VALID_REDIRECTS = ACTIVE_CONFIG["spending-restrictions"]["valid-redirects"];
    VALID_TRANSITIONS = ACTIVE_CONFIG["spending-restrictions"]["valid-transitions"];
    VAR_RESET = ACTIVE_CONFIG["var-reset"];
    VAR_RESET_MS = ACTIVE_CONFIG["var-reset-ms"];
    H2C_PARAMS = ACTIVE_CONFIG["h2c-params"];
    SEND_H2C_PARAMS = ACTIVE_CONFIG["send-h2c-params"];
    initECSettings(H2C_PARAMS);
    clearCachedCommitments();
    countStoredTokens();
}