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
/* exported getVerificationKey */
/* exported storageKeyTokens, storageKeyCount */
/* exported sendH2CParams, maxTokens, signResponseFMT, tokensPerRequest */
/* exported CONFIG_ID, CF_CONFIG_ID, HC_CONFIG_ID */
/* exported issueActionUrls */
/* exported LISTENER_URLS */
/* exported getTarget */
/* exported setFutureReload */
/* exported getConfigId */
/* exported getConfigName */
/* exported storedCommitments */
/* exported requestIdentifiers */
/* exported getMorePassesUrl */

"use strict";

const LISTENER_URLS = "<all_urls>";
let STORAGE_STR = "bypass-tokens-";
let COUNT_STR = STORAGE_STR + "count-";

// CF config is initialized by default
let CF_CONFIG_ID = 1;
let HC_CONFIG_ID = 2;
let CONFIG_ID = CF_CONFIG_ID;
let getConfigId = () => CONFIG_ID;
let setConfigId = (val) => CONFIG_ID = val;

let validConfigIds = () => PPConfigs().map((config) => config.id);
let checkConfigId = (configId) => validConfigIds().includes(configId);

// The active configuration drives the request flow
let activeConfig = () => PPConfigs()[getConfigId()];

// we need to use this function in the JS of the popup and let doesn't allow us
// to do this.
// eslint-disable-next-line no-var
var getConfigName = (id) => getConfigForId(id)["name"];
// returns the active config if no id is specified
let getConfigForId = (id) => {
    if (!id) {
        return activeConfig();
    } else if (!checkConfigId(id)) {
        throw new Error(`Incorrect config ID specified: ${id}`);
    }
    return PPConfigs()[id];
};
let dev = (id) => getConfigForId(id)["dev"];
let chlClearanceCookie = (id) => getConfigForId(id)["cookies"]["clearance-cookie"];
let chlCaptchaDomain = (id) => getConfigForId(id)["captcha-domain"]; // cookies have dots prepended
let chlVerificationError = (id) => getConfigForId(id)["error-codes"]["connection-error"];
let chlConnectionError = (id) => getConfigForId(id)["error-codes"]["verify-error"];
let chlBadRequestError = (id) => getConfigForId(id)["error-codes"]["bad-request-error"];
let chlUnknownError = (id) => getConfigForId(id)["error-codes"]["unknown-error"];
let getVerificationKey = (id) => getConfigForId(id)["comm-vk"];
let spendMax = (id) => getConfigForId(id)["max-spends"];
let maxTokens = (id) => getConfigForId(id)["max-tokens"];
let doSign = (id) => getConfigForId(id)["sign"];
let doRedeem = (id) => getConfigForId(id)["redeem"];
let redeemMethod = (id) => getConfigForId(id)["spend-action"]["redeem-method"];
let headerName = (id) => getConfigForId(id)["spend-action"]["header-name"];
let headerHostName = (id) => getConfigForId(id)["spend-action"]["header-host-name"];
let headerPathName = (id) => getConfigForId(id)["spend-action"]["header-path-name"];
let spendActionUrls = (id) => getConfigForId(id)["spend-action"]["urls"];
let spendStatusCode = (id) => getConfigForId(id)["spending-restrictions"]["status-code"];
let maxRedirect = (id) => getConfigForId(id)["spending-restrictions"]["max-redirects"];
let newTabs = (id) => getConfigForId(id)["spending-restrictions"]["new-tabs"];
let badNav = (id) => getConfigForId(id)["spending-restrictions"]["bad-navigation"];
let badTransition = (id) => getConfigForId(id)["spending-restrictions"]["bad-transition"];
let validRedirects = (id) => getConfigForId(id)["spending-restrictions"]["valid-redirects"];
let validTransitions = (id) => getConfigForId(id)["spending-restrictions"]["valid-transitions"];
let varReset = (id) => getConfigForId(id)["var-reset"];
let varResetMs = (id) => getConfigForId(id)["var-reset-ms"];
let storageKeyTokens = (id) => STORAGE_STR + getConfigForId(id)["id"];
let storageKeyCount = (id) => COUNT_STR + getConfigForId(id)["id"];
let h2cParams = (id) => getConfigForId(id)["h2c-params"];
let sendH2CParams = (id) => getConfigForId(id)["send-h2c-params"];
let issueActionUrls = (id) => getConfigForId(id)["issue-action"]["urls"];
let reloadOnSign = (id) => getConfigForId(id)["issue-action"]["sign-reload"];
let requestIdentifiers = (id) => getConfigForId(id)["issue-action"]["request-identifiers"];
let signResponseFMT = (id) => getConfigForId(id)["issue-action"]["sign-resp-format"];
let tokensPerRequest = (id) => getConfigForId(id)["issue-action"]["tokens-per-request"];
let optEndpoints = (id) => getConfigForId(id)["opt-endpoints"];
let emptyRespHeaders = (id) => getConfigForId(id)["spend-action"]["empty-resp-headers"];
let storedCommitments = (id) => getConfigForId(id)["commitments"];

/**
 * Allows access to get-more-passes-url from UpdatePopup
 * @param {Number} id
 * @return {string}
 */
function getMorePassesUrl(id) {
    return getConfigForId(id)["get-more-passes-url"];
}

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

// Indicates that a URL has been redirected to
let redirected = new Map();

// Monitor whether we have already sent tokens for signing
let sentTokens = new Map();

// URL string for determining where tokens should be spent
let target = new Map();

// Used for firefox primarily
let futureReload = new Map();

// Tabs that a spend occurred in
let spentTab = new Map();

// Track whether we should try to initiate a signing request for a
// specific config
let readyIssue = new Map();

// Tracks whether a recent change has occurred
// prevents overlay of conflicting resources
let recentConfigChange = false;

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

let getRedirected = (key) => redirected[key];
let setRedirected = (key, value) => redirected[key] = value;

let getRedirectCount = (key) => redirectCount[key];
let setRedirectCount = (key, value) => redirectCount[key] = value;
let incrRedirectCount = (key) => redirectCount[key] += 1;

let getReadyIssue = (key) => readyIssue[key];
let setReadyIssue = (key, value) => readyIssue[key] = value;


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
        if (getRedirected(details.url)) {
            // if a redirection has occurred then we want to update the browser
            // tab, this is to prevent an issue in Chrome that reloads the tab
            // for the old URL.
            updateBrowserTab(details.tabId);
            setRedirected(details.url, false);
        } else {
            reloadBrowserTab(details.tabId);
        }
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
        setRedirected(newUrl.href, true);
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
            switch (header.value) {
                case chlConnectionError():
                    throw new Error("[privacy-pass]: internal server connection error occurred");
                case chlVerificationError():
                    clearStorage();
                    throw new Error(`[privacy-pass]: token verification failed for ${url.href}`);
                case chlBadRequestError():
                    throw new Error(`[privacy-pass]: server indicated a bad client request`);
                case chlUnknownError():
                    throw new Error(`[privacy-pass]: unknown internal server error occurred`);
                default:
                    console.warn(`[privacy-pass]: server sent unrecognised response code (${header.value})`);
            }
        }

        // correct status code with the right header indicates a
        // bypassable Cloudflare CAPTCHA
        let cfgId = isBypassHeader(header);
        if (cfgId > 0 && spendStatusCode().includes(details.statusCode)) {
            ret.attempted = decideRedeem(details, url, cfgId);
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
        ret.xhr = tryRequestChallenge(details, url);
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
            let cfgId = getConfigId();
            if (spendStatusCode().includes(xhr.status) && xhr.getResponseHeader(CHL_BYPASS_SUPPORT) === cfgId) {
                // don't return anything here because it is async
                decideRedeem(details, url, cfgId);
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
 * @param {Number} cfgId config identifier
 * @return {boolean}
 */
function decideRedeem(details, url, cfgId) {
    let attempted = false;
    if (!spentUrl[url.href]) {
        const count = countStoredTokens(getConfigId());
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
        if (!attempted && doSign(cfgId)) {
            setReadyIssue(cfgId, true);
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

            const count = countStoredTokens(getConfigId());
            if (count > 0 && isRedeemUrl) {
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
    // Different signing methods based on configs
    // We attempt to sign tokens for all available configs
    let xhrInfo;
    let issueId;
    validConfigIds().forEach((id) => {
        // check if signing is allowed and that we haven't already
        // constructed a request
        if (!doSign(id) || !getReadyIssue(id) || xhrInfo) {
            return;
        }

        switch (id) {
            case 1:
                xhrInfo = signReqCF(url, details);
                break;
            case 2:
                xhrInfo = signReqHC(url, details);
                break;
            default:
                throw new Error("Incorrect config ID specified");
        }

        issueId = id;
    });

    // If this is null then signing is not appropriate
    if (!xhrInfo) {
        return false;
    }
    setReadyIssue(issueId, false);

    // actually send the token signing request via xhr and return the xhr object
    const xhr = sendXhrSignReq(xhrInfo, url, issueId, details.tabId);

    // In the no-reload paradigm the issuance request is sent along side
    // the original solve request, we must return to avoid canceling the
    // original captcha solve request.
    if (xhrInfo.cancel === false) {
        return false;
    }

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
        sendResponse(getTokenNumbersForAllConfigs());
    } else if (request.clear) {
        clearStorage();
    } else if (request.redeem) {
        const tokLen = countStoredTokens(getConfigId());
        if (tokLen > 0) {
            const s1 = generateString();
            const s2 = generateString();
            const tokenToSpend = GetTokenForSpend();
            sendResponse(BuildRedeemHeader(tokenToSpend, s1, s2));
        } else {
            // respond with null
            sendResponse();
        }
    }
}

/**
 * Returns the number of tokens for each of the available configurations
 * @param {Array<Number>} configIds IDs of configs to query
 * @return {Object} Contains token & configuration information
 */
function getTokenNumbersForAllConfigs() {
    let configs = PPConfigs();
    configs.shift(); // remove example config
    let configTokLens = [];
    configs.forEach((config) => {
        let active = config.id == getConfigId();
        configTokLens.push({
            name: config["long-name"],
            id: config.id,
            tokLen: countStoredTokens(config.id, !active),
            url: config["get-more-passes-url"],
            active: active,
        });
    });
    return configTokLens;
}

/**
 * Generates a (non-crypto) random string
 * @return {String}
 */
function generateString() {
    return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
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
    const cfgId = getConfigId();
    storeTokens(cfgId, tokens);
    return tokenToSpend;
}


/**
 * Clears the stored tokens and other variables
 */
function clearStorage() {
    clear();
    clearCachedCommitments();
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
    redirected = new Map();
    recentConfigChange = false;
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
 * @param {Header} header
 * @return {Number} new config identifier
 */
function isBypassHeader(header) {
    const newConfigVal = parseInt(header.value);
    if (header.name.toLowerCase() === CHL_BYPASS_SUPPORT && newConfigVal !== 0) {
        if (checkConfigId(newConfigVal) && !recentConfigChange) {
            setConfig(newConfigVal);
            recentConfigChange = true;
        }
        return newConfigVal;
    }
    return -1;
}

/**
 * Changes the active configuration when the client receives a new configuration
 * value.
 * @param {int} val
 */
function setConfig(val) {
    // only reset everything if the value actually changes
    if (val !== getConfigId()) {
        setConfigId(val);
        initECSettings(h2cParams());
        countStoredTokens(val);
    }
}
