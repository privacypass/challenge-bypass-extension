/*
 * This background page handles the sending requests and dealing with responses.
 * Passes are exchanged with the server containing blinded tokens for bypassing CAPTCHAs.
 * Control flow is handled in the listeners. Cryptography uses SJCL.
 *
 * @author: George Tankersley
 * @author: Alex Davidson
 */

/*global sjcl*/
/* exported clearStorage */
/* exported ACTIVE_CONFIG */
"use strict";
/* Config variables that are reset in setConfig() depending on the header value that is received (see config.js) */
let CONFIG_ID = ACTIVE_CONFIG["id"];
let CHL_CLEARANCE_COOKIE = ACTIVE_CONFIG["cookies"]["clearance-cookie"];
let CHL_CAPTCHA_DOMAIN = ACTIVE_CONFIG["captcha-domain"]; // cookies have dots prepended
let CHL_VERIFICATION_ERROR = ACTIVE_CONFIG["error-codes"]["connection-error"];
let CHL_CONNECTION_ERROR = ACTIVE_CONFIG["error-codes"]["verify-error"];
let SPEND_MAX = ACTIVE_CONFIG["max-spends"];
let MAX_TOKENS = ACTIVE_CONFIG["max-tokens"];
let DO_SIGN = ACTIVE_CONFIG["sign"];
let DO_REDEEM = ACTIVE_CONFIG["redeem"];
let RELOAD_ON_SIGN = ACTIVE_CONFIG["sign-reload"];
let SIGN_RESPONSE_FMT = ACTIVE_CONFIG["sign-resp-format"];
let STORAGE_KEY_TOKENS = ACTIVE_CONFIG["storage-key-tokens"];
let STORAGE_KEY_COUNT = ACTIVE_CONFIG["storage-key-count"];
let REDEEM_METHOD = ACTIVE_CONFIG["spend-action"]["redeem-method"];
let HEADER_NAME = ACTIVE_CONFIG["spend-action"]["header-name"];
let LISTENER_URLS = ACTIVE_CONFIG["spend-action"]["urls"];
let TOKENS_PER_REQUEST = ACTIVE_CONFIG["tokens-per-request"];
let SPEND_STATUS_CODE = ACTIVE_CONFIG["spending-restrictions"]["status-code"];
let SPEND_IFRAME = ACTIVE_CONFIG["spending-restrictions"]["iframe"];
let CHECK_COOKIES = ACTIVE_CONFIG["cookies"]["check-cookies"];
let MAX_REDIRECT = ACTIVE_CONFIG["spending-restrictions"]["max-redirects"];
let NEW_TABS = ACTIVE_CONFIG["spending-restrictions"]["new-tabs"];
let BAD_NAV = ACTIVE_CONFIG["spending-restrictions"]["bad-navigation"];
let BAD_TRANSITION = ACTIVE_CONFIG["spending-restrictions"]["bad-transition"];
let VALID_REDIRECTS = ACTIVE_CONFIG["spending-restrictions"]["valid-redirects"];
let VALID_TRANSITIONS = ACTIVE_CONFIG["spending-restrictions"]["valid-transitions"];
let VAR_RESET = ACTIVE_CONFIG["var-reset"];
let VAR_RESET_MS = ACTIVE_CONFIG["var-reset-ms"];

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

// Tracks whether we should trigger the signing mechanism
// Previously we attempted to send tokens with any request that used a matching url
// Now this variable also has to be true.
let readySign = false;

/* Event listeners manage control flow
    - web request listeners act to send signable/redemption tokens when needed
    - web navigation listener sets the target url for the execution
    - cookie listener clears cookie for captcha.website to enable getting more
    tokens in the future
*/

// Once we've completed the request if a spend went badly
// (no cookie received) then we need to reload and try another resource
chrome.webRequest.onCompleted.addListener(
    handleCompletion,
    { urls: [LISTENER_URLS] },
);
function handleCompletion(details) {
    timeSinceLastResp = Date.now();
    // If we had a spend then reload the page
    if (spendId[details.requestId]) {
        chrome.tabs.reload(details.tabId);
    }
    spendId[details.requestId] = false;
}

// If a redirect occurs then we want to see if we had spent previously
// If so then it is likely that we will want to spend on the redirect
chrome.webRequest.onBeforeRedirect.addListener(
    processRedirect,
    { urls: [LISTENER_URLS] },
);
function processRedirect(details) {
    let oldUrl = new URL(details.url);
    let newUrl = new URL(details.redirectUrl);
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
    let httpInd = oldUrl.indexOf("http://");
    let valids = VALID_REDIRECTS;
    if (httpInd != -1) {
        let urlStr = oldUrl.substring(7);
        for (let i=0; i<valids.length; i++) {
            let newUrl = valids[i] + urlStr;
            if (newUrl == redirectUrl) {
                return true;
            }
        }
    }
    return false;
}


// Watches headers for CF-Chl-Bypass and CF-Chl-Bypass-Resp headers.
chrome.webRequest.onHeadersReceived.addListener(
    processHeaders,                 // callback
    { urls: [LISTENER_URLS] },       // targeted pages
    ["responseHeaders", "blocking"] // desired traits
);

// Headers are received before document render. The blocking attributes allows
// us to cancel requests instead of loading an unnecessary ReCaptcha widget.
function processHeaders(details) {
    let url = new URL(details.url);
    let activated = false;
    for (var i = 0; i < details.responseHeaders.length; i++) {
        const header = details.responseHeaders[i];
        if (header.name.toLowerCase() == CHL_BYPASS_RESPONSE) {
            if (header.value == CHL_VERIFICATION_ERROR
                || header.value == CHL_CONNECTION_ERROR) {
                // If these errors occur then something bad is happening.
                // Either tokens are bad or some resource is calling the server in a bad way
                throw new Error("[privacy-pass]: There may be a problem with the stored tokens. Redemption failed for: " + url.href + " with error code: " + header.value);
            }
        }

        // correct status code with the right header indicates a bypassable Cloudflare CAPTCHA
        if (isBypassHeader(header) && SPEND_STATUS_CODE.indexOf(details.statusCode) > -1) {
            let iframe = (details.frameId > 0);
            // check if the token should only be spent on an iframe
            if ((SPEND_IFRAME && iframe) || !SPEND_IFRAME) {
                activated = true
            }
        }
    }

    // If we have tokens to spend, cancel the request and pass execution over to the token handler.
    if (activated && !spentUrl[url.href]) {
        let redeemOccurred = false;
        if (DO_REDEEM) {
            if (countStoredTokens() > 0) {
                redeemOccurred = attemptRedeem(url, details.tabId);
            } else if (countStoredTokens() == 0) {
                // Update icon to show user that token may be spent here
                updateIcon("!");
            }
        }

        // If signing is permitted then we should note this
        if (!redeemOccurred && DO_SIGN) {
            readySign = true;
        }
    }
}

// Attempts to redeem a token
// Returns true if a redemption is fired, and false otherwise.
function attemptRedeem(url, respTabId) {
    // Prevent reloading on captcha.website
    if (url.host.indexOf(CHL_CAPTCHA_DOMAIN) != -1) {
        return false;
    }

    // Check all cookie stores to see if a clearance cookie is held
    let fired = false;
    if (CHECK_COOKIES) {
        chrome.cookies.getAllCookieStores(function(stores) {
            let clearanceHeld = false;
            stores.forEach( function(store, index) {
                var tabIds = store.tabIds;
                if (tabIds.length && tabIds[0].id !== undefined) {
                    tabIds = tabIds.map((tab) => respTabId.id);
                }
                var storeMatches = tabIds.indexOf(respTabId) > -1;
                if (storeMatches) {
                    chrome.cookies.get({"url": url.href, "name": CHL_CLEARANCE_COOKIE, "storeId": store.id}, function(cookie) {
                        // Require an existing, non-expired cookie.
                        if (cookie) {
                            clearanceHeld = (cookie.expirationDate * 1000 >= Date.now());
                        }
                    });
                }
            });

            // If a clearance cookie is not held then set the spend flag
            if (!clearanceHeld) {
                fireRedeem(url, respTabId);
                fired = true;
            }
        });
    } else {
        // If cookies aren't checked then we always attempt to redeem.
        fireRedeem(url, respTabId);
        fired = true;
    }
    return fired;
}

// Actually activate the redemption request
function fireRedeem(url, respTabId) {
    if (REDEEM_METHOD == "reload") {
        setSpendFlag(url.host, true);
        let targetUrl = target[respTabId];
        if (url.href == targetUrl) {
            chrome.tabs.update(respTabId, { url: targetUrl });
        } else if (!targetUrl || (targetUrl != url.href && !isFaviconUrl(targetUrl))) {
            // set a reload in the future when the target has been inited
            futureReload[respTabId] = url.href;
        }
    } else {
        throw new Error("[privacy-pass]: Incompatible redeem method selected. Only 'reload' is supported currently.");
    }
}

// Intercepts token-spend reload requests to add a redemption header.
chrome.webRequest.onBeforeSendHeaders.addListener(
    beforeSendHeaders,        // callback
    { urls: [LISTENER_URLS] }, // targeted pages
    ["requestHeaders", "blocking"]
);
function beforeSendHeaders(request) {
    let url = new URL(request.url);
    let headers = request.requestHeaders;

    // Cancel if we don't have a token to spend or config says no redeem
    if (!DO_REDEEM || !getSpendFlag(url.host) || checkMaxSpend(url.host) || spentUrl[url.href] || isErrorPage(url.href) || isFaviconUrl(url.href) || REDEEM_METHOD != "reload") {
        return {cancel: false};
    }

    headers = getReloadHeaders(url, headers, request);
    return {requestHeaders: headers};
}

function getReloadHeaders(url,headers,request) {
    setSpendFlag(url.host, null);
    incrementSpentHost(url.host);
    target[request.tabId] = "";

    // Create a pass and reload to send it to the edge
    const tokenToSpend = GetTokenForSpend();
    if (tokenToSpend == null) {
        return {cancel: false};
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
    return headers;
}


// Intercepts CAPTCHA solution requests to add our token blob to the body.
chrome.webRequest.onBeforeRequest.addListener(
    beforeRequest,            // callback
    { urls: [LISTENER_URLS] }, // targeted pages
    ["blocking", "requestBody"] // desired traits
);

// This function filters requests before we've made a connection. If we don't
// have tokens, it asks for new ones when we solve a captcha.
function beforeRequest(details) {
    // Clear vars if they haven't been used for a while
    if (VAR_RESET && Date.now() - VAR_RESET_MS > timeSinceLastResp) {
        resetVars();
    }

    // Only sign tokens if config says so and the appropriate header was received previously
    if (!DO_SIGN || !readySign) {
        return {cancel: false};
    }

    // Different signing methods based on configs
    let xhrInfo;
    switch (CONFIG_ID) {
        case 1:
            xhrInfo = signReqCF(details);
            break;
        default:
            return {cancel: false};
    }

    // If this is null then signing is not appropriate
    if (xhrInfo == null) {
        return {cancel: false};
    }
    readySign = false;

    // actually send the token signing request via xhr
    xhrSignRequest(xhrInfo, details.url, details.tabId);

    // Cancel the original request
    return {redirectUrl: "javascript:void(0)"};
}

// Sending tokens to be signed for Cloudflare
function signReqCF(details) {
    let reqUrl = details.url;
    const manualChallenge = reqUrl.indexOf("manual_challenge") != -1;
    const captchaResp = reqUrl.indexOf("g-recaptcha-response") != -1;
    const alreadyProcessed = reqUrl.indexOf("&captcha-bypass=true") != -1;

    // We're only interested in CAPTCHA solution requests that we haven't already altered.
    if ((captchaResp && alreadyProcessed) || (!manualChallenge && !captchaResp) || sentTokens[reqUrl]) {
        return null;
    }
    sentTokens[reqUrl] = true;
    let tokens = GenerateNewTokens(TOKENS_PER_REQUEST);
    const request = BuildIssueRequest(tokens);

    // Tag the URL of the new request to prevent an infinite loop (see above)
    let newUrl = markSignUrl(reqUrl);
    // Construct info for xhr signing request
    let xhrInfo = {newUrl: newUrl, requestBody: "blinded-tokens=" + request, tokens: tokens};

    return xhrInfo;
}

// Send tokens for signing via XHR request
function xhrSignRequest(xhrInfo, reqUrl, tabId) {
    let newUrl = xhrInfo["newUrl"];
    let requestBody = xhrInfo["requestBody"];
    let tokens = xhrInfo["tokens"];

    let xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
        // When we receive a response...
        if (xhr.status < 300 && xhr.readyState == 4 && countStoredTokens() < (MAX_TOKENS - TOKENS_PER_REQUEST)) {
            const resp_data = xhr.responseText;
            const signedPoints = parseIssueResponse(resp_data, tokens);
            if (signedPoints !== null) {
                storeNewTokens(tokens, signedPoints);
            }
            // Reload the page for the originally intended url
            if (RELOAD_ON_SIGN) {
                let url = new URL(reqUrl);
                if (url.href.indexOf(CHL_CAPTCHA_DOMAIN) == -1){
                    let captchaPath = url.pathname;
                    let pathIndex = url.href.indexOf(captchaPath);
                    let reloadUrl = url.href.substring(0, pathIndex+1);
                    setSpendFlag(url.host, true);
                    chrome.tabs.update(tabId, { url: reloadUrl });
                }
            }
        } else if (countStoredTokens() >= (MAX_TOKENS - TOKENS_PER_REQUEST)) {
            throw new Error("[privacy-pass]: Cannot receive new tokens due to upper bound.");
        }
    };

    xhr.open("POST", newUrl, true);
    xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
    xhr.setRequestHeader(CHL_BYPASS_SUPPORT, "1");
    // We seem to get back some odd mime types that cause problems...
    xhr.overrideMimeType("text/plain");

    xhr.send(requestBody);
}

// Removes cookies for captcha.website to enable getting more tokens
// in the future.
chrome.cookies.onChanged.addListener(function(changeInfo) {
    let cookieDomain = changeInfo.cookie.domain;
    let cookieName = changeInfo.cookie.name;
    if (!changeInfo.removed) {
        if (cookieDomain == "." + CHL_CAPTCHA_DOMAIN // cookies have dots prepended
            && cookieName == CHL_CLEARANCE_COOKIE) {
            chrome.cookies.remove({url: "http://" + CHL_CAPTCHA_DOMAIN, name: CHL_CLEARANCE_COOKIE});
        } else if (cookieName == CHL_CLEARANCE_COOKIE) {
            reloadTab(cookieDomain);
        }
    } else if (changeInfo.removed
            && cookieName == CHL_CLEARANCE_COOKIE
            && cookieDomain != "." + CHL_CAPTCHA_DOMAIN) {
        resetSpendVars();
    }
});

// Reset spend vars when window is closed in case we're private browsing
chrome.windows.onRemoved.addListener(function() {
    resetSpendVars();
})

// An issue response takes the form "signatures=[b64 blob]"
// The blob is an array of base64-encoded marshaled curve points.
// The points are uncompressed (TODO).
//
// If the blinded points are P = H(t)rB, these are Q = kP.
function parseIssueResponse(data, tokens) {
    let signaturesJSON;
    switch (SIGN_RESPONSE_FMT) {
        case "string":
            signaturesJSON = parseSigString(data);
            break;
        case "json":
            signaturesJSON = parseSigJson(data);
            break;
        default:
            throw new Error("[privacy-pass]: invalid signature response format " + SIGN_RESPONSE_FMT);
    }

    if (signaturesJSON == null) {
        throw new Error("[privacy-pass]: signature response invalid or in unexpected format, got response: " + data);
    }

    // decodes base-64
    // parses into JSON
    const issueResp = JSON.parse(signaturesJSON);
    let batchProof = issueResp[issueResp.length - 1];
    let signatures = issueResp.slice(0, issueResp.length - 1);
    if (!batchProof) {
        throw new Error("[privacy-pass]: No batch proof provided");
    }

    let usablePoints = [];
    signatures.forEach(function(signature) {
        let usablePoint = sec1DecodePoint(signature);
        if (usablePoint == null) {
            throw new Error("[privacy-pass]: unable to decode point " + signature + " in " + JSON.stringify(signatures));
        }
        usablePoints.push(usablePoint);
    })

    // Verify the DLEQ batch proof before handing back the usable points
    if (!verifyProof(batchProof, tokens, usablePoints)) {
        throw new Error("[privacy-pass]: Unable to verify DLEQ proof.")
    }

    return usablePoints;
}

// Parses signatures that are sent back in JSON format
function parseSigJson(data) {
    let json = JSON.parse(data)
    return json["signatures"];
}

// Parses signatures that are sent back in the CF string format
function parseSigString(data) {
    let split = data.split("signatures=", 2);
    if (split.length != 2) {
        return null;
    }
    return atob(split[1]);
}

// Set the target URL for the spend and update the tab if necessary
chrome.webNavigation.onCommitted.addListener(function(details) {
    let redirect = details.transitionQualifiers[0];
    let tabId = details.tabId;
    let url = new URL(details.url);
    if (BAD_NAV.indexOf(details.transitionType) == -1
        && (!badTransition(url.href, redirect, details.transitionType))
        && !isNewTab(url.href)) {
        target[tabId] = url.href;
        let id = getTabId(tabId);
        // If a reload was attempted but target hadn't been inited then reload now
        if (futureReload[id] == target[tabId]) {
            futureReload[id] = false;
            chrome.tabs.update(id, {url: target[tabId]});
        }
    }
});

// Handle messages from popup
chrome.runtime.onMessage.addListener(handleMessage);
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

function countStoredTokens() {
    const count = localStorage.getItem(STORAGE_KEY_COUNT);
    if (count == null) {
        return 0;
    }

    // We change the png file to show if tokens are stored or not
    const countInt = JSON.parse(count);
    updateIcon(countInt);
    return countInt;
}

// Pops a token from storage for a redemption
function GetTokenForSpend() {
    let tokens = loadTokens();
    const tokenToSpend = tokens[0];
    tokens = tokens.slice(1);
    storeTokens(tokens);
    return tokenToSpend;
}

// This is for persisting valid tokens after some manipulation, like a spend.
function storeTokens(tokens) {
    let storableTokens = [];
    for (var i = 0; i < tokens.length; i++) {
        let t = tokens[i];
        storableTokens[i] = getTokenEncoding(t,t.point);
    }
    const json = JSON.stringify(storableTokens);
    localStorage.setItem(STORAGE_KEY_TOKENS, json);
    localStorage.setItem(STORAGE_KEY_COUNT, tokens.length);

    // Update the count on the actual icon
    updateIcon(tokens.length);
}

// This is for storing tokens we've just received from a new issuance response.
function storeNewTokens(tokens, signedPoints) {
    let storableTokens = [];
    for (var i = 0; i < tokens.length; i++) {
        let t = tokens[i];
        storableTokens[i] = getTokenEncoding(t,signedPoints[i]);
    }
    // Append old tokens to the newly received tokens
    if (countStoredTokens() > 0) {
        let oldTokens = loadTokens();
        for (let i=0; i<oldTokens.length; i++) {
            let oldT = oldTokens[i];
            storableTokens.push(getTokenEncoding(oldT,oldT.point));
        }
    }
    const json = JSON.stringify(storableTokens);
    localStorage.setItem(STORAGE_KEY_TOKENS, json);
    localStorage.setItem(STORAGE_KEY_COUNT, storableTokens.length);

    // Update the count on the actual icon
    updateIcon(storableTokens.length);
}

// SJCL points are cyclic as objects, so we have to flatten them.
function getTokenEncoding(t, curvePoint) {
    let storablePoint = encodeStorablePoint(curvePoint);
    let storableBlind = t.blind.toString();
    return { token: t.token, point: storablePoint, blind: storableBlind };
}

function loadTokens() {
    const storedJSON = localStorage.getItem(STORAGE_KEY_TOKENS);
    if (storedJSON == null) {
        return null;
    }

    let usableTokens = [];
    const storedTokens = JSON.parse(storedJSON);
    for (var i = 0; i < storedTokens.length; i++) {
        let t = storedTokens[i];
        let usablePoint = decodeStorablePoint(t.point);
        let usableBlind = new sjcl.bn(t.blind);
        usableTokens[i] = { token: t.token, point: usablePoint, blind: usableBlind };
    }
    return usableTokens;
}

function clearStorage() {
    localStorage.clear(function() {
        if (chrome.runtime.lastError) {
            console.error(chrome.runtime.lastError.message);
        }
    });
    resetVars();
    resetSpendVars();
    // Update icons
    updateIcon(0);
    UpdateCallback();
}

function setSpendFlag(key, value) {
    if (value) {
        localStorage.setItem(key, "true");
    } else {
        localStorage.removeItem(key);
    }
}

function getSpendFlag(key) {
    return localStorage.getItem(key);
}

// We use this function for updating the popup when tokens are cleared
// The function is passed from bc-plugin.js
var UpdateCallback = function() { }

/* Utility functions */

function reloadTab(cookieDomain) {
    let found = false;
    chrome.windows.getAll(function(windows) {
        windows.forEach( function(w) {
            let wId = w.id;
            chrome.tabs.query({windowId: wId}, function(tabs) {
                tabs.forEach( function(tab, index) {
                    if (!found) {
                        let id = getTabId(tab.id);
                        let hrefs = spentTab[id];
                        if (!hrefs) {
                            return;
                        }
                        if (isCookieForTab(hrefs, cookieDomain)) {
                            chrome.tabs.reload(id);
                            found = true;
                        }
                    }
                });
            });
        });
    });
}

function isCookieForTab(hrefs, cookieDomain) {
    if (hrefs.indexOf(cookieDomain) > -1) {
        return true;
    }
    // remove preceding dot and try again
    if (cookieDomain[0] == ".") {
        let noDot = cookieDomain.substring(1);
        if (hrefs.indexOf(noDot) > -1) {
            return true;
        }
    }

    return false;
}

function isErrorPage(url) {
    let found = false;
    const errorPagePaths = ["/cdn-cgi/styles/", "/cdn-cgi/scripts/", "/cdn-cgi/images/"];
    errorPagePaths.forEach(function(str) {
        if (url.indexOf(str) != -1) {
            found = true;
        }
    });
    return found;
}

//  Favicons have caused us problems...
function isFaviconUrl(url) {
    return url.indexOf("favicon") != -1;
}

// Tor seems to have an object here whereas chrome/firefox just have an id
function getTabId(tabId) {
    let id = tabId.id;
    if (!id) {
        id = tabId;
    }
    return id;
}

// Checks whether a transition is deemed to be bad to prevent loading subresources
// in address bar
function badTransition(href, type, transitionType) {
    if (httpsRedirect[href]) {
        httpsRedirect[href] = false;
        return false;
    }
    let maybeGood = (VALID_TRANSITIONS.indexOf(transitionType) > -1);
    if (!type && !maybeGood) {
        return true;
    }
    return BAD_TRANSITION.indexOf(type) > -1;
}

// Mark the url so that a sign doesn't occur again.
function markSignUrl(url) {
    return url + "&captcha-bypass=true";
}

function isNewTab(url) {
    for (let i=0; i<NEW_TABS.length; i++) {
        if (url.indexOf(NEW_TABS[i]) > -1) {
            return true;
        }
    }
    return false;
}

function resetVars() {
    redirectCount = new Map();
    sentTokens = new Map();
    target = new Map();
    spendId = new Map();
    futureReload = new Map();
    spentHosts = new Map();
}

function resetSpendVars() {
    spentTab = new Map();
    spentUrl = new Map();
}

function updateIcon(count) {
    let warn = (count.toString().indexOf("!") != -1)
    if (count != 0 && !warn) {
        chrome.browserAction.setIcon({ path: "icons/ticket-32.png", });
        chrome.browserAction.setBadgeText({text: count.toString()});
        chrome.browserAction.setBadgeBackgroundColor({color: "#408BC9"});
    } else if (warn) {
        chrome.browserAction.setIcon({ path: "icons/ticket-empty-32.png", });
        chrome.browserAction.setBadgeText({text: "!!!"});
    } else {
        chrome.browserAction.setIcon({ path: "icons/ticket-empty-32.png", });
        chrome.browserAction.setBadgeText({text: ""});
    }
}

function isBypassHeader(header) {
    if (header.name.toLowerCase() == CHL_BYPASS_SUPPORT && header.value != "0") {
        setConfig(parseInt(header.value));
        return true
    }
    return false;
}

function setConfig(val) {
    ACTIVE_CONFIG = PPConfigs[val]
    CONFIG_ID = ACTIVE_CONFIG["id"];
    CHL_CLEARANCE_COOKIE = ACTIVE_CONFIG["cookies"]["clearance-cookie"];
    CHL_CAPTCHA_DOMAIN = ACTIVE_CONFIG["captcha-domain"]; // cookies have dots prepended
    CHL_VERIFICATION_ERROR = ACTIVE_CONFIG["error-codes"]["connection-error"];
    CHL_CONNECTION_ERROR = ACTIVE_CONFIG["error-codes"]["verify-error"];
    SPEND_MAX = ACTIVE_CONFIG["max-spends"];
    MAX_TOKENS = ACTIVE_CONFIG["max-tokens"];
    DO_SIGN = ACTIVE_CONFIG["sign"];
    DO_REDEEM = ACTIVE_CONFIG["redeem"];
    RELOAD_ON_SIGN = ACTIVE_CONFIG["sign-reload"];
    SIGN_RESPONSE_FMT = ACTIVE_CONFIG["sign-resp-format"];
    STORAGE_KEY_TOKENS = ACTIVE_CONFIG["storage-key-tokens"];
    STORAGE_KEY_COUNT = ACTIVE_CONFIG["storage-key-count"];
    REDEEM_METHOD = ACTIVE_CONFIG["spend-action"]["redeem-method"];
    LISTENER_URLS = ACTIVE_CONFIG["spend-action"]["urls"];
    HEADER_NAME = ACTIVE_CONFIG["spend-action"]["header-name"];
    TOKENS_PER_REQUEST = ACTIVE_CONFIG["tokens-per-request"];
    SPEND_STATUS_CODE = ACTIVE_CONFIG["spending-restrictions"]["status-code"];
    SPEND_IFRAME = ACTIVE_CONFIG["spending-restrictions"]["iframe"];
    CHECK_COOKIES = ACTIVE_CONFIG["cookies"]["check-cookies"];
    MAX_REDIRECT = ACTIVE_CONFIG["spending-restrictions"]["max-redirects"];
    NEW_TABS = ACTIVE_CONFIG["spending-restrictions"]["new-tabs"];
    BAD_NAV = ACTIVE_CONFIG["spending-restrictions"]["bad-navigation"];
    BAD_TRANSITION = ACTIVE_CONFIG["spending-restrictions"]["bad-transition"];
    VALID_REDIRECTS = ACTIVE_CONFIG["spending-restrictions"]["valid-redirects"];
    VALID_TRANSITIONS = ACTIVE_CONFIG["spending-restrictions"]["valid-transitions"];
    VAR_RESET = ACTIVE_CONFIG["var-reset"];
    VAR_RESET_MS = ACTIVE_CONFIG["var-reset-ms"];
    setActiveCommitments();
    countStoredTokens();
}