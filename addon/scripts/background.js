/**
 * This background page handles the sending requests and dealing with responses.
 * Passes are exchanged with the server containing blinded tokens for bypassing CAPTCHAs.
 * Control flow is handled in the listeners. Cryptography uses SJCL.
 *
 * @author: George Tankersley
 * @author: Alex Davidson
 */

/*global sjcl*/
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
/* exported spentTab, spendId, timeSinceLastResp */
"use strict";

const CHL_BYPASS_SUPPORT  = "cf-chl-bypass";
const CHL_BYPASS_RESPONSE = "cf-chl-bypass-resp";
const CHL_CLEARANCE_COOKIE = "cf_clearance";
const CHL_CAPTCHA_DOMAIN = "captcha.website"; // cookies have dots prepended
const CHL_VERIFICATION_ERROR = "6";
const CHL_CONNECTION_ERROR = "5";
const MAX_REDIRECT = 3;
const SPEND_MAX = 3;
const MAX_TOKENS = 300;
const TOKENS_PER_REQUEST = 30;
const FF_PRIV_TAB = "about:privatebrowsing";
const CHROME_TABS = "chrome://";
const FF_BLANK = "about:blank";
const SERVER_REDIRECT = "server_redirect";
const AUTO_SUBFRAME = "auto_subframe";
const VALID_REDIRECTS = ["https://","https://www.","http://www."];
const POTENTIALLY_GOOD_TRANSITIONS = ["link", "typed", "auto_bookmark", "reload"];

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

/**
 * Headers are received before document render. The blocking attributes allows
 * us to cancel requests instead of loading an unnecessary ReCaptcha widget.
 * @param details contains the HTTP response info
 * @param url request URL object
 */
function processHeaders(details, url) {
    let doRedeem = false;
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

        // 403 with the right header indicates a bypassable CAPTCHA
        if (isBypassHeader(header) && details.statusCode == 403) {
            doRedeem = true;
        }
    }

    // If we have tokens to spend, cancel the request and pass execution over to the token handler.
    let attempted = false;
    if (doRedeem && !spentUrl[url.href]) {
        if (countStoredTokens() > 0) {
            // Prevent reloading on captcha.website
            if (url.host.indexOf(CHL_CAPTCHA_DOMAIN) != -1) {
                return;
            }

            // Check all cookie stores to see if a clearance cookie is held
            attemptRedeem(url, details.tabId, CHL_CLEARANCE_COOKIE, target, futureReload);
            attempted = true;
        } else {
            // Update icon to show user that token may be spent here
            updateIcon("!");
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
    let headers = request.requestHeaders;

    // Cancel if we don't have a token to spend
    if (!getSpendFlag(url.host) || checkMaxSpend(url.host) || spentUrl[url.href] || isErrorPage(url.href) || isFaviconUrl(url.href)) {
        return { cancel: false };
    }
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
    const newHeader = { name: "challenge-bypass-token", value: redemptionString };
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
    if (Date.now() - 2000 > timeSinceLastResp) {
        resetVars();
    }

    let reqUrl = url.href;
    const manualChallenge = reqUrl.indexOf("manual_challenge") != -1;
    const captchaResp = reqUrl.indexOf("g-recaptcha-response") != -1;
    const alreadyProcessed = reqUrl.indexOf("&captcha-bypass=true") != -1;

    // We're only interested in CAPTCHA solution requests that we haven't already altered.
    if ((captchaResp && alreadyProcessed) || (!manualChallenge && !captchaResp) || sentTokens[reqUrl]) {
        return false
    }
    sentTokens[reqUrl] = true;

    // Generate tokens and create a JSON request for signing
    let tokens = GenerateNewTokens(TOKENS_PER_REQUEST);
    const request = BuildIssueRequest(tokens);

    // Send an XHR request containing the tokens that we want to sign
    let xhr = sendXhrSignReq(details, url, tokens, request);

    // return the XMLHttpRequest in case we want to inspect it
    return {xhr: xhr};
}

/**
 * Sends an XHR request containing a BlindTokenRequest for signing a set of tokens
 * @param details HTTP request details
 * @param url URL object of the HTTP request
 * @param tokens generated tokens that will be signed
 * @param signReq JSON signing request for tokens
 */
function sendXhrSignReq(details, url, tokens, signReq) {
    // Tag the URL of the new request to prevent an infinite loop (see above)
    let newUrl = url.href + "&captcha-bypass=true";
    let xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
        // When we receive a response...
        if (xhr.status < 300 && xhr.readyState == 4 && countStoredTokens() < (MAX_TOKENS - TOKENS_PER_REQUEST)) {
            const resp_data = xhr.responseText;
            const signedPoints = parseIssueResponse(resp_data, tokens);
            if (signedPoints !== null) {
                storeNewTokens(tokens, signedPoints);
            }
            if (url.href.indexOf(CHL_CAPTCHA_DOMAIN) == -1){
                let captchaPath = url.pathname;
                let pathIndex = url.href.indexOf(captchaPath);
                let reloadUrl = url.href.substring(0, pathIndex+1);
                setSpendFlag(url.host, true);
                updateBrowserTab(details.tabId, reloadUrl)
            }
        } else if (countStoredTokens() >= (MAX_TOKENS - TOKENS_PER_REQUEST)) {
            throw new Error("[privacy-pass]: Cannot receive new tokens due to upper bound.")
        }
    };
    xhr.open("POST", newUrl, true);
    xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
    xhr.setRequestHeader("CF-Chl-Bypass", "1");
    // We seem to get back some odd mime types that cause problems...
    xhr.overrideMimeType("text/plain");
    xhr.send("blinded-tokens=" + signReq);
    return xhr;
}

// An issue response takes the form "signatures=[b64 blob]"
// The blob is an array of base64-encoded marshaled curve points.
// The points are uncompressed (TODO).
//
// If the blinded points are P = H(t)rB, these are Q = kP.
function parseIssueResponse(data, tokens) {
    const split = data.split("signatures=", 2);
    if (split.length != 2) {
        throw new Error("[privacy-pass]: signature response invalid or in unexpected format, got response: " + data);
    }
    // decodes base-64
    const signaturesJSON = atob(split[1]);
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

/**
 * When navigation is committed we may want to reload.
 * @param details Navigation details
 * @param url url of navigation
 */
function committedNavigation(details, url) {
    let redirect = details.transitionQualifiers[0];
    let tabId = details.tabId;
    if (details.transitionType != AUTO_SUBFRAME
        && (!badTransition(url.href, redirect, details.transitionType))
        && !isNewTab(url.href)) {
        target[tabId] = url.href;
        let id = getTabId(tabId);
        // If a reload was attempted but target hadn't been inited then reload now
        if (futureReload[id] == target[tabId]) {
            futureReload[id] = false;
            updateBrowserTab(id, target[tabId]);
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

// Counts the tokens that are stored for the background page
function countStoredTokens() {
    const count = get(STORAGE_KEY_COUNT);
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
 * This is for persisting valid tokens after some manipulation, like a spend.
 * @param tokens set of tokens to store
 */
function storeTokens(tokens) {
    let storableTokens = [];
    for (var i = 0; i < tokens.length; i++) {
        let t = tokens[i];
        storableTokens[i] = getTokenEncoding(t,t.point);
    }
    const json = JSON.stringify(storableTokens);
    set(STORAGE_KEY_TOKENS, json);
    set(STORAGE_KEY_COUNT, tokens.length);

    // Update the count on the actual icon
    updateIcon(tokens.length);
}

/**
 * This is for storing tokens that we've just received from a new issuance response.
 * @param tokens set of tokens to store
 * @param signedPoints signed tokens that have been received from server
 */
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
    set(STORAGE_KEY_TOKENS, json);
    set(STORAGE_KEY_COUNT, storableTokens.length);

    // Update the count on the actual icon
    updateIcon(storableTokens.length);
}

// SJCL points are cyclic as objects, so we have to flatten them.
function getTokenEncoding(t, curvePoint) {
    let storablePoint = encodeStorablePoint(curvePoint);
    let storableBlind = t.blind.toString();
    return { token: t.token, point: storablePoint, blind: storableBlind };
}

// Load tokens from browser storage
function loadTokens() {
    const storedJSON = get(STORAGE_KEY_TOKENS);
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

//  Favicons have caused us problems...
function isFaviconUrl(url) {
    return url.indexOf("favicon") != -1;
}

// Checks whether a transition is deemed to be bad to prevent loading subresources
// in address bar
function badTransition(href, type, transitionType) {
    if (httpsRedirect[href]) {
        httpsRedirect[href] = false;
        return false;
    }
    let maybeGood = (POTENTIALLY_GOOD_TRANSITIONS.indexOf(transitionType) >= 0);
    if (!type && !maybeGood) {
        return true;
    }
    return type == SERVER_REDIRECT;
}

// Checks if the tab is deemed to be new or not
function isNewTab(url) {
    return url == FF_PRIV_TAB || url == FF_BLANK || url.indexOf(CHROME_TABS) === 0;
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

// Checks whether the correct header for initiating the workflow is received
function isBypassHeader(header) {
    return header.name.toLowerCase() == CHL_BYPASS_SUPPORT && header.value == "1";
}