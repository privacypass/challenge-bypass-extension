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
"use strict";

const STORAGE_KEY_TOKENS = "cf-bypass-tokens";
const STORAGE_KEY_COUNT  = "cf-token-count";
const CF_BYPASS_SUPPORT  = "cf-chl-bypass";
const CF_BYPASS_RESPONSE = "cf-chl-bypass-resp";
const CF_CLEARANCE_COOKIE = "cf_clearance";
const CF_CAPTCHA_DOMAIN = "captcha.website"; // cookies have dots prepended
const CF_VERIFICATION_ERROR = "6";
const CF_CONNECTION_ERROR = "5";
const MAX_REDIRECT = 3;
const SPEND_MAX = 3;
const MAX_TOKENS = 300;
const TOKENS_PER_REQUEST = 30;
const FF_PRIV_TAB = "about:privatebrowsing";
const CHROME_TAB = "chrome://newtab/";
const FF_BLANK = "about:blank";
const SERVER_REDIRECT = "server_redirect";
const AUTO_SUBFRAME = "auto_subframe";
const SET_COOKIE_HEADER = "set-cookie";
const VALID_REDIRECTS = ["https://","https://www.","http://www."];

// Used for resetting variables below
let timeSinceLastResp = 0;

// store the url of captcha pages here for future reloading
let storedUrl = null;

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

// Used for checking redirects after a bad spend has occurred
let checkRedirect = new Map();

// Used for firefox primarily
let futureReload = new Map();

// Already reloaded for bad spend
let alreadyBad = new Map();

// TODO: DLEQ proofs
// let activeCommConfig = DevCommitmentConfig;

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
    { urls: ["<all_urls>"] },
);
function handleCompletion(details) {
    timeSinceLastResp = Date.now();
    let url = new URL(details.url);
    // If we had a bad spend then reload the page
    if (spendId[details.requestId] && checkRedirect[url.href] && !alreadyBad[url.href]) {
        chrome.cookies.get({"url": url.href, "name": CF_CLEARANCE_COOKIE}, function(cookie) {
            if (!cookie) {
                setSpendFlag(url.host, true);
                alreadyBad[url.href] = true;
                chrome.tabs.reload(details.tabId);
            }
        });
    }
    checkRedirect[url.href] = false;
    spendId[details.requestId] = false;
}

// If a redirect occurs then we want to see if we had spent previously
// If so then it is likely that we will want to spend on the redirect
chrome.webRequest.onBeforeRedirect.addListener(
    processRedirect,
    { urls: ["<all_urls>"] },
);
function processRedirect(details) {
    let oldUrl = new URL(details.url);
    let newUrl = new URL(details.redirectUrl);
    httpsRedirect[newUrl.href] = validRedirect(oldUrl.href, newUrl.href);
    if (redirectCount[details.requestId] === undefined) {
        redirectCount[details.requestId] = 0;
    }
    if (spendId[details.requestId] && redirectCount[details.requestId] < MAX_REDIRECT) {
        setSpendOnRedirect(oldUrl, newUrl);
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
    { urls: ["<all_urls>"] },       // targeted pages
    ["responseHeaders", "blocking"] // desired traits
);

// Headers are received before document render. The blocking attributes allows
// us to cancel requests instead of loading an unnecessary ReCaptcha widget.
function processHeaders(details) {
    let url = new URL(details.url);
    let doRedeem = false;
    let cookieFound = false;
    let needCookie = spendId[details.requestId];
    for (var i = 0; i < details.responseHeaders.length; i++) {
        const header = details.responseHeaders[i];
        if (header.name.toLowerCase() == CF_BYPASS_RESPONSE) {
            if (header.value == CF_VERIFICATION_ERROR
                || header.value == CF_CONNECTION_ERROR) {
                // If these errors occur then something bad is happening.
                // Either tokens are bad or some resource is calling the server in a bad way
                // Remove most recent token
                RemoveToken();
                throw new Error("[privacy-pass]: There may be a problem with the stored tokens. Redemption failed for: " + url.href + " with error code: " + header.value);
            }
        } else if (needCookie) {
            if (clearanceCookieFound(header)) {
                cookieFound = true;
            }
        }

        // 403 with the right header indicates a bypassable CAPTCHA
        if (isBypassHeader(header) && details.statusCode == 403) {
            doRedeem = true;
        }
    }

    // If we have tokens to spend, cancel the request and pass execution over to the token handler.
    if (doRedeem && !spentUrl[url.href]) {
        if (countStoredTokens() > 0) {
            let ok = attemptRedeem(url, details.tabId);
            if (!ok) {
                return {cancel: false};
            }
        } else {
            // Store the url for redirection after captcha is solved
            // Manual check for favicon urls
            storedUrl = url.href;
            let faviconIndex = storedUrl.indexOf("favicon");
            if (faviconIndex != -1) {
                storedUrl = storedUrl.substring(0, faviconIndex);
            }
            // Update icon to show user that token may be spent here
            updateIcon("!");
        }
    }

    // We remove the token if the spend is valid
    if (needCookie) {
        if (!cookieFound) {
            // If not valid we need to ascertain whether a redirect is occurring
            checkRedirect[url.href] = true;
        } else {
            RemoveToken();
        }
        spentUrl[url.href] = true;
    }
}

// Attempts to redeem a token if we should do
function attemptRedeem(url, respTabId) {
    // Prevent reloading on captcha.website
    if (url.host.indexOf(CF_CAPTCHA_DOMAIN) != -1) {
        return false;
    }

    // Check all cookie stores to see if a clearance cookie is held
    chrome.cookies.getAllCookieStores(function(stores) {
        let clearanceHeld = false;
        stores.forEach( function(store, index) {
            var tabIds = store.tabIds;
            if (tabIds.length && tabIds[0].id !== undefined) {
                tabIds = tabIds.map((tab) => respTabId.id);
            }
            var storeMatches = tabIds.indexOf(respTabId) >= 0;
            if (storeMatches) {
                chrome.cookies.get({"url": url.href, "name": CF_CLEARANCE_COOKIE, "storeId": store.id}, function(cookie) {
                    // Require an existing, non-expired cookie.
                    if (cookie) {
                        clearanceHeld = (cookie.expirationDate * 1000 >= Date.now());
                        if (!clearanceHeld) {
                            alreadyBad[url.href] = false;
                        }
                    }
                });
            }
        });

        // If a clearance cookie is not held then set the spend flag
        if (!clearanceHeld) {
            setSpendFlag(url.host, true);
            let targetUrl = target[respTabId];
            if (url.href == targetUrl) {
                chrome.tabs.update(respTabId, { url: targetUrl });
                targetUrl = "";
            } else if (!targetUrl || (targetUrl != url.href && !isFaviconUrl(targetUrl))) {
                // set a reload in the future when the target has been inited
                futureReload[respTabId] = url.href;
            }
        }
    });

    return true;
}

// Intercepts token-spend reload requests to add a redemption header.
chrome.webRequest.onBeforeSendHeaders.addListener(
    beforeSendHeaders,        // callback
    { urls: ["<all_urls>"] }, // targeted pages
    ["requestHeaders", "blocking"]
);

function beforeSendHeaders(request) {
    let url = new URL(request.url);
    let headers = request.requestHeaders;

    // Cancel if we don't have a token to spend
    if (!getSpendFlag(url.host) || checkMaxSpend(url.host) || spentUrl[url.href] || isErrorPage(url.href) || isFaviconUrl(url.href)) {
        return {cancel: false};
    }
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
    const newHeader = { name: "challenge-bypass-token", value: redemptionString };
    headers.push(newHeader);
    spendId[request.requestId] = true;
    return {requestHeaders: headers};
}


// Intercepts CAPTCHA solution requests to add our token blob to the body.
chrome.webRequest.onBeforeRequest.addListener(
    beforeRequest,            // callback
    { urls: ["<all_urls>"] }, // targeted pages
    ["blocking"]              // desired traits
);

// This function filters requests before we've made a connection. If we don't
// have tokens, it asks for new ones when we solve a captcha.
function beforeRequest(details) {
    // Clear vars if they haven't been used for a while
    checkRedirect[details.url] = false;
    if (Date.now() - 2000 > timeSinceLastResp) {
        resetVars();
    }

    let reqUrl = details.url;
    const manualChallenge = reqUrl.indexOf("manual_challenge") != -1;
    const captchaResp = reqUrl.indexOf("g-recaptcha-response") != -1;
    const alreadyProcessed = reqUrl.indexOf("&captcha-bypass=true") != -1;

    // We're only interested in CAPTCHA solution requests that we haven't already altered.
    if ((captchaResp && alreadyProcessed) || (!manualChallenge && !captchaResp) || sentTokens[reqUrl]) {
        return {cancel: false};
    }
    sentTokens[reqUrl] = true;

    let tokens = GenerateNewTokens(TOKENS_PER_REQUEST);
    const request = BuildIssueRequest(tokens);

    // Tag the URL of the new request to prevent an infinite loop (see above)
    let newUrl = reqUrl + "&captcha-bypass=true";

    let xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
        // When we receive a response...
        if (xhr.status < 300 && xhr.readyState == 4 && countStoredTokens() < (MAX_TOKENS - TOKENS_PER_REQUEST)) {
            const resp_data = xhr.responseText;
            const signedPoints = parseIssueResponse(resp_data);
            if (signedPoints !== null) {
                storeNewTokens(tokens, signedPoints);
            }
            // Reload the page for the originally intended url
            let url = new URL(reqUrl);
            if (url.href.indexOf(CF_CAPTCHA_DOMAIN) == -1){
                let captchaPath = url.pathname;
                let pathIndex = url.href.indexOf(captchaPath);
                let reloadUrl = url.href.substring(0, pathIndex+1);
                setSpendFlag(reloadUrl, true);
                chrome.tabs.update(details.tabId, { url: reloadUrl });
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

    xhr.send("blinded-tokens=" + request);

    // Cancel the original request
    return {redirectUrl: "javascript:void(0)"};
}

// Removes cookies for captcha.website to enable getting more tokens
// in the future.
chrome.cookies.onChanged.addListener(function(changeInfo) {
    let cookieDomain = changeInfo.cookie.domain;
    let cookieName = changeInfo.cookie.name;
    if (!changeInfo.removed) {
        if (cookieDomain == "." + CF_CAPTCHA_DOMAIN // cookies have dots prepended
            && cookieName == CF_CLEARANCE_COOKIE) {
            chrome.cookies.remove({url: "http://" + CF_CAPTCHA_DOMAIN, name: CF_CLEARANCE_COOKIE});
        } else if (cookieName == CF_CLEARANCE_COOKIE) {
            createAlarm("reload-page", Date.now() + 500);
        }
    } else if (changeInfo.removed && cookieName == CF_CLEARANCE_COOKIE) {
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
function parseIssueResponse(data) {
    const split = data.split("signatures=", 2);
    if (split.length != 2) {
        throw new Error("[privacy-pass]: signature response invalid or in unexpected format, got response: " + data);
    }
    // decodes base-64
    const signaturesJSON = atob(split[1]);
    // parses into JSON
    const issueResp = JSON.parse(signaturesJSON);
    let proof;
    let signatures;
    // Only separate the proof if it has been sent (it should be included in the
    // last element of the array).
    if (TOKENS_PER_REQUEST == issueResp.length-1) {
        proof = issueResp[issueResp.length - 1];
        signatures = issueResp.slice(0, issueResp.length - 1);
    } else {
        signatures = issueResp;
    }

    let usablePoints = [];

    // We also include the DLEQ proof in the final entry now
    signatures.forEach(function(signature) {
        let usablePoint = sec1DecodePoint(signature);
        if (usablePoint == null) {
            throw new Error("[privacy-pass]: unable to decode point " + signature + " in " + JSON.stringify(signatures));
        }
        usablePoints.push(usablePoint);
    })

    // TODO: handle the DLEQ proof
    void proof; // ignore eslint warnings about unused-vars.

    return usablePoints;
}

// Alarm listener allows us to get out of the page load path.
if (chrome.alarms !== undefined) {
    chrome.alarms.onAlarm.addListener(alarmListener);
} else if (browser.alarms !== undefined) {
    browser.alarms.onAlarm.addListener(alarmListener);
}
function alarmListener(alarm) {
    switch(alarm.name) {
        // Fired on cookie reloads
        case "reload-page":
            chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
                let tabId = tabs[0].id;
                if (tabs[0].status == "loading") {
                    createAlarm("reload-page", Date.now() + 10);
                    return;
                }
                chrome.tabs.reload(tabId);
            });
            break;
    }
    removeAlarm(alarm.name);
}

// Set the target URL for the spend and update the tab if necessary
chrome.webNavigation.onCommitted.addListener(function(details) {
    let redirect = details.transitionQualifiers[0];
    let tabId = details.tabId;
    let url = new URL(details.url);
    if (details.transitionType != AUTO_SUBFRAME
        && (!badTransition(redirect) || httpsRedirect[url.href])
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


function setSpendOnRedirect(oldUrl, newUrl) {
    checkRedirect[oldUrl.href] = false;
    // Remove the token that we spent previously
    RemoveToken();
    setSpendFlag(newUrl.host, true);
}

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

// Removes a token if the spend went well
function RemoveToken() {
    let tokens = loadTokens();
    tokens = tokens.slice(1);
    storeTokens(tokens);
}

// Returns a token for a redemption
function GetTokenForSpend() {
    let tokens = loadTokens();
    const tokenToSpend = tokens[0];
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

function clearanceCookieFound(header) {
    if (header.name.toLowerCase() == SET_COOKIE_HEADER) {
        if (header.value.indexOf(CF_CLEARANCE_COOKIE) != -1) {
            return true;
        }
    }
    return false;
}

// Tor seems to have an object here whereas chrome/firefox just have an id
function getTabId(tabId) {
    let id = tabId.id;
    if (!id) {
        id = tabId;
    }
    return id;
}

function badTransition(type) {
    if (!type) {
        return true;
    }
    return type == SERVER_REDIRECT;
}

function isNewTab(url) {
    return url == CHROME_TAB || url == FF_PRIV_TAB || url == FF_BLANK;
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
    spentUrl = new Map();
    alreadyBad = new Map();
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
    return header.name.toLowerCase() == CF_BYPASS_SUPPORT && header.value == "1";
}

function createAlarm(name, when) {
    if (chrome.alarms !== undefined) {
        chrome.alarms.create(name, {
            when: when
        });
    } else if (browser.alarms !== undefined) {
        browser.alarms.create(name, {
            when: when
        });
    } else {
        throw new Error("[privacy-pass]: Browser may not support alarms");
    }
}

function removeAlarm(name) {
    if (chrome.alarms !== undefined) {
        chrome.alarms.clear(name);
    } else if (browser.alarms !== undefined) {
        browser.alarms.clear(name);
    } else {
        throw new Error("[privacy-pass]: Browser may not support alarms");
    }
}
