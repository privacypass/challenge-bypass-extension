/*
 * This background page handles the sending requests and dealing with responses.
 * Passes are exchanged with the server containing blinded tokens for bypassing CAPTCHAs.
 * Control flow is handled in the listeners. Cryptography uses SJCL.
 *
 * @author: George Tankersley
 * @author: Alex Davidson
 */

/*jshint esversion: 6 */
/*global chrome,window,document,console,localStorage,browser*/
'use strict';

const STORAGE_KEY_TOKENS = "cf-bypass-tokens";
const STORAGE_KEY_COUNT  = "cf-token-count";
const CF_BYPASS_SUPPORT  = "cf-chl-bypass";
const CF_BYPASS_RESPONSE = "cf-chl-bypass-resp";
const CF_CLEARANCE_COOKIE = "cf_clearance";
const CF_CAPTCHA_DOMAIN = "captcha.website"; // cookies have dots prepended
const CF_VERIFICATION_ERROR = "6";
const CF_CONNECTION_ERROR = "5";
const RELOAD_MAX = 3; // This is mainly to stop runaway webpages

const MAX_TOKENS = 300;
const TOKENS_PER_REQUEST = 30;

// store the url of captcha pages here for future reloading
let storedUrl = null;

// This url is inited when a token is about to be spent
// This allows us to force tabs to update to the targeted url
let targetUrl = null;

// Monitors number of reloads for a url to prevent passes
// being eaten.
let reloadCount = new Map();

// We use this to clear the reload map temporally
let timeOfLastResp = 0;

// We monitor referers so that we don't load sub-resources that 
// passes are required for
let refererMap = new Map();

// If clearance is applied for then we don't want to keep sending requests
// before a cookie has been stored
let clearanceApplied = new Map();

// Set if a spend has occurred for a req id
let spendId = new Map();

// last set target URLs used for reloading compatibility with slow browsers
let usedTargets = [];

// TODO: DLEQ proofs
// let activeCommConfig = DevCommitmentConfig;

/* Event listeners manage control flow 
    - web request listeners act to send signable/redemption tokens when needed
    - cookie listener clears cookie for captcha.website to enable getting more 
    tokens in the future
*/

// If a redirect occurs then we want to see if we had spent previously
// If so then it is likely that we will want to spend on the redirect
chrome.webRequest.onBeforeRedirect.addListener(
    processRedirect,
    { urls: ["<all_urls>"] },
);
function processRedirect(details) {
    if (spendId[details.requestId]) {
        let url = document.createElement('a');
        url.href = details.redirectUrl;
        setSpendFlag(url.host, true);
        spendId[details.requestId] = false;
    }
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
    timeOfLastResp = Date.now();
    for (var i = 0; i < details.responseHeaders.length; i++) {
        let url = new URL(details.url);
        const header = details.responseHeaders[i];
        if (header.name.toLowerCase() == CF_BYPASS_RESPONSE) {
            if (header.value == CF_VERIFICATION_ERROR
                || header.value == CF_CONNECTION_ERROR) {
                // If these errors occur then something bad is happening.
                // Either tokens are bad or some resource is calling the server in a bad way
                // Consider clearing storage
                throw new Error("[privacy-pass]: There may be a problem with the stored tokens. Redemption failed for: " + url.href + " with error code: " + header.value);
            } 
        }

        // 403 with the right header indicates a bypassable CAPTCHA
        if (!isBypassHeader(header) || details.statusCode != 403) {
            continue;
        }

        // If we have tokens to spend, cancel the request and pass execution over to the token handler.        
        let hostName = url.hostname;
        if (countStoredTokens() > 0) {
            // Prevent reloading on captcha.website
            if (url.host.indexOf(CF_CAPTCHA_DOMAIN) != -1) {
                return {cancel: false};
            }

            // Only reload a specific url if no referer is set.
            let referer = refererMap.get(details.requestId);
            if (!referer && !isFaviconUrl(url.href) && !targetUrl) {
                targetUrl = url;
            }

            // reload page
            chrome.cookies.get({"url": url.href, "name": CF_CLEARANCE_COOKIE}, function(cookie) {
                if (!cookie) {
                    if (!clearanceApplied[url.hostname]) {
                        clearanceApplied[url.hostname] = true;
                        setSpendFlag(url.host, true);  
                        createAlarm("reload-page", Date.now() + 200);
                    }
                } else {
                    // Clear this record out now since we don't need it once we have a cookie
                    if (clearanceApplied[url.hostname]) {
                        clearanceApplied[url.hostName] = null;
                    }

                    // Only persist reloading for a short amount of time
                    // Otherwise can get stuck in loops
                    let reloads = reloadCount[url.href]
                    if (!reloads) {
                        createAlarm("reload-page", Date.now() + 200);
                        reloadCount[url.href] = 1;
                    } else if (reloads < RELOAD_MAX) {
                        createAlarm("reload-page", Date.now() + 200);
                        reloadCount[url.href] = reloads+1;
                    } else {
                        throw new Error("[privacy-pass]: Max reloads reached for resource: " + url.href);
                    }
                }
            });
            

            // We don't use cancel: true since in chrome the page appears 
            // blocked for a second
            return {redirectUrl: 'javascript:void(0)'};
        }

        // Store the url for redirection after captcha is solved
        // Manual check for favicon urls
        storedUrl = url.href;
        let faviconIndex = storedUrl.indexOf("favicon");
        if (faviconIndex != -1) {
            storedUrl = storedUrl.substring(0, faviconIndex);
        }
        return {cancel: false};
    }
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
    for (let i = 0; i < headers.length; i++) {
        if (headers[i].name == "Referer") {
            refererMap.set(request.requestId, headers[i].value);
        }
    }

    // might need to add a force header or cancel the reload for captcha.website
    if (!getSpendFlag(url.host)) {
        return {requestHeaders: headers};
    }

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
    setSpendFlag(url.host, null);
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
    if (Date.now() - 3000 > timeOfLastResp) {
        resetVars();
    }

    let reqURL = details.url;
    const manualChallenge = reqURL.indexOf("manual_challenge") != -1;
    const captchaResp = reqURL.indexOf("g-recaptcha-response") != -1;
    const alreadyProcessed = reqURL.indexOf("&captcha-bypass=true") != -1;

    // We're only interested in CAPTCHA solution requests that we haven't already altered.
    if ((captchaResp && alreadyProcessed) || (!manualChallenge && !captchaResp)) {
        return {cancel: false};
    }

    let tokens = GenerateNewTokens(TOKENS_PER_REQUEST);
    const request = BuildIssueRequest(tokens);

    // Tag the URL of the new request to prevent an infinite loop (see above)
    let newURL = reqURL + "&captcha-bypass=true";

    let xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
        // When we receive a response...
        if (xhr.status < 300 && xhr.readyState == 4 && countStoredTokens() < (MAX_TOKENS - TOKENS_PER_REQUEST)) {
            const resp_data = xhr.responseText;
            const signedPoints = parseIssueResponse(resp_data);
            if (signedPoints !== null) {
                storeNewTokens(tokens, signedPoints);
            } else {
                // reload the page.
                createAlarm("reload-page-xhr", Date.now() + 10);
                return;
            }
        } else if (countStoredTokens() >= (MAX_TOKENS - TOKENS_PER_REQUEST)) {
            throw new Error("[privacy-pass]: Cannot receive new tokens due to upper bound.")
        }

        // Finally, we can reload and spend a token
        if (xhr.readyState == 4 && countStoredTokens() > 0) {
            createAlarm("reload-page-xhr", Date.now() + 10);
        }
    };

    xhr.open("POST", newURL, true);
    xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
    xhr.setRequestHeader("CF-Chl-Bypass", "1");
    // We seem to get back some odd mime types that cause problems...
    xhr.overrideMimeType("text/plain");
    
    xhr.send("blinded-tokens=" + request);

    // Cancel the original request
    return {redirectUrl: 'javascript:void(0)'};
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
            // Reload the page when we get a cookie back as we might need to use it.
            createAlarm("reload-page", Date.now() + 1000);
        }
    }
});

// An issue response takes the form "signatures=[b64 blob]"
// The blob is an array of base64-encoded marshaled curve points.
// The points are uncompressed (TODO).
//
// If the blinded points are P = H(t)rB, these are Q = kP.
function parseIssueResponse(data) {
    const split = data.split("signatures=", 2);
    if (split.length != 2) {
        throw new Error("[privacy-pass]: signature response invalid or in unexpected format, got response: " + data);
        return null;
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
            throw new Error("[privacy-pass]: unable to decode point" + signature + " in " + JSON.stringify(signatures));
            return;
        }
        usablePoints.push(usablePoint);
    })

    // TODO: handle the DLEQ proof
    
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
        // Fired when a user sends tokens to be signed
        case "reload-page-xhr":
            chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
                if (tabs[0].id) {
                    chrome.tabs.update(tabs[0].id, { url: storedUrl });               
                    storedUrl = null;
                }
            });
            break;
        // Fired on redemptions or errors
        case "reload-page":
            chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
                // If we don't have a target then try using the last one we had
                let lastTarget = usedTargets.pop()
                if (!targetUrl) {
                    targetUrl = lastTarget;
                }
                if (!!targetUrl) {
                    chrome.tabs.update(tabs[0].id, { url: targetUrl.href });
                    usedTargets.push(targetUrl);
                    setTimeout(function() {
                        targetUrl = null;
                    } , 1000);
                    // Clear the refererMap if it is getting large
                    if (refererMap.size > 100) {
                        refererMap = new Map();
                    }
                } else {
                    chrome.tabs.reload(tabs[0].id);
                }
            });
            break;
        case "generate-new-tokens":
            // TODO use this alarm to generate tokens in more efficient manner
            // storeTokens(GenerateNewTokens(TOKENS_PER_REQUEST));
            break;
    }
    removeAlarm(alarm.name);
}

// Listens for a message sent by the content script at document_end.
chrome.runtime.onMessage.addListener(handleDocumentEnd);

/*
    The content script is not currently used
    We instead use a header sent from Cloudflare to verify a CAPTCHA page
 */
// We expect to have the meta tags at this point but not to have loaded the
// captcha iframe, which gives us a chance to stop needless requests to Google.
function handleDocumentEnd(message, sender) {
    // have to do the undefined check for new versions of firefox
    if (message == undefined) {
        throw new Error("[privacy-pass]: Message from content script was undefined");
        return;
    }
    // ignore anything that isn't our trigger message
    if (message.type != "triggerChallengeBypass" || !message.content) {
        return;
    }
}


/* Token storage functions */

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

function GetStoredTokens() {
    const tokens = loadTokens();
    if (tokens == null || tokens.length == 0) {
        return null;
    }
    return tokens;
}

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
    return !!localStorage.getItem(key);
}

// We use this function for updating the popup when tokens are cleared
// The function is passed from bc-plugin.js
var UpdateCallback = function() { }

/* Utility functions */
//  Favicons have caused us problems...
function isFaviconUrl(href) {
    return href.indexOf("favicon") != -1;
}

function resetVars() {
    reloadCount = new Map();
    clearanceApplied = new Map();
    usedTargets = [];
    spendId = new Map();
}

function updateIcon(count) {
    if (count != 0) {
        chrome.browserAction.setIcon({ path: "icons/ticket-32.png", });
        chrome.browserAction.setBadgeText({text: count.toString()});
        chrome.browserAction.setBadgeBackgroundColor({color: "#408BC9"});
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
