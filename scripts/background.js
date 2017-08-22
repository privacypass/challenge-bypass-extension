/*
 * This background page handles the sending requests and dealing with responses.
 * Control flow is handled in the listeners. Cryptography uses SJCL.
 */

/*jshint esversion: 6 */
/*global chrome,window,document,console,localStorage,browser*/
'use strict';

const STORAGE_KEY_TOKENS = "cf-bypass-tokens";
const STORAGE_KEY_COUNT  = "cf-token-count";
const CF_BYPASS_SUPPORT  = "cf-chl-bypass";
const CF_BYPASS_RESPONSE = "cf-chl-bypass-resp";
const CF_CLEARANCE_COOKIE = "cf_clearance";
const CF_FORCE_CHALLENGE_HEADER = "";
const CF_VERIFICATION_ERROR = "6";
const CF_CONNECTION_ERROR = "5";
const CF_DBG_FORCE_CHALLENGE = false;

const TOKENS_PER_REQUEST = 10;

// store the url of captcha pages here for future reloading
let storedUrl = null;

// This url is inited when a token is about to be spent
// This allows us to force tabs to update to the targeted url
let targetUrl = null;

// TODO: DLEQ proofs
// let activeCommConfig = DevCommitmentConfig;

/* Event listeners manage control flow 
    web request listeners act to send signable/redemption tokens when needed
*/

// Watches headers for CF-Chl-Bypass and CF-Chl-Bypass-Resp headers.
chrome.webRequest.onHeadersReceived.addListener(
    processHeaders,                 // callback
    { urls: ["<all_urls>"] },       // targeted pages
    ["responseHeaders", "blocking"] // desired traits
);

// Headers are received before document render. The blocking attributes allows
// us to cancel requests instead of loading an unnecessary ReCaptcha widget.
function processHeaders(details) {

    for (var i = 0; i < details.responseHeaders.length; i++) {
        const header = details.responseHeaders[i];

        if (header.name.toLowerCase() == CF_BYPASS_RESPONSE) {
            if (header.value == CF_VERIFICATION_ERROR
                || header.value == CF_CONNECTION_ERROR) {
                // If these errors occur then something bad is happening.
                // We clear token storage so that access is possible.
                console.log("redemption failed: ", header.value);
                clearStorage();
                createAlarm("reload-page", Date.now() + 10);
                
                // We don't use cancel: true since in chrome the page appears 
                // blocked for a second
                return {redirectUrl: 'javascript:void(0)'};
            } 
        }

        // 403 with the right header indicates a bypassable CAPTCHA
        if (!isBypassHeader(header) || details.statusCode != 403) {
            continue;
        }

        // If we have tokens, cancel the request and pass execution over to the token handler.
        let url = new URL(details.url);
        var hostName = url.hostname;
        if (countStoredTokens() > 0) {
            console.log('reloading');
            setSpendFlag(url.host, true);
            targetUrl = url;
            createAlarm("reload-page", Date.now() + 10);

            // We don't use cancel: true since in chrome the page appears 
            // blocked for a second
            return {redirectUrl: 'javascript:void(0)'};
        } else if (!storedUrl) {
            // For chrome we have to store the url for redirection after captcha is solved
            storedUrl = url;
        }

        // Otherwise, allow the request to complete while we generate some tokens.
        // TODO: start generating tokens here to speed up the request processing
        // createAlarm("generate-new-tokens", Date.now() + 10);
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

    // Force challenge!!
    if (CF_DBG_FORCE_CHALLENGE) {
        let chlHeader = { name: CF_FORCE_CHALLENGE_HEADER, value: "1" };
        headers.push(chlHeader);
    }

    // might need to add a force header
    if (!getSpendFlag(url.host)) {
        return {requestHeaders: headers};
    }

    console.log("attempting to spend token: " + url.href)
    const tokenToSpend = GetTokenForSpend();
    if (tokenToSpend == null) {
        console.log("no tokens to spend");
        return {cancel: false};
    }

    const method = request.method;
    const http_path = method + " " + url.pathname + url.search;

    const redemptionString = BuildRedeemHeader(tokenToSpend, url.hostname, http_path);

    const newHeader = { name: "challenge-bypass-token", value: redemptionString };
    headers.push(newHeader);

    setSpendFlag(url.host, null);

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
    let reqURL = details.url;

    const manualChallenge = reqURL.indexOf("manual_challenge") != -1;
    const captchaResp = reqURL.indexOf("g-recaptcha-response") != -1;
    const alreadyProcessed = reqURL.indexOf("&captcha-bypass=true") != -1;

    // We're only interested in CAPTCHA solution requests that we haven't already altered.
    if ((captchaResp && alreadyProcessed) || (!manualChallenge && !captchaResp)) {
        return {cancel: false};
    }

    let tokens = null;

    // If no tokens exist, we'll need to make some first.
    if (countStoredTokens() == 0) {
        // createAlarm("generate-new-tokens", Date.now() + 10);
        // console.log("tried to solve a CAPTCHA, didn't have any tokens prepared");
        // return {cancel: false};
        console.log("generating tokens");
        tokens = GenerateNewTokens(TOKENS_PER_REQUEST);
        console.log("done")
    } else {
        tokens = GetStoredTokens();
        if (tokens == null) {
            console.log("tried to solve a CAPTCHA, couldn't retrieve stored tokens");
            // Can't do anything with this request, so get out of the way.
            return {cancel: false};
        }
    }

    const request = BuildIssueRequest(tokens);

    // Tag the URL of the new request to prevent an infinite loop (see above)
    let newURL = reqURL + "&captcha-bypass=true";

    let xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
        // When we receive a response...
        if (xhr.status < 300 && xhr.readyState == 4 && countStoredTokens() == 0) {
            const resp_data = xhr.responseText;
            const signedPoints = parseIssueResponse(resp_data);
            if (signedPoints !== null) {
                console.log("storing tokens");
                storeNewTokens(tokens, signedPoints);
            } else {
                // If signed tokens are not respond we probably still have a cookie.
                // reload the page.
                console.log("No tokens stored");
                createAlarm("reload-page-xhr", Date.now() + 10);
                return;
            }
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

// An issue response takes the form "signatures=[b64 blob]"
// The blob is an array of base64-encoded marshaled curve points.
// The points are uncompressed (TODO).
//
// If the blinded points are P = H(t)rB, these are Q = kP.
function parseIssueResponse(data) {
    const split = data.split("signatures=", 2);
    if (split.length != 2) {
        console.log("signature response invalid or in unexpected format");
        console.log("got response:", data);
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
            console.log("unable to decode point" + signature + " in " + JSON.stringify(signatures));
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
                    chrome.tabs.update(tabs[0].id, { url: storedUrl.href });
                    storedUrl = null;
                }
            });
            break;
        // Fired on redemptions or errors
        case "reload-page":
            chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
                if (targetUrl) {
                    chrome.tabs.update(tabs[0].id, { url: targetUrl.href });
                    targetUrl = null;
                } else {
                    chrome.tabs.reload(tabs[0].id);
                }
            });
            break;
        case "generate-new-tokens":
            console.log("generate-new-tokens alarm fired");
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
        console.log("bg: message from content script was undefined");
        return;
    }
    // ignore anything that isn't our trigger message
    if (message.type != "triggerChallengeBypass" || !message.content) {
        return;
    }
    console.log("page load finished");
}


/* Token storage functions */

function countStoredTokens() {
    const count = localStorage.getItem(STORAGE_KEY_COUNT);
    if (count == null) {
        return 0;
    }

    // We change the png file to show if tokens are stored or not
    const countInt = JSON.parse(count); 
    if (countInt == 0) {
        chrome.browserAction.setIcon({ path: "icons/tokenjar-empty-32.png", });
    } else {
        chrome.browserAction.setIcon({ path: "icons/tokenjar-32.png", });
    }
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
    console.log("token", tokenToSpend);
    tokens = tokens.slice(1);
    storeTokens(tokens);
    return tokenToSpend;
}

// This is for persisting valid tokens after some manipulation, like a spend.
function storeTokens(tokens) {
    let storableTokens = [];
    for (var i = 0; i < tokens.length; i++) {
        let t = tokens[i];
        // SJCL points are cyclic as objects, so we have to flatten them.
        let storablePoint = encodeStorablePoint(t.point);
        let storableBlind = t.blind.toString();
        storableTokens[i] = { token: t.token, point: storablePoint, blind: storableBlind };
    }
    const json = JSON.stringify(storableTokens);
    localStorage.setItem(STORAGE_KEY_TOKENS, json);
    localStorage.setItem(STORAGE_KEY_COUNT, tokens.length);
}

// This is for storing tokens we've just received from a new issuance response
// that don't yet have signed points assigned to them.
function storeNewTokens(tokens, signedPoints) {
    let storableTokens = [];
    for (var i = 0; i < tokens.length; i++) {
        let t = tokens[i];
        // SJCL points are cyclic as objects, so we have to flatten them.
        let storablePoint = encodeStorablePoint(signedPoints[i]);
        let storableBlind = t.blind.toString();
        storableTokens[i] = { token: t.token, point: storablePoint, blind: storableBlind };
    }
    const json = JSON.stringify(storableTokens);
    localStorage.setItem(STORAGE_KEY_TOKENS, json);
    localStorage.setItem(STORAGE_KEY_COUNT, tokens.length);
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
            console.log(chrome.runtime.lastError.message);
        }
    });
    // Update icons
    chrome.browserAction.setIcon({ path: "icons/tokenjar-empty-32.png", });
    UpdateCallback()
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
        console.log("does your browser not support alarms?");
    }
}

function removeAlarm(name) {
    if (chrome.alarms !== undefined) {
        chrome.alarms.clear(name);
    } else if (browser.alarms !== undefined) {
        browser.alarms.clear(name);
    } else {
        console.log("does your browser not support alarms?");
    }
}
