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

const TOKENS_PER_REQUEST = 10;

/* Event listeners manage control flow */

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
            if (header.value == "6") {
                // The number 6 has well-known magical properties.
                // Our existing tokens are no good anymore, clear & reload.
                console.log("redemption failed");
                clearStorage();
                createAlarm("reload-page", Date.now() + 10);
                return {cancel: true};
            }
        }

        // 403 with the right header indicates a bypassable CAPTCHA
        if (!isBypassHeader(header) || details.statusCode != 403) {
            continue;
        }

        // If we have tokens, cancel the request and pass execution over to the token handler.
        if (CountStoredTokens() > 0) {
            let url = new URL(details.url);
            setSpendFlag(url.host, true);
            createAlarm("reload-page", Date.now() + 10);
            return {cancel: true};
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

    if (getSpendFlag(url.host) != "true") {
        console.log("not true: " + url.host);
        return {cancel: false};
    }

    const tokenToSpend = GetTokenForSpend();
    if (tokenToSpend === null) {
        console.log("no tokens to spend");
        return {cancel: false};
    }

    const method = request.method;
    const http_path = method + " " + url.pathname + url.search;
    console.log(http_path);

    let headers = request.requestHeaders;
    let hostHeader = "";
    for (var i = 0; i < headers.length; i++) {
        if (headers[i].name.toLowerCase() == "host") {
            hostHeader = headers[i].value;
            break;
        }
    }

    const redemptionString = BuildRedeemHeader(tokenToSpend, hostHeader, http_path);

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

    // XXX HACK TO BYPASS BROKEN DEV STACK CAPTCHAS
    const bypassHack = false;

    // We're only interested in CAPTCHA solution requests that we haven't already altered.
    if ((captchaResp && alreadyProcessed) || (!manualChallenge && !captchaResp)) {
        return {cancel: false};
    }

    let tokens = null;

    // If no tokens exist, we'll need to make some first.
    if (CountStoredTokens() === 0) {
        // createAlarm("generate-new-tokens", Date.now() + 10);
        // console.log("tried to solve a CAPTCHA, didn't have any tokens prepared");
        // return {cancel: false};
        console.log("generating tokens");
        tokens = GenerateNewTokens(TOKENS_PER_REQUEST);
    } else {
        tokens = GetStoredTokens();
        if (tokens === null) {
            console.log("tried to solve a CAPTCHA, couldn't retrieve stored tokens");
            // Can't do anything with this request, so get out of the way.
            return {cancel: false};
        }
    }

    const request = BuildIssueRequest(tokens);

    // Tag the URL of the new request to prevent an infinite loop (see above)
    let newURL = reqURL + "&captcha-bypass=true";

    if (bypassHack) {
        const paramsIndex = reqURL.indexOf("chk_captcha?") + 12;
        newURL = reqURL.slice(0, paramsIndex) + "g-recaptcha-response=blah&captcha-bypass=true";
        console.log("hack: ", newURL);
    }

    let xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
        // When we receive a response...
        if (xhr.status < 300 && xhr.readyState == 4 && CountStoredTokens() === 0) {
            const resp_data = xhr.responseText;
            const signedPoints = parseIssueResponse(resp_data);
            if (signedPoints !== null) {
                storeNewTokens(tokens, signedPoints);
            }
        }

        // Finally, we can reload and spend a token
        if (xhr.readyState == 4 && CountStoredTokens() > 0) {
            createAlarm("reload-page", Date.now() + 10);
            return;
        }
    };

    xhr.open("POST", newURL, true);
    xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
    xhr.setRequestHeader("CF-Chl-Bypass", "1");
    xhr.send("blinded-tokens=" + request);

    // Cancel the original request
    return {cancel: true};
}

// An issue response takes the form "signatures=[b64 blob]"
// The blob is an array of base64-encoded marshaled curve points.
// The points are uncompressed (TODO).
//
// If the blinded points are P = H(t)rB, these are Q = kP.
function parseIssueResponse(data) {
    console.log("got response:", data);
    const split = data.split("signatures=", 2);
    if (split.length != 2) {
        console.log("signature response invalid or in unexpected format");
        return null;
    }
    const signaturesJSON = atob(split[1]);
    const signatures = JSON.parse(signaturesJSON);

    let usablePoints = [];
    for (var i = 0; i < signatures.length; i++) {
        let usablePoint = sec1DecodePoint(signatures[i]);
        if (usablePoint === null) {
            console.log("unable to decode point", i, signatures[i]);
            return null;
        }
        usablePoints.push(usablePoint);
    }
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
        case "reload-page":
            chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
                chrome.tabs.reload(tabs[0].id);
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

// We expect to have the meta tags at this point but not to have loaded the
// captcha iframe, which gives us a chance to stop needless requests to Google.
function handleDocumentEnd(message, sender) {
    // have to do the undefined check for new versions of firefox
    if (message === undefined) {
        console.log("bg: message from content script was undefined");
        return;
    }
    // ignore anything that isn't our trigger message
    if (message.type != "triggerChallengeBypass" || !message.content) {
        return;
    }
    console.log("page load finished");
    // TODO the meta tags can contain a DLEQ validation reference (pubkey, relay fingerprint)
}


/* Token storage functions */

function CountStoredTokens() {
    const count = localStorage.getItem(STORAGE_KEY_COUNT);
    if (count === null) {
        return 0;
    }
    return JSON.parse(count);
}

function GetStoredTokens() {
    const tokens = loadTokens();
    if (tokens === null || tokens.length === 0) {
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
    if (storedJSON === null) {
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
}

function setSpendFlag(key, value) {
    if (value === null) {
        localStorage.removeItem(key);
    } else {
        localStorage.setItem(key, value);
    }
}

function getSpendFlag(key) {
    return localStorage.getItem(key);
}


/* Utility functions */

function isBypassHeader(header) {
    return header.name == CF_BYPASS_SUPPORT && header.value == "1";
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
