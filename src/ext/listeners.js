/**
 * Background listeners
 *
 * @author: Alex Davidson
 */
"use strict";

// Always listen on <all_urls> as ISSUE and SPEND urls do not need to be the same

/* Event listeners manage control flow
    - web request listeners act to send signable/redemption tokens when needed
    - web navigation listener sets the target url for the execution
    - cookie listener clears cookie for captcha.website to enable getting more
    tokens in the future
*/

chrome.webRequest.onCompleted.addListener(
    function(details) {
        handleCompletion(details);
    },
    {urls: [LISTENER_URLS]},
);

chrome.webRequest.onBeforeRedirect.addListener(
    function(details) {
        const oldUrl = new URL(details.url);
        const newUrl = new URL(details.redirectUrl);
        processRedirect(details, oldUrl, newUrl);
    },
    {urls: [LISTENER_URLS]},
);

// Watches headers for CF-Chl-Bypass and CF-Chl-Bypass-Resp headers.
chrome.webRequest.onHeadersReceived.addListener(
    function(details) {
        const url = new URL(details.url);
        processHeaders(details, url);
    }, // callback
    {urls: [LISTENER_URLS]}, // targeted pages
    ["responseHeaders", "blocking"] // desired traits
);

// Intercepts token-spend reload requests to add a redemption header.
chrome.webRequest.onBeforeSendHeaders.addListener(
    function(details) {
        const url = new URL(details.url);
        return beforeSendHeaders(details, url);
    }, // callback
    {urls: [LISTENER_URLS]}, // targeted pages
    ["requestHeaders", "blocking"]
);

// Intercepts CAPTCHA solution requests to add our token blob to the body.
chrome.webRequest.onBeforeRequest.addListener(
    function(details) {
        const url = new URL(details.url);
        const b = beforeRequest(details, url);
        if (!b) {
            return {cancel: false};
        }
        return {redirectUrl: "javascript:void(0)"};
    }, // callback
    {urls: [LISTENER_URLS]}, // targeted pages
    ["blocking"] // desired traits
);


// Removes cookies for captcha.website to enable getting more tokens
// in the future.
chrome.cookies.onChanged.addListener(function(changeInfo) {
    const cookieDomain = changeInfo.cookie.domain;
    const cookieName = changeInfo.cookie.name;
    if (!changeInfo.removed) {
        if (cookieDomain === "." + chlCaptchaDomain() // cookies have dots prepended
            && cookieName === chlClearanceCookie()) {
            chrome.cookies.remove({url: "http://" + chlCaptchaDomain(), name: chlClearanceCookie()});
        } else if (cookieName === chlClearanceCookie()) {
            reloadTabForCookie(cookieDomain);
        }
    } else if (changeInfo.removed
            && cookieName === chlClearanceCookie()
            && cookieDomain !== "." + chlCaptchaDomain()) {
        resetSpendVars();
    }
});

// Reset spend vars when window is closed in case we're private browsing
chrome.windows.onRemoved.addListener(function() {
    resetSpendVars();
});

// Set the target URL for the spend and update the tab if necessary
chrome.webNavigation.onCommitted.addListener(function(details) {
    const url = new URL(details.url);
    committedNavigation(details, url);
});

// Processes messages from the extension popup window
chrome.runtime.onMessage.addListener(handleMessage);
