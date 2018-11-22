/**
 * This file contains logic that makes calls to the chrome browser API
 * We separate these functions from the rest of the workflow for testing purposes
 * (since jest does not recognise the chrome keyword)
 *
 * All variables/functions are global
 *
 * @author: Alex Davidson
 */

/* exported CHECK_COOKIES */
/* exported attemptRedeem */
/* exported reloadTabForCookie */
/* exported setSpendFlag */
/* exported getSpendFlag */
/* exported getTabId */
/* exported updateIcon */
/* exported updateBrowserTab */
/* exported reloadBrowserTab */
/* exported isErrorPage */
/* exported isFaviconUrl */
/* exported clear */
/* exported get */
/* exported set */
/* exported UpdateCallback */
"use strict"

let CHECK_COOKIES = ACTIVE_CONFIG["cookies"]["check-cookies"];

// Attempts to redeem a token if the series of checks passes
function attemptRedeem(url, respTabId, target) {
    // Check all cookie stores to see if a clearance cookie is held
    if (CHECK_COOKIES) {
        chrome.cookies.getAllCookieStores(function(stores) {
            let clearanceHeld = false;
            stores.forEach( function(store, index) {
                var tabIds = store.tabIds;
                if (tabIds.length > 0 && tabIds[0].id !== undefined) {
                    // some browser use the id key to store the id instead
                    tabIds = tabIds.map((tab) => tab.id);
                }

                if (tabIds.includes(respTabId)) {
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
                fireRedeem(url, respTabId, target);
            }
        });
    } else {
        // If cookies aren't checked then we always attempt to redeem.
        fireRedeem(url, respTabId, target);
    }
}

// Actually activate the redemption request
function fireRedeem(url, respTabId, target) {
    if (REDEEM_METHOD == "reload") {
        setSpendFlag(url.host, true);
        let targetUrl = target[respTabId];
        if (url.href == targetUrl) {
            chrome.tabs.update(respTabId, { url: targetUrl });
        } else {
            // set a reload in the future when the target has been inited, also
            // reset timer for resetting vars
            futureReload[respTabId] = url.href;
            timeSinceLastResp = Date.now();
        }
    } else {
        throw new Error("[privacy-pass]: Incompatible redeem method selected.");
    }
}

// Reload the chosen tab
function reloadTabForCookie(cookieDomain) {
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

// Check if the cookie is defined for that tab
function isCookieForTab(hrefs, cookieDomain) {
    if (hrefs.includes(cookieDomain)) {
        return true;
    }
    // remove preceding dot and try again
    if (cookieDomain[0] == ".") {
        let noDot = cookieDomain.substring(1);
        if (hrefs.includes(noDot)) {
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

// Set the spend flag so that we will attempt to redeem a token for the url
function setSpendFlag(key, value) {
    if (value) {
        localStorage.setItem(key, "true");
    } else {
        localStorage.removeItem(key);
    }
}

// Check whether the spend flag is set
function getSpendFlag(key) {
    return localStorage.getItem(key);
}

// Update the icon and badge colour if tokens have changed
function updateIcon(count) {
    let warn = (count.toString().includes("!"))
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

// Updates the chosen tab
function updateBrowserTab(id, targetUrl) {
    chrome.tabs.update(id, {url: targetUrl});
}

// Reloads the browser tab with the chosen id
function reloadBrowserTab(id) {
    chrome.tabs.reload(id);
}

// Checks if the url corresponds to a probable error page
function isErrorPage(url) {
    let found = false;
    const errorPagePaths = ["/cdn-cgi/styles/", "/cdn-cgi/scripts/", "/cdn-cgi/images/"];
    errorPagePaths.forEach(function(str) {
        found = url.includes(str) || found;
    });
    return found;
}

//  Favicons have caused us problems...
function isFaviconUrl(url) {
    return url.includes("favicon");
}

// localStorage API function for getting values
function get(key) {
    return localStorage.getItem(key);
}

function set(key, value) {
    localStorage.setItem(key, value);
}

// localStorage API function for clearing the browser storage
function clear() {
    localStorage.clear(function() {
        if (chrome.runtime.lastError) {
            console.error(chrome.runtime.lastError.message);
        }
    });
}

// We use this function for updating the popup when tokens are cleared
// The function is passed from bc-plugin.js
var UpdateCallback = function() { }