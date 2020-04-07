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
/* exported clearCachedCommitments */
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
"use strict";
const checkCookies = () => activeConfig()["cookies"]["check-cookies"];

/**
 * Attempts to redeem a token if the series of checks passes
 * @param {URL} url URL of request
 * @param {Number} respTabId ID of the tab where the request originated
 */
function attemptRedeem(url, respTabId) {
    // Check all cookie stores to see if a clearance cookie is held
    if (checkCookies()) {
        chrome.cookies.getAllCookieStores(function(stores) {
            let clearanceHeld = false;
            stores.forEach(function(store, index) {
                let tabIds = store.tabIds;
                if (tabIds.length > 0 && tabIds[0].id !== undefined) {
                    // some browser use the id key to store the id instead
                    tabIds = tabIds.map((tab) => tab.id);
                }

                if (tabIds.includes(respTabId)) {
                    chrome.cookies.get({
                        "url": url.href,
                        "name": chlClearanceCookie(),
                        "storeId": store.id,
                    }, function(cookie) {
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
            }
        });
    } else {
        // If cookies aren't checked then we always attempt to redeem.
        fireRedeem(url, respTabId);
    }
}


/**
 * Sets a reload to occur for the targeted URL string that is provided
 * @param {URL} url URL of request
 * @param {Number} respTabId ID of the tab where the request originated
 */
function fireRedeem(url, respTabId) {
    if (!isValidRedeemMethod(redeemMethod())) {
        throw new Error("[privacy-pass]: Incompatible redeem method selected.");
    }
    setSpendFlag(url.host, true);
    if (redeemMethod() === "reload") {
        const targetUrl = getTarget(respTabId);
        if (url.href === targetUrl) {
            chrome.tabs.update(respTabId, {url: targetUrl});
        } else {
            // set a reload in the future when the target has been inited, also
            // reset timer for resetting vars
            setFutureReload(respTabId, url.href);
            timeSinceLastResp = Date.now();
        }
    }
}

/**
 * Reload the chosen tab if a cookie is owned for the associated domain
 * @param {string} cookieDomain string href for domain of cookie
 */
function reloadTabForCookie(cookieDomain) {
    let found = false;
    chrome.windows.getAll(function(windows) {
        windows.forEach(function(w) {
            const wId = w.id;
            chrome.tabs.query({windowId: wId}, function(tabs) {
                tabs.forEach(function(tab, index) {
                    if (!found) {
                        const id = getTabId(tab.id);
                        const hrefs = spentTab[id];
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

/**
 * Indicates if a cookie corresponds to any of any of the URL strings provided
 * @param {Array<string>} hrefs
 * @param {string} cookieDomain
 * @return {boolean}
 */
function isCookieForTab(hrefs, cookieDomain) {
    if (hrefs.includes(cookieDomain)) {
        return true;
    }
    // remove preceding dot and try again
    if (cookieDomain[0] === ".") {
        const noDot = cookieDomain.substring(1);
        if (hrefs.includes(noDot)) {
            return true;
        }
    }

    return false;
}

/**
 * Returns the ID of the tab in the correct format
 * @param {Object} tabId An Object or a Number
 * @return {Number}
 */
function getTabId(tabId) {
    // Tor seems to have an object here whereas chrome/firefox just have an id
    let id = tabId.id;
    if (!id) {
        id = tabId;
    }
    return id;
}

/**
 * Set the spend flag so that we will attempt to redeem a token for the url
 * @param {string} key
 * @param {string} value
 */
function setSpendFlag(key, value) {
    if (value) {
        localStorage.setItem(key, "true");
    } else {
        localStorage.removeItem(key);
    }
}

/**
 * Check whether the spend flag is set
 * @param {string} key
 * @return {string} returns the item as a string
 */
function getSpendFlag(key) {
    return localStorage.getItem(key);
}

/**
 * Update the icon and badge colour of the plugin if tokens have changed
 * @param {Number} count
 */
function updateIcon(count) {
    const warn = (count.toString().includes("!"));
    if (count !== 0 && !warn) {
        chrome.browserAction.setIcon({path: "icons/ticket-32.png"});
        chrome.browserAction.setBadgeText({text: count.toString()});
        chrome.browserAction.setBadgeBackgroundColor({color: "#408BC9"});
    } else if (warn) {
        chrome.browserAction.setIcon({path: "icons/ticket-empty-32.png"});
        chrome.browserAction.setBadgeText({text: "!!!"});
    } else {
        chrome.browserAction.setIcon({path: "icons/ticket-empty-32.png"});
        chrome.browserAction.setBadgeText({text: ""});
    }
}

/**
 * Updates the chosen tab (causes a browser reload)
 * @param {Number} id ID of the tab to update
 * @param {string} targetUrl target of tab update
 */
function updateBrowserTab(id, targetUrl) {
    chrome.tabs.update(id, {url: targetUrl});
}

/**
 * Reloads the browser tab with the chosen id
 * @param {Number} id
 */
function reloadBrowserTab(id) {
    if (id >= 0) {
        // if id < 0 this caused error messages
        chrome.tabs.reload(id);
    }
}

/**
 * Checks if the provided url corresponds to a probable error page
 * @param {URL} url
 * @return {boolean}
 */
function isErrorPage(url) {
    let found = false;
    const errorPagePaths = ["/cdn-cgi/styles/", "/cdn-cgi/scripts/", "/cdn-cgi/images/"];
    errorPagePaths.forEach(function(str) {
        found = url.includes(str) || found;
    });
    return found;
}

/**
 * Indicates whether the URL is for a favicon
 * @param {URL} url
 * @return {boolean}
 */
function isFaviconUrl(url) {
    return url.includes("favicon");
}

/**
 * Checks whether the configured redemption method is valid
 * @param {string} method Config string indicating how redemptions are handled
 * @return {boolean}
 */
const isValidRedeemMethod = (method) => validRedemptionMethods().includes(method);


/**
 * Clears the commitments that are cached for the active configuration
 * @param {Number} cfgId config ID initiating issue request
 */
function clearCachedCommitments(cfgId) {
    let id = cfgId;
    if (!id) {
        id = getConfigId();
    }
    localStorage.removeItem(cachedCommitmentsKey(id));
}

/**
 * localStorage API function for getting string values for the key provided
 * @param {string} key
 * @return {string}
 */
function get(key) {
    return localStorage.getItem(key);
}

/**
 * localStorage API function for setting string values for the key provided
 * @param {string} key
 * @param {string} value
 */
function set(key, value) {
    localStorage.setItem(key, value);
}

/**
 * localStorage API function for clearing the browser storage
 */
function clear() {
    localStorage.clear(function() {
        if (chrome.runtime.lastError) {
            console.error(chrome.runtime.lastError.message);
        }
    });
}

/**
 * We use this function for updating the popup when tokens are cleared
 * The function is passed from bc-plugin.js
 */
let UpdateCallback = function() { };
