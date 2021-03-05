/**
 * This page is for the popup in the browser toolbar
 *
 * @author: Alex Davidson
 */
"use strict";

let background = chrome.extension.getBackgroundPage();
if (background) {
    background.UpdateCallback = UpdatePopup;
    // update version text
    document.getElementById("version-text").textContent = "Version " + background.extVersion();
} else {
    browser.runtime.sendMessage({
        callback: UpdatePopup,
    });
    // update version text
    browser.runtime.sendMessage({
        version: true,
    }).then((extVersion) => {
        document.getElementById("version-text").textContent = "Version " + extVersion;
    });
}

/**
 * Sens a message to the background page to receover the latest token
 * counts for each of the available configurations
 */
function UpdatePopup() {
    if (background) {
        let configTokLens = background.getTokenNumbersForAllConfigs();
        handleResponse(configTokLens);
    } else {
        browser.runtime.sendMessage({
            tokLen: true,
        }).then(handleResponse);
    }
}

/**
 * Handles the response from the background page with the number of
 * tokens for each config
 * @param {Array<Object>} configTokLens An array of object literals
 * containing token info relating to each othe available configs
 */
function handleResponse(configTokLens) {
    // Replace the count displayed in the popup
    replaceTokensStoredCount(configTokLens);

    document.getElementById("clear").addEventListener("click", function() {
        if (background) {
            background.clearStorage();
            UpdatePopup();
        } else {
            browser.runtime.sendMessage({
                clear: true,
            }).then(() => {
                UpdatePopup();
            });
        }
    });

    // this allows the client to generate a redemption token for CF API.
    document.getElementById("redeem").addEventListener("click", () => {
        if (background) {
            const tokLen = background.countStoredTokens(1);
            if (tokLen > 0) {
                const s1 = background.generateString();
                const s2 = background.generateString();
                const t = background.GetTokenForSpend();
                const v = background.BuildRedeemHeader(t, s1, s2);
                outputRedemption(v, s1, s2);
                UpdatePopup();
            } else {
                background.console.log("No tokens for redemption!");
            }
        } else {
            browser.runtime.sendMessage({
                redeem: true,
            }).then((ret) => {
                const [v, s1, s2] = ret;
                if (!v) {
                    // eslint-disable-next-line
                    console.log("No tokens for redemption!");
                    return;
                }
                outputRedemption(v, s1, s2);
                UpdatePopup();
            });
        }
    });
}

/**
 * takes redemption contents and outputs it to console
 * @param {string} v base64 encoded redemption contents
 * @param {string} s1 binding
 * @param {string} s2 binding
 */
function outputRedemption(v, s1, s2) {
    const contents = JSON.parse(atob(v)).contents;
    const json = {
        data: contents,
        bindings: [s1, s2],
    };

    const out = JSON.stringify(json, null, 4);
    if (background) {
        background.console.log(out);
    } else {
        // eslint-disable-next-line
        console.log(out);
    }
}

/**
 * Rewrites HTML based on token numbers
 * @param {Array<Object>} configTokLens Config token info
 */
function replaceTokensStoredCount(configTokLens) {
    configTokLens.map((ele) => {
        // remove old count
        const span = document.getElementById(`stored-${ele.id}`);
        if (span) {
            span.parentNode.removeChild(span);
        }
    });

    // replace with new count
    configTokLens.forEach((ele) => {
        const stored = document.createElement("span");
        stored.setAttribute("id", `stored-${ele.id}`);
        stored.className = "stored";
        stored.onclick = () => {
            chrome.tabs.create({
                url: ele.url,
            });
        };

        const passtext = document.createElement("span");
        passtext.setAttribute("id", `passtext-${ele.id}`);
        passtext.className = "passtext";
        passtext.textContent = ele.name;
        stored.appendChild(passtext);

        const newCount = document.createElement("span");
        newCount.setAttribute("id", `tokens-${ele.id}`);
        newCount.className = "tokens";
        newCount.textContent = ele.tokLen;
        stored.appendChild(newCount);

        stored.onmouseover = () => {
            const passesText = document.getElementById(`passtext-${ele.id}`);
            passesText.textContent = "Get more passes!";
        };
        stored.onmouseleave = () => {
            const passesText = document.getElementById(`passtext-${ele.id}`);
            passesText.textContent = ele.name;
        };

        document.getElementById("popup-http").appendChild(stored);
    });
}

window.onload = UpdatePopup;
