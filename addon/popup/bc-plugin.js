/**
 * This page is for the popup in the browser toolbar
 *
 * @author: Alex Davidson
 */
"use strict";

let background = chrome.extension.getBackgroundPage();
if (background) {
    background.UpdateCallback = UpdatePopup;
} else {
    browser.runtime.sendMessage({
        callback: UpdatePopup
    });
}

function UpdatePopup() {
    let tokLen = 0
    if (background) {
        tokLen = background.countStoredTokens();
        handleResponse(tokLen, background.getMorePassesUrl());
    } else {
        let send = browser.runtime.sendMessage({
            tokLen: true
        });
        send.then(handleResponse);
    }
}

function handleResponse(tokLen, url) {
    // Replace the count displayed in the popup
    replaceTokensStoredCount(tokLen);
    document.getElementById("website").setAttribute("href", url)

    document.getElementById("clear").addEventListener("click", function() {
        if (background) {
            background.clearStorage();
        } else {
            let send = browser.runtime.sendMessage({
                clear: true
            });
            send.then(function() {
                replaceTokensStoredCount(0);
            });
        }
    });

    // this allows the client to generate a redemption token for CF API.
    document.getElementById("redeem").addEventListener("click", () => {
        if (background) {
            tokLen = background.countStoredTokens();
            if (tokLen > 0) {
                const s1 = background.generateString();
                const s2 = background.generateString();
                const t = background.GetTokenForSpend();
                const v = background.BuildRedeemHeader(t, s1, s2);
                outputRedemption(v, s1, s2);
            } else {
                background.console.log("No tokens for redemption!");
            }
        } else {
            let send = browser.runtime.sendMessage({
                redeem: true
            });
            send.then((ret) => {
                const [v, s1, s2] = ret;
                if (!v) {
                    console.log("No tokens for redemption!");
                    return;
                }
                outputRedemption(v, s1, s2);
            });
        }
    });
}

// takes redemption contents and outputs it to console
function outputRedemption(v, s1, s2) {
    const contents = JSON.parse(atob(v)).contents;
    const json = {
        data: contents,
        bindings: [s1, s2],
    }

    const out = JSON.stringify(json, null, 4);
    if (background) {
        background.console.log(out)
    } else {
        console.log(out);
    }
}

// We have to do replace this way as using innerHtml is unsafe
function replaceTokensStoredCount(tokLen) {
    // remove old count
    var oldCount = document.getElementById("tokens");
    if (oldCount) {
        oldCount.parentNode.removeChild(oldCount);
    }
    var oldText = document.getElementById("passtext");
    if (oldText) {
        oldText.parentNode.removeChild(oldText);
    }
    var oldName = document.getElementById("name");
    if (oldName) {
        oldName.parentNode.removeChild(oldName);
    }

    // replace with new count
    var passtext = document.createElement("span");
    passtext.setAttribute("id", "passtext");
    passtext.appendChild(document.createTextNode(`Passes`));
    document.getElementById("stored").appendChild(passtext);

    var newCount = document.createElement("span");
    newCount.setAttribute("id", "tokens");
    newCount.appendChild(document.createTextNode(tokLen));
    document.getElementById("stored").appendChild(newCount);
}

window.onload = UpdatePopup;
