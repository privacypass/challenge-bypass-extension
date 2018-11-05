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
        handleResponse(tokLen);
    } else {
        let send = browser.runtime.sendMessage({
            tokLen: true
        });
        send.then(handleResponse);
    }
}

function handleResponse(tokLen) {
    // Replace the count displayed in the popup
    replaceTokensStoredCount(tokLen);

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

    // replace with new count
    var passtext = document.createElement("span");
    passtext.setAttribute("id", "passtext");
    passtext.appendChild(document.createTextNode("Passes"));
    document.getElementById("stored").appendChild(passtext);

    var newCount = document.createElement("span");
    newCount.setAttribute("id", "tokens");
    newCount.appendChild(document.createTextNode(tokLen));
    document.getElementById("stored").appendChild(newCount);
}

window.onload = UpdatePopup;
