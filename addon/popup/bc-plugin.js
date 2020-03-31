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
    if (background) {
        let configTokLens = background.getTokenNumbersForAllConfigs();
        handleResponse(configTokLens);
    } else {
        browser.runtime.sendMessage({
            tokLen: true,
        }).then(handleResponse);
    }
}

function handleResponse(configTokLens) {
    // Replace the count displayed in the popup
    replaceTokensStoredCount(configTokLens);

    document.getElementById("clear").addEventListener("click", function() {
        if (background) {
            background.clearStorage();
            UpdatePopup();
        } else {
            browser.runtime.sendMessage({
                clear: true
            }).then(() => {
                UpdatePopup();
            })
        }
    });

    // this allows the client to generate a redemption token for CF API.
    document.getElementById("redeem").addEventListener("click", () => {
        if (background) {
            tokLen = background.countStoredTokens(background.getConfigId());
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
            browser.runtime.sendMessage({
                redeem: true
            }).then((ret) => {
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
function replaceTokensStoredCount(configTokLens) {
    configTokLens.map((ele) => {
        // remove old count
        var span = document.getElementById(`stored-${ele.id}`);
        if (span) {
            span.parentNode.removeChild(span);
        }
    });

    // replace with new count
    configTokLens.forEach((ele) => {
        var stored = document.createElement("span");
        stored.setAttribute("id", `stored-${ele.id}`);
        stored.className = "stored";
        stored.onclick = () => {
            chrome.tabs.create({
                url: ele.url,
            });
        };

        const active = ele.active ? "(active)" : "";

        var passtext = document.createElement("span");
        passtext.setAttribute("id", `passtext-${ele.id}`);
        passtext.className = "passtext";
        passtext.textContent = `${ele.name} ${active}`;
        stored.appendChild(passtext);

        var newCount = document.createElement("span");
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
            passesText.textContent = `${ele.name} ${active}`;
        }

        document.getElementById("popup-http").appendChild(stored);
    });
}

window.onload = UpdatePopup;
