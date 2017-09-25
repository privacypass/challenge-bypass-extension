/* This page is for the popup in the browser toolbar */
"use strict";

chrome.extension.getBackgroundPage().UpdateCallback = UpdatePopup;

function UpdatePopup() {
  var background = chrome.extension.getBackgroundPage();
  var tokLen = background.countStoredTokens();
  
  // Replace the count displayed in the popup
  replaceTokensStoredCount(tokLen);

  document.getElementById("clear").addEventListener("click", function() {
    var background = chrome.extension.getBackgroundPage();
	  background.clearStorage();
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
