/* This page is for the popup in the browser toolbar */
'use strict';

chrome.extension.getBackgroundPage().UpdateCallback = UpdatePopup;

function UpdatePopup() {
  var background = chrome.extension.getBackgroundPage();
  var tokLen = background.countStoredTokens();
  
  // Replace the count displayed in the popup
  replaceTokensStoredCount(tokLen);

  document.getElementById("clear").addEventListener('click', function() {
    var background = chrome.extension.getBackgroundPage();
	  background.clearStorage();
  });
}

// We have to do replace this way as using innerHtml is unsafe
function replaceTokensStoredCount(tokLen) {
    // remove old count
    var oldCount = document.getElementById("tokens");
    if (!!oldCount) {
    	oldCount.parentNode.removeChild(oldCount);
    }

    // replace with new count
    var newCount = document.createElement("p");
    newCount.setAttribute("id", "tokens");
    newCount.appendChild(document.createTextNode("Tokens: " + tokLen));
    document.getElementById("stored").appendChild(newCount);
}

window.onload = UpdatePopup;