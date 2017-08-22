/* This page is for the popup in the browser toolbar */
'use strict';

chrome.extension.getBackgroundPage().UpdateCallback = UpdatePopup;

function UpdatePopup() {
  var background = chrome.extension.getBackgroundPage();
  var len = background.countStoredTokens();
  document.getElementById("stored").innerHTML = "Tokens: " + len;

  document.getElementById("clear").addEventListener('click', function() {
    var background = chrome.extension.getBackgroundPage();
	  background.clearStorage();
  });
}

window.onload = UpdatePopup;