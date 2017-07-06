/* This page is for the popup in the browser toolbar */
'use strict';

window.onload = function() {
  var background = chrome.extension.getBackgroundPage();
  var len = background.CountStoredTokens();
  document.getElementById("stored").innerHTML = "Number of tokens left: " + len;

  document.getElementById("clear").addEventListener('click', function() {
    var background = chrome.extension.getBackgroundPage();
	  background.clearStorage();
  });
}
