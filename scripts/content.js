/*
    This content script is not currently used by the extensions
    We currently rely on the use of headers returned by sites with Privacy Pass support
    The option is there to use the HTML tags instead if need be.
 */

// Trigger the token manager if bypass tags are present.
// Returns a map with the certs on success or null if any of the cert tags don't exist.
function getBypassTags() {
    // If there isn't a captcha-bypass meta tag, do nothing.
    var captchaTriggerTag = document.getElementById("captcha-bypass");
    if (captchaTriggerTag !== null && captchaTriggerTag.tagName == "META") {
        var message = { data: captchaTriggerTag };
        return message;
    }
}

// Start from the content script to avoid race conditions - we know the DOM
// will be rendered because we specified run_at "document_end" in the manifest.
// This puts us after DOM render but before subresources like frames (i.e. the
// recaptcha widget) so we have time to cancel the page load if needed.
// see https://developer.chrome.com/extensions/content_scripts#run_at
chrome.runtime.sendMessage({
    "type": "triggerChallengeBypass",
    "content": getBypassTags(),
}, function(response) {
    if (!response && chrome.runtime.lastError) {
        console.error("[captcha_bypass]: " + chrome.runtime.lastError.message);
    }
});
