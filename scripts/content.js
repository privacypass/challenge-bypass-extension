// Trigger the token manager if bypass tags are present.
// Returns a map with the certs on success or null if any of the cert tags don't exist.
function getBypassTags() {
    // If there isn't a captcha-bypass meta tag, do nothing.
    var captchaTriggerTag = document.getElementById('captcha-bypass');
    if (captchaTriggerTag !== null && captchaTriggerTag.tagName == "META") {
        var chlCertTag = document.getElementById('chl-cert');
        var encCertTag = document.getElementById('enc-cert');
        if (chlCertTag && encCertTag) {
            var chlCert = chlCertTag.getAttribute('content');
            var encCert = encCertTag.getAttribute('content');
            var message = { data: captchaTriggerTag, sigCert: chlCert, encCert: encCert};
            return message;
        } else {
            console.log("captcha_bypass: cert tags were not present");
            return null;
        }
    }
}

// Start from the content script to avoid race conditions - we know the DOM
// will be rendered because we specified run_at "document_end" in the manifest.
// This puts us after DOM render but before subresources like frames (i.e. the
// recaptcha widget) so we have time to cancel the page load if needed.
// see https://developer.chrome.com/extensions/content_scripts#run_at
console.log("pageload");
chrome.runtime.sendMessage({
    "type": "triggerChallengeBypass",
    "content": getBypassTags(),
}, function(response) {
    if (!response && chrome.runtime.lastError) {
        console.log("captcha_bypass: " + chrome.runtime.lastError.message);
    }
});
