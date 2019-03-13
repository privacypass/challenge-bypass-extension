/*
* Config file for handling DLEQ proofs from edge
*
* @author: Alex Davidson
*/
/* exported DevCommitmentConfig */
/* exported CHL_BYPASS_SUPPORT */
/* exported CHL_BYPASS_RESPONSE */
/* exported ACTIVE_CONFIG */
/* exported PPConfigs */

const CHL_BYPASS_SUPPORT = "cf-chl-bypass"; // header from server to indicate that Privacy Pass is supported
const CHL_BYPASS_RESPONSE = "cf-chl-bypass-resp"; // response header from server, e.g. with erorr code

function cloneConfig(config) {
    return JSON.parse(JSON.stringify(config));
}

const exampleConfig = {
    "id": 0, // unique integer identifying each individual config
    "dev": true, // sets whether the configuration should only be used in development
    "sign": true, // sets whether tokens should be sent for signing
    "redeem": true, // sets whether tokens should be sent for redemption
    "max-spends": 3, // for each host header, sets the max number of tokens that will be spent
    "max-tokens": 10, // max number of tokens held by the extension
    "var-reset": true, // whether variables should be reset after time limit expires
    "var-reset-ms": 100, // variable reset time limit
    "commitments": "example", // public key commitments for verifying DLEQ proofs (dev/prod) in curve P256
    "spending-restrictions": {
        "status-code": [200,], // array of status codes that should trigger token redemption (e.g. 403 for CF)
        "max-redirects": "3", // when page redirects occur, sets the max number of redirects that tokens will be spent on
        "new-tabs": ["about:privatebrowsing", "chrome://", "about:blank",], // urls that should not trigger page reloads/redemptions (these should probably be standard)
        "bad-navigation": ["auto_subframe",], // navigation types that should not trigger page reloads/redemptions (see: https://developer.mozilla.org/en-US/Add-ons/WebExtensions/API/webNavigation/TransitionType)
        "bad-transition": ["server_redirect",], // transition types that should not trigger page reloads/redemptions (see: https://developer.mozilla.org/en-US/Add-ons/WebExtensions/API/webNavigation/TransitionType)
        "valid-redirects": ["https://", "https://www.", "http://www.",], // valid redirects that should trigger token redemptions
        "valid-transitions": ["link", "typed", "auto_bookmark", "reload",], // transition types that fine for triggering redemptions (see: https://developer.mozilla.org/en-US/Add-ons/WebExtensions/API/webNavigation/TransitionType)
    }, // These spending restrictions are examples that apply in the CF case
    "spend-action": {
        "urls": ["<all_urls>"], // urls that listeners act on
        "redeem-method": "", // what method to use to perform redemption, currently we support "reload" for CF.
        "header-name": "challenge-bypass-token", // name of header for sending redemption token
        "header-host-name": "challenge-bypass-host", // needed for no-reload method
        "header-path-name": "challenge-bypass-path", // needed for no-reload method
    },
    "issue-action": {
        "urls": ["<all_urls>"],
        "sign-reload": true, // whether pages should be reloaded after signing tokens (e.g. to immediately redeem a token)
        "sign-resp-format": "string", // formatting of response to sign request (string or json)
        "tokens-per-request": 5, // number of tokens sent for each signing request (e.g. 30 for CF)
    },
    "cookies": {
        "check-cookies": true, // whether cookies should be checked before spending
        "clearance-cookie": "", // name of clearance cookies for checking (cookies that are optionally acquired after redemption occurs)
    },
    "captcha-domain": "", // optional domain for acquiring tokens
    "error-codes": {
        "verify-error": "5", // error code sent by server for verification error
        "connection-error": "6", // error code sent by server for connection error
    }, // generic error codes (can add more)
    "h2c-params": { // parameters for establishing which hash-to-curve setting the client wants to use
        "curve": "p256", // elliptic curve that generated tokens should be mapped to
        "hash": "sha256", // hash function for mapping bytes to base-field of elliptic curve
        "method": "increment", // specifies which hash-to-curve method we should use; "increment" = hash-and-increment (the original but deprecated method); "swu" = optimised affine SWU algorithm (new method)
    },
    "send-h2c-params": false, // specifies whether to send the additional h2c-params with issue requests
};

// The configuration used by Cloudflare
let cfConfig = cloneConfig(exampleConfig);
cfConfig.id = 1;
cfConfig.dev = false;
cfConfig["max-tokens"] = 300;
cfConfig["var-reset-ms"] = 2000;
cfConfig.commitments = "CF";
cfConfig["spending-restrictions"]["status-code"] = [403,];
cfConfig["spend-action"]["redeem-method"] = "reload";
cfConfig["issue-action"]["tokens-per-request"] = 30;
cfConfig.cookies["clearance-cookie"] = "cf_clearance";
cfConfig["captcha-domain"] = "captcha.website";
cfConfig["send-h2c-params"] = true;

// The configuration used by hcaptcha
// let hcConfig = lodash.cloneDeep(cfConfig);
let hcConfig = cloneConfig(cfConfig);
hcConfig.id = 2;
hcConfig.commitments = "HC"
hcConfig["spending-restrictions"]["status-code"] = [200,];
hcConfig["spend-action"]["redeem-method"] = "no-reload";
hcConfig["spend-action"]["urls"] = ["https://*.hcaptcha.com/getcaptcha", "https://*.hmt.ai/getcaptcha", "http://localhost/getcaptcha"];
hcConfig["issue-action"]["urls"] = ["https://*.hcaptcha.com/checkcaptcha/*", "https://*.hmt.ai/checkcaptcha/*", "http://localhost/checkcaptcha/*",];
hcConfig["issue-action"]["sign-reload"] = false;
hcConfig["issue-action"]["sign-response-format"] = "json";
hcConfig.cookies["clearance-cookie"] = "hc_clearance";
hcConfig["captcha-domain"] = "hcaptcha.com";

// Ordering of configs should correspond to value of cf-chl-bypass header
// i.e. the first config should have "id": 1, the second "id":2, etc.
const PPConfigs = [exampleConfig, cfConfig, hcConfig];
// set CF to be active config by default
let ACTIVE_CONFIG = PPConfigs[1];
