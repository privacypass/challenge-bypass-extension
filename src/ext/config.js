/*
* Config file for handling DLEQ proofs from edge
*
* @author: Alex Davidson
*/
/* exported DevCommitmentConfig */
/* exported CHL_BYPASS_SUPPORT */
/* exported CHL_BYPASS_RESPONSE */
/* exported CONFIGURATION_URL */
/* exported PPConfigs */
/* exported processConfigPatches */
/* exported validRedemptionMethods */
/* exported retrieveConfiguration */
/* exported extVersion */

/**
 * Returns the version of the extension that is currently running
 * @return {string} Extension version
 */
function extVersion() {
    return chrome.runtime.getManifest().version;
}

/**
 * Returns the version of the extension as a separated array
 * @return {Array<Number>} Extension version
 */
function extVersionAsArray() {
    return versionStringAsNumbers(extVersion());
}

const CHL_BYPASS_SUPPORT = "cf-chl-bypass"; // header from server to indicate that Privacy Pass is supported
const CHL_BYPASS_RESPONSE = "cf-chl-bypass-resp"; // response header from server, e.g. with erorr code
const validRedemptionMethods = () => ["reload", "no-reload"]; // specifies valid token redemption methods
const CONFIGURATION_URL = "https://raw.githubusercontent.com/privacypass/ec-commitments/master/commitments-p256.json";

// initialise configurations from base settings, and potentially modify
// with patches later
let VALID_CONFIGS = [
    exampleConfig(),
    cfBaseConfig(),
    hcBaseConfig(),
];

let PPConfigs = () => Object.assign([], VALID_CONFIGS);

/**
 * Generates exampleConfig configuration object
 * @return {Object} Example configuration object
 */
function exampleConfig() {
    return {
        "id": 0, // unique integer identifying each individual config
        "name": "example", // string identifier of the configuration
        "long-name": "example", // full name of config
        "dev": true, // sets whether the configuration should only be used in development
        "sign": true, // sets whether tokens should be sent for signing
        "redeem": true, // sets whether tokens should be sent for redemption
        "max-spends": 1, // for each host header, sets the max number of tokens that will be spent, undefined for unlimited
        "max-tokens": 10, // max number of tokens held by the extension
        "var-reset": true, // whether variables should be reset after time limit expires
        "var-reset-ms": 100, // variable reset time limit
        "comm-vk":
            "-----BEGIN PUBLIC KEY-----\n" +
            "(PEM)\n" +
            "-----END PUBLIC KEY-----", // a PEM-encoded public key for ecdsa P-256.
        "commitments": { // an optional set of commitments that are specified inside the extension
            "1.0": {
                "G": "",
                "H": "",
            },
        },
        "spending-restrictions": {
            "status-code": [200], // array of status codes that should trigger token redemption (e.g. 403 for CF)
            "max-redirects": 2, // when page redirects occur, sets the max number of redirects that tokens will be spent on
            "new-tabs": ["about:privatebrowsing", "chrome://", "about:blank"], // urls that should not trigger page reloads/redemptions (these should probably be standard)
            "bad-navigation": ["auto_subframe"], // navigation types that should not trigger page reloads/redemptions (see: https://developer.mozilla.org/en-US/Add-ons/WebExtensions/API/webNavigation/TransitionType)
            "bad-transition": ["server_redirect"], // transition types that should not trigger page reloads/redemptions (see: https://developer.mozilla.org/en-US/Add-ons/WebExtensions/API/webNavigation/TransitionType)
            "valid-redirects": ["https://", "https://www.", "http://www."], // valid redirects that should trigger token redemptions
            "valid-transitions": ["link", "typed", "auto_bookmark", "reload"], // transition types that fine for triggering redemptions (see: https://developer.mozilla.org/en-US/Add-ons/WebExtensions/API/webNavigation/TransitionType)
        }, // These spending restrictions are examples that apply in the CF case
        "spend-action": {
            "urls": ["<all_urls>"], // urls that listeners act on
            "redeem-method": "", // what method to use to perform redemption, currently we support "reload" for CF and "no-reload" for HC.
            "header-name": "challenge-bypass-token", // name of header for sending redemption token
            "header-host-name": "challenge-bypass-host", // needed for no-reload method
            "header-path-name": "challenge-bypass-path", // needed for no-reload method
            "empty-resp-headers": [], // if a HTTP response returns with no headers, specify what action to take; default is no action, also support "direct-request"
        },
        "issue-action": {
            "urls": ["<all_urls>"],
            "sign-reload": true, // whether pages should be reloaded after signing tokens (e.g. to immediately redeem a token)
            "sign-resp-format": "string", // formatting of response to sign request (string or json)
            "tokens-per-request": 5, // number of tokens sent for each signing request (e.g. 30 for CF)
            "request-identifiers": { // parameters used to identify requests that issuance data should be included into
                "query-param": "", // request identifier in query params of URL
                "body-param": [""], // request identifier array for checking of HTTP request body and adding to request
                "post-processed": "", // identifier for requests that have already been processed by WebRequest API
            },
        },
        "cookies": {
            "check-cookies": true, // whether cookies should be checked before spending
            "clearance-cookie": "", // name of clearance cookies for checking (cookies that are optionally acquired after redemption occurs)
        },
        "captcha-domain": "", // optional domain for acquiring tokens
        "get-more-passes-url": "", // optional url that the Get More Passes menu item will point, must be valid URL with protocol
        "opt-endpoints": {}, // optional endpoints for integration-specific operations
        "error-codes": {
            "connection-error": "5", // error code sent by server for connection error
            "verify-error": "6", // error code sent by server for verification error
            "bad-request-error": "7", // error code sent by server for signalling that a bad request was made
            "unknown-error": "8", // error code sent by server in case of an unknown error occurring
        }, // generic error codes (can add more)
        "h2c-params": {// parameters for establishing which hash-to-curve setting the client wants to use
            "curve": "p256", // elliptic curve that generated tokens should be mapped to
            "hash": "sha256", // hash function for mapping bytes to base-field of elliptic curve
            "method": "increment", // specifies which hash-to-curve method we should use; "increment" = hash-and-increment (the original but deprecated method); "swu" = optimised affine SWU algorithm (new method)
        },
        "send-h2c-params": false, // specifies whether to send the additional h2c-params with issue requests
    };
}

/**
* Returns the base configuration (without patches) used to integrated
* with Cloudflare
* @return {Object} base JSON configuration
 */
function cfBaseConfig() {
    const cfDomain = "captcha.website";
    const cfConfig = exampleConfig();
    cfConfig.id = 1;
    cfConfig.dev = false;
    cfConfig.name = "CF";
    cfConfig["long-name"] = "Cloudflare";
    cfConfig["max-tokens"] = 300;
    cfConfig["max-spends"] = 2;
    cfConfig["var-reset-ms"] = 2000;
    cfConfig["comm-vk"] =
        "-----BEGIN PUBLIC KEY-----\n" +
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExf0AftemLr0YSz5odoj3eJv6SkOF\n" +
        "VcH7NNb2xwdEz6Pxm44tvovEl/E+si8hdIDVg1Ys+cbaWwP0jYJW3ygv+Q==\n" +
        "-----END PUBLIC KEY-----";
    cfConfig["spending-restrictions"]["status-code"] = [403];
    cfConfig["spend-action"]["redeem-method"] = "reload";
    cfConfig["issue-action"]["tokens-per-request"] = 30;
    cfConfig["issue-action"]["request-identifiers"]["query-param"] = "__cf_chl_captcha_tk__";
    cfConfig["issue-action"]["request-identifiers"]["body-param"] = ["g-recaptcha-response", "h-captcha-response", "cf_captcha_kind"];
    cfConfig["issue-action"]["request-identifiers"]["post-processed"] = "captcha-bypass";
    cfConfig.cookies["clearance-cookie"] = "cf_clearance";
    cfConfig["captcha-domain"] = cfDomain;
    cfConfig["get-more-passes-url"] = `https://${cfDomain}`;
    cfConfig["send-h2c-params"] = true;
    cfConfig["opt-endpoints"].challenge = "/cdn-cgi/challenge";
    cfConfig["spend-action"]["empty-resp-headers"] = ["direct-request"];
    // old version 1.0 commitments for backwards compatibility
    cfConfig["commitments"]["1.0"]["G"] = "BOidEuO9HSJsMZYE/Pfc5D+0ELn0bqhjEef2O0u+KAw3fPMHHXtVlEBvYjE5I/ONf9SyTFSkH3mLNHkS06Du6hQ=";
    cfConfig["commitments"]["1.0"]["H"] = "BHOPNAWXRi4r/NEptOiLOp8MSwcX0vHrVDRXv16Jnowc1eXXo5xFFKIOI6mUp8k9/eca5VY07dBhAe8QfR/FSRY=";
    return cfConfig;
}

/**
* Returns the base configuration (without patches) used to integrated
* with hCaptcha
* @return {Object} base JSON configuration
 */
function hcBaseConfig() {
    const hcConfig = exampleConfig();
    hcConfig.id = 2;
    hcConfig.dev = false;
    hcConfig.name = "HC";
    hcConfig["long-name"] = "hCaptcha";
    hcConfig["max-spends"] = undefined;
    hcConfig["max-tokens"] = 300;
    hcConfig["var-reset-ms"] = 2000;
    hcConfig["comm-vk"] =
        "-----BEGIN PUBLIC KEY-----\n" +
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4OifvSTxGcy3T/yac6LVugArFb89\n" +
        "wvqGivp0/54wgeyWkvUZiUdlbIQF7BuGeO9C4sx4nHkpAgRfvd8jdBGz9g==\n" +
        "-----END PUBLIC KEY-----";
    hcConfig["spending-restrictions"]["status-code"] = [200];
    hcConfig["spend-action"]["redeem-method"] = "no-reload";
    hcConfig["spend-action"]["urls"] = ["https://*.hcaptcha.com/getcaptcha", "https://*.hmt.ai/getcaptcha", "http://127.0.0.1/getcaptcha"];
    hcConfig["issue-action"]["urls"] = ["https://*.hcaptcha.com/checkcaptcha/*", "https://*.hmt.ai/checkcaptcha/*", "http://127.0.0.1/checkcaptcha/*"];
    hcConfig["issue-action"]["sign-reload"] = false;
    hcConfig["issue-action"]["sign-resp-format"] = "json";
    hcConfig.cookies["clearance-cookie"] = "hc_clearance";
    hcConfig["captcha-domain"] = null;
    hcConfig["get-more-passes-url"] = "https://www.hcaptcha.com/privacy-pass";
    hcConfig["send-h2c-params"] = true;
    hcConfig["commitments"] = {
        "1.0": {
            "G": "BMKCnVDWUEBNiyAR+p0YT7QvtrOfpHAeatzipwo6x98Ch1q3ZoCkNdiQvUTEwDzG20RplG/IE2NCpsXZGLsUdvA=",
            "H": "BNJIpofS4RhbUfnkblr5yvuymaEfV+ViKshsoN9DkCRaHBB+TiKUnicc14gBswpLfBaKXuC102Cvwzq3YIN8dVo=",
        },
    };
    return hcConfig;
}

// Top-level configuration keys that can be patched externally
const PATCHABLE_KEYS = [
    "max-spends",
    "max-tokens",
    "var-reset",
    "var-reset-ms",
    "spending-restrictions",
    "spend-action",
    "issue-action",
    "cookies",
    "captcha-domain",
    "get-more-passes-url",
    "opt-endpoints",
    "error-codes",
    "h2c-params",
    "send-h2c-params",
];

/**
 * Processes valid patches to the available configurations. This
 * function is run in init.js
 * @param {Number} cfgId ID of the configuration being used
 * @return {XMLHttpRequest} the XHR used to retrieve any patches
 */
function processConfigPatches(cfgId) {
    const callback = (retrieved) => {
        const patches = retrieved["patches"];
        if (!patches) {
            return;
        } else if (!(patches instanceof Array)) {
            console.warn("[privacy-pass]: Patches not specified in correct format");
            return;
        }

        // process patches if they verify correctly
        patches.forEach((patch) => {
            if (!patch || typeof patch !== "object") {
                console.warn("[privacy-pass]: Patch not specified in correct format");
                return;
            }

            // try to verify patch
            if (!applicablePatch(patch["min-version"])) {
                console.warn("[privacy-pass]: Patch version criteria not met. Not applying following: " + JSON.stringify(patch, null, 4));
                return;
            }

            // check if signature is valid
            if (patch["sig"] === undefined) {
                console.warn("[privacy-pass]: Signature field for patch is missing not processing them");
                return;
            }

            // error is thrown if bad verification, just ignore if it
            // fails
            try {
                verifyConfiguration(cfgId, patch);
            } catch (e) {
                console.warn("[privacy-pass]: Not processing patch as unable to verify signature");
                return;
            }

            const config = getConfigForId(cfgId);
            const patchConfig = patch["config"];
            Object.keys(patchConfig).forEach((key) => {
                if (!PATCHABLE_KEYS.includes(key)) {
                    // do not process patch for non-patchable fields
                    console.warn(`[privacy-pass]: Patches for ${key} are not permitted`);
                    return;
                }
                const patchValue = patchConfig[key];
                let current = config[key];
                switch (typeof current) {
                    case "object":
                        if (current !== null) {
                            Object.assign(current, patchValue);
                        } else {
                            current = patchValue;
                        }
                        break;
                    default:
                        current = patchValue;
                        break;
                }
                config[key] = current;
            });

            // modify valid configs
            VALID_CONFIGS[cfgId] = config;
        });
    };
    const xhr = retrieveConfiguration(cfgId, callback);
    xhr.send();
    return xhr;
}

/**
 * Creates an XMLHttpRequest object to retrieve the active JSON
 * configuration for the given provider
 * @param {Number} cfgId ID of configuration to retrieve
 * @param {Function} callback function to execute after configuration is
 * retrieved
 * @return {XMLHttpRequest}
 */
function retrieveConfiguration(cfgId, callback) {
    if (!callback) {
        throw new Error("[privacy-pass]: Invalid configuration retrieval callback specified");
    }
    const xhr = new XMLHttpRequest();
    xhr.open("GET", CONFIGURATION_URL, true);
    xhr.setRequestHeader("Accept", "application/json");
    xhr.onreadystatechange = function() {
        if (xhrGoodStatus(xhr.status) && xhrDone(xhr.readyState)) {
            const provider = getConfigName(cfgId);
            const resp = JSON.parse(xhr.responseText);
            const config = resp[provider];
            callback(config);
        }
    };
    return xhr;
}

/**
 * Returns the version number (string of form x.y.z) as an array of
 * three numbers to make comparisons easier
 * @param {string} version
 * @return {Array<Number>}
 */
function versionStringAsNumbers(version) {
    return version.split(".").map((s) => parseInt(s));
}

/**
 * Compares the version of a patch with that of the extension and
 * returns true if the min patch version is satisfied.
 * @param {string} pv Patch version to compare with extension version
 * @return {boolean}
 */
function applicablePatch(pv) {
    if (!pv) {
        console.warn("[privacy-pass]: No version specified in patch.");
        return false;
    }

    let arr;
    try {
        arr = versionStringAsNumbers(pv);
    } catch (e) {
        console.warn("[privacy-pass]: Failed to parse patch version.");
        return false;
    }

    // compare version strings
    const extVersion = extVersionAsArray();
    if (extVersion[0] < arr[0]) {
        return false;
    } else if (extVersion[0] === arr[0]) {
        if (extVersion[1] < arr[1]) {
            return false;
        } else if (extVersion[1] === arr[1]) {
            if (extVersion[2] < arr[2]) {
                return false;
            } else if (
                // typically versions consist of 3 numbers, but Chrome
                // supports up to 4 so we should check for this. If the
                // lengths differ and they are equal up to this point
                // then just return true.
                extVersion.length === 4
                && arr.length === 4
                && extVersion[2] === arr[2]
            ) {
                if (extVersion[3] < arr[3]) {
                    return false;
                }
            }
        }
    }
    return true;
}
