/**
 * Functions for handling issue requests and server responses
 *
 * @author: Alex Davidson
 */

/* exported signReqCF */
/* exported signReqHC */
/* exported sendXhrSignReq */
/* export CACHED_COMMITMENTS_STRING */

function xhrDone(readystate) {
    return readystate === 4;
} // readystate == 4 implies that the response has completed successfully
function xhrGoodStatus(status) {
    return status === 200;
} // we used to check < 300 but we should be more specific
const CACHED_COMMITMENTS_STRING = "cached-commitments";
const COMMITMENT_URL = "https://raw.githubusercontent.com/privacypass/ec-commitments/master/commitments-p256.json";

/**
 * Constructs an issue request for sending tokens in Cloudflare-friendly format
 * @param {URL} url URL object for request
 */
function signReqCF(url) {
    let reqUrl = url.href;
    const manualChallenge = reqUrl.includes("manual_challenge");
    const captchaResp = reqUrl.includes("g-recaptcha-response");
    const alreadyProcessed = reqUrl.includes("&captcha-bypass=true");

    // We're only interested in CAPTCHA solution requests that we haven't already altered.
    if ((captchaResp && alreadyProcessed) || (!manualChallenge && !captchaResp) || sentTokens[reqUrl]) {
        return null;
    }
    sentTokens[reqUrl] = true;

    // Generate tokens and create a JSON request for signing
    let tokens = GenerateNewTokens(TOKENS_PER_REQUEST);
    const request = BuildIssueRequest(tokens);

    // Tag the URL of the new request to prevent an infinite loop (see above)
    let newUrl = markSignUrl(reqUrl);
    // Construct info for xhr signing request
    let xhrInfo = {newUrl: newUrl, requestBody: "blinded-tokens=" + request, tokens: tokens};

    return xhrInfo;
}

function signReqHC(url) {
    let reqUrl = url.href;
    const isIssuerUrl = ACTIVE_CONFIG["issue-action"]["urls"]
        .map(issuerUrl => patternToRegExp(issuerUrl))
        .filter(re => reqUrl.match(re)).length > 0;

    if (!isIssuerUrl) {
        return null;
    }

    sentTokens[reqUrl] = true;
    // Generate tokens and create a JSON request for signing
    let tokens = GenerateNewTokens(TOKENS_PER_REQUEST);
    const request = BuildIssueRequest(tokens);
    // Construct info for xhr signing request
    let xhrInfo = {newUrl: reqUrl, requestBody: `blinded-tokens=${request}&captcha-bypass=true`, tokens: tokens};
    return xhrInfo;
}

/**
 * Sends an XHR request containing a BlindTokenRequest for signing a set of tokens
 * @param {object} xhrInfo Object containing information for the XHR that will
 * be returned.
 * @param {URL} url URL object
 * @param {int} tabId Tab ID for the current request
 * @returns {XMLHttpRequest}
 */
function sendXhrSignReq(xhrInfo, url, tabId) {
    let newUrl = xhrInfo["newUrl"];
    let requestBody = xhrInfo["requestBody"];
    let tokens = xhrInfo["tokens"];
    let xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function () {
        // When we receive a response...
        if (xhrGoodStatus(xhr.status) && xhrDone(xhr.readyState)
            && countStoredTokens() < (MAX_TOKENS - TOKENS_PER_REQUEST)) {
            const resp_data = xhr.responseText;
            // Validates the response and stores the signed points for redemptions
            validateResponse(url, tabId, resp_data, tokens);
        } else if (countStoredTokens() >= (MAX_TOKENS - TOKENS_PER_REQUEST)) {
            throw new Error("[privacy-pass]: Cannot receive new tokens due to upper bound.");
        }
    };
    xhr.open("POST", newUrl, true);
    xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
    xhr.setRequestHeader(CHL_BYPASS_SUPPORT, CONFIG_ID);
    // We seem to get back some odd mime types that cause problems...
    xhr.overrideMimeType("text/plain");
    xhr.send(requestBody);
    return xhr;
}

/**
 * Validates the server response and stores the new signed points for future
 * redemptions
 * @param {URL} url URL object
 * @param {int} tabId Tab ID for the current request
 * @param data An issue response takes the form "signatures=[b64 blob]"
 *             where the blob is an array of b64-encoded curve points
 * @param tokens client-generated tokens that correspond to the signed points
 */
function validateResponse(url, tabId, data, tokens) {
    let signaturesJSON;
    switch (SIGN_RESPONSE_FMT) {
    case "string":
        signaturesJSON = parseSigString(data);
        break;
    case "json":
        signaturesJSON = parseSigJson(data);
        break;
    default:
        throw new Error("[privacy-pass]: invalid signature response format " + SIGN_RESPONSE_FMT);
    }

    if (signaturesJSON == null) {
        throw new Error("[privacy-pass]: signature response invalid or in unexpected format, got response: " + data);
    }
    // parses into JSON
    const issueResp = JSON.parse(signaturesJSON);
    let out = parsePointsAndProof(issueResp);
    if (!out.signatures) {
        throw new Error("[privacy-pass]: No signed tokens provided");
    } else if (!out.proof) {
        throw new Error("[privacy-pass]: No batch proof provided");
    }

    // Validate the received information and store the tokens
    validateAndStoreTokens(url, tabId, tokens, out.signatures, out.proof, out.version);
}

/**
 * Parses the server (JSON) response for the issuance data
 * @param {string} data stringified server response
 */
function parseSigJson(data) {
    let json = JSON.parse(data);
    // Data should always be b64 encoded
    return atob(json["signatures"]);
}

/**
 * Parses the server (string) response for the issuance data
 * @param {string} data stringified server response
 */
function parseSigString(data) {
    let split = data.split("signatures=", 2);
    if (split.length !== 2) {
        return null;
    }
    // Data should always be b64 encoded
    return atob(split[1]);
}

/**
 * Retrieves the batchProof and signatures, depending on the type of object received
 * @param {JSON/array} issueResp object containing signed points, DLEQ proof and potentially commitment version
 * @return {object} Formatted object for inputs
 */
function parsePointsAndProof(issueResp) {
    let signatures;
    let batchProof;
    let version;
    // If this is not an array then the object is probably JSON.
    if (!issueResp[0]) {
        signatures = issueResp.sigs;
        batchProof = issueResp.proof;
        version = issueResp.version;
    } else {
        batchProof = issueResp[issueResp.length - 1];
        signatures = issueResp.slice(0, issueResp.length - 1);
    }
    return {signatures: signatures, proof: batchProof, version: version};
}

/**
 * Creates an issuance request for the current set of stored tokens. The format
 * is base64(json(BlindTokenRequest)), where BlindTokenRequest is a JSON struct
 * with "type":"Issue" and "contents":[ base64.encode(compressed_curve_points) ]
 *
 * @param {object array} tokens contains curve points to be signed by the server
 */
function BuildIssueRequest(tokens) {
    let contents = [];
    for (var i = 0; i < tokens.length; i++) {
        const encodedPoint = compressPoint(tokens[i].point);
        contents.push(encodedPoint);
    }
    return btoa(JSON.stringify({type: "Issue", contents: contents}));
}

/**
 * Retrieves cached commitments or sends an XHR for acquiring them, and verifies
 * server response (returns the xhr object for testing purposes)
 * @param {URL} url URL object for the original request
 * @param {int} tabId Tab ID where the request took place
 * @param {object array} tokens Client-generated token objects
 * @param {string} signatures base64-encoded curve points
 * @param {object} batchProof batched DLEQ proof object
 * @param {string} version version of commitments to use
 */
function validateAndStoreTokens(url, tabId, tokens, signatures, batchProof, version) {
    let cXhr;
    let commitments = getCachedCommitments(version);
    // If cached commitments exist then attempt to verify proof
    if (commitments) {
        if (!commitments.G || !commitments.H) {
            console.warn("[privacy-pass]: cached commitments are corrupted: " + commitments + ", version: " + version + ", will retrieve via XHR.");
        } else {
            verifyProofAndStoreTokens(url, tabId, tokens, signatures, commitments, batchProof);
            return;
        }
    }
    cXhr = createVerificationXHR(url, tabId, tokens, signatures, batchProof, version);
    cXhr.send();
    return cXhr;
}

/**
 * Asynchronously retrieves the commitments from the GH beacon and verifies
 * server-sent information
 * @param {URL} url URL object for the original request
 * @param {int} tabId Tab ID where the request took place
 * @param {object} tokens Client-generated token objects
 * @param {string} signatures base64-encoded curve points
 * @param {object} batchProof batched DLEQ proof object
 * @param {string} version version of commitments to use
 */
function createVerificationXHR(url, tabId, tokens, signatures, batchProof, version) {
    let xhr = new XMLHttpRequest();
    xhr.open("GET", COMMITMENT_URL, true);
    xhr.setRequestHeader("Content-Type", "application/json");
    xhr.onreadystatechange = function () {
        if (xhrGoodStatus(xhr.status) && xhrDone(xhr.readyState)) {
            const commitments = retrieveCommitments(xhr, version);
            if (!commitments.G || !commitments.H) {
                throw new Error("[privacy-pass]: Retrieved commitments are are incorrectly specified: " + commitments + ", version: " + version);
            }
            cacheCommitments(version, commitments.G, commitments.H);
            verifyProofAndStoreTokens(url, tabId, tokens, signatures, commitments, batchProof);
        }
    };
    return xhr;
}

/**
 * Uses the client-acquired commitments to verify the batched DLEQ from the
 * server. If this passes then the tokens are stored.
 * @param {URL} url URL object for the original request
 * @param {int} tabId Tab ID where the request took place
 * @param {object} tokens Client-generated token objects
 * @param {string} signatures base64-encoded curve points
 * @param {string} commitments base64-encoded curve points
 * @param {object} batchProof batched DLEQ proof object
 */
function verifyProofAndStoreTokens(url, tabId, tokens, signatures, commitments, batchProof) {
    const sigPoints = getCurvePoints(signatures);

    // Verify the DLEQ batch proof before handing back the usable points
    if (!verifyProof(batchProof, tokens, sigPoints, commitments)) {
        throw new Error("[privacy-pass]: Unable to verify DLEQ proof.")
    }

    // Store the tokens for future usage
    storeNewTokens(tokens, sigPoints);

    // Reload the page for the originally intended url
    if (RELOAD_ON_SIGN && !url.href.includes(CHL_CAPTCHA_DOMAIN)) {
        let captchaPath = url.pathname;
        let pathIndex = url.href.indexOf(captchaPath);
        let reloadUrl = url.href.substring(0, pathIndex + 1);
        setSpendFlag(url.host, true);
        updateBrowserTab(tabId, reloadUrl);
    }
}

/**
 * Retrieves the public commitments that are used for validating the DLEQ proof
 * @param {XMLHttpRequest} xhr XHR for retrieving the active EC commitments
 * @param {string} version commitment version string
 */
function retrieveCommitments(xhr, version) {
    let commG;
    let commH;
    const respBody = xhr.responseText;
    let resp = JSON.parse(respBody);
    let comms = resp[COMMITMENTS_KEY];
    version = checkVersion(version);
    if (comms) {
        if (DEV) {
            commG = comms["dev"]["G"];
            commH = comms["dev"]["H"];
        } else {
            commG = comms[version]["G"];
            commH = comms[version]["H"];
        }
    }

    return {G: commG, H: commH};
}

/**
 * Adds the specified commitment pair to the localStorage cache as a JSON string
 * (we have to use JSON.stringify as localStorage only deals in strings)
 * @param {string} version the version of commitments as specified by the server
 * @param {string} G base64-encoded curve point
 * @param {string} H base64-encoded curve point
 */
function cacheCommitments(version, G, H) {
    let cache = getAllCached();
    if (!cache) {
        cache = {};
    }
    let cachable = {G: G, H: H};
    version = checkVersion(version);
    cache[version] = cachable;
    set(CACHED_COMMITMENTS_STRING, JSON.stringify(cache));
}

/**
 * Recovers all commitments pairs from the cache
 */
function getAllCached() {
    let cache = get(CACHED_COMMITMENTS_STRING);
    if (!cache) {
        return;
    }
    return JSON.parse(cache);
}

/**
 * Gets the cached commitments for a particular version string
 * @param {string} version the version of commitments as specified by the server
 */
function getCachedCommitments(version) {
    version = checkVersion(version);
    let cached = getAllCached();
    if (!cached) {
        return;
    }
    return cached[version];
}

/**
 * Sets the version to be "1.0" if it is undefined
 * @param {string} version version string specified by server
 */
function checkVersion(version) {
    return version || "1.0";
}

/**
 * Mark the url so that a sign doesn't occur again.
 * @param {URL} url URL object for modification
 */
function markSignUrl(url) {
    return url + "&captcha-bypass=true";
}