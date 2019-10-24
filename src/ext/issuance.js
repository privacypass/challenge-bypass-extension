/**
 * Functions for handling issue requests and server responses
 *
 * @author: Alex Davidson
 */

/* exported signReqCF */
/* exported signReqHC */
/* exported sendXhrSignReq */
/* export CACHED_COMMITMENTS_STRING */

/**
 * Checks readystate == 4, this implies a successful response
 * @param {Number} readystate
 * @return {boolean}
 */
function xhrDone(readystate) {
    return readystate === 4;
}

/**
 * Checks a good HTTP response
 * @param {Number} status
 * @return {boolean}
 */
function xhrGoodStatus(status) {
    return status === 200;
}

const CACHED_COMMITMENTS_STRING = "cached-commitments";
const COMMITMENT_URL = "https://raw.githubusercontent.com/privacypass/ec-commitments/master/commitments-p256.json";

/**
 * Constructs an issue request for sending tokens in Cloudflare-friendly format
 * @param {URL} url URL object for request
 * @return {XMLHttpRequest} XHR info for asynchronous token issuance
 */
function signReqCF(url) {
    const reqUrl = url.href;
    const manualChallenge = reqUrl.includes("manual_challenge");
    const captchaResp = reqUrl.includes("g-recaptcha-response");
    const alreadyProcessed = reqUrl.includes("&captcha-bypass=true");

    // We're only interested in CAPTCHA solution requests that we haven't already altered.
    if ((captchaResp && alreadyProcessed) || (!manualChallenge && !captchaResp) || sentTokens[reqUrl]) {
        return null;
    }
    sentTokens[reqUrl] = true;

    // Generate tokens and create a JSON request for signing
    const tokens = GenerateNewTokens(tokensPerRequest());
    const request = BuildIssueRequest(tokens);

    // Tag the URL of the new request to prevent an infinite loop (see above)
    const newUrl = markSignUrl(reqUrl);
    // Construct info for xhr signing request
    const xhrInfo = {newUrl: newUrl, requestBody: "blinded-tokens=" + request, tokens: tokens};

    return xhrInfo;
}

/**
 * hCaptcha issuance request
 * @param {URL} url
 * @param {Object} details
 * @return {XMLHttpRequest} XHR info for asynchronous token issuance
 */
function signReqHC(url, details) {
    const reqUrl = url.href;
    const isIssuerUrl = issueActionUrls()
        .map((issuerUrl) => patternToRegExp(issuerUrl))
        .some((re) => reqUrl.match(re));

    if (!isIssuerUrl || details.method === "OPTIONS") {
        return null;
    }

    sentTokens[reqUrl] = true;
    // Generate tokens and create a JSON request for signing
    const tokens = GenerateNewTokens(tokensPerRequest());
    const request = BuildIssueRequest(tokens);
    // Construct info for xhr signing request, set `cancel: false` in order to prevent canceling the original captcha solve request.
    const xhrInfo = {newUrl: reqUrl, requestBody: `blinded-tokens=${request}&captcha-bypass=true`, tokens: tokens, cancel: false};
    return xhrInfo;
}

/**
 * Sends an XHR request containing a BlindTokenRequest for signing a set of tokens
 * @param {Object} xhrInfo XHR info for asynchronous issuance request
 * @param {URL} url URL object
 * @param {Number} tabId Tab ID for the current request
 * @return {XMLHttpRequest}
 */
function sendXhrSignReq(xhrInfo, url, tabId) {
    const newUrl = xhrInfo["newUrl"];
    const requestBody = xhrInfo["requestBody"];
    const tokens = xhrInfo["tokens"];
    const xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
        // When we receive a response...
        if (xhrGoodStatus(xhr.status) && xhrDone(xhr.readyState)
            && countStoredTokens() < (maxTokens() - tokensPerRequest())) {
            const respData = xhr.responseText;
            // Validates the response and stores the signed points for redemptions
            validateResponse(url, tabId, respData, tokens);
        } else if (countStoredTokens() >= (maxTokens() - tokensPerRequest())) {
            throw new Error("[privacy-pass]: Cannot receive new tokens due to upper bound.");
        }
    };
    xhr.open("POST", newUrl, true);
    xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
    xhr.setRequestHeader(CHL_BYPASS_SUPPORT, getConfigId());
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
 * @param {string} data An issue response takes the form "signatures=[b64 blob]"
 * where the blob is an array of b64-encoded curve points
 * @param {Array<Object>} tokens stored tokens corresponding to signed points
 */
function validateResponse(url, tabId, data, tokens) {
    let signaturesJSON;
    switch (signResponseFMT()) {
        case "string":
            signaturesJSON = parseSigString(data);
            break;
        case "json":
            signaturesJSON = parseSigJson(data);
            break;
        default:
            throw new Error("[privacy-pass]: invalid signature response format " + signResponseFMT());
    }

    if (signaturesJSON == null) {
        throw new Error("[privacy-pass]: signature response invalid or in unexpected format, got response: " + data);
    }

    // creates issueResp object from JSON
    // includes the fields:
    // - signatures
    // - proof
    // - version (optional)
    // - prng (optional)
    const issueResp = parseIssueResp(JSON.parse(signaturesJSON));
    if (!issueResp.signatures) {
        throw new Error("[privacy-pass]: No signed tokens provided");
    } else if (!issueResp.proof) {
        throw new Error("[privacy-pass]: No batch proof provided");
    }

    // Validate the received information and store the tokens
    validateAndStoreTokens(url, tabId, tokens, issueResp);
}

/**
 * Parses the server (JSON) response for the issuance data
 * @param {string} data stringified server response
 * @return {string}
 */
function parseSigJson(data) {
    const json = JSON.parse(data);
    // Data should always be b64 encoded
    return atob(json["signatures"]);
}

/**
 * Parses the server (string) response for the issuance data
 * @param {string} data stringified server response
 * @return {string}
 */
function parseSigString(data) {
    const split = data.split("signatures=", 2);
    if (split.length !== 2) {
        return null;
    }
    // Data should always be b64 encoded
    return atob(split[1]);
}

/**
 * Retrieves the batchProof and signatures, depending on the type of object received
 * @param {Object} issueResp object containing signed points, DLEQ proof and
 * optional commitment version
 * @return {Object} Formatted object for inputs
 */
function parseIssueResp(issueResp) {
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
    const prng = issueResp.prng || "shake";
    return {signatures: signatures, proof: batchProof, version: version, prng: prng};
}

/**
 * Creates an issuance request for the current set of stored tokens. The format
 * is base64(json(BlindTokenRequest)), where BlindTokenRequest is a JSON struct
 * with "type":"Issue" and "contents":[ base64.encode(compressed_curve_points) ]
 *
 * @param {Array<Object>} tokens contains curve points for server signing
 * @return {string} base64-encoded issuance request
 */
function BuildIssueRequest(tokens) {
    const contents = [];
    for (let i = 0; i < tokens.length; i++) {
        const encodedPoint = sec1EncodeToBase64(tokens[i].point, true);
        contents.push(encodedPoint);
    }
    return btoa(JSON.stringify({type: "Issue", contents: contents}));
}

/**
 * Retrieves cached commitments or sends an XHR for acquiring them, and verifies
 * server response (returns the xhr object for testing purposes)
 * @param {URL} url URL object for the original request
 * @param {Number} tabId Tab ID where the request took place
 * @param {Array<Object>} tokens Client-generated token objects
 * @param {Object} issueResp Contains the parameters sent back by the server,
 * including signed tokens, batched DLEQ proof and optional others
 * @return {XMLHttpRequest} commitment XHR object
 */
function validateAndStoreTokens(url, tabId, tokens, issueResp) {
    const version = checkVersion(issueResp.version);
    let commitments;
    // retrieve CF 1.0 commitments from source code or cache otherwise
    if (version === "1.0") {
        commitments = storedCommitments()[version];
    } else {
        commitments = getCachedCommitments(version);
    }

    // If cached commitments exist then attempt to verify proof
    if (commitments) {
        if (!commitments.G || !commitments.H) {
            console.warn("[privacy-pass]: stored commitments are corrupted: " + commitments + ", version: " + version + ", will retrieve via XHR.");
        } else {
            verifyProofAndStoreTokens(url, tabId, tokens, issueResp, commitments);
            return;
        }
    }
    const cXhr = createVerificationXHR(url, tabId, tokens, issueResp, version);
    cXhr.send();
    return cXhr;
}

/**
 * Asynchronously retrieves the commitments from the GH beacon and verifies
 * server-sent information
 * @param {URL} url URL object for the original request
 * @param {Number} tabId Tab ID where the request took place
 * @param {Object} tokens Client-generated token objects
 * @param {Object} issueResp Contains the parameters sent back by the server
 * @param {String} version commitments version
 * @return {XMLHttpRequest} XHR object for verifying server response
 */
function createVerificationXHR(url, tabId, tokens, issueResp, version) {
    const xhr = new XMLHttpRequest();
    xhr.open("GET", COMMITMENT_URL, true);
    xhr.setRequestHeader("Content-Type", "application/json");
    xhr.onreadystatechange = function() {
        if (xhrGoodStatus(xhr.status) && xhrDone(xhr.readyState)) {
            const commitments = retrieveCommitments(xhr, version);
            if (!commitments.G || !commitments.H) {
                throw new Error("[privacy-pass]: Retrieved commitments are incorrectly specified: " + commitments + ", version: " + version);
            }
            cacheCommitments(version, commitments.G, commitments.H);
            verifyProofAndStoreTokens(url, tabId, tokens, issueResp, commitments);
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
 * @param {Object} issueResp Contains the parameters sent back by the server
 * @param {String} commitments base64-encoded curve points
 */
function verifyProofAndStoreTokens(url, tabId, tokens, issueResp, commitments) {
    const ret = getCurvePoints(issueResp.signatures);

    // Verify the DLEQ batch proof before handing back the usable points
    if (!verifyProof(issueResp.proof, tokens, ret, commitments, issueResp.prng)) {
        throw new Error("[privacy-pass]: Unable to verify DLEQ proof.");
    }

    // Store the tokens for future usage (we don't store compressed for now)
    storeNewTokens(tokens, ret.points);

    // Reload the page for the originally intended url
    if (reloadOnSign() && !url.href.includes(chlCaptchaDomain())) {
        const captchaPath = url.pathname;
        const pathIndex = url.href.indexOf(captchaPath);
        const reloadUrl = url.href.substring(0, pathIndex + 1);
        setSpendFlag(url.host, true);
        updateBrowserTab(tabId, reloadUrl);
    }
}

/**
 * Retrieves the public commitments that are used for validating the DLEQ proof
 * @param {XMLHttpRequest} xhr XHR for retrieving the active EC commitments
 * @param {string} version commitment version string
 * @return {Object} Object containing commitment data
 */
function retrieveCommitments(xhr, version) {
    const resp = JSON.parse(xhr.responseText);
    const comms = resp[getConfigName()];

    const cmt = comms[version];
    if (typeof cmt === "undefined") {
        throw new Error("[privacy-pass]: Retrieved version: " + version + " not available.");
    }
    const expDate = new Date(cmt.expiry);
    if (Date.now() >= expDate) {
        throw new Error("[privacy-pass]: Commitments expired in " + expDate);
    }
    if (cmt.sig === undefined) {
        throw new Error("[privacy-pass]: Signature field is missing.");
    }
    verifyCommitments(cmt, getCommitmentsKey());
    return {G: cmt.G, H: cmt.H};
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
    const cachable = {G: G, H: H};
    cache[version] = cachable;
    set(CACHED_COMMITMENTS_STRING, JSON.stringify(cache));
}

/**
 * Recovers all commitments pairs from the cache
 * @return {Object}
 */
function getAllCached() {
    const cache = get(CACHED_COMMITMENTS_STRING);
    if (!cache) {
        return;
    }
    return JSON.parse(cache);
}

/**
 * Gets the cached commitments for a particular version string
 * @param {string} version the version of commitments as specified by the server
 * @return {Object} cache object for specific version
 */
function getCachedCommitments(version) {
    const cached = getAllCached();
    if (!cached) {
        return;
    }
    return cached[version];
}

/**
 * Sets the version to be "1.0" if it is undefined
 * @param {string} version version string (possibly null) specified by server
 * @return {string} the version string or "1.0" if it is null
 */
function checkVersion(version) {
    if (dev()) {
        return "dev";
    }
    return version || "1.0";
}

/**
 * Mark the url so that a sign doesn't occur again.
 * @param {string} url URL href string for modification
 * @return {string} marked URL string
 */
function markSignUrl(url) {
    return url + "&captcha-bypass=true";
}
