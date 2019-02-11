/**
 * Handles functions that are specific to token generation and storage
 *
 * @author: George Tankersley
 * @author: Alex Davidson
 */

/*global sjcl*/
/* exported CreateBlindToken */
/* exported GenerateNewTokens */
/* exported BuildIssueRequest */
/* exported BuildRedeemHeader */
/* exported storeNewTokens */
/* exported storeTokens */
/* exported getTokenEncoding */
/* exported loadTokens */
/* exported countStoredTokens */
"use strict";


// Creates
// Inputs:
//  none
// Returns:
//  token bytes
//  T sjcl point
//  r blinding factor, sjcl bignum
function CreateBlindToken() {
    let t = newRandomPoint();
    let tok;
    if (t) {
        let bpt = blindPoint(t.point);
        tok = { data: t.data, point: bpt.point, blind: bpt.blind };
    }
    return tok;
}

// returns: array of blind tokens
function GenerateNewTokens(n) {
    let tokens = [];
    for (let i=0; i<n; i++) {
        let tok = CreateBlindToken();
        if (!tok) {
            console.warn("[privacy-pass]: Tried to generate a random point on the curve, but failed.");
            console.warn("[privacy-pass]: Will drop the null point.");
        }
        tokens[i] = tok;
    }
    // remove array entries that are null
    tokens = tokens.filter(function(ele) { return !!ele; });
    return tokens;
}

// Creates an issuance request for the current set of stored tokens. The format
// is base64(json(BlindTokenRequest)) where BlindTokenRequest
// corresponds to the following Go struct:
//
// type BlindTokenRequest struct {
//      Type     ReqType  `json:"type"`
//      Contents [][]byte `json:"contents"`
// }
//
// Note that Go will automatically render and decode []byte as base64 encoded
// strings.
//
// For an issuance request, type will be "Issue" and the contents will be a
// list of base64-encoded marshaled curve points. We can transmit compressed
// curve points here because the service code knows how to decompress them, but
// should remember we use uncompressed points for all key derivations.
function BuildIssueRequest(tokens) {
    let contents = [];
    for (var i = 0; i < tokens.length; i++) {
        const encodedPoint = compressPoint(tokens[i].point);
        contents.push(encodedPoint);
    }
    return btoa(JSON.stringify({ type: "Issue", contents: contents}));
}

// Creates a redemption header for the specified request. The format is
// base64(json(BlindTokenRequest)) where BlindTokenRequest corresponds to the
// following Go struct:
//
// type BlindTokenRequest struct {
//      Type     ReqType  `json:"type"`
//      Contents [][]byte `json:"contents"`
// }
//
// Note that Go will automatically render and decode []byte as base64 encoded
// strings.
//
// For a redemption request, type will be "Redeem" and the contents will be a
// list of [token preimage, HMAC(host, "%s %s" % (method, uri))] where the HMAC
// key is derived from the signed point corresponding to the token preimage.
function BuildRedeemHeader(token, host, path) {
    const sharedPoint = unblindPoint(token.blind, token.point);
    const derivedKey = deriveKey(sharedPoint, token.data);

    // TODO: this could be more efficient, but it's easier to check correctness when everything is bytes
    const hostBits = sjcl.codec.utf8String.toBits(host);
    const hostBytes = sjcl.codec.bytes.fromBits(hostBits);

    const pathBits = sjcl.codec.utf8String.toBits(path);
    const pathBytes = sjcl.codec.bytes.fromBits(pathBits);

    const binding = createRequestBinding(derivedKey, [hostBytes, pathBytes]);

    let contents = [];
    contents.push(token.data);
    contents.push(binding);

    if (SEND_H2C_PARAMS) {
        const h2cString = JSON.stringify(H2C_PARAMS);
        const h2cBits = sjcl.codec.utf8String.toBits(h2cString);
        const h2cBytes = sjcl.codec.bytes.fromBits(h2cBits);
        contents.push(h2cBytes);
    }

    return btoa(JSON.stringify({ type: "Redeem", contents: contents}));
}

/**
 * This is for storing tokens that we've just received from a new issuance response.
 * @param tokens set of tokens to store
 * @param signedPoints signed tokens that have been received from server
 */
function storeNewTokens(tokens, signedPoints) {
    let storableTokens = [];
    for (var i = 0; i < tokens.length; i++) {
        let t = tokens[i];
        storableTokens[i] = getTokenEncoding(t,signedPoints[i]);
    }
    // Append old tokens to the newly received tokens
    if (countStoredTokens() > 0) {
        let oldTokens = loadTokens();
        for (let i=0; i<oldTokens.length; i++) {
            let oldT = oldTokens[i];
            storableTokens.push(getTokenEncoding(oldT,oldT.point));
        }
    }
    const json = JSON.stringify(storableTokens);
    set(STORAGE_KEY_TOKENS, json);
    set(STORAGE_KEY_COUNT, storableTokens.length);

    // Update the count on the actual icon
    updateIcon(storableTokens.length);
}

/**
 * This is for persisting valid tokens after some manipulation, like a spend.
 * @param tokens set of tokens to store
 */
function storeTokens(tokens) {
    let storableTokens = [];
    for (var i = 0; i < tokens.length; i++) {
        let t = tokens[i];
        storableTokens[i] = getTokenEncoding(t,t.point);
    }
    const json = JSON.stringify(storableTokens);
    set(STORAGE_KEY_TOKENS, json);
    set(STORAGE_KEY_COUNT, tokens.length);

    // Update the count on the actual icon
    updateIcon(tokens.length);
}

// SJCL points are cyclic as objects, so we have to flatten them.
function getTokenEncoding(t, curvePoint) {
    let storablePoint = encodeStorablePoint(curvePoint);
    let storableBlind = t.blind.toString();
    return { data: t.data, point: storablePoint, blind: storableBlind };
}

// Load tokens from browser storage
function loadTokens() {
    const storedJSON = get(STORAGE_KEY_TOKENS);
    if (storedJSON == null) {
        return null;
    }

    let usableTokens = [];
    const storedTokens = JSON.parse(storedJSON);
    for (var i = 0; i < storedTokens.length; i++) {
        let t = storedTokens[i];
        let usablePoint = decodeStorablePoint(t.point);
        let usableBlind = new sjcl.bn(t.blind);
        usableTokens[i] = { data: t.data, point: usablePoint, blind: usableBlind };
    }
    return usableTokens;
}

// Counts the tokens that are stored for the background page
function countStoredTokens() {
    const count = get(STORAGE_KEY_COUNT);
    if (count == null) {
        return 0;
    }

    // We change the png file to show if tokens are stored or not
    const countInt = JSON.parse(count);
    updateIcon(countInt);
    return countInt;
}