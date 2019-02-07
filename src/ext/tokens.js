/**
 * Handles functions that are specific to token generation and storage
 *
 * @author: George Tankersley
 * @author: Alex Davidson
 */

/*global sjcl*/
/* exported GenerateNewTokens */
/* exported storeNewTokens */
/* exported storeTokens */
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