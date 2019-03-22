/**
 * Handles functions that are specific to token generation and storage
 *
 * @author: George Tankersley
 * @author: Alex Davidson
 */

/* global sjcl*/
/* exported GenerateNewTokens */
/* exported storeNewTokens */
/* exported storeTokens */
/* exported loadTokens */
/* exported countStoredTokens */
"use strict";


/**
 * Creates a blinded token and returns the random data, curve point and blinding
 * scalar
 * @return {Object}
 */
function CreateBlindToken() {
    const t = newRandomPoint();
    let tok;
    if (t) {
        const bpt = blindPoint(t.point);
        tok = {data: t.data, point: bpt.point, blind: bpt.blind};
    }
    return tok;
}

/**
 * Generates n blind tokens
 * @param {Number} n number of tokns to generate
 * @return {Array<Object>} array of blinded tokens
 */
function GenerateNewTokens(n) {
    let tokens = [];
    for (let i=0; i<n; i++) {
        const tok = CreateBlindToken();
        if (!tok) {
            console.warn("[privacy-pass]: Tried to generate a random point on the curve, but failed.");
            console.warn("[privacy-pass]: Will drop the null point.");
        }
        tokens[i] = tok;
    }
    // remove array entries that are null
    tokens = tokens.filter(function(ele) {
        return !!ele;
    });
    return tokens;
}

/**
 * This is for storing tokens that we've just received from a new issuance
 * response.
 * @param {Array<Object>} tokens set of tokens to store
 * @param {Array<sjcl.ecc.point>} signedPoints signed tokens that have been
 * received from server
 */
function storeNewTokens(tokens, signedPoints) {
    const storableTokens = [];
    for (let i = 0; i < tokens.length; i++) {
        const t = tokens[i];
        storableTokens[i] = getTokenEncoding(t, signedPoints[i]);
    }
    // Append old tokens to the newly received tokens
    if (countStoredTokens() > 0) {
        const oldTokens = loadTokens();
        for (let i=0; i<oldTokens.length; i++) {
            const oldT = oldTokens[i];
            storableTokens.push(getTokenEncoding(oldT, oldT.point));
        }
    }
    const json = JSON.stringify(storableTokens);
    set(storageKeyTokens(), json);
    set(storageKeyCount(), storableTokens.length);

    // Update the count on the actual icon
    updateIcon(storableTokens.length);
}

/**
 * Persists valid tokens after some manipulation, like a spend.
 * @param {Array<Object>} tokens set of tokens to store
 */
function storeTokens(tokens) {
    const storableTokens = [];
    for (let i = 0; i < tokens.length; i++) {
        const t = tokens[i];
        storableTokens[i] = getTokenEncoding(t, t.point);
    }
    const json = JSON.stringify(storableTokens);
    set(storageKeyTokens(), json);
    set(storageKeyCount(), tokens.length);

    // Update the count on the actual icon
    updateIcon(tokens.length);
}

/**
 * Encodes the token object for storage (flattens sjcl.ecc.point object)
 * @param {Object} t token object for curvePoint
 * @param {sjcl.ecc.point} curvePoint
 * @return {Object}
 */
function getTokenEncoding(t, curvePoint) {
    const storablePoint = encodeStorablePoint(curvePoint);
    const storableBlind = t.blind.toString();
    return {data: t.data, point: storablePoint, blind: storableBlind};
}

/**
 * Load tokens from browser storage
 * @return {Array<Object>} returns null if no tokens stored
 */
function loadTokens() {
    const storedJSON = get(storageKeyTokens());
    if (storedJSON == null) {
        return null;
    }

    const usableTokens = [];
    const storedTokens = JSON.parse(storedJSON);
    for (let i = 0; i < storedTokens.length; i++) {
        const t = storedTokens[i];
        const usablePoint = decodeStorablePoint(t.point);
        const usableBlind = new sjcl.bn(t.blind);
        usableTokens[i] = {data: t.data, point: usablePoint, blind: usableBlind};
    }
    return usableTokens;
}

/**
 * Counts the tokens that are stored in localStorage
 * @return {Number}
 */
function countStoredTokens() {
    const count = get(storageKeyCount());
    if (count == null) {
        return 0;
    }

    // We change the png file to show if tokens are stored or not
    const countInt = JSON.parse(count);
    updateIcon(countInt);
    return countInt;
}
