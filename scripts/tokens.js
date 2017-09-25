/*
 * Handles the creation of 'privacy passes' for bypassing CAPTCHAs
 * A pass is an object containing a token for signing/redemption
 *
 * @main_author: George Tankersley
 * @other_contribs: Alex Davidson
 */

/*global sjcl*/
/* exported CreateBlindToken */
/* exported GenerateNewTokens */
/* exported BuildIssueRequest */
/* exported BuildRedeemHeader */
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
    let bpt = blindPoint(t.point);
    return { token: t.token, point: bpt.point, blind: bpt.blind };
}

// returns: array of blind tokens
function GenerateNewTokens(n) {
    let i = 0;
    let tokens = new Array(n);
    for (i = 0; i < tokens.length; i++) {
        tokens[i] = CreateBlindToken();
    }
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
    const derivedKey = deriveKey(sharedPoint, token.token);

    // TODO: this could be more efficient, but it's easier to check correctness when everything is bytes
    const hostBits = sjcl.codec.utf8String.toBits(host);
    const hostBytes = sjcl.codec.bytes.fromBits(hostBits);

    const pathBits = sjcl.codec.utf8String.toBits(path);
    const pathBytes = sjcl.codec.bytes.fromBits(pathBits);

    const binding = createRequestBinding(derivedKey, [hostBytes, pathBytes]);

    let contents = [];
    contents.push(token.token);
    contents.push(binding);

    return btoa(JSON.stringify({ type: "Redeem", contents: contents}));
}


