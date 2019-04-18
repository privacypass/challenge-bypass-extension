/**
 * Functions for handling redemption requests
 *
 * @author: Alex Davidson
 */

/* global sjcl*/
/* exported BuildRedeemHeader */

/**
 * Constructs the header 'challenge-bypass-token' for redeeming a token with the
 * server. Uses the same BlindTokenRequest as in BuildIssueRequest but sets
 * "type" to "Redeem" and "contents" to [ token_data , request_binding ].
 *
 * @param {Object} token token object to redeem
 * @param {string} host Host that is being requested
 * @param {string} path Path of the requested HTTP request
 * @return {string} base64-encoded redemption requestx
 */
function BuildRedeemHeader(token, host, path) {
    const sharedPoint = unblindPoint(token.blind, token.point);
    const derivedKey = deriveKey(sharedPoint, token.data);

    const hostBits = sjcl.codec.utf8String.toBits(host);
    const hostBytes = sjcl.codec.bytes.fromBits(hostBits);

    const pathBits = sjcl.codec.utf8String.toBits(path);
    const pathBytes = sjcl.codec.bytes.fromBits(pathBits);

    const b64Binding = createRequestBinding(derivedKey, [hostBytes, pathBytes]);

    // Fortunately Go interprets base64-encoded strings as []bytes when
    // unmarshaling JSON.
    const contents = [];
    contents.push(sjcl.codec.base64.fromBits(sjcl.codec.bytes.toBits(token.data)));
    contents.push(b64Binding);
    if (sendH2CParams()) {
        const h2cString = JSON.stringify(h2cParams());
        const h2cBits = sjcl.codec.utf8String.toBits(h2cString);
        const h2cB64 = sjcl.codec.base64.fromBits(h2cBits);
        contents.push(h2cB64);
    }

    return btoa(JSON.stringify({type: "Redeem", contents: contents}));
}

/**
 * Creates the binding to a particular HTTP request by evaluating a HMAC keyed
 * by key material derived from signed token data and evaluated over
 * request-specific data (host and http path)
 *
 * @param {sjcl.codec.bytes} key Derived HMAC key
 * @param {sjcl.codec.bytes} data Input HMAC data
 * @return {string} base64-encoded HMAC output
 */
function createRequestBinding(key, data) {
    // the exact bits of the string "hash_request_binding"
    const tagBits = sjcl.codec.utf8String.toBits("hash_request_binding");
    const keyBits = sjcl.codec.bytes.toBits(key);
    const hash = getActiveECSettings().hash;

    const h = new sjcl.misc.hmac(keyBits, hash);
    h.update(tagBits);

    let dataBits = null;
    for (let i = 0; i < data.length; i++) {
        dataBits = sjcl.codec.bytes.toBits(data[i]);
        h.update(dataBits);
    }

    return sjcl.codec.base64.fromBits(h.digest());
}

/**
 * Derives the shared key used for redemption MACs
 * @param {sjcl.ecc.point} N Signed curve point associated with token
 * @param {Object} token client-generated token data
 * @return {sjcl.codec.bytes} bytes of derived key
 */
function deriveKey(N, token) {
    // the exact bits of the string "hash_derive_key"
    const tagBits = sjcl.codec.hex.toBits("686173685f6465726976655f6b6579");
    const hash = getActiveECSettings().hash;
    const h = new sjcl.misc.hmac(tagBits, hash);

    // Always compute derived key using uncompressed point bytes
    const encodedPoint = sec1Encode(N, false);
    const tokenBits = sjcl.codec.bytes.toBits(token);
    const pointBits = sjcl.codec.bytes.toBits(encodedPoint);

    h.update(tokenBits);
    h.update(pointBits);

    const keyBytes = sjcl.codec.bytes.fromBits(h.digest());
    return keyBytes;
}
