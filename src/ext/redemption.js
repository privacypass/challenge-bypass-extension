/**
 * Functions for handling redemption requests
 *
 * @author: Alex Davidson
 */

 /* exported BuildRedeemHeader */

/**
 * Constructs the header 'challenge-bypass-token' for redeeming a token with the
 * server. Uses the same BlindTokenRequest as in BuildIssueRequest but sets
 * "type" to "Redeem" and "contents" to [ token_data , request_binding ].
 * 
 * @param {object} token token object to redeem
 * @param {string} host Host that is being requested
 * @param {string} path Path of the requested HTTP request
 */
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

/**
 * Creates the binding to a particular HTTP request by evaluating a HMAC keyed
 * by key material derived from signed token data and evaluated over
 * request-specific data (host and http path)
 * 
 * @param {[]byte} key Derived HMAC key
 * @param {[]byte} data Input HMAC data
 */
function createRequestBinding(key, data) {
    // the exact bits of the string "hash_request_binding"
    const tagBits = sjcl.codec.utf8String.toBits("hash_request_binding");
    const keyBits = sjcl.codec.bytes.toBits(key);

    const h = new sjcl.misc.hmac(keyBits, sjcl.hash.sha256);
    h.update(tagBits);

    let dataBits = null;
    for (var i = 0; i < data.length; i++) {
        dataBits = sjcl.codec.bytes.toBits(data[i]);
        h.update(dataBits);
    }

    const digestBytes = sjcl.codec.bytes.fromBits(h.digest());
    return digestBytes;
}

/**
 * Derives the shared key used for redemption MACs
 * @param {curvePoint} N Signed curve point associated with token
 * @param {object} token client-generated token data
 */
function deriveKey(N, token) {
    // the exact bits of the string "hash_derive_key"
    const tagBits = sjcl.codec.hex.toBits("686173685f6465726976655f6b6579");
    const h = new sjcl.misc.hmac(tagBits, sjcl.hash.sha256);

    const encodedPoint = sec1EncodePoint(N);
    const tokenBits = sjcl.codec.bytes.toBits(token);
    const pointBits = sjcl.codec.bytes.toBits(encodedPoint);

    h.update(tokenBits);
    h.update(pointBits);

    const keyBytes = sjcl.codec.bytes.fromBits(h.digest());
    return keyBytes;
}