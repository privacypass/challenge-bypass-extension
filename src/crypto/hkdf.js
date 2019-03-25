/** Modified HKDF implementation from:
 * https://mozilla.github.io/fxa-js-client/files/client_lib_hkdf.js.html
 * includes compatibility for any hash function.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * @author Alex Davidson
 */

/* global sjcl*/

/**
 * hkdf - The HMAC-based Key Derivation Function
 * based on https://github.com/mozilla/node-hkdf
 *
 * @class hkdf
 * @param {bitArray} ikm Initial keying material
 * @param {integer} length Length of the derived key in bytes
 * @param {bitArray} info Key derivation data
 * @param {bitArray} salt Salt
 * @param {sjcl.hash} hash hash function
 * @return {bitArray}
 */
sjcl.misc.hkdf = function(ikm, length, info, salt, hash) {
    const mac = new sjcl.misc.hmac(salt, hash);
    mac.update(ikm);
    const prk = mac.digest();

    const hashLength = sjcl.bitArray.bitLength(prk)/8;
    const numBlocks = Math.ceil(length / hashLength);
    let prev = sjcl.codec.hex.toBits("");
    let output = "";
    for (let i = 0; i < numBlocks; i++) {
        const hmac = new sjcl.misc.hmac(prk, hash);
        const input = sjcl.bitArray.concat(
            sjcl.bitArray.concat(prev, info),
            sjcl.codec.utf8String.toBits((String.fromCharCode(i + 1)))
        );
        hmac.update(input);
        prev = hmac.digest();
        output += sjcl.codec.hex.fromBits(prev);
    }
    return sjcl.bitArray.clamp(sjcl.codec.hex.toBits(output), length * 8);
};
