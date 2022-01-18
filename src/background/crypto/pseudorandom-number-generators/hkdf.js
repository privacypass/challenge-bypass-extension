import sjcl from 'sjcl';

/**
 * hkdf - The HMAC-based Key Derivation Function
 * based on https://github.com/mozilla/node-hkdf
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * @param {bitArray} ikm Initial keying material
 * @param {integer} length Length of the derived key in bytes
 * @param {bitArray} info Key derivation data
 * @param {bitArray} salt Salt
 * @param {sjcl.hash} hash hash function
 * @return {bitArray}
 */
export function evaluateHkdf(ikm, length, info, salt, hash) {
    const mac = new sjcl.misc.hmac(salt, hash);
    mac.update(ikm);
    const prk = mac.digest();

    const hashLength = Math.ceil(sjcl.bitArray.bitLength(prk) / 8);
    const numBlocks = Math.ceil(length / hashLength);
    if (numBlocks > 255) {
        throw new Error(
            `[privacy-pass]: HKDF error, number of proposed iterations too large: ${numBlocks}`,
        );
    }

    let prev = sjcl.codec.hex.toBits('');
    let output = '';
    for (let i = 0; i < numBlocks; i++) {
        const hmac = new sjcl.misc.hmac(prk, hash);
        const input = sjcl.bitArray.concat(
            sjcl.bitArray.concat(prev, info),
            sjcl.codec.utf8String.toBits(String.fromCharCode(i + 1)),
        );
        hmac.update(input);
        prev = hmac.digest();
        output += sjcl.codec.hex.fromBits(prev);
    }
    return sjcl.bitArray.clamp(sjcl.codec.hex.toBits(output), length * 8);
}
