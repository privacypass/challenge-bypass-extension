import { emsa_pss_encode, i2osp, os2ip, rsasp1, rsavp1 } from './util';

import sjcl from './sjcl';

export async function blind(
    publicKey: CryptoKey,
    msg: Uint8Array,
    saltLength = 0,
): Promise<{
    blindedMsg: Uint8Array;
    blindInv: Uint8Array;
}> {
    if (publicKey.type !== 'public' || publicKey.algorithm.name !== 'RSA-PSS') {
        throw new Error('key is not RSA-PSS');
    }
    if (!publicKey.extractable) {
        throw new Error('key is not extractable');
    }

    const { modulusLength, hash: hashFn } = publicKey.algorithm as RsaHashedKeyGenParams;
    const kBits = modulusLength;
    const kLen = Math.ceil(kBits / 8);
    const hash = (hashFn as Algorithm).name;

    // 1. encoded_msg = EMSA-PSS-ENCODE(msg, kBits - 1)
    //    with MGF and HF as defined in the parameters
    // 2. If EMSA-PSS-ENCODE raises an error, raise the error and stop
    const encoded_msg = await emsa_pss_encode(msg, kBits - 1, { sLen: saltLength, hash });

    // 3. m = bytes_to_int(encoded_msg)
    const m = os2ip(encoded_msg);
    const jwkKey = await crypto.subtle.exportKey('jwk', publicKey);
    if (!jwkKey.n || !jwkKey.e) {
        throw new Error('key has invalid parameters');
    }
    const n = new sjcl.bn(Buffer.from(jwkKey.n, 'base64url').toString('hex'));
    const e = new sjcl.bn(Buffer.from(jwkKey.e, 'base64url').toString('hex'));

    // 4. r = random_integer_uniform(1, n)
    let r: sjcl.bn;
    do {
        r = os2ip(crypto.getRandomValues(new Uint8Array(kLen)));
    } while (r.greaterEquals(n));

    // 5. r_inv = inverse_mod(r, n)
    // 6. If inverse_mod fails, raise an "invalid blind" error
    //    and stop
    let r_inv: sjcl.bn;
    try {
        r_inv = r.inverseMod(new sjcl.bn(n));
    } catch (e) {
        throw new Error('invalid blind');
    }
    // 7. x = RSAVP1(pkS, r)
    const x = rsavp1({ n, e }, r);

    // 8. z = m * x mod n
    const z = m.mulmod(x, n);

    // 9. blinded_msg = int_to_bytes(z, kLen)
    const blindedMsg = i2osp(z, kLen);

    // 10. inv = int_to_bytes(r_inv, kLen)
    const blindInv = i2osp(r_inv, kLen);

    // 11. output blinded_msg, inv
    return { blindedMsg, blindInv };
}

export async function finalize(
    publicKey: CryptoKey,
    msg: Uint8Array,
    blindInv: Uint8Array,
    blindSig: Uint8Array,
    saltLength = 0,
): Promise<Uint8Array> {
    if (publicKey.type !== 'public' || publicKey.algorithm.name !== 'RSA-PSS') {
        throw new Error('key is not RSA-PSS');
    }
    if (!publicKey.extractable) {
        throw new Error('key is not extractable');
    }
    const { modulusLength } = publicKey.algorithm as RsaHashedKeyGenParams;
    const kLen = Math.ceil(modulusLength / 8);

    // 1. If len(blind_sig) != kLen, raise "unexpected input size" and stop
    // 2. If len(inv) != kLen, raise "unexpected input size" and stop
    if (blindSig.length != kLen || blindInv.length != kLen) {
        throw new Error('unexpected input size');
    }

    // 3. z = bytes_to_int(blind_sig)
    const z = os2ip(blindSig);

    // 4. r_inv = bytes_to_int(inv)
    const r_inv = os2ip(blindInv);

    // 5. s = z * r_inv mod n
    const jwkKey = await crypto.subtle.exportKey('jwk', publicKey);
    if (!jwkKey.n) {
        throw new Error('key has invalid parameters');
    }
    const n = new sjcl.bn(Buffer.from(jwkKey.n, 'base64url').toString('hex'));
    const s = z.mulmod(r_inv, n);

    // 6. sig = int_to_bytes(s, kLen)
    const sig = i2osp(s, kLen);

    // 7. result = RSASSA-PSS-VERIFY(pkS, msg, sig)
    // 8. If result = "valid signature", output sig, else
    //    raise "invalid signature" and stop
    const algorithm = { name: 'RSA-PSS', saltLength };
    if (!(await crypto.subtle.verify(algorithm, publicKey, sig, msg))) {
        throw new Error('invalid signature');
    }

    return sig;
}

export async function blindSign(privateKey: CryptoKey, blindMsg: Uint8Array): Promise<Uint8Array> {
    if (privateKey.type !== 'private' || privateKey.algorithm.name !== 'RSA-PSS') {
        throw new Error('key is not RSA-PSS');
    }
    if (!privateKey.extractable) {
        throw new Error('key is not extractable');
    }
    const { modulusLength } = privateKey.algorithm as RsaHashedKeyGenParams;
    const kLen = Math.ceil(modulusLength / 8);

    // 1. If len(blinded_msg) != kLen, raise "unexpected input size"
    //    and stop
    if (blindMsg.length != kLen) {
        throw new Error('unexpected input size');
    }

    // 2. m = bytes_to_int(blinded_msg)
    const m = os2ip(blindMsg);

    // 3. If m >= n, raise "invalid message length" and stop
    const jwkKey = await crypto.subtle.exportKey('jwk', privateKey);
    if (!jwkKey.n || !jwkKey.d) {
        throw new Error('key is not a private key');
    }
    const n = new sjcl.bn(Buffer.from(jwkKey.n, 'base64url').toString('hex'));
    const d = new sjcl.bn(Buffer.from(jwkKey.d, 'base64url').toString('hex'));
    if (m.greaterEquals(n)) {
        throw new Error('invalid message length');
    }

    // 4. s = RSASP1(skS, m)
    const s = rsasp1({ n, d }, m);

    // 5. blind_sig = int_to_bytes(s, kLen)
    // 6. output blind_sig
    return i2osp(s, kLen);
}
