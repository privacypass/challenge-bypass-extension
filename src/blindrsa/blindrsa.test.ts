import blindRSA from './index';
import { jest } from '@jest/globals';
import sjcl from './sjcl';
// Test vector
// https://www.ietf.org/archive/id/draft-irtf-cfrg-rsa-blind-signatures-03.html#appendix-A
import vectors from './testdata/rsablind_vectors.json';

function hexToB64URL(x: string): string {
    return Buffer.from(x, 'hex').toString('base64url');
}

function hexToUint8(x: string): Uint8Array {
    return new Uint8Array(Buffer.from(x, 'hex'));
}

function paramsFromVector(v: typeof vectors[number]): {
    n: string;
    e: string;
    d: string;
    p: string;
    q: string;
    dp: string;
    dq: string;
    qi: string;
} {
    const n = hexToB64URL(v.n);
    const e = hexToB64URL(v.e);
    const d = hexToB64URL(v.d);
    const p = hexToB64URL(v.p);
    const q = hexToB64URL(v.q);

    // Calculate CRT values
    const bnD = new sjcl.bn(v.d);
    const bnP = new sjcl.bn(v.p);
    const bnQ = new sjcl.bn(v.q);
    const one = new sjcl.bn(1);
    const dp = hexToB64URL(bnD.mod(bnP.sub(one)).toString());
    const dq = hexToB64URL(bnD.mod(bnQ.sub(one)).toString());
    const qi = hexToB64URL(bnQ.inverseMod(bnP).toString());
    return { n, e, d, p, q, dp, dq, qi };
}

async function keysFromVector(
    v: typeof vectors[number],
    extractable: boolean,
): Promise<CryptoKeyPair> {
    const params = paramsFromVector(v);
    const { n, e } = params;
    const publicKey = await crypto.subtle.importKey(
        'jwk',
        { kty: 'RSA', ext: true, n, e },
        { name: 'RSA-PSS', hash: 'SHA-384' },
        extractable,
        ['verify'],
    );

    const privateKey = await crypto.subtle.importKey(
        'jwk',
        { kty: 'RSA', ext: true, ...params },
        { name: 'RSA-PSS', hash: 'SHA-384' },
        extractable,
        ['sign'],
    );
    return { privateKey, publicKey };
}

describe.each(vectors)('BlindRSA-vec$#', (v: typeof vectors[number]) => {
    test('test-vector', async () => {
        const r_inv = new sjcl.bn(v.inv);
        const r = r_inv.inverseMod(new sjcl.bn(v.n));
        const r_bytes = hexToUint8(r.toString().slice(2));

        const { privateKey, publicKey } = await keysFromVector(v, true);
        const msg = hexToUint8(v.msg);
        const saltLength = v.salt.length / 2;

        // Mock for randomized blind operation.
        jest.spyOn(crypto, 'getRandomValues')
            .mockReturnValueOnce(hexToUint8(v.salt)) // mock for random salt
            .mockReturnValueOnce(r_bytes); // mock for random blind

        const { blindedMsg, blindInv } = await blindRSA.blind(publicKey, msg, saltLength);
        expect(blindedMsg).toStrictEqual(hexToUint8(v.blinded_msg));
        expect(blindInv).toStrictEqual(hexToUint8(v.inv));

        const blindedSig = await blindRSA.blindSign(privateKey, blindedMsg);
        expect(blindedSig).toStrictEqual(hexToUint8(v.blind_sig));

        const signature = await blindRSA.finalize(publicKey, msg, blindInv, blindedSig, saltLength);
        expect(signature).toStrictEqual(hexToUint8(v.sig));
    });

    test('non-extractable-keys', async () => {
        const { privateKey, publicKey } = await keysFromVector(v, false);
        const msg = crypto.getRandomValues(new Uint8Array(10));
        const blindedMsg = crypto.getRandomValues(new Uint8Array(32));
        const blindInv = crypto.getRandomValues(new Uint8Array(32));
        const blindedSig = crypto.getRandomValues(new Uint8Array(32));
        const errorMsg = 'key is not extractable';

        await expect(blindRSA.blind(publicKey, msg, 32)).rejects.toThrow(errorMsg);
        await expect(blindRSA.blindSign(privateKey, blindedMsg)).rejects.toThrow(errorMsg);
        await expect(blindRSA.finalize(publicKey, msg, blindInv, blindedSig, 32)).rejects.toThrow(
            errorMsg,
        );
    });

    test('wrong-key-type', async () => {
        const { privateKey, publicKey } = await crypto.subtle.generateKey(
            {
                name: 'RSASSA-PKCS1-v1_5', // not RSA-PSS.
                modulusLength: 2048,
                publicExponent: Uint8Array.from([0x01, 0x00, 0x01]),
                hash: 'SHA-256',
            },
            true,
            ['sign', 'verify'],
        );

        const msg = crypto.getRandomValues(new Uint8Array(10));
        const blindedMsg = crypto.getRandomValues(new Uint8Array(32));
        const blindInv = crypto.getRandomValues(new Uint8Array(32));
        const blindedSig = crypto.getRandomValues(new Uint8Array(32));
        const errorMsg = 'key is not RSA-PSS';

        await expect(blindRSA.blind(publicKey, msg, 32)).rejects.toThrow(errorMsg);
        await expect(blindRSA.blindSign(privateKey, blindedMsg)).rejects.toThrow(errorMsg);
        await expect(blindRSA.finalize(publicKey, msg, blindInv, blindedSig, 32)).rejects.toThrow(
            errorMsg,
        );
    });
});
