import { PublicVerifClient, PublicVerifIssuer } from './pubVerifToken';

import { jest } from '@jest/globals';
import sjcl from '../blindrsa/sjcl';
import vectors from './testdata/public_verif_token.json';

function hexToUint8(x: string): Uint8Array {
    return new Uint8Array(Buffer.from(x, 'hex'));
}

function uint8ToHex(x: Uint8Array): string {
    return Buffer.from(x).toString('hex');
}

function b64ToUint8(x: string): Uint8Array {
    return new Uint8Array(sjcl.codec.bytes.fromBits(sjcl.codec.base64.toBits(x)));
}

type Vectors = typeof vectors[number];

async function keysFromVector(v: Vectors): Promise<[CryptoKeyPair, Uint8Array]> {
    const hexEncoded = hexToUint8(v.skS);
    const pem = new TextDecoder().decode(hexEncoded);
    const pemHeader = '-----BEGIN PRIVATE KEY-----';
    const pemFooter = '-----END PRIVATE KEY-----';
    const pemContents = pem.replace(pemHeader, '').replace(pemFooter, '');
    const payload = b64ToUint8(pemContents);

    const privateKey = await crypto.subtle.importKey(
        'pkcs8',
        payload,
        { name: 'RSA-PSS', hash: 'SHA-384' },
        true,
        ['sign'],
    );

    const publicKey = await crypto.subtle.importKey(
        'spki',
        hexToUint8(v.pkS),
        { name: 'RSA-PSS', hash: 'SHA-384' },
        true,
        ['verify'],
    );
    const publicKeyEnc = hexToUint8(v.pkS);

    return [{ privateKey, publicKey }, publicKeyEnc];
}

describe.each(vectors)('PublicVerifToken', (v: Vectors) => {
    test('test-vector', async () => {
        const [{ privateKey, publicKey }, publicKeyEnc] = await keysFromVector(v);
        expect(privateKey).toBeDefined();
        expect(publicKey).toBeDefined();

        const salt = hexToUint8(v.salt);
        const nonce = hexToUint8(v.nonce);
        const blind = hexToUint8(v.blind);
        const challenge = hexToUint8(v.challenge);

        // Mock for randomized operations.
        jest.spyOn(crypto, 'getRandomValues')
            .mockReturnValueOnce(nonce)
            .mockReturnValueOnce(salt)
            .mockReturnValueOnce(blind);

        const client = new PublicVerifClient(publicKey, publicKeyEnc, salt.length);
        const tokReq = await client.createTokenRequest(challenge);
        const tokReqSer = tokReq.serialize();
        expect(uint8ToHex(tokReqSer)).toStrictEqual(v.token_request);

        const tokRes = await PublicVerifIssuer.issue(privateKey, tokReq);
        const tokResSer = tokRes.serialize();
        expect(tokResSer).toStrictEqual(hexToUint8(v.token_response));

        const token = await client.finalize(tokRes);
        const tokenSer = token.serialize();
        expect(tokenSer).toStrictEqual(hexToUint8(v.token));
    });
});
