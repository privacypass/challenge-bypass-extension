import { emsa_pss_encode } from './util';
import { jest } from '@jest/globals';
// Test vector in file pss_test.go from: https://cs.opensource.google/go/go/+/refs/tags/go1.18.2:src/crypto/rsa/pss_test.go
// Test vector in file pss-int.txt from: ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1-vec.zip
import vector from './testdata/emsa_pss_vectors.json';

function hexToUint8(x: string): Uint8Array {
    return new Uint8Array(Buffer.from(x, 'hex'));
}

test('emsa_pss_encode', async () => {
    const hash = 'SHA-1';
    const msg = hexToUint8(vector.msg);
    const salt = hexToUint8(vector.salt);
    const sLen = salt.length;

    jest.spyOn(crypto, 'getRandomValues').mockReturnValueOnce(salt);

    const encoded = await emsa_pss_encode(msg, 1023, { hash, sLen });
    expect(encoded).toStrictEqual(hexToUint8(vector.expected));
});
