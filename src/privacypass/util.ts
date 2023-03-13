import * as asn1js from 'asn1js';

import sjcl from '../blindrsa/sjcl';

export function uint8ToB64URL(x: Uint8Array): string {
    return sjcl.codec.base64url.fromBits(sjcl.codec.bytes.toBits(x));
}

// Convert a RSA-PSS key into a RSA Encryption key.
// This is required because browsers do not support import RSA-PSS keys.
//
// Chromium: https://www.chromium.org/blink/webcrypto/#supported-key-formats
// Firefox: https://github.com/mozilla/pkipolicy/blob/master/rootstore/policy.md#511-rsa
//
// Documentation: https://www.rfc-editor.org/rfc/rfc4055#section-6
export function convertPSSToEnc(keyRSAPSSEncSpki: Uint8Array): Uint8Array {
    const RSAEncryptionAlgID = '1.2.840.113549.1.1.1';
    const obj = asn1js.fromBER(keyRSAPSSEncSpki);
    const schema = new asn1js.Sequence({
        value: [
            new asn1js.Sequence({ name: 'algorithm' }),
            new asn1js.BitString({ name: 'subjectPublicKey' }),
        ],
    });
    const cmp = asn1js.compareSchema(obj.result, obj.result, schema);
    if (cmp.verified != true) {
        throw new Error('bad parsing');
    }

    const keyASN = new asn1js.Sequence({
        value: [
            new asn1js.Sequence({
                value: [
                    new asn1js.ObjectIdentifier({ value: RSAEncryptionAlgID }),
                    new asn1js.Null(),
                ],
            }),
            cmp.result.subjectPublicKey,
        ],
    });

    return new Uint8Array(keyASN.toBER());
}
