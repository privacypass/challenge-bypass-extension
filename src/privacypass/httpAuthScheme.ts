import { Buffer } from 'buffer';
import sjcl from '../blindrsa/sjcl';

export class TokenChallenge {
    constructor(
        public tokenType: number,
        public issuerName: string,
        public redemptionNonce: Uint8Array,
        public originInfo: string[],
    ) {}

    static parse(bytes: Uint8Array): TokenChallenge {
        let offset = 0;
        const input = Buffer.from(bytes);

        const type = input.readUint16BE(offset);
        offset += 2;

        let len = input.readUint16BE(offset);
        offset += 2;
        const issuerName = input.subarray(offset, offset + len).toString();
        offset += len;

        len = input.readUInt8(offset);
        offset += 1;
        const redemptionNonce = new Uint8Array(input.subarray(offset, offset + len));
        offset += len;

        len = input.readUint16BE(offset);
        offset += 2;
        const allOriginInfo = input.subarray(offset, offset + len).toString();
        const originInfo = allOriginInfo.split(',');

        return new TokenChallenge(type, issuerName, redemptionNonce, originInfo);
    }

    serialize(): Uint8Array {
        const output = new Array<Buffer>();

        let b = Buffer.alloc(2);
        b.writeUint16BE(this.tokenType);
        output.push(b);

        b = Buffer.alloc(2);
        b.writeUint16BE(this.issuerName.length);
        output.push(b);

        b = Buffer.from(this.issuerName);
        output.push(b);

        b = Buffer.alloc(1);
        b.writeUint8(this.redemptionNonce.length);
        output.push(b);

        b = Buffer.from(this.redemptionNonce);
        output.push(b);

        const allOriginInfo = this.originInfo.join(',');
        b = Buffer.alloc(2);
        b.writeUint16BE(allOriginInfo.length);
        output.push(b);

        b = Buffer.from(allOriginInfo);
        output.push(b);

        return new Uint8Array(Buffer.concat(output));
    }
}

// WWW-Authenticate authorization challenge attributes
const authorizationAttributeChallenge = 'challenge';
const authorizationAttributeMaxAge = 'max-age';
const authorizationAttributeTokenKey = 'token-key';
// const authorizationAttributeNameKey = "origin-name-key"

export interface TokenDetails {
    type: number;
    attester: string;
    challenge: Uint8Array;
    publicKeyEncoded: Uint8Array;
}

function tryB64UrlToUint8(x: string): Uint8Array {
    let bits = [];
    try {
        bits = sjcl.codec.base64url.toBits(x);
    } catch (_) {
        try {
            bits = sjcl.codec.base64.toBits(x);
        } catch (_) {
            return new Uint8Array();
        }
    }
    return new Uint8Array(sjcl.codec.bytes.fromBits(bits));
}

export function parseWWWAuthHeader(header: string): TokenDetails[] {
    const challenges = header.split('PrivateToken ');
    const allTokenDetails = new Array<TokenDetails>();

    for (const challenge of challenges) {
        if (challenge.length === 0) {
            continue;
        }

        const attributes = challenge.split(',');
        let challengeBlob = new Uint8Array();
        let tokenKeyEnc = new Uint8Array();

        // parse attributes of a challenge
        for (const attribute of attributes) {
            let [attrKey, attrValue] = attribute.split('=', 2);
            attrKey = attrKey.trim();
            attrValue = attrValue.trim();

            switch (attrKey) {
                case authorizationAttributeChallenge:
                    challengeBlob = tryB64UrlToUint8(attrValue);
                    break;
                case authorizationAttributeTokenKey:
                    tokenKeyEnc = tryB64UrlToUint8(attrValue);
                    break;
                case authorizationAttributeMaxAge:
                    // not used now
                    break;
            }
        }

        if (challengeBlob.length === 0) {
            continue;
        }

        // Determine type of token
        const type = (challengeBlob[0] << 8) | challengeBlob[1];
        const attester = 'attester.example:4569';
        const details: TokenDetails = {
            type,
            attester,
            challenge: new Uint8Array(challengeBlob),
            publicKeyEncoded: new Uint8Array(tokenKeyEnc),
        };

        allTokenDetails.push(details);
    }

    return allTokenDetails;
}
