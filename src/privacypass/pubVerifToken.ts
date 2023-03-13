import { TokenChallenge, TokenDetails } from './httpAuthScheme';
import { blind, blindSign, finalize } from '../blindrsa';

import { Buffer } from 'buffer';
import { convertPSSToEnc } from './util';

export const BasicPublicTokenType = 0x0002;
export const RateLimitedTokenType = 0x0003;

export class TokenRequest {
    constructor(
        public tokenType: number,
        public tokenKeyId: number,
        public blindedMsg: Uint8Array,
    ) {}

    serialize(): Uint8Array {
        const output = new Array<Buffer>();

        let b = Buffer.alloc(2);
        b.writeUint16BE(this.tokenType);
        output.push(b);

        b = Buffer.alloc(1);
        b.writeUint8(this.tokenKeyId);
        output.push(b);

        b = Buffer.from(this.blindedMsg);
        output.push(b);

        return new Uint8Array(Buffer.concat(output));
    }
}

class TokenPayload {
    constructor(
        public tokenType: number,
        public nonce: Uint8Array,
        public context: Uint8Array,
        public keyId: Uint8Array,
    ) {}

    serialize(): Uint8Array {
        const output = new Array<Buffer>();

        let b = Buffer.alloc(2);
        b.writeUint16BE(this.tokenType);
        output.push(b);

        b = Buffer.from(this.nonce);
        output.push(b);

        b = Buffer.from(this.context);
        output.push(b);

        b = Buffer.from(this.keyId);
        output.push(b);

        return new Uint8Array(Buffer.concat(output));
    }
}

export class Token {
    constructor(public payload: TokenPayload, public authenticator: Uint8Array) {}

    serialize(): Uint8Array {
        return new Uint8Array(Buffer.concat([this.payload.serialize(), this.authenticator]));
    }
}

export class TokenResponse {
    constructor(public blindSig: Uint8Array) {}
    serialize(): Uint8Array {
        return new Uint8Array(this.blindSig);
    }
}

export class PublicVerifClient {
    static TYPE = BasicPublicTokenType;
    private finData?: {
        tokenInput: Uint8Array;
        tokenPayload: TokenPayload;
        tokenRequest: TokenRequest;
        blindInv: Uint8Array;
    };

    constructor(
        private readonly publicKey: CryptoKey,
        private readonly publicKeyEnc: Uint8Array,
        private readonly saltLength: number = 0,
    ) {}

    async createTokenRequest(challenge: Uint8Array): Promise<TokenRequest> {
        // https://www.ietf.org/archive/id/draft-ietf-privacypass-protocol-04.html#name-client-to-issuer-request-2
        const nonce = crypto.getRandomValues(new Uint8Array(32));
        const context = new Uint8Array(await crypto.subtle.digest('SHA-256', challenge));
        const keyId = new Uint8Array(await crypto.subtle.digest('SHA-256', this.publicKeyEnc));
        const tokenPayload = new TokenPayload(PublicVerifClient.TYPE, nonce, context, keyId);
        const tokenInput = tokenPayload.serialize();

        const { blindedMsg, blindInv } = await blind(this.publicKey, tokenInput, this.saltLength);
        const tokenKeyId = keyId[keyId.length - 1];
        const tokenRequest = new TokenRequest(PublicVerifClient.TYPE, tokenKeyId, blindedMsg);
        this.finData = { tokenInput, tokenPayload, blindInv, tokenRequest };

        return tokenRequest;
    }

    async finalize(t: TokenResponse): Promise<Token> {
        if (!this.finData) {
            throw new Error('no token request was created yet.');
        }

        const authenticator = await finalize(
            this.publicKey,
            this.finData.tokenInput,
            this.finData.blindInv,
            t.blindSig,
            this.saltLength,
        );
        const token = new Token(this.finData.tokenPayload, authenticator);
        this.finData = undefined;

        return token;
    }
}

export class PublicVerifIssuer {
    static TYPE = BasicPublicTokenType;
    static async issue(privateKey: CryptoKey, tokReq: TokenRequest): Promise<TokenResponse> {
        return new TokenResponse(await blindSign(privateKey, tokReq.blindedMsg));
    }
}

const TOKEN_ISSUER_DIRECTORY = '/.well-known/token-issuer-directory';
const TOKEN_REQUEST_MEDIA_TYPE = 'message/token-request';
const TOKEN_RESPONSE_MEDIA_TYPE = 'message/token-response';

const IC_ISSUER_REQ_KEY_URI = 'issuer-request-key-uri';
const IC_ISSUER_REQ_URI = 'issuer-request-uri';
const IC_TOKEN_KEYS = 'token-keys';
const IC_TOKEN_TYPE = 'token-type';
const IC_TOKEN_KEY = 'token-key';

interface IssuerConfiguration {
    [IC_ISSUER_REQ_KEY_URI]: string;
    [IC_ISSUER_REQ_URI]: string;
    [IC_TOKEN_KEYS]: Array<{
        [IC_TOKEN_TYPE]: number;
        [IC_TOKEN_KEY]: string;
        version: number;
    }>;
}

interface IssuerError {
    err: string;
}

export async function fetchPublicVerifToken(params: TokenDetails): Promise<Token> {
    // Fetch issuer URL
    const tokenChallenge = TokenChallenge.parse(params.challenge);
    const configURI = 'https://' + tokenChallenge.issuerName + TOKEN_ISSUER_DIRECTORY;
    const res = await fetch(configURI);
    if (res.status !== 200) {
        throw new Error(`issuerConfig: no configuration was found at ${configURI}`);
    }
    const issuerConfig = (await res.json()) as unknown as IssuerConfiguration;

    // Create a TokenRequest.
    const spkiEncoded = convertPSSToEnc(params.publicKeyEncoded);
    const publicKey = await crypto.subtle.importKey(
        'spki',
        spkiEncoded,
        { name: 'RSA-PSS', hash: 'SHA-384' },
        true,
        ['verify'],
    );
    const saltLen = 48; // For SHA-384
    const client = new PublicVerifClient(publicKey, params.publicKeyEncoded, saltLen);
    const tokenRequest = await client.createTokenRequest(params.challenge);

    // Send TokenRequest to Issuer (fetch w/POST).
    const { [IC_ISSUER_REQ_URI]: req_uri } = issuerConfig;
    const issuerURI = 'https://' + tokenChallenge.issuerName + req_uri;
    const issuerResponse = await fetch(issuerURI, {
        method: 'POST',
        headers: [
            ['Content-Type', TOKEN_REQUEST_MEDIA_TYPE],
            ['Accept', TOKEN_RESPONSE_MEDIA_TYPE],
        ],
        body: tokenRequest.serialize().buffer,
    });
    if (issuerResponse.status !== 200) {
        const e = (await issuerResponse.json()) as unknown as IssuerError;
        throw new Error(`tokenRequest: ${e.err}`);
    }
    const contentType = issuerResponse.headers.get('Content-Type');
    if (!contentType || contentType.toLowerCase() !== TOKEN_RESPONSE_MEDIA_TYPE) {
        throw new Error(`tokenRequest: missing ${TOKEN_RESPONSE_MEDIA_TYPE} header`);
    }

    //  Receive a TokenResponse,
    const resp = new Uint8Array(await issuerResponse.arrayBuffer());
    const tokenResponse = new TokenResponse(resp);

    // Produce a token by Finalizing the TokenResponse.
    const token = client.finalize(tokenResponse);

    return token;
}
