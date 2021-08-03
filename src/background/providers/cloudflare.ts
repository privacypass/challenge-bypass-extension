import axios  from 'axios';
import qs     from 'qs';
import crypto from '@background/crypto';
import Token  from '@background/token';

const ISSUE_HEADER_NAME          = 'cf-chl-bypass';
const NUMBER_OF_REQUESTED_TOKENS = 30;
const ISSUANCE_BODY_PARAM_NAME   = 'blinded-tokens';

const COMMITMENT_URL = 'https://raw.githubusercontent.com/privacypass/ec-commitments/master/commitments-p256.json';

const QUALIFIED_QUERY_PARAMS = [
    '__cf_chl_captcha_tk__',
    '__cf_chl_managed_tk__',
];
const QUALIFIED_BODY_PARAMS  = [
    'g-recaptcha-response',
    'h-captcha-response',
    'cf_captcha_kind',
];

const CHL_BYPASS_SUPPORT = 'cf-chl-bypass';
const DEFAULT_ISSUING_HOSTNAME = 'captcha.website';

const VERIFICATION_KEY =
`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExf0AftemLr0YSz5odoj3eJv6SkOF
VcH7NNb2xwdEz6Pxm44tvovEl/E+si8hdIDVg1Ys+cbaWwP0jYJW3ygv+Q==
-----END PUBLIC KEY-----`;

const TOKEN_STORE_KEY = 'tokens';

interface RedeemInfo {
    requestId: string,
    token: Token,
}

export default class Cloudflare {
    static readonly id: number = 1;
    private storage: Storage;

    private redeemInfo: RedeemInfo | null;

    constructor(storage: Storage) {
        // TODO This changes the global state in the crypto module, which can be a side effect outside of this object.
        // It's better if we can refactor the crypto module to be in object-oriented concept.
        crypto.initECSettings({
            'curve':  'p256',
            'hash':   'sha256',
            'method': 'increment',
        });

        this.storage = storage;
        this.redeemInfo = null;
    }

    private getStoredTokens(): Token[] {
        const stored = this.storage.getItem(TOKEN_STORE_KEY);
        if (stored === null) {
            return [];
        }

        const tokens: string[] = JSON.parse(stored);
        return tokens.map(token => Token.fromString(token));
    }

    private setStoredTokens(tokens: Token[]) {
        this.storage.setItem(TOKEN_STORE_KEY, JSON.stringify(tokens.map(token => token.toString())));
    }

    private async getCommitment(version: string): Promise<{ G: string, H: string }> {
        const keyPrefix = 'commitment-';
        const cached = this.storage.getItem(`${keyPrefix}${version}`);
        if (cached !== null) {
            return JSON.parse(cached);
        }

        interface Response {
            CF: { [version: string]: { H: string, expiry: string, sig: string } },
        }

        // Download the commitment
        const { data }   = await axios.get<Response>(COMMITMENT_URL);
        const commitment = data.CF[version];
        if (commitment === undefined) {
            throw new Error(`No commitment for the version ${version} is found`);
        }

        // Check the expiry date.
        const expiry = new Date(commitment.expiry);
        if (Date.now() >= +expiry) {
            throw new Error(`Commitments expired in ${expiry.toString()}`);
        }

        // This will throw an error on a bad signature.
        crypto.verifyConfiguration(VERIFICATION_KEY, {
            H: commitment.H,
            expiry: commitment.expiry,
        }, commitment.sig);

        // Cache.
        const item = {
            G: crypto.sec1EncodeToBase64(crypto.getActiveECSettings().curve.G, false),
            H: commitment.H,
        };
        this.storage.setItem(`${keyPrefix}${version}`, JSON.stringify(item));
        return item;
    }

    private async issue(url: string, formData: { [key: string]: string[] | string }): Promise<Token[]> {
        const tokens = Array.from(Array(NUMBER_OF_REQUESTED_TOKENS).keys()).map(() => new Token());
        const issuance = {
            type: "Issue",
            contents: tokens.map(token => token.getEncodedBlindedPoint()),
        };
        const param = btoa(JSON.stringify(issuance));

        const body  = qs.stringify({
            ...formData,
            [ISSUANCE_BODY_PARAM_NAME]: param,
        });

        const headers = {
            'content-type': 'application/x-www-form-urlencoded',
            [ISSUE_HEADER_NAME]: Cloudflare.id,
        };

        const response = await axios.post<string>(url, body, { headers, responseType: 'text' });

        const { signatures } = qs.parse(response.data);
        if (signatures === undefined) {
            throw new Error("There is no signatures parameter in the issuance response.");
        }
        if (typeof signatures !== 'string') {
            throw new Error("The signatures parameter in the issuance response is not a string.");
        }

        interface SignaturesParam {
            sigs: string[],
            version: string,
            proof: string,
            prng: string,
        }

        const data: SignaturesParam = JSON.parse(atob(signatures));
        const returned = crypto.getCurvePoints(data.sigs);

        const commitment = await this.getCommitment(data.version);

        const result = crypto.verifyProof(
            data.proof,
            tokens.map(token => token.toLegacy()),
            returned,
            commitment,
            data.prng,
        );
        if (!result) {
            throw new Error("DLEQ proof is invalid.");
        }

        tokens.forEach((token, index) => {
            token.setSignedPoint(returned.points[index]);
        });

        return tokens;
    }

    handleBeforeSendHeaders(details: chrome.webRequest.WebRequestHeadersDetails) {
        if (this.redeemInfo === null || details.requestId !== this.redeemInfo.requestId) {
            return;
        }

        const url = new URL(details.url);

        const token = this.redeemInfo!.token;
        // Clear the redeem info to indicate that we are already redeeming the token.
        this.redeemInfo = null;

        const key = token.getMacKey();
        const binding = crypto.createRequestBinding(key, [
            crypto.getBytesFromString(url.hostname),
            crypto.getBytesFromString(details.method + ' ' + url.pathname),
        ]);

        const contents = [
            crypto.getBase64FromBytes(token.getInput()),
            binding,
            crypto.getBase64FromString(JSON.stringify({
                // TODO There should be a better way to retrieve this info.
                // Currently I just copied this from the old code base.
                'curve': 'p256',
                'hash': 'sha256',
                'method': 'increment',
            })),
        ];
        const redemption = btoa(JSON.stringify({ type: "Redeem", contents }));

        const headers = details.requestHeaders ?? [];
        headers.push({ name: 'challenge-bypass-token', value: redemption });

        return {
            requestHeaders: headers,
        };
    }

    handleBeforeRequest(details: chrome.webRequest.WebRequestBodyDetails) {
        const url = new URL(details.url);

        if (details.requestBody === null || details.requestBody === undefined || details.requestBody.formData === undefined) {
            return;
        }

        const hasQueryParams = QUALIFIED_QUERY_PARAMS.some(param => {
            return url.searchParams.has(param);
        });
        const hasBodyParams  = QUALIFIED_BODY_PARAMS.some(param => {
            return details.requestBody !== null && param in details.requestBody.formData!;
        });
        if (!hasQueryParams || !hasBodyParams) {
            return;
        }

        const flattenFormData: { [key: string]: string[] | string } = {};
        for(const key in details.requestBody.formData) {
            if (details.requestBody.formData[key].length == 1) {
                const [value]        = details.requestBody.formData[key];
                flattenFormData[key] = value;
            } else {
                flattenFormData[key] = details.requestBody.formData[key];
            }
        }

        (async () => {
            // Issue tokens.
            const tokens = await this.issue(details.url, flattenFormData);
            // Store tokens.
            const cached = this.getStoredTokens();
            this.setStoredTokens(cached.concat(tokens));
        })();

        return {
            cancel: true,
        };
    }

    handleHeadersReceived(details: chrome.webRequest.WebResponseHeadersDetails) {
        // Don't redeem a token in the issuing website.
        const url = new URL(details.url);
        if (url.host === DEFAULT_ISSUING_HOSTNAME) {
            return;
        }

        // Check if it's the response of the request that we should insert a token.
        if (details.statusCode !== 403 || details.responseHeaders === undefined) {
            return;
        }
        const hasSupportHeader = details.responseHeaders.some(header => {
            return header.name.toLowerCase() === CHL_BYPASS_SUPPORT && header.value !== undefined && +header.value === Cloudflare.id;
        });
        if (!hasSupportHeader) {
            return;
        }

        // Let's try to redeem.

        // Get one token.
        const tokens = this.getStoredTokens();
        const token  = tokens.shift();
        this.setStoredTokens(tokens);

        if (token === undefined) {
            return;
        }

        this.redeemInfo = { requestId: details.requestId, token };
        // Redirect to resend the request attached with the token.
        return {
            redirectUrl: details.url,
        };
    }
}
