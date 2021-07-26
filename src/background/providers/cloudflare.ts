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

const VERIFICATION_KEY =
`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExf0AftemLr0YSz5odoj3eJv6SkOF
VcH7NNb2xwdEz6Pxm44tvovEl/E+si8hdIDVg1Ys+cbaWwP0jYJW3ygv+Q==
-----END PUBLIC KEY-----`;

export default class Cloudflare {
    static readonly id: number = 1;
    private storage: Storage;

    constructor(storage: Storage) {
        // This changes the global state in the crypto module, which can be a side effect outside of this object.
        // It's better if we can refactor the crypto module to be in object-oriented concept.
        crypto.initECSettings({
            'curve':  'p256',
            'hash':   'sha256',
            'method': 'increment',
        });

        this.storage = storage;
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

    private async issue(url: string, formData: { [key: string]: string[] | string }) {
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

        // TODO Work on storing tokens
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
            return param in details.requestBody.formData!;
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

        this.issue(details.url, flattenFormData);

        return {
            cancel: true,
        };
    }
}
