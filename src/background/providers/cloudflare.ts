import axios  from 'axios';
import qs     from 'qs';
import crypto from '@background/crypto';
import Token  from '@background/token';

const ISSUE_HEADER_NAME          = 'cf-chl-bypass';
const NUMBER_OF_REQUESTED_TOKENS = 30;
const ISSUANCE_BODY_PARAM_NAME   = 'blinded-tokens';

const QUALIFIED_QUERY_PARAMS = [
    '__cf_chl_captcha_tk__',
    '__cf_chl_managed_tk__',
];
const QUALIFIED_BODY_PARAMS  = [
    'g-recaptcha-response',
    'h-captcha-response',
    'cf_captcha_kind',
];

export default class Cloudflare {
    static readonly id: number = 1;

    constructor() {
        // This changes the global state in the crypto module, which can be a side effect outside of this object.
        // It's better if we can refactor the crypto module to be in object-oriented concept.
        crypto.initECSettings({
            'curve':  'p256',
            'hash':   'sha256',
            'method': 'increment',
        });
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
        const json = JSON.parse(atob(signatures));
        // TODO Work on the json response
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
