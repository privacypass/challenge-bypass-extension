import * as voprf from '../crypto/voprf';

import { Provider, EarnedTokenCookie, Callbacks } from './provider';
import { Storage } from '../storage';
import Token from '../token';
import axios from 'axios';
import qs from 'qs';

const ISSUE_HEADER_NAME = 'cf-chl-bypass';
const NUMBER_OF_REQUESTED_TOKENS = 30;
const ISSUANCE_BODY_PARAM_NAME = 'blinded-tokens';

const COMMITMENT_URL =
    'https://raw.githubusercontent.com/privacypass/ec-commitments/master/commitments-p256.json';

const QUALIFIED_QUERY_PARAMS = ['__cf_chl_captcha_tk__', '__cf_chl_managed_tk__'];
const QUALIFIED_BODY_PARAMS = ['g-recaptcha-response', 'h-captcha-response', 'cf_captcha_kind'];

const CHL_BYPASS_SUPPORT = 'cf-chl-bypass';
const DEFAULT_ISSUING_HOSTNAME = 'captcha.website';

const VERIFICATION_KEY = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExf0AftemLr0YSz5odoj3eJv6SkOF
VcH7NNb2xwdEz6Pxm44tvovEl/E+si8hdIDVg1Ys+cbaWwP0jYJW3ygv+Q==
-----END PUBLIC KEY-----`;

interface RedeemInfo {
    requestId: string;
    token: Token;
}

export class CloudflareProvider extends Provider {
    static readonly ID: number = 1;

    static readonly EARNED_TOKEN_COOKIE: EarnedTokenCookie = {
        url:    `https://${DEFAULT_ISSUING_HOSTNAME}`,
        domain: `.${DEFAULT_ISSUING_HOSTNAME}`,
        name:   'cf_clearance'
    };

    private VOPRF:      voprf.VOPRF;
    private callbacks:  Callbacks;
    private storage:    Storage;
    private redeemInfo: RedeemInfo | null;

    constructor(storage: Storage, callbacks: Callbacks) {
        super(storage, callbacks);

        this.VOPRF      = new voprf.VOPRF(voprf.defaultECSettings);
        this.callbacks  = callbacks;
        this.storage    = storage;
        this.redeemInfo = null;
    }

    private getStoredTokens(): Token[] {
        const stored = this.storage.getItem(Provider.TOKEN_STORE_KEY);
        if (stored === null) {
            return [];
        }

        const tokens: string[] = JSON.parse(stored);
        return tokens.map((token) => Token.fromString(token));
    }

    private setStoredTokens(tokens: Token[]) {
        this.storage.setItem(
            Provider.TOKEN_STORE_KEY,
            JSON.stringify(tokens.map((token) => token.toString())),
        );
    }

    private async getCommitment(version: string): Promise<{ G: string; H: string }> {
        const keyPrefix = 'commitment-';
        const cached = this.storage.getItem(`${keyPrefix}${version}`);
        if (cached !== null) {
            return JSON.parse(cached);
        }

        interface Response {
            CF: { [version: string]: { H: string; expiry: string; sig: string } };
        }

        // Download the commitment
        const { data } = await axios.get<Response>(COMMITMENT_URL);
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
        this.VOPRF.verifyConfiguration(
            VERIFICATION_KEY,
            {
                H: commitment.H,
                expiry: commitment.expiry,
            },
            commitment.sig,
        );

        // Cache.
        const item = {
            G: voprf.sec1EncodeToBase64(this.VOPRF.getActiveECSettings().curve.G, false),
            H: commitment.H,
        };
        this.storage.setItem(`${keyPrefix}${version}`, JSON.stringify(item));
        return item;
    }

    private async issue(
        url: string,
        formData: { [key: string]: string[] | string },
    ): Promise<Token[]> {
        const tokens = Array.from(Array(NUMBER_OF_REQUESTED_TOKENS).keys()).map(() => new Token());
        const issuance = {
            type: 'Issue',
            contents: tokens.map((token) => token.getEncodedBlindedPoint()),
        };
        const param = btoa(JSON.stringify(issuance));

        const body = qs.stringify({
            ...formData,
            [ISSUANCE_BODY_PARAM_NAME]: param,
        });

        const headers = {
            'content-type': 'application/x-www-form-urlencoded',
            [ISSUE_HEADER_NAME]: CloudflareProvider.ID.toString(),
        };

        const response = await axios.post<string, { data: string }>(url, body, {
            headers,
            responseType: 'text',
        });

        const { signatures } = qs.parse(response.data);
        if (signatures === undefined) {
            throw new Error('There is no signatures parameter in the issuance response.');
        }
        if (typeof signatures !== 'string') {
            throw new Error('The signatures parameter in the issuance response is not a string.');
        }

        interface SignaturesParam {
            sigs: string[];
            version: string;
            proof: string;
            prng: string;
        }

        const data: SignaturesParam = JSON.parse(atob(signatures));
        const returned = this.VOPRF.getCurvePoints(data.sigs);

        const commitment = await this.getCommitment(data.version);

        const result = this.VOPRF.verifyProof(
            data.proof,
            tokens.map((token) => token.toLegacy()),
            returned,
            commitment,
            data.prng,
        );
        if (!result) {
            throw new Error('DLEQ proof is invalid.');
        }

        tokens.forEach((token, index) => {
            token.setSignedPoint(returned.points[index]);
        });

        return tokens;
    }

    private getBadgeText(): string {
        return this.getStoredTokens().length.toString();
    }

    forceUpdateIcon(): void {
        this.callbacks.updateIcon(this.getBadgeText());
    }

    handleActivated(): void {
        this.callbacks.updateIcon(this.getBadgeText());
    }

    handleBeforeSendHeaders(
        details: chrome.webRequest.WebRequestHeadersDetails,
    ): chrome.webRequest.BlockingResponse | void {
        if (this.redeemInfo === null || details.requestId !== this.redeemInfo.requestId) {
            return;
        }

        const url = new URL(details.url);

        const token = this.redeemInfo!.token;
        // Clear the redeem info to indicate that we are already redeeming the token.
        this.redeemInfo = null;

        const key = token.getMacKey();
        const binding = this.VOPRF.createRequestBinding(key, [
            voprf.getBytesFromString(url.hostname),
            voprf.getBytesFromString(details.method + ' ' + url.pathname),
        ]);

        const contents = [
            voprf.getBase64FromBytes(token.getInput()),
            binding,
            voprf.getBase64FromString(JSON.stringify(voprf.defaultECSettings)),
        ];
        const redemption = btoa(JSON.stringify({ type: 'Redeem', contents }));

        const headers = details.requestHeaders ?? [];
        headers.push({ name: 'challenge-bypass-token', value: redemption });

        this.callbacks.updateIcon(this.getBadgeText());

        return {
            requestHeaders: headers,
        };
    }

    handleBeforeRequest(
        details: chrome.webRequest.WebRequestBodyDetails,
    ): chrome.webRequest.BlockingResponse | void {
        const url = new URL(details.url);

        if (
            details.requestBody === null ||
            details.requestBody === undefined ||
            details.requestBody.formData === undefined
        ) {
            return;
        }

        const hasQueryParams = QUALIFIED_QUERY_PARAMS.some((param) => {
            return url.searchParams.has(param);
        });
        const hasBodyParams = QUALIFIED_BODY_PARAMS.some((param) => {
            return details.requestBody !== null && param in details.requestBody.formData!;
        });
        if (!hasQueryParams || !hasBodyParams) {
            return;
        }

        const flattenFormData: { [key: string]: string[] | string } = {};
        for (const key in details.requestBody.formData) {
            if (details.requestBody.formData[key].length == 1) {
                const [value] = details.requestBody.formData[key];
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

            this.callbacks.navigateUrl(`${url.origin}${url.pathname}`);
        })();

        // TODO I tried to use redirectUrl with data URL or text/html and text/plain but it didn't work, so I continue
        // cancelling the request. However, it seems that we can use image/* except image/svg+html. Let's figure how to
        // use image data URL later.
        // https://blog.mozilla.org/security/2017/11/27/blocking-top-level-navigations-data-urls-firefox-59/
        return { cancel: true };
    }

    handleHeadersReceived(
        details: chrome.webRequest.WebResponseHeadersDetails,
    ): chrome.webRequest.BlockingResponse | void {
        // Don't redeem a token in the issuing website.
        const url = new URL(details.url);
        if (url.host === DEFAULT_ISSUING_HOSTNAME) {
            return;
        }

        // Check if it's the response of the request that we should insert a token.
        if (details.statusCode !== 403 || details.responseHeaders === undefined) {
            return;
        }
        const hasSupportHeader = details.responseHeaders.some((header) => {
            return (
                header.name.toLowerCase() === CHL_BYPASS_SUPPORT &&
                header.value !== undefined &&
                parseInt(header.value, 10) === CloudflareProvider.ID
            );
        });
        if (!hasSupportHeader) {
            return;
        }

        // Let's try to redeem.

        // Get one token.
        const tokens = this.getStoredTokens();
        const token = tokens.shift();
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
