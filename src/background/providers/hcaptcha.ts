import * as voprf from '../crypto/voprf';

import { Provider, EarnedTokenCookie, Callbacks, QUALIFIED_HOSTNAMES, QUALIFIED_PATHNAMES, QUALIFIED_PARAMS, isIssuingHostname, isQualifiedPathname, areQualifiedQueryParams, areQualifiedBodyFormParams } from './provider';
import { Storage } from '../storage';
import Token from '../token';
import axios from 'axios';
import qs from 'qs';

const NUMBER_OF_REQUESTED_TOKENS: number = 5;
const DEFAULT_ISSUING_HOSTNAME:   string = 'hcaptcha.com';
const CHL_BYPASS_SUPPORT:         string = 'cf-chl-bypass';
const ISSUE_HEADER_NAME:          string = 'cf-chl-bypass';
const ISSUANCE_BODY_PARAM_NAME:   string = 'blinded-tokens';

const COMMITMENT_URL: string =
    'https://raw.githubusercontent.com/privacypass/ec-commitments/master/commitments-p256.json';

const ALL_ISSUING_CRITERIA: {
    HOSTNAMES:    QUALIFIED_HOSTNAMES;
    PATHNAMES:    QUALIFIED_PATHNAMES;
    QUERY_PARAMS: QUALIFIED_PARAMS;
    BODY_PARAMS:  QUALIFIED_PARAMS;
} = {
    HOSTNAMES: {
        exact :   [DEFAULT_ISSUING_HOSTNAME],
        contains: [`.${DEFAULT_ISSUING_HOSTNAME}`],
    },
    PATHNAMES: {
        contains: ['/checkcaptcha'],
    },
    QUERY_PARAMS: {
        some: ['s=00000000-0000-0000-0000-000000000000'],
    },
    BODY_PARAMS: {
    }
}

const VERIFICATION_KEY: string = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4OifvSTxGcy3T/yac6LVugArFb89
wvqGivp0/54wgeyWkvUZiUdlbIQF7BuGeO9C4sx4nHkpAgRfvd8jdBGz9g==
-----END PUBLIC KEY-----`;

interface RedeemInfo {
    requestId: string;
    token: Token;
}

export class HcaptchaProvider extends Provider {
    static readonly ID: number = 2;

    static readonly EARNED_TOKEN_COOKIE: EarnedTokenCookie = {
        url:    `https://www.${DEFAULT_ISSUING_HOSTNAME}/privacy-pass`,
        domain: `.${DEFAULT_ISSUING_HOSTNAME}`,
        name:   'hc_clearance'
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
        return tokens.map((token) => Token.fromString(token, this.VOPRF));
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
            HC: { [version: string]: { H: string; expiry: string; sig: string } };
        }

        // Download the commitment
        const { data } = await axios.get<Response>(COMMITMENT_URL);
        const commitment = data.HC[version];
        if (commitment === undefined) {
            throw new Error(`No commitment for the version ${version} is found`);
        }

        // Check the expiry date.
        const expiry: number = (new Date(commitment.expiry)).getTime();
        if (Date.now() >= expiry) {
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
        const tokens = Array.from(Array(NUMBER_OF_REQUESTED_TOKENS).keys()).map(() => new Token(this.VOPRF));
        const issuance = {
            type: 'Issue',
            contents: tokens.map((token) => token.getEncodedBlindedPoint()),
        };
        const param = btoa(JSON.stringify(issuance));

        const body = qs.stringify({
            ...formData,
            [ISSUANCE_BODY_PARAM_NAME]: param,
            'captcha-bypass': true,
        });

        const headers = {
            'accept':            'application/json',
            'content-type':      'application/x-www-form-urlencoded',
            [ISSUE_HEADER_NAME]: HcaptchaProvider.ID.toString(),
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
            sigs:    string[];
            version: string;
            proof:   string;
            prng:    string;
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
        // Only issue tokens for POST requests that contain 'application/x-www-form-urlencoded' data.
        if (
            details.requestBody === null ||
            details.requestBody === undefined
        ) {
            return;
        }

        const url = new URL(details.url);
        const formData: { [key: string]: string[] | string } = details.requestBody.formData || {};

        // Only issue tokens on the issuing website.
        if (!isIssuingHostname(ALL_ISSUING_CRITERIA.HOSTNAMES, url)) {
            return;
        }

        // Only issue tokens when the pathname passes defined criteria.
        if (!isQualifiedPathname(ALL_ISSUING_CRITERIA.PATHNAMES, url)) {
            return;
        }

        // Only issue tokens when querystring parameters pass defined criteria.
        if (!areQualifiedQueryParams(ALL_ISSUING_CRITERIA.QUERY_PARAMS, url)) {
            return;
        }

        // Only issue tokens when POST data parameters pass defined criteria.
        if (!areQualifiedBodyFormParams(ALL_ISSUING_CRITERIA.BODY_PARAMS, formData)) {
            return;
        }

        const flattenFormData: { [key: string]: string[] | string } = {};
        for (const key in formData) {
            if (Array.isArray(formData[key]) && (formData[key].length === 1)) {
                const [value] = formData[key];
                flattenFormData[key] = value;
            } else {
                flattenFormData[key] = formData[key];
            }
        }

        // delay the request to issue tokens until next tick of the event loop
        setTimeout(
            async () => {
                // Issue tokens.
                const tokens = await this.issue(details.url, flattenFormData);
                // Store tokens.
                const cached = this.getStoredTokens();
                this.setStoredTokens(cached.concat(tokens));

                this.callbacks.navigateUrl(`${url.origin}${url.pathname}`);
            },
            0
        );

        // do NOT cancel the original captcha solve request
        return { cancel: false };
    }

    handleHeadersReceived(
        details: chrome.webRequest.WebResponseHeadersDetails,
    ): chrome.webRequest.BlockingResponse | void {
        // Don't redeem a token on the issuing website.
        if (isIssuingHostname(ALL_ISSUING_CRITERIA.HOSTNAMES, new URL(details.url))) {
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
                parseInt(header.value, 10) === HcaptchaProvider.ID
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
