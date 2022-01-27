import * as voprf from '../crypto/voprf';

import { Provider, EarnedTokenCookie, Callbacks, QUALIFIED_HOSTNAMES, QUALIFIED_PATHNAMES, QUALIFIED_PARAMS, isIssuingHostname, isQualifiedPathname, areQualifiedQueryParams, areQualifiedBodyFormParams } from './provider';
import { Storage } from '../storage';
import Token from '../token';
import axios from 'axios';
import qs from 'qs';

const NUMBER_OF_REQUESTED_TOKENS: number = 5;
const DEFAULT_ISSUING_HOSTNAME:   string = 'hcaptcha.com';
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

const ALL_REDEMPTION_CRITERIA: {
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
        contains: ['/getcaptcha'],
    },
    QUERY_PARAMS: {
        some: ['s!=00000000-0000-0000-0000-000000000000'],
    },
    BODY_PARAMS: {
        every: ['sitekey!=00000000-0000-0000-0000-000000000000', 'motionData', 'host!=www.hcaptcha.com'],
    }
}

const VERIFICATION_KEY: string = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4OifvSTxGcy3T/yac6LVugArFb89
wvqGivp0/54wgeyWkvUZiUdlbIQF7BuGeO9C4sx4nHkpAgRfvd8jdBGz9g==
-----END PUBLIC KEY-----`;

interface IssueInfo {
    requestId: string;
    url:       string;
}

interface RedeemInfo {
    requestId: string;
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
    private issueInfo:  IssueInfo  | null;
    private redeemInfo: RedeemInfo | null;

    constructor(storage: Storage, callbacks: Callbacks) {
        super(storage, callbacks);

        this.VOPRF      = new voprf.VOPRF(voprf.defaultECSettings);
        this.callbacks  = callbacks;
        this.storage    = storage;
        this.issueInfo  = null;
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

        this.forceUpdateIcon();
    }

    private getBadgeText(): string {
        return this.getStoredTokens().length.toString();
    }

    forceUpdateIcon(): void {
        this.callbacks.updateIcon(this.getBadgeText());
    }

    handleActivated(): void {
        this.forceUpdateIcon();
    }

    handleBeforeRequest(
        details: chrome.webRequest.WebRequestBodyDetails,
    ): chrome.webRequest.BlockingResponse | void {
        const url = new URL(details.url);
        const formData: { [key: string]: string[] | string } = (details.requestBody && details.requestBody.formData)
            ? details.requestBody.formData
            : {}
        ;

        if (this.matchesIssuingCriteria(details, url, formData)) {
            this.issueInfo = { requestId: details.requestId, url: details.url };

            // do NOT cancel the request with captcha solution.
            return { cancel: false };
        }

        if (this.matchesRedemptionCriteria(details, url, formData)) {
            this.redeemInfo = { requestId: details.requestId };

            // do NOT cancel the request to generate a new captcha.
            // note: "handleBeforeSendHeaders" will add request headers to embed a token.
            return { cancel: false };
        }
    }

    private matchesIssuingCriteria(
        details:  chrome.webRequest.WebRequestBodyDetails,
        url:      URL,
        formData: { [key: string]: string[] | string }
    ): boolean {
        // Only issue tokens for POST requests that contain data in body.
        if (
            (details.method.toUpperCase() !== 'POST'   ) ||
            (details.requestBody          === null     ) ||
            (details.requestBody          === undefined)
        ) {
            return false;
        }

        // Only issue tokens to hosts belonging to the provider.
        if (!isIssuingHostname(ALL_ISSUING_CRITERIA.HOSTNAMES, url)) {
            return false;
        }

        // Only issue tokens when the pathname passes defined criteria.
        if (!isQualifiedPathname(ALL_ISSUING_CRITERIA.PATHNAMES, url)) {
            return false;
        }

        // Only issue tokens when querystring parameters pass defined criteria.
        if (!areQualifiedQueryParams(ALL_ISSUING_CRITERIA.QUERY_PARAMS, url)) {
            return false;
        }

        // Only issue tokens when 'application/x-www-form-urlencoded' data parameters in POST body pass defined criteria.
        if (!areQualifiedBodyFormParams(ALL_ISSUING_CRITERIA.BODY_PARAMS, formData)) {
            return false;
        }

        return true;
    }

    private matchesRedemptionCriteria(
        details:  chrome.webRequest.WebRequestBodyDetails,
        url:      URL,
        formData: { [key: string]: string[] | string }
    ): boolean {
        // Only redeem tokens for POST requests that contain data in body.
        if (
            (details.method.toUpperCase() !== 'POST'   ) ||
            (details.requestBody          === null     ) ||
            (details.requestBody          === undefined)
        ) {
            return false;
        }

        // Only redeem tokens to hosts belonging to the provider.
        if (!isIssuingHostname(ALL_REDEMPTION_CRITERIA.HOSTNAMES, url)) {
            return false;
        }

        // Only redeem tokens when the pathname passes defined criteria.
        if (!isQualifiedPathname(ALL_REDEMPTION_CRITERIA.PATHNAMES, url)) {
            return false;
        }

        // Only redeem tokens when querystring parameters pass defined criteria.
        if (!areQualifiedQueryParams(ALL_REDEMPTION_CRITERIA.QUERY_PARAMS, url)) {
            return false;
        }

        // Only redeem tokens when 'application/x-www-form-urlencoded' data parameters in POST body pass defined criteria.
        if (!areQualifiedBodyFormParams(ALL_REDEMPTION_CRITERIA.BODY_PARAMS, formData)) {
            return false;
        }

        return true;
    }

    handleBeforeSendHeaders(
        details: chrome.webRequest.WebRequestHeadersDetails,
    ): chrome.webRequest.BlockingResponse | void {
        if (
            (this.redeemInfo === null) ||
            (this.redeemInfo.requestId !== details.requestId)
        ) {
            return;
        }

        // Clear the redeem info.
        this.redeemInfo = null;

        // Redeem one token (if available)

        const tokens = this.getStoredTokens();
        const token = tokens.shift();
        this.setStoredTokens(tokens);

        // No tokens in wallet!
        if (token === undefined) {
            return;
        }

        const url = new URL(details.url);
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
        headers.push(
            { name: 'challenge-bypass-host',  value: 'hcaptcha.com'     },
            { name: 'challenge-bypass-path',  value: 'POST /getcaptcha' },
            { name: 'challenge-bypass-token', value: redemption         },
        );

        return {
            requestHeaders: headers,
        };
    }

    handleHeadersReceived(
        _details: chrome.webRequest.WebResponseHeadersDetails,
    ): chrome.webRequest.BlockingResponse | void {
        return;
    }

    handleOnCompleted(
        details: chrome.webRequest.WebResponseHeadersDetails,
    ): void {
        this.sendIssueRequest(details.requestId);
    }

    handleOnErrorOccurred(
        details: chrome.webRequest.WebResponseErrorDetails,
    ): void {
        this.sendIssueRequest(details.requestId);
    }

    private sendIssueRequest(requestId: string): void {
        // Is the completed request a trigger to initiate a secondary request to the provider for the issuing of signed tokens?
        if (
            (this.issueInfo           !== null) &&
            (this.issueInfo.requestId === requestId)
        ) {
            const url: string = this.issueInfo!.url;

            // Clear the issue info.
            this.issueInfo = null;

            (async () => {
                // Issue tokens.
                const tokens = await this.issue(url);

                // Store tokens.
                const cached = this.getStoredTokens();
                this.setStoredTokens(cached.concat(tokens));

                this.callbacks.navigateUrl(HcaptchaProvider.EARNED_TOKEN_COOKIE.url);
            })();
        }
    }

    private async issue(
        url: string,
    ): Promise<Token[]> {
        const tokens = Array.from(Array(NUMBER_OF_REQUESTED_TOKENS).keys()).map(() => new Token(this.VOPRF));
        const issuance = {
            type: 'Issue',
            contents: tokens.map((token) => token.getEncodedBlindedPoint()),
        };
        const param = btoa(JSON.stringify(issuance));

        const body = qs.stringify({
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
            prng?:   string;
        }

        const data: SignaturesParam = JSON.parse(atob(signatures));
        const returned = this.VOPRF.getCurvePoints(data.sigs);

        const commitment = await this.getCommitment(data.version);

        const result = this.VOPRF.verifyProof(
            data.proof,
            tokens.map((token) => token.toLegacy()),
            returned,
            commitment,
            data.prng || 'shake',
        );
        if (!result) {
            throw new Error('DLEQ proof is invalid.');
        }

        tokens.forEach((token, index) => {
            token.setSignedPoint(returned.points[index]);
        });

        return tokens;
    }

    private async getCommitment(version: string): Promise<{ G: string; H: string }> {
        const keyPrefix = 'commitment-';
        const cached = this.storage.getItem(`${keyPrefix}${version}`);
        if (cached !== null) {
            return JSON.parse(cached);
        }

        interface Response {
            HC: { [version: string]: { G: string; H: string } | { H: string; expiry: string; sig: string } };
        }

        // Download the commitment
        const { data } = await axios.get<Response>(COMMITMENT_URL);
        const commitment = data.HC[version];
        if (commitment === undefined) {
            throw new Error(`No commitment for the version ${version} is found`);
        }

        let item: { G: string; H: string };

        // Does the commitment require verification?
        if ('G' in commitment) {
            item = commitment;
        }
        else {
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

            item = {
                G: voprf.sec1EncodeToBase64(this.VOPRF.getActiveECSettings().curve.G, false),
                H: commitment.H,
            };
        }

        // Cache.
        this.storage.setItem(`${keyPrefix}${version}`, JSON.stringify(item));

        return item;
    }
}
