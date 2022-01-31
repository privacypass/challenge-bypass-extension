import * as voprf from '../crypto/voprf';

import { Provider, EarnedTokenCookie, Callbacks, QUALIFIED_HOSTNAMES, QUALIFIED_PATHNAMES, QUALIFIED_PARAMS, isIssuingHostname, isQualifiedPathname, areQualifiedQueryParams, areQualifiedBodyFormParams, getNormalizedFormData } from './provider';
import { Storage } from '../storage';
import Token from '../token';
import axios from 'axios';
import qs from 'qs';

const NUMBER_OF_REQUESTED_TOKENS: number = 30;
const DEFAULT_ISSUING_HOSTNAME:   string = 'captcha.website';
const CHL_BYPASS_SUPPORT:         string = 'cf-chl-bypass';
const ISSUE_HEADER_NAME:          string = 'cf-chl-bypass';
const ISSUANCE_BODY_PARAM_NAME:   string = 'blinded-tokens';

const COMMITMENT_URL: string =
    'https://raw.githubusercontent.com/privacypass/ec-commitments/master/commitments-p256.json';

const ALL_ISSUING_CRITERIA: {
    HOSTNAMES:    QUALIFIED_HOSTNAMES | void;
    PATHNAMES:    QUALIFIED_PATHNAMES | void;
    QUERY_PARAMS: QUALIFIED_PARAMS    | void;
    BODY_PARAMS:  QUALIFIED_PARAMS    | void;
} = {
    HOSTNAMES: {
        exact :   [DEFAULT_ISSUING_HOSTNAME],
        contains: [`.${DEFAULT_ISSUING_HOSTNAME}`],
    },
    PATHNAMES: {
        exact :   ['/'],
    },
    QUERY_PARAMS: {
        some:     ['__cf_chl_captcha_tk__', '__cf_chl_managed_tk__'],
    },
    BODY_PARAMS: {
        some:     ['g-recaptcha-response', 'h-captcha-response', 'cf_captcha_kind'],
    },
}

const VERIFICATION_KEY: string = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExf0AftemLr0YSz5odoj3eJv6SkOF
VcH7NNb2xwdEz6Pxm44tvovEl/E+si8hdIDVg1Ys+cbaWwP0jYJW3ygv+Q==
-----END PUBLIC KEY-----`;

interface IssueInfo {
    requestId: string;
    url:       string;
    formData:  { [key: string]: string[] | string };
}

interface RedeemInfo {
    requestId: string;
    token: Token;
}

export class CloudflareProvider extends Provider {
    static readonly ID: number = 1;

    static readonly EARNED_TOKEN_COOKIE: EarnedTokenCookie = {
        url:    `https://${DEFAULT_ISSUING_HOSTNAME}/`,
        domain: `.${DEFAULT_ISSUING_HOSTNAME}`,
        name:   'cf_clearance'
    };

    private VOPRF:      voprf.VOPRF;
    private callbacks:  Callbacks;
    private storage:    Storage;
    private issueInfo:  IssueInfo | null;
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

        if (this.matchesIssuingBodyCriteria(details)) {
            // do NOT cancel the request with captcha solution.
            // note: "handleBeforeSendHeaders" will cancel this request if additional criteria are satisfied.
            return { cancel: false };
        }
    }

    private matchesIssuingBodyCriteria(
        details: chrome.webRequest.WebRequestBodyDetails,
    ): boolean {

        // Only issue tokens for POST requests that contain data in body.
        if (
            (details.method.toUpperCase() !== 'POST'   ) ||
            (details.requestBody          === null     ) ||
            (details.requestBody          === undefined)
        ) {
            return false;
        }

        const url: URL = new URL(details.url);

        // Only issue tokens to hosts belonging to the provider.
        if (!isIssuingHostname(ALL_ISSUING_CRITERIA.HOSTNAMES, url)) {
            return false;
        }

        // Only issue tokens when the pathname passes defined criteria.
        if (!isQualifiedPathname(ALL_ISSUING_CRITERIA.PATHNAMES, url)) {
            return false;
        }

        const formData: { [key: string]: string[] | string } = getNormalizedFormData(details, /* flatten= */ true);

        // Only issue tokens when 'application/x-www-form-urlencoded' or 'application/json' data parameters in POST body pass defined criteria.
        if (!areQualifiedBodyFormParams(ALL_ISSUING_CRITERIA.BODY_PARAMS, formData)) {
            return false;
        }

        this.issueInfo = { requestId: details.requestId, url: details.url, formData };

        return true;
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
                parseInt(header.value, 10) === CloudflareProvider.ID
            );
        });
        if (!hasSupportHeader) {
            return;
        }

        // Redeem one token (if available)

        const tokens = this.getStoredTokens();
        const token = tokens.shift();
        this.setStoredTokens(tokens);

        // No tokens in wallet!
        if (token === undefined) {
            return;
        }

        this.redeemInfo = { requestId: details.requestId, token };

        // Redirect to resend the request attached with the token.
        return {
            redirectUrl: details.url,
        };
    }

    handleBeforeSendHeaders(
        details: chrome.webRequest.WebRequestHeadersDetails,
    ): chrome.webRequest.BlockingResponse | void {

        if (
            (this.issueInfo           !== null) &&
            (this.issueInfo.requestId === details.requestId)
        ) {
            if (this.matchesIssuingHeadersCriteria(details)) {
                this.triggerIssueRequest(details.requestId);

                // cancel the request with captcha solution.
                return { cancel: true };
            }
            else {
                // Clear the issue info.
                this.issueInfo = null;
            }
        }

        return this.redeemToken(details);
    }

    private redeemToken(
        details: chrome.webRequest.WebRequestHeadersDetails,
    ): chrome.webRequest.BlockingResponse | void {
        if (
            (this.redeemInfo === null) ||
            (this.redeemInfo.requestId !== details.requestId)
        ) {
            return;
        }

        const token = this.redeemInfo!.token;

        // Clear the redeem info.
        this.redeemInfo = null;

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
        headers.push({ name: 'challenge-bypass-token', value: redemption });

        return {requestHeaders: headers};
    }

    private matchesIssuingHeadersCriteria(
        details: chrome.webRequest.WebRequestHeadersDetails,
    ): boolean {
        let href: string;
        let url:  URL;

        if (
            (this.issueInfo === null) ||
            (this.issueInfo.requestId !== details.requestId)
        ) {
            return false;
        }

        href = this.issueInfo.url;
        url  = new URL(href);

        // Only issue tokens when querystring parameters pass defined criteria.
        if (areQualifiedQueryParams(ALL_ISSUING_CRITERIA.QUERY_PARAMS, url)) {
            return true;
        }

        if (details.requestHeaders) {
            const ref_header = details.requestHeaders.find(h => (h !== undefined) && h.name && h.value && (h.name.toLowerCase() === 'referer'));

            if (ref_header !== undefined) {
                href = ref_header.value!.replace(/([\?&])(?:__cf_chl_tk)([=])/ig, ('$1' + '__cf_chl_captcha_tk__' + '$2'));
                url  = new URL(href);

                // Only issue tokens when querystring parameters pass defined criteria.
                if (areQualifiedQueryParams(ALL_ISSUING_CRITERIA.QUERY_PARAMS, url)) {
                    this.issueInfo.url = href;
                    return true;
                }
            }
        }

        return false;
    }

    private triggerIssueRequest(requestId: string): void {
        // Is the current (cancelled) request a trigger to initiate a secondary request to the provider for the issuing of signed tokens?
        if (
            (this.issueInfo           !== null) &&
            (this.issueInfo.requestId === requestId)
        ) {
            const issueInfo: IssueInfo = { ...this.issueInfo };

            // Clear the issue info.
            this.issueInfo = null;

            setTimeout(
                (): void => {
                    this.sendIssueRequest(issueInfo.url, issueInfo.formData);
                },
                0
            );
        }
    }

    private async sendIssueRequest(
        url:      string,
        formData: { [key: string]: string[] | string },
    ): Promise<void> {
        try {
            // Issue tokens.
            const tokens = await this.issue(url, formData);

            // Store tokens.
            const cached = this.getStoredTokens();
            this.setStoredTokens(cached.concat(tokens));
        }
        catch(error: any) {
            console.error(error.message);
        }

        this.callbacks.navigateUrl(CloudflareProvider.EARNED_TOKEN_COOKIE.url);
    }

    private async issue(
        url:      string,
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
        });

        const headers = {
            'accept':            'application/json',
            'content-type':      'application/x-www-form-urlencoded',
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
            CF: { [version: string]: { G: string; H: string } | { H: string; expiry: string; sig: string } };
        }

        // Download the commitment
        const { data } = await axios.get<Response>(COMMITMENT_URL);
        const commitment = data.CF[version];
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

    handleOnCompleted(
        _details: chrome.webRequest.WebResponseHeadersDetails,
    ): void {
        return;
    }

    handleOnErrorOccurred(
        _details: chrome.webRequest.WebResponseErrorDetails,
    ): void {
        return;
    }
}
