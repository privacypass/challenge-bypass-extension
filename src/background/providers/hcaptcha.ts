import * as voprf from '../voprf';

import { Callbacks, Provider } from '.';
import Token from '../token';
import { Storage } from '../storage';
import qs from 'qs';

const COMMITMENT_URL =
    'https://raw.githubusercontent.com/privacypass/ec-commitments/master/commitments-p256.json';
const SPEND_REGEX = RegExp('^https:\\/\\/(.+\\.)*hcaptcha.com\\/getcaptcha\\/(.*)$');
const ISSUER_REGEX = RegExp('^https:\\/\\/(.+\\.)*hcaptcha.com\\/checkcaptcha\\/(.*)$');
const NON_SPEND_HCAPTCHA_URLS = [
    'https://hcaptcha.com/getcaptcha/00000000-0000-0000-0000-000000000000',
    'https://hcaptcha.com/getcaptcha/10000000-ffff-ffff-ffff-000000000001',
    'https://hcaptcha.com/getcaptcha/20000000-ffff-ffff-ffff-000000000002',
    'https://hcaptcha.com/getcaptcha/30000000-ffff-ffff-ffff-000000000003',
];

const NUMBER_OF_REQUESTED_TOKENS = 5;
const MAX_NUM_OF_TOKENS = 100;

const TOKEN_STORE_KEY = 'tokens';

export interface IssueInfo {
    newUrl: string;
    tabId: number;
}

interface SignaturesParam {
    sigs: string[];
    version: string;
    proof: string;
    prng: string;
}

export class HcaptchaProvider implements Provider {
    static readonly ID: number = 2;
    private callbacks: Callbacks;
    private storage: Storage;

    protected issueInfo: IssueInfo | null;

    constructor(storage: Storage, callbacks: Callbacks) {
        voprf.initECSettings(voprf.defaultECSettings);
        this.issueInfo = null;
        this.callbacks = callbacks;
        this.storage = storage;
    }

    private getStoredTokens(): Token[] {
        const stored = this.storage.getItem(TOKEN_STORE_KEY);
        if (stored === null) {
            return [];
        }

        const tokens: string[] = JSON.parse(stored);
        return tokens.map((token) => Token.fromString(token));
    }

    private setStoredTokens(tokens: Token[]) {
        this.storage.setItem(
            TOKEN_STORE_KEY,
            JSON.stringify(tokens.map((token) => token.toString())),
        );
    }

    getID(): number {
        return HcaptchaProvider.ID;
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

    private handleUrl(url: URL) {
        const reqUrl = url.origin + url.pathname;
        const isIssuerUrl = ISSUER_REGEX.test(reqUrl);

        // test if the URL is not a special hCaptcha url, and if it a valid spend URL.
        const isSpendUrl = !NON_SPEND_HCAPTCHA_URLS.includes(reqUrl) && SPEND_REGEX.test(reqUrl);

        return {
            reqUrl,
            isIssuerUrl,
            isSpendUrl,
        };
    }

    private async getCommitment(version: string): Promise<{ G: string; H: string }> {
        const key = `commitment-${version}`;
        const cached = this.storage.getItem(key);
        if (cached !== null) {
            return JSON.parse(cached);
        }

        interface Response {
            HC: { [version: string]: { G: string; H: string; expiry: string; sig: string } };
        }

        // Download the commitment
        const data: Response = await fetch(COMMITMENT_URL).then((r) => r.json());
        const commitment = data.HC[version as string];
        if (commitment === undefined) {
            throw new Error(`No commitment for the version ${version} is found`);
        }

        // Cache.
        const item = {
            G: commitment.G ?? voprf.sec1EncodeToBase64(voprf.getActiveECSettings().curve.G, false),
            H: commitment.H,
        };
        this.storage.setItem(key, JSON.stringify(item));
        return item;
    }

    private async issue(url: string) {
        const newTokens = Array(NUMBER_OF_REQUESTED_TOKENS).fill(new Token());
        const issuePayload = {
            type: 'Issue',
            contents: newTokens.map((token) => token.getEncodedBlindedPoint()),
        };
        const blindedTokens = btoa(JSON.stringify(issuePayload));
        const requestBody = `blinded-tokens=${blindedTokens}&captcha-bypass=true`;
        const headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'cf-chl-bypass': this.getID().toString(),
        };

        const response = await fetch(url, {
            method: 'POST',
            body: requestBody,
            headers,
        }).then((r) => r.text());

        const { signatures } = qs.parse(response);
        if (signatures === undefined) {
            throw new Error('There is no signatures parameter in the issuance response.');
        }
        if (typeof signatures !== 'string') {
            throw new Error('The signatures parameter in the issuance response is not a string.');
        }

        const data: SignaturesParam = JSON.parse(atob(signatures));
        const returned = voprf.getCurvePoints(data.sigs);
        const commitment = await this.getCommitment(data.version);
        const prng = data.prng || 'shake';

        const result = voprf.verifyProof(
            data.proof,
            newTokens.map((token) => token.toLegacy()),
            returned,
            commitment,
            prng,
        );

        if (!result) {
            throw new Error('DLEQ proof is invalid.');
        }

        newTokens.forEach((token, index) => {
            token.setSignedPoint(returned.points[index as number]);
        });
        const oldTokens = this.getStoredTokens();
        this.setStoredTokens(oldTokens.concat(newTokens));
        this.forceUpdateIcon();
    }

    handleBeforeRequest(
        _details: chrome.webRequest.WebRequestBodyDetails,
    ): chrome.webRequest.BlockingResponse | void {
        return;
    }

    handleBeforeSendHeaders(
        details: chrome.webRequest.WebRequestHeadersDetails,
    ): chrome.webRequest.BlockingResponse | void {
        if (details.method.toLowerCase() !== 'post') return;

        const url = new URL(details.url);
        const urlType = this.handleUrl(url);

        if (urlType.isIssuerUrl) {
            // Erase any previous attempt
            this.issueInfo = null;

            // Do not store infinite tokens
            const tokens = this.getStoredTokens();
            if (tokens.length + NUMBER_OF_REQUESTED_TOKENS > MAX_NUM_OF_TOKENS) return;

            this.issueInfo = {
                newUrl: details.url,
                tabId: details.tabId,
            };
        } else if (urlType.isSpendUrl) {
            // Get one token
            const tokens = this.getStoredTokens();
            const oneToken = tokens.shift();
            if (oneToken === undefined) return;
            this.setStoredTokens(tokens);
            this.forceUpdateIcon();

            // Spend logic here
            const httpPath = `${details.method} ${url.pathname}`;
            const binding = voprf.createRequestBinding(oneToken.getMacKey(), [
                voprf.getBytesFromString(url.hostname),
                voprf.getBytesFromString(httpPath),
            ]);
            const contents = [
                voprf.getBase64FromBytes(oneToken.getInput()),
                binding,
                voprf.getBase64FromString(JSON.stringify(voprf.defaultECSettings)),
            ];
            const redemption = btoa(JSON.stringify({ type: 'Redeem', contents }));

            const headers = details.requestHeaders ?? [];
            headers.push({ name: 'challenge-bypass-token', value: redemption });
            headers.push({ name: 'challenge-bypass-host', value: url.hostname });
            headers.push({ name: 'challenge-bypass-path', value: httpPath });

            this.issueInfo = null;
            return {
                requestHeaders: headers,
            };
        }
        return;
    }

    handleHeadersReceived(
        details: chrome.webRequest.WebResponseHeadersDetails,
    ): chrome.webRequest.BlockingResponse | void {
        const url = new URL(details.url);
        const urlType = this.handleUrl(url);
        // wrong url or invalid status code
        if (!urlType.isIssuerUrl || details.statusCode === 403) return;

        // issueInfo was not loaded or the tab changed
        if (this.issueInfo === null || details.tabId !== this.issueInfo.tabId) return;

        this.issue(this.issueInfo.newUrl).then();

        this.issueInfo = null;
        return;
    }
}
