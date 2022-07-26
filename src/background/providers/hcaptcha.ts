import * as voprf from '../voprf';

import { Callbacks, Provider } from '.';
import Token from "../token";
import {Storage} from "../storage";
import axios from "axios";
import qs from "qs";


const COMMITMENT_URL = 'https://raw.githubusercontent.com/privacypass/ec-commitments/master/commitments-p256.json';
const SPEND_URLS = ["https://*.hcaptcha.com/getcaptcha", "https://*.hmt.ai/getcaptcha", "http://localhost/getcaptcha"];
const ISSUER_URLS = ["https://*.hcaptcha.com/checkcaptcha/*", "https://*.hmt.ai/checkcaptcha/*", "http://localhost/checkcaptcha/*"];

const NUMBER_OF_REQUESTED_TOKENS = 10
const MAXIMUN_NUMBER_OF_TOKENS = 100

const TOKEN_STORE_KEY = 'tokens';

interface IssueInfo {
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

    private issueInfo: IssueInfo | null;

    constructor(storage: Storage, callbacks: Callbacks) {

        this.issueInfo = null;
        this.callbacks = callbacks;
        this.storage = storage;
    }

    private patternToRegExp(pattern: string) {

        let split = /^(http|https):\/\/(.*)$/.exec(pattern);
        if (!split) throw Error("Invalid schema in " + pattern);
        const schema = split[1];
        const fullpath = split[2];
        split = /^([^/]*)\/(.*)$/.exec(fullpath);
        if (!split) throw Error("No path specified in " + pattern);
        const host = split[1];
        const path = split[2];

        if (host === "") {
            throw Error("No host specified in " + pattern);
        }

        if (!(/^(\*|\*\.[^*]+|[^*]*)$/.exec(host))) {
            throw Error("Illegal wildcard in host in " + pattern);
        }

        let reString = "^";
        reString += (schema === "*") ? "https*" : schema;
        reString += ":\\/\\/";
        // Not overly concerned with intricacies
        //   of domain name restrictions and IDN
        //   as we're not testing domain validity
        reString += host.replace(/\*\.?/, "[^\\/]*");
        reString += "(:\\d+)?";
        reString += "\\/";
        reString += path.replace("*", ".*");
        reString += "$";

        return RegExp(reString);
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

        const isIssuerUrl = ISSUER_URLS
            .map((issuerUrl) => this.patternToRegExp(issuerUrl))
            .some((re) => reqUrl.match(re));

        const isSpendUrl = SPEND_URLS
            .map((spendUrl) => this.patternToRegExp(spendUrl))
            .some((re) => reqUrl.match(re));

        return {
            reqUrl,
            isIssuerUrl,
            isSpendUrl
        }
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
        const commitment = data.HC[version as string];
        if (commitment === undefined) {
            throw new Error(`No commitment for the version ${version} is found`);
        }

        // Cache.
        const item = {
            G: voprf.sec1EncodeToBase64(voprf.getActiveECSettings().curve.G, false),
            H: commitment.H,
        };
        this.storage.setItem(`${keyPrefix}${version}`, JSON.stringify(item));
        return item;
    }

    private issue(url: string) {
        (async () => {
            const newTokens = Array.from(Array(NUMBER_OF_REQUESTED_TOKENS).keys()).map(() => new Token());
            const issuePayload = {
                type: 'Issue',
                contents: newTokens.map((token) => token.getEncodedBlindedPoint()),
            };
            const blindedTokens = btoa(JSON.stringify(issuePayload));
            const requestBody = `blinded-tokens=${blindedTokens}&captcha-bypass=true`;
            const headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "cf-chl-bypass": this.getID().toString()
            };

            const response = await axios.post<string, { data: string }>(url, requestBody, {
                headers,
                responseType: 'text',
            });
            console.info(response);

            const { signatures } = qs.parse(response.data);
            if (signatures === undefined) {
                throw new Error('There is no signatures parameter in the issuance response.');
            }
            if (typeof signatures !== 'string') {
                throw new Error('The signatures parameter in the issuance response is not a string.');
            }

            const data: SignaturesParam = JSON.parse(atob(signatures));
            const returned = voprf.getCurvePoints(data.sigs);

            console.info(returned, data, signatures)

            newTokens.forEach((token, index) => {
                token.setSignedPoint(returned.points[index as number]);
            });
            const oldTokens = this.getStoredTokens()
            this.setStoredTokens(oldTokens.concat(newTokens))
            this.forceUpdateIcon()
        })();
    }

    handleBeforeRequest(
        _details: chrome.webRequest.WebRequestBodyDetails,
    ): chrome.webRequest.BlockingResponse | void {
        return;
    }

    handleBeforeSendHeaders(
        details: chrome.webRequest.WebRequestHeadersDetails,
    ): chrome.webRequest.BlockingResponse | void {
        const url = new URL(details.url);
        const urlType = this.handleUrl(url);

        if (urlType.isIssuerUrl && details.method.toLowerCase() === "post") {
            this.issueInfo = null;

            // Do not store infinite tokens
            const tokens = this.getStoredTokens()
            if ((tokens.length + NUMBER_OF_REQUESTED_TOKENS) > MAXIMUN_NUMBER_OF_TOKENS) return;

            this.issueInfo = {
                newUrl: details.url,
                tabId: details.tabId,
            }
            return;

        } else if (urlType.isSpendUrl) {
            // spend logic here
            const tokens = this.getStoredTokens();
            const oneToken = tokens.shift();
            this.setStoredTokens(tokens);

            if (oneToken === undefined) {
                return;
            }

            const key = oneToken.getMacKey();
            const binding = voprf.createRequestBinding(key, [
                voprf.getBytesFromString(url.hostname),
                voprf.getBytesFromString(details.method + ' ' + url.pathname),
            ]);

            const contents = [
                voprf.getBase64FromBytes(oneToken.getInput()),
                binding,
                voprf.getBase64FromString(JSON.stringify(voprf.defaultECSettings)),
            ];
            const redemption = btoa(JSON.stringify({ type: 'Redeem', contents }));

            const headers = details.requestHeaders ?? [];
            headers.push({ name: 'challenge-bypass-token', value: redemption });
            console.info({oneToken, redemption})
            this.issueInfo = null;
        }
        return;
    }

    handleHeadersReceived(
        details: chrome.webRequest.WebResponseHeadersDetails,
    ): chrome.webRequest.BlockingResponse | void {
        if (details.responseHeaders === undefined) return;
        const url = new URL(details.url);
        const urlType = this.handleUrl(url);

        if (!urlType.isIssuerUrl) return;

        if (this.issueInfo === null) return;

        if (details.tabId !== this.issueInfo.tabId) return;

        // TODO: check if the captcha failed to not try to issue new tokens
        this.issue(this.issueInfo.newUrl)

        this.issueInfo = null;
        return;
    }
}
