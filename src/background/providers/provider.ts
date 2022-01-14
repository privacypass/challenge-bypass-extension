import { Storage } from '../storage';

export interface Callbacks {
    updateIcon(text: string): void;
    navigateUrl(url: string): void;
}

export interface EarnedTokenCookie {
   url:    string;
   domain: string;
   name:   string;
}

export abstract class Provider {
    static readonly ID: number;
    static readonly EARNED_TOKEN_COOKIE: EarnedTokenCookie | void;

    constructor(_storage: Storage, _callbacks: Callbacks){}

    abstract forceUpdateIcon(): void;
    abstract handleActivated(): void;
    abstract handleBeforeRequest(
        details: chrome.webRequest.WebRequestBodyDetails,
    ): chrome.webRequest.BlockingResponse | void;
    abstract handleHeadersReceived(
        details: chrome.webRequest.WebResponseHeadersDetails,
    ): chrome.webRequest.BlockingResponse | void;
    abstract handleBeforeSendHeaders(
        details: chrome.webRequest.WebRequestHeadersDetails,
    ): chrome.webRequest.BlockingResponse | void;
}
