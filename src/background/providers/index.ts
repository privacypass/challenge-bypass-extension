export { CloudflareProvider } from './cloudflare';
export { HcaptchaProvider } from './hcaptcha';

export interface Provider {
    getID(): number;
    forceUpdateIcon(): void;
    handleBeforeRequest(
        details: chrome.webRequest.WebRequestBodyDetails,
    ): chrome.webRequest.BlockingResponse | void;
    handleHeadersReceived(
        details: chrome.webRequest.WebResponseHeadersDetails,
    ): chrome.webRequest.BlockingResponse | void;
    handleBeforeSendHeaders(
        details: chrome.webRequest.WebRequestHeadersDetails,
    ): chrome.webRequest.BlockingResponse | void;
    handleActivated(): void;
}

export interface Callbacks {
    updateIcon(text: string): void;
    navigateUrl(url: string): void;
}
