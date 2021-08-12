export { CloudflareProvider } from './cloudflare';
export { HcaptchaProvider } from './hcaptcha';

export interface Provider {
    getID(): number;
    getBadgeText(): string;
    handleBeforeRequest(
        details: chrome.webRequest.WebRequestBodyDetails,
    ): chrome.webRequest.BlockingResponse | void;
    handleHeadersReceived(
        details: chrome.webRequest.WebResponseHeadersDetails,
    ): chrome.webRequest.BlockingResponse | void;
    handleBeforeSendHeaders(
        details: chrome.webRequest.WebRequestHeadersDetails,
    ): chrome.webRequest.BlockingResponse | void;
}
