import { Provider } from '.';

export class HcaptchaProvider implements Provider {
    static readonly ID: number = 2;

    getID(): number {
        return HcaptchaProvider.ID;
    }

    getBadgeText(): string {
        return 'N/A';
    }

    handleBeforeRequest(
        _details: chrome.webRequest.WebRequestBodyDetails,
    ): chrome.webRequest.BlockingResponse | void {
        return;
    }
    handleBeforeSendHeaders(
        _details: chrome.webRequest.WebRequestHeadersDetails,
    ): chrome.webRequest.BlockingResponse | void {
        return;
    }
    handleHeadersReceived(
        _details: chrome.webRequest.WebResponseHeadersDetails,
    ): chrome.webRequest.BlockingResponse | void {
        return;
    }
}
