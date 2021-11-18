import { Callbacks, Provider } from '.';

export class HcaptchaProvider implements Provider {
    static readonly ID: number = 2;
    private callbacks: Callbacks;

    constructor(callbacks: Callbacks) {
        this.callbacks = callbacks;
    }

    getID(): number {
        return HcaptchaProvider.ID;
    }

    private getBadgeText(): string {
        return 'N/A';
    }

    forceUpdateIcon(): void {
        this.callbacks.updateIcon(this.getBadgeText());
    }

    handleActivated(): void {
        this.callbacks.updateIcon(this.getBadgeText());
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
