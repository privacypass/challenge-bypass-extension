import { Provider, EarnedTokenCookie, Callbacks } from './provider';
import { Storage } from '../storage';

export class HcaptchaProvider extends Provider {
    static readonly ID: number = 2;

    static readonly EARNED_TOKEN_COOKIE: EarnedTokenCookie = {
        url:    'https://www.hcaptcha.com/privacy-pass',
        domain: '.hcaptcha.com',
        name:   'hc_clearance'
    };

    private callbacks: Callbacks;
//  private storage:   Storage;

    constructor(storage: Storage, callbacks: Callbacks) {
        super(storage, callbacks);

        this.callbacks = callbacks;
//      this.storage   = storage;
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
