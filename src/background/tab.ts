import { CloudflareProvider, HcaptchaProvider, Provider } from './providers';
import { Storage } from './storage';

// Header from server to indicate that Privacy Pass is supported.
const CHL_BYPASS_SUPPORT = 'cf-chl-bypass';

export class Tab {
    private context: Provider | null;
    /* private */ chromeTabId: number;
    /* private */ active: boolean;

    constructor(tabId: number) {
        this.context = null;
        this.chromeTabId = tabId;
        this.active = false;
    }

    private updateIcon(): void {
        if (this.context !== null) {
            const text = this.context.getBadgeText();
            chrome.browserAction.setIcon({ path: 'icons/32/gold.png' });
            chrome.browserAction.setBadgeText({ text });
        } else {
            chrome.browserAction.setIcon({ path: 'icons/32/grey.png' });
            chrome.browserAction.setBadgeText({ text: '' });
        }
    }

    handleActivated(): void {
        this.active = true;
        this.updateIcon();
    }

    handleDeactivated(): void {
        this.active = false;
    }

    handleBeforeRequest(
        details: chrome.webRequest.WebRequestBodyDetails,
    ): chrome.webRequest.BlockingResponse | void {
        let result;
        if (this.context !== null) {
            result = this.context.handleBeforeRequest(details);
        }

        return result;
    }

    handleBeforeSendHeaders(
        details: chrome.webRequest.WebRequestHeadersDetails,
    ): chrome.webRequest.BlockingResponse | void {
        let result;
        if (this.context !== null) {
            result = this.context.handleBeforeSendHeaders(details);
        }

        return result;
    }

    handleHeadersReceived(
        details: chrome.webRequest.WebResponseHeadersDetails,
    ): chrome.webRequest.BlockingResponse | void {
        if (details.responseHeaders === undefined) {
            return;
        }
        const [providerId] = details.responseHeaders
            .filter((header) => header.name.toLowerCase() === CHL_BYPASS_SUPPORT)
            .map((header) => header.value !== undefined && +header.value);

        if (details.type === 'main_frame') {
            // The page in the tab is changed, so the context should change.
            this.context = null;
            this.active && this.updateIcon();
        }

        // Cloudflare has higher precedence than Hcaptcha.
        if (providerId === CloudflareProvider.ID && !(this.context instanceof CloudflareProvider)) {
            const context = new CloudflareProvider(this.chromeTabId, new Storage('pp-cf'));

            // Update the toolbar icon, after issuances and redemptions.
            context.addEventListener('issue', () => this.active && this.updateIcon());
            context.addEventListener('redeem', () => this.active && this.updateIcon());
            this.context = context;
            this.active && this.updateIcon();
        } else if (
            providerId === HcaptchaProvider.ID &&
            !(this.context instanceof CloudflareProvider) &&
            !(this.context instanceof HcaptchaProvider)
        ) {
            this.context = new HcaptchaProvider();
            this.active && this.updateIcon();
        }

        let result;
        if (this.context !== null) {
            result = this.context.handleHeadersReceived(details);
        }

        return result;
    }
}
