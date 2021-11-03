import { CloudflareProvider, HcaptchaProvider, Provider } from './providers';
import { LocalStorage } from './storage';

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

        this.updateIcon = this.updateIcon.bind(this);
        this.navigateUrl = this.navigateUrl.bind(this);
    }

    private updateIcon(text: string): void {
        if (this.active) {
            if (this.context !== null) {
                chrome.browserAction.setIcon({ path: 'icons/32/gold.png' });
                chrome.browserAction.setBadgeText({ text });
            } else {
                this.clearIcon();
            }
        }
    }

    private clearIcon(): void {
        if (this.active) {
            chrome.browserAction.setIcon({ path: 'icons/32/grey.png' });
            chrome.browserAction.setBadgeText({ text: '' });
        }
    }

    forceUpdateIcon(): void {
        if (this.active) {
            if (this.context !== null) {
                this.context.forceUpdateIcon();
            } else {
                this.clearIcon();
            }
        }
    }

    private navigateUrl(url: string): void {
        chrome.tabs.update(this.chromeTabId, { url });
    }

    handleActivated(): void {
        this.active = true;
        if (this.context !== null) {
            this.context.handleActivated();
        } else {
            this.clearIcon();
        }
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
            this.clearIcon();
        }

        // Cloudflare has higher precedence than Hcaptcha.
        if (providerId === CloudflareProvider.ID && !(this.context instanceof CloudflareProvider)) {
            const context = new CloudflareProvider(new LocalStorage('cf'), {
                updateIcon: this.updateIcon,
                navigateUrl: this.navigateUrl,
            });

            this.context = context;
            this.context.handleActivated();
        } else if (
            providerId === HcaptchaProvider.ID &&
            !(this.context instanceof CloudflareProvider) &&
            !(this.context instanceof HcaptchaProvider)
        ) {
            this.context = new HcaptchaProvider({
                updateIcon: this.updateIcon,
                navigateUrl: this.navigateUrl,
            });
            this.context.handleActivated();
        }

        let result;
        if (this.context !== null) {
            result = this.context.handleHeadersReceived(details);
        }

        return result;
    }
}
