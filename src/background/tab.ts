import Cloudflare from '@background/providers/cloudflare';
import Hcaptcha   from '@background/providers/hcaptcha';

// Header from server to indicate that Privacy Pass is supported.
const CHL_BYPASS_SUPPORT = 'cf-chl-bypass';

export default class Tab {
    private context: Cloudflare | Hcaptcha | null;
    private chromeTabId: number;
    private active: boolean;

    constructor(tabId: number) {
        this.context = null;
        this.chromeTabId = tabId;
        this.active = false;
    }

    private updateIcon() {
        if (this.context !== null) {
            const text = this.context.getBadgeText();
            chrome.browserAction.setIcon({ path: 'icons/32/gold.png' });
            chrome.browserAction.setBadgeText({ text });
        } else {
            chrome.browserAction.setIcon({ path: 'icons/32/grey.png' });
            chrome.browserAction.setBadgeText({ text: '' });
        }
    }

    handleActivated() {
        this.active = true;
        this.updateIcon();
    }

    handleDeactivated() {
        this.active = false;
    }

    handleBeforeRequest(details: chrome.webRequest.WebRequestBodyDetails) {
        let result;
        if (this.context !== null) {
            result = this.context.handleBeforeRequest(details);
        }

        return result;
    }

    handleBeforeSendHeaders(details: chrome.webRequest.WebRequestHeadersDetails) {
        let result;
        if (this.context !== null) {
            result = this.context.handleBeforeSendHeaders(details);
        }

        return result;
    }

    handleHeadersReceived(details: chrome.webRequest.WebResponseHeadersDetails) {
        if (details.responseHeaders === undefined) {
            return;
        }
        const [providerId] = details.responseHeaders
            .filter(header => header.name.toLowerCase() === CHL_BYPASS_SUPPORT)
            .map   (header => header.value !== undefined && +header.value);

        if (details.type === 'main_frame') {
            // The page in the tab is changed, so the context should change.
            this.context = null;
            this.active && this.updateIcon();
        }

        // Cloudflare has higher precedence than Hcaptcha.
        if (providerId === Cloudflare.id && !(this.context instanceof Cloudflare)) {
            const context = new Cloudflare(window.localStorage);

            // Update the toolbar icon, after issuances and redemptions.
            context.addEventListener('issue',  () => this.active && this.updateIcon());
            context.addEventListener('redeem', () => this.active && this.updateIcon());
            this.context = context;
            this.active && this.updateIcon();

        } else if (providerId === Hcaptcha.id && !(this.context instanceof Cloudflare) && !(this.context instanceof Hcaptcha)) {
            this.context = new Hcaptcha();
            this.active && this.updateIcon();
        }

        let result;
        if (this.context !== null) {
            result = this.context.handleHeadersReceived(details);
        }

        return result;
    }
}
