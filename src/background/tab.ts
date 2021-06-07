import Cloudflare from '@background/providers/cloudflare';
import Hcaptcha   from '@background/providers/hcaptcha';

// Header from server to indicate that Privacy Pass is supported.
const CHL_BYPASS_SUPPORT = 'cf-chl-bypass';

export default class Tab {
    private context: Cloudflare | Hcaptcha | null;
    private chromeTabId: number;

    constructor(tabId: number) {
        this.context     = null;
        this.chromeTabId = tabId;
    }

    handleBeforeRequest(details: chrome.webRequest.WebRequestBodyDetails) {
        let result;
        if (this.context !== null) {
            result = this.context.handleBeforeRequest(details);
        }

        if (details.type === 'main_frame') {
            // The page in the tab is changed, so the context should change.
            this.context = null;
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

        if (providerId === Cloudflare.id) {
            this.context = new Cloudflare();
        } else if (providerId === Hcaptcha.id && !(this.context instanceof Cloudflare)) {
            // Cloudflare has higher precedence than Hcaptcha.
            this.context = new Hcaptcha();
        }
    }
}
