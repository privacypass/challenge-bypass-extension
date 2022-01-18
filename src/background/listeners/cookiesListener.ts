import { Providers, EarnedTokenCookie } from '../providers';

export function handleChangedCookies(changeInfo: any): void {
    if (!changeInfo.removed && Array.isArray(Providers) && Providers.length) {
        for (const provider of Providers) {
            const cookie: EarnedTokenCookie | void = provider.EARNED_TOKEN_COOKIE;
            if (!cookie) continue;

            if (
                changeInfo.cookie.domain === cookie.domain &&
                changeInfo.cookie.name   === cookie.name
            ) {
                chrome.cookies.remove({ url: cookie.url, name: cookie.name });
            }
        }
    }
}
