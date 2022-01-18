import { Callbacks, EarnedTokenCookie, Provider } from './provider';

import { CloudflareProvider } from './cloudflare';
import { HcaptchaProvider }   from './hcaptcha';

export type {
    Callbacks,
    EarnedTokenCookie,
}

export {
    Provider,
    CloudflareProvider,
    HcaptchaProvider,
}

export const Providers: (typeof Provider)[] = [
    CloudflareProvider,
    HcaptchaProvider,
]
