import React from 'react';

import { PassButton } from '@popup/components/PassButton';

export function HcaptchaButton(): JSX.Element {
    const openHomePage = () => {
        chrome.tabs.create({ url: 'https://www.hcaptcha.com/privacy-pass' });
    };

    return <PassButton value={0} onClick={openHomePage}>Cloudflare</PassButton>;
}
