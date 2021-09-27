import React, { useEffect, useState } from 'react';

import { PassButton } from '@popup/components/PassButton';

export function CloudflareButton(): JSX.Element {
    const [tokens, setTokens] = useState([]);

    useEffect(() => {
        // TODO Using Message passing is dirty. It's better to use chrome.storage for sharing
        // common data between the popup and the background script.
        chrome.runtime.sendMessage({ key: 'tokens' }, (response) => {
            if (response !== undefined && typeof response === 'string') {
                setTokens(JSON.parse(response));
            }
        });
    }, []);

    const openHomePage = () => {
        chrome.tabs.create({ url: 'https://captcha.website' });
    };

    return <PassButton value={tokens.length} onClick={openHomePage}>Cloudflare</PassButton>;
}
