import React from 'react';
import { useSelector } from 'react-redux';

import { PassButton } from '@popup/components/PassButton';

export function CloudflareButton(): JSX.Element {
    const tokens: string[] = useSelector((state: { ['cf-tokens']?: string[] } | undefined) => {
        if (state !== undefined && state['cf-tokens'] !== undefined) {
            return state['cf-tokens'];
        }
        return [];
    });

    const openHomePage = () => {
        chrome.tabs.create({ url: 'https://captcha.website' });
    };

    return (
        <PassButton value={tokens.length} onClick={openHomePage}>
            Cloudflare
        </PassButton>
    );
}
