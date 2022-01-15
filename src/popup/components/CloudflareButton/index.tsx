import React from 'react';
import { useSelector } from 'react-redux';

import { PassButton } from '@popup/components/PassButton';

const providerID: string = '1';

export function CloudflareButton(): JSX.Element {
    const tokensCount: number = useSelector((state: {[key: string]: number} | void): number => {
        return ((state instanceof Object) && (typeof state[providerID] === 'number'))
            ? Number(state[providerID])
            : 0;
    });

    const openHomePage = () => {
        chrome.tabs.create({ url: 'https://captcha.website' });
    };

    return (
        <PassButton value={tokensCount} onClick={openHomePage}>
            {chrome.i18n.getMessage('providerNameCloudflare')}
        </PassButton>
    );
}
