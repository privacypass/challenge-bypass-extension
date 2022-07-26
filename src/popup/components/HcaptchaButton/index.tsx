import React from 'react';

import {PassButton} from '@popup/components/PassButton';
import {useSelector} from 'react-redux';

export function HcaptchaButton(): JSX.Element {
    const tokens: number = useSelector((state: { ['hc-tokens']?: string[] } | undefined) => {
        if (state !== undefined && state['hc-tokens'] !== undefined) {
            return state['hc-tokens'].length;
        }
        return 0;
    });

    const openHomePage = () => {
        chrome.tabs.create({url: 'https://www.hcaptcha.com/privacy-pass'});
    };

    return (
        <PassButton value={tokens} onClick={openHomePage}>
            hCaptcha
        </PassButton>
    );
}
