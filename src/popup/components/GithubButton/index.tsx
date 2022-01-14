import React from 'react';

import { Button } from '@popup/components/Button';

export function GithubButton(): JSX.Element {
    const openGithub = () => {
        chrome.tabs.create({ url: 'https://github.com/privacypass/challenge-bypass-extension' });
    };

    return <Button onClick={openGithub}>{chrome.i18n.getMessage('ctaViewOnGithub')}</Button>;
}
