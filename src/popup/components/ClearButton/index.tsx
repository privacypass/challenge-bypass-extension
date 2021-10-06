import React from 'react';

import { Button } from '@popup/components/Button';

export function ClearButton(): JSX.Element {
    const clearPasses = () => {
        // TODO Using Message passing is dirty. It's better to use chrome.storage for sharing
        // common data between the popup and the background script.
        chrome.runtime.sendMessage({ clear: true });
    };
    return <Button onClick={clearPasses}>Clear All Passes</Button>;
}
