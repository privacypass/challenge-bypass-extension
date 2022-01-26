import React from 'react';
import { useDispatch } from 'react-redux';

import { Button } from '@popup/components/Button';

export function RestoreButton(): JSX.Element {
    const dispatch = useDispatch();

    const restorePasses = () => {
        dispatch({ type: 'RESTORE_TOKENS' });
    };
    return <Button onClick={restorePasses}>{chrome.i18n.getMessage('ctaRestorePasses')}</Button>;
}
