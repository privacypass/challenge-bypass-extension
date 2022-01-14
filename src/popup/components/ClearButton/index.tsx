import React from 'react';
import { useDispatch } from 'react-redux';

import { Button } from '@popup/components/Button';

export function ClearButton(): JSX.Element {
    const dispatch = useDispatch();

    const clearPasses = () => {
        dispatch({ type: 'CLEAR_TOKENS' });
    };
    return <Button onClick={clearPasses}>{chrome.i18n.getMessage('ctaClearAllPasses')}</Button>;
}
