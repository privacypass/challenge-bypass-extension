import React from 'react';
import { useDispatch } from 'react-redux';

import { Button } from '@popup/components/Button';

export function BackupButton(): JSX.Element {
    const dispatch = useDispatch();

    const backupPasses = () => {
        dispatch({ type: 'BACKUP_TOKENS' });
    };
    return <Button onClick={backupPasses}>{chrome.i18n.getMessage('ctaBackupAllPasses')}</Button>;
}
