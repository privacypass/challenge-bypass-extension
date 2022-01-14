import React from 'react';
import badge from '@public/images/gold-badge.svg';
import packageJson from '@root/package.json';
import styles from './styles.module.scss';

export function Header(): JSX.Element {
    return (
        <div className={styles.header}>
            <img className={styles.badge} src={badge} />
            <div className={styles.detail}>
                <div className={styles.title}>{chrome.i18n.getMessage('appName')}</div>
                <div className={styles.version}>{chrome.i18n.getMessage('labelAppVersion')} {packageJson.version}</div>
            </div>
        </div>
    );
}
