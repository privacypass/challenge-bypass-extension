import React from 'react';
import badge from '@public/images/gold-badge.svg';
import { version } from '@root/package.json';
import styles from './styles.module.scss';

function Header() {
    return (
        <div className={styles.header}>
            <img className={styles.badge} src={badge} />
            <div className={styles.detail}>
                <div className={styles.title}>Privacy Pass</div>
                <div className={styles.version}>Version {version}</div>
            </div>
        </div>
    );
}

export default Header;
