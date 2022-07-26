import React from 'react';
import styles from './styles.module.scss';

export function Container(props: Props): JSX.Element {
    return <div className={styles.container}>{props.children}</div>;
}

interface Props {
    children: React.ReactNode;
}
