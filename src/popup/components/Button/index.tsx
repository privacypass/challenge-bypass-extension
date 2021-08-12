import React from 'react';
import styles from './styles.module.scss';

export function Button(props: Props): JSX.Element {
    return (
        <div className={styles.button} onClick={props.onClick}>
            {props.children}
        </div>
    );
}

interface Props {
    children: string;
    onClick?: () => void;
}
