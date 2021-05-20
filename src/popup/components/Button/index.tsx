import React from 'react';
import styles from './styles.module.scss';

function Button(props: Props) {
    return (
        <div className={styles.button} onClick={props.onClick}>
            {props.children}
        </div>
    );
}

interface Props {
    children: string,
    onClick?: () => void,
}

export default Button;
