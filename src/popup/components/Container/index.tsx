import React from 'react';
import styles from './styles.module.scss';

function Container(props: Props) {
    return (
        <div className={styles.container}>
            {props.children}
        </div>
    );
}

interface Props {
    children: React.ReactNode,
}

export default Container;
