import React, { useState } from 'react';
import styles from './styles.module.scss';

function PassButton(props: Props) {
    const [mouseover, setMouseover] = useState(false);

    function onEnter() {
        setMouseover(true);
    }

    function onLeave() {
        setMouseover(false);
    }

    const element = mouseover ? "Get more passes!" : props.children;

    return (
        <div className={styles.button} onClick={props.onClick} onMouseEnter={onEnter} onMouseLeave={onLeave}>
            <div className={styles.content}>{element}</div>
            <div className={styles.value}>{props.value}</div>
        </div>
    );
}

interface Props {
    value: number,
    children: string,
    onClick?: () => void,
}

export default PassButton;
