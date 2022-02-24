import React, { useState } from 'react';

import styles from './styles.module.scss';

export function PassButton(props: Props): JSX.Element {
    const [mouseover, setMouseover] = useState(false);

    function onEnter() {
        setMouseover(true);
    }

    function onLeave() {
        setMouseover(false);
    }

    const element = mouseover ? chrome.i18n.getMessage('ctaGetMorePasses') : props.children;

    return (
        <div
            className={styles.button}
            onClick={props.onClick}
            onMouseEnter={onEnter}
            onMouseLeave={onLeave}
        >
            <table className={styles.table}>
                <tr>
                    <td className={styles.content}>
                        {element}
                    </td>
                    <td className={styles.value}>
                        {props.value}
                    </td>
                </tr>
            </table>
        </div>
    );
}

interface Props {
    value: number;
    children: string;
    onClick?: () => void;
}
