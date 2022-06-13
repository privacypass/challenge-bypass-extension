import { Container } from '@popup/components/Container';
import { ClearButton } from '@popup/components/ClearButton';
import { CloudflareButton } from '@popup/components/CloudflareButton';
import { GithubButton } from '@popup/components/GithubButton';
import { Header } from '@popup/components/Header';
import React from 'react';
import styles from './styles.module.scss';

export function App(): JSX.Element {
    return (
        <div className={styles.app}>
            <Header />
            <Container>
                <CloudflareButton />
                <ClearButton />
                <GithubButton />
            </Container>
        </div>
    );
}
