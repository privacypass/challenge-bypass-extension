import { Button } from '@popup/components/Button';
import { Container } from '@popup/components/Container';
import { Header } from '@popup/components/Header';
import { PassButton } from '@popup/components/PassButton';
import React from 'react';
import styles from './styles.module.scss';

export function App(): JSX.Element {
    return (
        <div className={styles.app}>
            <Header />
            <Container>
                <PassButton value={0}>Cloudflare</PassButton>
                <PassButton value={0}>hCaptcha</PassButton>
                <Button>Log CF Redemption to Console</Button>
                <Button>Clear All Passes</Button>
                <Button>View on Github</Button>
            </Container>
        </div>
    );
}
