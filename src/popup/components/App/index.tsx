import React from 'react';
import Header from '@popup/components/Header';
import Container from '@popup/components/Container';
import PassButton from '@popup/components/PassButton';
import styles from './styles.module.scss';

function App() {
    return (
        <div className={styles.app}>
            <Header />
            <Container>
                <PassButton value={0}>Cloudflare</PassButton>
                <PassButton value={0}>hCaptcha</PassButton>
            </Container>
        </div>
    );
}

export default App;
