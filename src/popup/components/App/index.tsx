import React from 'react';
import styles from './styles.module.scss';

import Header     from '@popup/components/Header';
import Button     from '@popup/components/Button';
import Container  from '@popup/components/Container';
import PassButton from '@popup/components/PassButton';

function App() {
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

export default App;
