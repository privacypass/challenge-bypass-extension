import { Header           } from '@popup/components/Header';
import { Container        } from '@popup/components/Container';
import { CloudflareButton } from '@popup/components/CloudflareButton';
import { HcaptchaButton   } from '@popup/components/HcaptchaButton';
import { BackupButton     } from '@popup/components/BackupButton';
import { RestoreButton    } from '@popup/components/RestoreButton';
import { ClearButton      } from '@popup/components/ClearButton';
import { GithubButton     } from '@popup/components/GithubButton';
import React from 'react';
import styles from './styles.module.scss';

export function App(): JSX.Element {
    return (
        <div className={styles.app}>
            <Header />
            <Container>
                <CloudflareButton />
                <HcaptchaButton />
                <BackupButton />
                <RestoreButton />
                <ClearButton />
                <GithubButton />
            </Container>
        </div>
    );
}
