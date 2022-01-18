// Mocking crypto with Node webcrypto API.

// Requires Node v15.0+
//     https://nodejs.org/api/crypto.html#cryptowebcrypto

import { webcrypto } from 'crypto';

if (typeof crypto === 'undefined') {
    global.crypto = (webcrypto as unknown) as Crypto;
}
