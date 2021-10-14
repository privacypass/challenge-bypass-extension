// Mocking crypto with Node webcrypto API.
import { webcrypto } from 'crypto';

if (typeof crypto === 'undefined') {
    global.crypto = (webcrypto as unknown) as Crypto
}
