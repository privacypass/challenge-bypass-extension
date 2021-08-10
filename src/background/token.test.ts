import crypto from '@background/crypto';
import Token  from '@background/token';

beforeAll(() => {
    // TODO This shouldn't be needed after refactoring the crypto module.
    crypto.initECSettings({
        'curve':  'p256',
        'hash':   'sha256',
        'method': 'increment',
    });
});

test('Construct a token', () => {
    new Token();
});
