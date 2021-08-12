import Token from './token';
import { initECSettings } from './voprf';

beforeAll(() => {
    // TODO This shouldn't be needed after refactoring the voprf module.
    initECSettings({
        curve: 'p256',
        hash: 'sha256',
        method: 'increment',
    });
});

test('Construct a token', () => {
    new Token();
});
