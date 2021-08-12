import { defaultECSettings, initECSettings, newRandomPoint } from './voprf';

test('randomPoint', () => {
    initECSettings(defaultECSettings);
    const P = newRandomPoint();
    expect(P).toBeDefined();
});
