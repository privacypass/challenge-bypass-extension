import { VOPRF, defaultECSettings } from './voprf';

test('randomPoint', () => {
    const voprf = new VOPRF(defaultECSettings);
    const P     = voprf.newRandomPoint();

    expect(P).toBeDefined();
});
