import crypto from 'crypto';

Object.assign(window, {
    crypto: {
        getRandomValues: (buffer: Int32Array) => {
            return crypto.randomFillSync(buffer);
        },
    },
});
