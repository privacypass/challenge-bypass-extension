import createKeccakHash, { Shake, ShakeAlgorithm } from 'keccak';

export function createShake256(): Shake {
    const algorithm: ShakeAlgorithm = 'shake256';
    return createKeccakHash(algorithm);
}
