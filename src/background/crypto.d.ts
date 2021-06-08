// This is a declaration file for our legacy crypto module.

declare namespace crypto {
    export type Point  = unknown;
    export type Bytes  = unknown;
    export type BigNum = unknown;

    export type Curve      = 'p256';
    export type Hash       = 'sha256';
    export type HashMethod = 'increment' | 'swu';

    export function blindPoint(point: Point): { blind: BigNum, point: Point };
    export function newRandomPoint():         { data:  Bytes,  point: Point };

    export function initECSettings(params: { curve: Curve, hash: Hash, method: HashMethod });
    export function sec1EncodeToBase64(point: Point, compressed: boolean): string;
}

export default crypto;
