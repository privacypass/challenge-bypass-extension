// This is a declaration file for our legacy crypto module.

declare namespace crypto {
    export type Point  = unknown;
    export type Bytes  = unknown;
    export type BigNum = { toString(): string };

    export type Curve      = 'p256';
    export type Hash       = 'sha256';
    export type HashMethod = 'increment' | 'swu';

    // TODO This should be implemented in a new Point class.
    export function blindPoint(point: Point): { blind: BigNum, point: Point };
    // TODO This should be implemented in a new Point class.
    export function newRandomPoint():         { data:  Bytes,  point: Point };

    export function getActiveECSettings(): any;
    export function initECSettings(params: { curve: Curve, hash: Hash, method: HashMethod });

    // TODO This should be implemented in a new Point class.
    export function getCurvePoints(signatures: string[]): { points: Point[], compressed: boolean };

    // TODO This should be implemented in a new Point class.
    export function sec1EncodeToBase64(point: Point, compressed: boolean): string;
    // TODO This should be implemented in a new Point class.
    export function sec1DecodeFromBase64(encoded: string): Point;

    export function verifyConfiguration(publicKey: string, config: object, signature: string): boolean;
    // TODO Proof verification should be inside Token class.
    export function verifyProof(proof: string, tokens: unknown[], signatures: { points: Point[], compressed: boolean }, commitments, prngName);

    export function unblindPoint(factor: BigNum, blindedPoint: Point): Point;

    export function newBigNum(encoded: string): BigNum;
    export function deriveKey(point: Point, input: Bytes): Bytes;
    export function getBytesFromString(str: string): Bytes;
    export function getBase64FromString(str: string): string;
    export function getBase64FromBytes(bytes: Bytes): string;
    export function createRequestBinding(key: Bytes, bindingData: Bytes[]): string;
}

export default crypto;
