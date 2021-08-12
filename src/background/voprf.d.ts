export type Point = unknown;
export type Bytes = unknown;
export type BigNum = { toString(): string };

export type Curve = 'p256';
export type Hash = 'sha256';
export type HashMethod = 'increment' | 'swu';

export interface ECSettings {
    curve: any;
    hash: Hash;
    method: HashMethod;
}

export const defaultECSettings: ECSettings;

// TODO This should be implemented in a new Point class.
export function blindPoint(point: Point): { blind: BigNum; point: Point };
// TODO This should be implemented in a new Point class.
export function newRandomPoint(): { data: Bytes; point: Point };

export function getActiveECSettings(): ECSettings;

export function initECSettings(params: { curve: Curve; hash: Hash; method: HashMethod }): void;

// TODO This should be implemented in a new Point class.
export function getCurvePoints(signatures: string[]): {
    points: Point[];
    compressed: boolean;
};

// TODO This should be implemented in a new Point class.
export function sec1EncodeToBase64(point: Point, compressed: boolean): string;
// TODO This should be implemented in a new Point class.
export function sec1DecodeFromBase64(encoded: string): Point;

export function verifyConfiguration(publicKey: string, config: any, signature: string): boolean;
// TODO Proof verification should be inside Token class.
export function verifyProof(
    proof: string,
    tokens: unknown[],
    signatures: { points: Point[]; compressed: boolean },
    commitments: any,
    prngName: any,
): boolean;

export function unblindPoint(factor: BigNum, blindedPoint: Point): Point;

export function newBigNum(encoded: string): BigNum;

export function deriveKey(N: Point, token: any): any;
export function createRequestBinding(key: any, data: any): any;
export function getBytesFromString(str: any): any;
export function getBase64FromString(str: any): any;
export function getBase64FromBytes(bytes: any): any;
