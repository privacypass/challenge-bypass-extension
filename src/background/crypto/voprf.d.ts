export type Point = unknown;
export type Bytes = unknown;
export type BigNum = { toString(): string };

export type Curve = 'p256';
export type Hash  = 'sha256';
export type HashMethod = 'increment' | 'swu';
export type HashLabel  = 'H2C-P256-SHA256-SSWU-' | string;

export interface ECSettings {
    curve:  any;
    hash:   Hash;
    method: HashMethod;
    label?: HashLabel;
}

export const defaultECSettings: ECSettings;

export function sec1Encode(point: Point, compressed: boolean): any;
export function sec1EncodeToBase64(point: Point, compressed: boolean): string;
export function getBigNumFromBytes(bytes: any): BigNum;
export function newBigNum(encoded: string): BigNum;
export function getBytesFromString(str: any): any;
export function getBase64FromBytes(bytes: any): any;
export function getBase64FromString(str: any): any;

export class VOPRF {
    private CURVE:            any;
    private CURVE_H2C_HASH:   Hash;
    private CURVE_H2C_METHOD: HashMethod;
    private CURVE_H2C_LABEL:  HashLabel | void;

    constructor(h2cParams: ECSettings | void): void;
    getActiveECSettings(): ECSettings;
    newRandomPoint(): { data: Bytes; point: Point };
    sec1DecodeFromBase64(encoded: string): Point;
    sec1DecodeFromBytes(sec1Bytes: Bytes): Point;
    blindPoint(point: Point): { blind: BigNum; point: Point };
    unblindPoint(factor: BigNum, blindedPoint: Point): Point;
    verifyConfiguration(publicKey: string, config: any, signature: string): boolean;
    verifyProof(
        proof: string,
        tokens: unknown[],
        signatures: { points: Point[]; compressed: boolean },
        commitments: any,
        prngName: string,
    ): boolean;
    deriveKey(N: Point, token: any): any;
    createRequestBinding(key: any, data: any): any;
    getCurvePoints(signatures: string[]): {
        points: Point[];
        compressed: boolean;
    };

    private decompressPoint(bytes: Bytes): Point | null;
    private parsePublicKeyfromPEM(pemPublicKey: string): any;
    private recomputeComposites(
        tokens: unknown[],
        signatures: { points: Point[]; compressed: boolean },
        pointG: Point,
        pointH: Point,
        prngName: string
    ): {M: Point; Z: Point};
    private computePRNGScalar(
        prng:  any,
        seed:  string,
        salt?: any
    ): BigNum;
    private computeSeed(
        chkM:   any,
        chkZ:   Point[],
        pointG: Point,
        pointH: Point
    ): string;
    private hashAndInc(seed: any, hash: any, label: any): Point;
    private h2Curve(alpha: any, ecSettings: ECSettings): Point;
}
