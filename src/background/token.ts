import crypto from '@background/crypto';

interface SignedComponent {
    blindedPoint:   crypto.Point,
    unblindedPoint: crypto.Point,
}

export default class Token {
    private input:  crypto.Bytes;
    private factor: crypto.BigNum;

    private blindedPoint:   crypto.Point;
    private unblindedPoint: crypto.Point;

    private signed: SignedComponent | null;

    constructor() {
        const { data:  input,  point: unblindedPoint } = crypto.newRandomPoint();
        const { blind: factor, point: blindedPoint   } = crypto.blindPoint(unblindedPoint);

        this.input  = input;
        this.factor = factor;

        this.blindedPoint   = blindedPoint;
        this.unblindedPoint = unblindedPoint;

        this.signed = null;
    }

    setSignedPoint(point: crypto.Point) {
        const blindedPoint   = point;
        const unblindedPoint = crypto.unblindPoint(this.factor, point);

        this.signed = {
            blindedPoint,
            unblindedPoint,
        };
    }

    getEncodedBlindedPoint(): string {
        return crypto.sec1EncodeToBase64(this.blindedPoint, true); // true is for compression
    }

    toLegacy(): { data: crypto.Bytes, point: crypto.Point, blind: crypto.BigNum } {
        return { data: this.input, point: this.blindedPoint, blind: this.factor };
    }
}
