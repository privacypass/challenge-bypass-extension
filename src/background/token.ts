import crypto from '@background/crypto';

export default class Token {
    private input:  crypto.Bytes;
    private factor: crypto.BigNum;

    private blindedPoint:   crypto.Point;
    private unblindedPoint: crypto.Point;

    constructor() {
        const { data:  input,  point: unblindedPoint } = crypto.newRandomPoint();
        const { blind: factor, point: blindedPoint   } = crypto.blindPoint(unblindedPoint);

        this.input  = input;
        this.factor = factor;

        this.blindedPoint   = blindedPoint;
        this.unblindedPoint = unblindedPoint;
    }

    getEncodedBlindedPoint(): string {
        return crypto.sec1EncodeToBase64(this.blindedPoint, true); // true is for compression
    }

    toLegacy(): { data: crypto.Bytes, point: crypto.Point, blind: crypto.BigNum } {
        return { data: this.input, point: this.blindedPoint, blind: this.factor };
    }
}
