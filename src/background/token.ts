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

    static fromString(str: string): Token {
        const json = JSON.parse(str);

        const token: Token = Object.create(Token.prototype);

        token.input  = json.input;
        token.factor = crypto.newBigNum(json.factor);

        token.blindedPoint   = crypto.sec1DecodeFromBase64(json.blindedPoint);
        token.unblindedPoint = crypto.sec1DecodeFromBase64(json.unblindedPoint);

        token.signed = json.signed !== null ? {
            blindedPoint:   crypto.sec1DecodeFromBase64(json.signed.blindedPoint),
            unblindedPoint: crypto.sec1DecodeFromBase64(json.signed.unblindedPoint),
        } : null;

        return token;
    }

    setSignedPoint(point: crypto.Point) {
        const blindedPoint   = point;
        const unblindedPoint = crypto.unblindPoint(this.factor, point);

        this.signed = {
            blindedPoint,
            unblindedPoint,
        };
    }

    // TODO This should be implemented in a new Point class.
    getEncodedBlindedPoint(): string {
        return crypto.sec1EncodeToBase64(this.blindedPoint, true); // true is for compression
    }

    toLegacy(): { data: crypto.Bytes, point: crypto.Point, blind: crypto.BigNum } {
        return { data: this.input, point: this.blindedPoint, blind: this.factor };
    }

    toString(): string {
        const signed = this.signed !== null ? {
            blindedPoint:   crypto.sec1EncodeToBase64(this.signed.blindedPoint, false),
            unblindedPoint: crypto.sec1EncodeToBase64(this.signed.unblindedPoint, false),
        } : null;

        const json = {
            input:  this.input,
            factor: this.factor.toString(),
            blindedPoint:   crypto.sec1EncodeToBase64(this.blindedPoint, false),
            unblindedPoint: crypto.sec1EncodeToBase64(this.unblindedPoint, false),
            signed,
        };
        return JSON.stringify(json);
    }
}
