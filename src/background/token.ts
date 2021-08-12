import * as voprf from './voprf';

interface SignedComponent {
    blindedPoint: voprf.Point;
    unblindedPoint: voprf.Point;
}

export default class Token {
    private input: voprf.Bytes;
    private factor: voprf.BigNum;

    private blindedPoint: voprf.Point;
    private unblindedPoint: voprf.Point;

    private signed: SignedComponent | null;

    constructor() {
        const { data: input, point: unblindedPoint } = voprf.newRandomPoint();
        const { blind: factor, point: blindedPoint } = voprf.blindPoint(unblindedPoint);

        this.input = input;
        this.factor = factor;

        this.blindedPoint = blindedPoint;
        this.unblindedPoint = unblindedPoint;

        this.signed = null;
    }

    static fromString(str: string): Token {
        const json = JSON.parse(str);

        const token: Token = Object.create(Token.prototype);

        token.input = json.input;
        token.factor = voprf.newBigNum(json.factor);

        token.blindedPoint = voprf.sec1DecodeFromBase64(json.blindedPoint);
        token.unblindedPoint = voprf.sec1DecodeFromBase64(json.unblindedPoint);

        token.signed =
            json.signed !== null
                ? {
                      blindedPoint: voprf.sec1DecodeFromBase64(json.signed.blindedPoint),
                      unblindedPoint: voprf.sec1DecodeFromBase64(json.signed.unblindedPoint),
                  }
                : null;

        return token;
    }

    setSignedPoint(point: voprf.Point): void {
        const blindedPoint = point;
        const unblindedPoint = voprf.unblindPoint(this.factor, point);

        this.signed = {
            blindedPoint,
            unblindedPoint,
        };
    }

    // TODO This should be implemented in a new Point class.
    getEncodedBlindedPoint(): string {
        return voprf.sec1EncodeToBase64(this.blindedPoint, true); // true is for compression
    }

    toLegacy(): { data: voprf.Bytes; point: voprf.Point; blind: voprf.BigNum } {
        return {
            data: this.input,
            point: this.blindedPoint,
            blind: this.factor,
        };
    }

    getMacKey(): voprf.Bytes {
        if (this.signed === null) {
            throw new Error('Unsigned token is used to derive a MAC key');
        }
        return voprf.deriveKey(this.signed.unblindedPoint, this.input);
    }

    getInput(): voprf.Bytes {
        return this.input;
    }

    toString(): string {
        const signed =
            this.signed !== null
                ? {
                      blindedPoint: voprf.sec1EncodeToBase64(this.signed.blindedPoint, false),
                      unblindedPoint: voprf.sec1EncodeToBase64(this.signed.unblindedPoint, false),
                  }
                : null;

        const json = {
            input: this.input,
            factor: this.factor.toString(),
            blindedPoint: voprf.sec1EncodeToBase64(this.blindedPoint, false),
            unblindedPoint: voprf.sec1EncodeToBase64(this.unblindedPoint, false),
            signed,
        };
        return JSON.stringify(json);
    }
}
