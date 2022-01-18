import * as voprf from './crypto/voprf';

interface SignedComponent {
    blindedPoint: voprf.Point;
    unblindedPoint: voprf.Point;
}

export default class Token {
    private VOPRF: voprf.VOPRF;

    private input: voprf.Bytes;
    private factor: voprf.BigNum;

    private blindedPoint: voprf.Point;
    private unblindedPoint: voprf.Point;

    private signed: SignedComponent | null;

    constructor(VOPRF: voprf.VOPRF | void) {
        if (VOPRF === undefined) {
            VOPRF = new voprf.VOPRF(voprf.defaultECSettings);
        }

        this.VOPRF = VOPRF;

        const { data: input, point: unblindedPoint } = this.VOPRF.newRandomPoint();
        const { blind: factor, point: blindedPoint } = this.VOPRF.blindPoint(unblindedPoint);

        this.input = input;
        this.factor = factor;

        this.blindedPoint = blindedPoint;
        this.unblindedPoint = unblindedPoint;

        this.signed = null;
    }

    static fromString(str: string, VOPRF: voprf.VOPRF | void): Token {
        if (VOPRF === undefined) {
            VOPRF = new voprf.VOPRF(voprf.defaultECSettings);
        }

        const json = JSON.parse(str);

        const token: Token = Object.create(Token.prototype);

        token.VOPRF  = VOPRF;
        token.input  = json.input;
        token.factor = voprf.newBigNum(json.factor);

        token.blindedPoint   = VOPRF.sec1DecodeFromBase64(json.blindedPoint);
        token.unblindedPoint = VOPRF.sec1DecodeFromBase64(json.unblindedPoint);

        token.signed =
            json.signed !== null
                ? {
                      blindedPoint:   VOPRF.sec1DecodeFromBase64(json.signed.blindedPoint),
                      unblindedPoint: VOPRF.sec1DecodeFromBase64(json.signed.unblindedPoint),
                  }
                : null;

        return token;
    }

    setSignedPoint(point: voprf.Point): void {
        const blindedPoint   = point;
        const unblindedPoint = this.VOPRF.unblindPoint(this.factor, point);

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
        return this.VOPRF.deriveKey(this.signed.unblindedPoint, this.input);
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
