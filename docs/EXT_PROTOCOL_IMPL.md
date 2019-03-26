# Privacy Pass extension protocol implementation and data format

We explain the data format used by the extension in sending and receiving
responses. All protocol-specific terms that we use are explained in
[GLOSSARY.md](GLOSSARY.md).

The data types that we present are only implicitly represented in the way that
the client and server communicate. In the future we hope to transition to using
explicit data formats mirroring these types.

## Common data types

- `BlindTokenRequest`: A (JSON) struct of the form:

	```
	type IssueRequest struct {
        Type      string
        Contents  [][]byte
    }
	```

### IssueRequest

__Description__: A (JSON) struct used for sending blinded tokens to be signed by
the edge, this message is appended to the body of a HTTP request holding a
CAPTCHA solution.

- `BlindToken`: An elliptic curve point `P` (stored in compressed format as
  defined in Section 2.3.3 of http://www.secg.org/sec1-v2.pdf). `P` is computed
  as `rT` where `r` is a random scalar (or 'blind'), `T = h2c(t)` for some
  random sequence of bytes `t` and where `h2c` is a method for hashing to the
  appropriate elliptic curve.

- `b64BlindTokenArray` is an array of N base64-encoded `BlindToken` objects.

- `IssueRequest`: A BlindTokenRequest where `Type = "Issue"` and `Contents =
  [][]byte(b64BlindTokenArray)`.

- HTTP request body contents:

	`"blinded-tokens=" || base64.encode(IssueRequest)`

### IssueResponse

__Description__: A (JSON) struct returning signed blinded tokens to the client
along with a batched DLEQ proof evaluated over all the tokens.

- `PointData`: Is an array of elliptic curve points stored as
  uncompressed byte arrays. This array contains the signed, blinded tokens
  produced by the server.

- `DLEQProof`: A struct of the following form:

    ```
    type DLEQProof struct {
        R, C        BigInt
    }
    ```

    where `R` and `C` are scalar values associated with the proof (see
    [PROTOCOL.md](PROTOCOL.md) for more information).

- `BatchProof`: A struct of the following form:

    ```
    type BatchProof struct {
        P     DLEQProof
    }
    ```

    where `P` is a `DLEQProof` object.

    Remark: All extra information sent by the server should be ignored. In
    addition, in a future change we hope to remove the arbirary

- `EncodedDLEQProof`: A base64-encoded `DLEQProof` object, where all fields are
  also individually base64-encoded.

- `EncodedBatchProof`: A base64-encoded `BatchProof` object where `P` is
  marshalled separately into an individual `EncodedDLEQProof` object.

- `KeyVersion`: A string sent by the server indicating the ID of the key
  rotation schedule that is being used.

- `DeprecatedIssueResponse`: A deprecated data type that will be removed in
  future releases. Essentially an array of the form:

    ```
    [ []PointData, EncodedBatchProof ]
    ```
- `IssueResponse`: A (JSON) struct of the form:

    ```
    type IssueResponse struct {
        Sigs     []PointData
        Proof    EncodedBatchProof
        Version  KeyVersion
    }
    ```

- HTTP response body contains a string of the form:

        `"signatures=" || base64.encode(IssueResponse)`

- (Optional)

### ClientStorageObject

__Description__: A (JSON) struct that is stored in the browser local storage for
handling redemptions in the future.

- `ClientStorageObject`: A struct of the form:

    ```
    type ClientStorageObject struct {
        Token  []byte
        Blind  string
        Point  string
    }
    ```
    where `Token.Token` is an array of bytes, `Token.Blind` is a hex-encoded
    `BitInteger` and `Token.Point` is a base64-encoded octet-string that is the
    result of an elliptic point to octet-string conversion.

## RedemptionRequest

__Description__: A (JSON) struct for constructing requests to the server to
bypass future server-generated authentication challenges using signed tokens
from the server.

- `SharedPoint`: A curve point.

- `SharedPointBytes`: A `SharedPoint` object after conversion to an
  octet-string.

- `Host`: is the string contents of the host header of a HTTP request.

- `Path`: is the string HTTP path of a HTTP request.

- `DerivedKey`: A `[]byte` object output by computing:

    ```
	HMAC([]byte("hash_derive_key"), (Token || SharedPointBytes))
    ```
    where `Token` is some `[]byte` object.

- `RequestBinding`: A base64-encoded `[]byte` object output by computing:

    ```
	base64.encode(HMAC([]byte("hash_request_binding"), (DerivedKey || []byte(Host) || []byte(Path))))
    ```

- `H2CParams`: A base64-encoded JSON struct of the form:

    ```
    base64.encode({ curve: <curve_string>, hash: <hash_string>, method: <method_string> })
    ```
    where `<curve_string>` is the name of the elliptic curve used by Privacy
    Pass (e.g. `"p256"`), `<hash_string>` is the name of the hash function used
    for hashing to curve (e.g. `"sha256"`) and `<method_string>` is the
    hash-to-curve method that is used (e.g. `"increment"` or `"swu"`).

- `RedeemRequest`: A `BlindTokenRequest` object of the form:

	```
	BlindTokenRequest{Type:"Redeem", Contents:[base64.encode(Token), RequestBinding]}
	```
    where `Token` is some `[]byte` object. If `ACTIVE_CONFIG["send-h2c-params"]`
    is set to `true`, then we append `H2CParams` to the array stored in
    `BlindTokenRequest.Contents`.

- HTTP request header: `challenge-bypass-token:base64-encode(RedeemRequest)`

## RedemptionResponse

__Description__: There is no designated server response in the case of a
success. In a success we just expect that the server returns with a successful
HTTP response. In the case of a failure, the server appends the following error:

```
chl-bypass-response: <error-code>
```

where an error code of `5` indicates a connection failure, and `6` indicates a
verification error.

## Token issuance

In the token issuance step, the client generates some blinded tokens that are
then signed by the server and returned on completion of some undefined
authentication challenge. The signed blinded tokens that the client receives are
stored unblinded against the original tokens (or blinded with the corresponding
scalar that was used for blinding).

We detail the steps taken by the client (& extension) in carrying out the Token
issuance part of the protocol.

Let `N ≤ 100` be some positive integer. Let `(G,H)` be a trusted pair of
commitments that are received by the server at some point in the past.

### Client request

1. The client completes some server-generated authentication challenge and
  generates `N` `token` objects `t_i`.
2. Samples `N` scalars `r_i`
3. Computes `T_i <- h2c(t_i)` and a BlindToken object `P_i <- (r_i)T_i`.
4. Generates a new array `b64BlindTokenArray` of `[]byte` objects, of length `N`
5. Base64-encodes each of the BlindToken objects into `[]byte` and appends each
   to `b64BlindTokenArray`
6. Constructs an `IssueRequest` with `Contents` set to `b64BlindTokenArray`.
7. Sends the `IssueRequest` in the body of a HTTP request to the
   server.<sup>1</sup>
8. Stores an array `Tokens` of `ClientStorageObject` objects where:

    ```
    Tokens[i] = ClientStorageObject{Token: t_i, Blind: hex(r_i), Point: null}
    ```

### Server response

1. The client receives a string of the form `signatures=<base64-encoded data>`.
2. Client base64-decodes `<base64-encoded data>` and parses the result in the
   following way:

    - If the result is an array then it parses it as a `DeprecatedIssueResponse`
     object, and sets a global variable `keyVersion` equal to `1.0`.
    - If the result is JSON then it parses it as a `IssueResponse` and sets
      `keyVersion` equal to `IssueResponse.KeyVersion`.

3. Converts `IssueResponse.Sigs` into an array of elliptic curve points
   `CurvePoints` by applying the [SEC1](http://www.secg.org/sec1-v2.pdf)
   transformation from Section 2.3.3 on each individual byte array.
4. Converts `IssueResponse.Proof` into a `BatchProof` object by computing:

    - `resBP <- JSON.parse(base64-decode(IssueResponse.Proof))`
    - `resDLEQ <- JSON.parse(base64-decode(resBP.P))`

    and then returning:

    ```
    BP = BatchProof{P: base64-decode(resDLEQ), M: resBP.M, Z: resBP.Z, C: resBP.C}
    ```
    where `base64-decode(resDLEQ)` indicates base64-decoding all the individual
    proof values into their correct types (either curvePoint or BigInteger).
5. Validates `BP` using the process laid out in [PROTOCOL.md](PROTOCOL.md).
6. Lets `Tokens[i].Point = base64-encode(CurvePoints[i])`.
7. Appends `Tokens` to the browser localStorage.

## Token Redemption

In the token redemption step, the client aims to 'redeem' one of the signed
tokens that they received from the server. A redemption occurs when the server
asks for another authentication challenge to be solved by the client. The
redemption request enables the client to bypass the challenge.

### Client request

1. Assume that the client requests a resource from the server using a request
   with the Host header set to `Host`, and the path of the request equal to
   `Path`.
2. The client is served with a challenge by the server and does the following.
3. Pops `c = ClientStorageObject[0]` from localStorage.
4. Unblinds `c.Point` using `c.Blind` and the unblinding method explained in
   [PROTOCOL.md](PROTOCOL.md) and returns the result as a `SharedPoint`
   object `sp`.
5. Computes `spBytes` as the conversion of `sp` into a `[]byte` object.
6. Computes a `DerivedKey` object `dk` by computing:

    ```
    dk <- HMAC([]byte("hash_derive_key"), (c.Token || spBytes))
    ```

7. Computes `HostBytes <- []byte(Host)` and `PathBytes <- []byte(Path)` where
   `Host` and `Path` are linked to the original resource requested
8. Computes `RequestBinding` object `rb` by computing:

    ```
    rb <- HMAC([]byte("hash_request_binding"), (DerivedKey || HostBytes || PathBytes))
    ```

9. Constructs a `RedemptionRequest` object of the form:

    ```
    RedemptionRequest{Type:"Redeem", Contents: [c.Token,rb]}
    ```
    optionally appending `H2CParams` if `ACTIVE_CONFIG["send-h2c-params"] =
    true`.

10. Sends the HTTP request with the header:

    ```
    challenge-bypass-token: base64-encode(RedemptionRequest)
    ```

<sup>1</sup>In the current implementation, this is done by interception of the
outgoing HTTP request with a solution to the server-generated challenge and
sending it instead as an XHR with body set to be the IssueRequest.


