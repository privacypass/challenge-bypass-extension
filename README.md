# Challenge Bypass Extension

The Cloudflare Privacy Pass extension allows a user to bypass challenge pages provided by Cloudflare using the blinded tokens protocol similar to the one described [here](https://github.com/cloudflare/challenge-bypass-specification). The protocol we use here is actually based on a 'Verifiable, Oblivious Pseudorandom Function' (VOPRF). We provide a short description of how this fits into our original specification below. The VOPRF we now use is based heavily on the design first established by Jarecki et al. [JKK14]. For a technical description of the protocol see the [Technical Overview](#overview-of-protocol).

The protocol has received extensive review and testing, but this extension is a work in progress. We welcome contributions from the wider community, and also feel free to notify us of any issues that occur. In the below, we detail the exact message specification that is required for interacting with Cloudflare's edge server. Pull requests and reviews of the extension detailed here are welcome and encouraged.

The browser is compatible with Chrome, Firefox and the Tor Browser Bundle.

### Contents

  * [Stable releases](#stable-releases)
  * [Main authors](#main-authors)
  * [Other contributors](#other-contributors)
  * [Acknowledgements](#acknowledgements)
  * [Cryptography](#cryptography)
  * [Testing](#testing)
     * [Firefox](#firefox)
     * [Chrome](#chrome)
     * [Firefox pre-version 48](#firefox-pre-version-48)
  * [Plugin overview](#plugin-overview)
     * [Workflow](#workflow)
     * [Message formatting](#message-formatting)
        * [Issuance request](#issuance-request)
        * [Issue response](#issue-response)
        * [Redemption request (privacy pass)](#redemption-request-privacy-pass)
        * [Redemption response](#redemption-response)
     * [DLEQ handling](#dleq-handling)
  * [Overview of protocol](#overview-of-protocol)
     * [Notation](#notation)
     * [Overview](#overview)
     * [Preliminaries](#preliminaries)
     * [Protocol description](#protocol-description)
     * [NIZK proofs of discrete-log equality](#nizk-proofs-of-discrete-log-equality)
     * [Batch Requests](#batch-requests)
     * [Attacks](#attacks)
        * [Tagging by the edge](#tagging-by-the-edge)
        * [Stockpiling of passes](#stockpiling-of-passes)
     * [Appendix A: Tor-specific public key publication](#appendix-a-tor-specific-public-key-publication)
     * [Appendix B: Benefits vs blind RSA](#appendix-b-benefits-vs-blind-rsa)
  * [Blog post](#blog-post)
  * [IETF draft](#ietf-draft)
  * [Server-side release](#server-side-release)
  * [References](#references)

## Stable releases

Download the latest stable release of the extension:
- [Chrome](https://chrome.google.com/webstore/detail/cloudflare-token-jar/pielknblobdnllhdjbebccpfgohaodgh)
- [Firefox](https://addons.mozilla.org/en-GB/firefox/addon/cloudflare-token-jar/?src=search)

## Main authors

- [George Tankersley](https://github.com/gtank) (george.tankersley@gmail.com)
- [Alex Davidson](https://github.com/alxdavids) (alex.davidson.92@gmail.com) 

## Other contributors

- [Nick Sullivan](https://github.com/grittygrease) (nick@cloudflare.com)
- [Filippo Valsorda](https://github.com/filosottile) (hello@filippo.io)
- [Eric Tsai](https://github.com/eetom) (etsai@cloudflare.com)

## Acknowledgements

We'd like to thank Dan Boneh for suggesting OPRFs in the first place; Ian Goldberg for his extensive advice and the batch proof; and Brian Warner, Zaki Manian, Tony Arcieri, Isis Lovecruft, Henry de Valence, Trevor Perrin, and several anonymous others for their valuable help, input, and review.

## Cryptography

Cryptography is implemented using the elliptic-curve library [SJCL](https://github.com/bitwiseshiftleft/sjcl) and compression of points is done in accordance with the standard SEC1. This work uses the NIST standard P256 elliptic curve for performing operations. Third-party implementers should note that the outputs of the hash-to-curve, key derivation, and point encoding functions must match their Go equivalents exactly for interaction with Cloudflare. More information about this will be provided when the edge implementation is open-sourced.

## Testing

### Firefox

- `git clone git@github.com:cloudflare/challenge-bypass-extension.git`
- Open Firefox and go to `about:debugging`
- Click 'Load Temporary Add-on' button
- Select manifest.json from <your-repos>/challenge-bypass-extension/
- Check extension logo appears in top-right corner and 0 passes are stored (by clicking on it)
- Go to a web page where CAPTCHAs are on and bypassing is on (e.g. https://captcha.website)
- Solve CAPTCHA and check that some passes are stored in the extension now
	- captcha.website cannot be bypassed (this is only for gaining tokens)
- Go to webpage where CAPTCHA would normally be displayed
- Check that webpage is displayed and that 1 or more passes are spent
	- No interaction with a CAPTCHA page should occur
- A clearance cookie should have been received 
	- This can be used in the future instead of spending more tokens for this domain

### Chrome

Same as above, except the extension should be loaded at `chrome://extensions` instead.

### Firefox pre-version 48 

We have provided a manifest.json file in ff-48/ that adds the `applications` tag that is necessary for compatibility with older versions of Firefox (pre-48). Replace the used manifest.json with this one if you plan to use an older version of Firefox.

## Plugin overview

- background.js: Processes the necessary interactions with web-pages directly. Sends messages and processes edge replies

- config.js: Config file containing commitments to edge private key for checking DLEQ proofs (currently not implemented)

- content.js: (currently unused) Content script for reading page html

- token.js: Constructs issuance and redemption requests (i.e. privacy passes) from stored blinded tokens

- crypto.js: Wrapper for performing various cryptographic operations required for manipulating tokens

- sjcl.js: Local copy of SJCL library

- In the following we may use 'pass' or 'token' interchangeably. In short, a token refers to the random nonce that is blind signed by the edge. A pass refers to the object that the extension sends to the edge in order to bypass a CAPTCHA.

### Workflow

- **edge**: protects origin webpages from malicious activity
- **user**: human user interacting with a browser
- **plugin**: acts on behalf of user in interaction with edge
- **client**: the browser
- **(blinded) token**: Random EC point that is 'signed' by the edge
- **pass**: redemption request containing token for bypassing CAPTCHA

- Issuing:
	- Browser requests an origin protected by the edge
	- Browser arrives at challenge page (aka CAPTCHA) provided by the edge
	- User solves CAPTCHA
	- User sends CAPTCHA solution back to the edge
	- Browser plugin generates N tokens (N=<100; N=10;) and cryptographically blinds them
	- The plugin adds an ['issue request'](#issuance-request) to the body of the request before it is sent
	- The edge verifies the CAPTCHA solution
	- If fine, the edge signs the tokens and returns them back to the client in the form of a ['issue response'](#issue-response)
	- The plugin disassembles the response and stores the signed tokens for future use. It also reloads the origin webpage and gains access (e.g. sending a pass containing the token as below or a single-domain cookie given by the edge)

- Redemption:
	- User visits an origin and a CAPTCHA page is returned
	- The plugin catches the response and gets an unspent blinded token and signature from the store and creates an ['privacy pass'](#redemption-request) 
	- The plugin unblinds the token on the pass and sends up a new request with a header `challenge-bypass-token`; with the value set to the value of the pass
	- The edge verifies the redemption request<sup>1</sup> and checks that the pass has not been used before
	- If all is fine, the edge grants the user access to the origin

<sup>1</sup> The validation is slightly different depending on the blinding scheme. In the VOPRF scheme the validation requires deriving a shared key and verifying a MAC over the pass and associated request data.

### Message formatting

We provide a brief overview of the message types that are sent and received by this plugin. These messages are sent in base64 encoding and either within HTTP bodies or within specific headers. In the following `||` will denote concatenation.

#### Issuance request

JSON struct used for sending blinded tokens to be signed by the edge, this message is appended to the body of a request holding a CAPTCHA solution.

- `<blind-token>` is a randomly sampled, blinded elliptic curve point (this point is sent in compressed format as defined in Section 2.3.3 of http://www.secg.org/sec1-v2.pdf). The blind is also randomly sampled with respect to the same group.

- `<contents>` is an array of N `<blind-token>` objects.

- `<Issue-JSON-struct>`:

	```
	{
		"type": "Issue",
		"contents": "<contents>",
	}
	```

- Body contents:
	
	`"blinded-tokens=" || base64.encode(<Issue-JSON-struct>)`

#### Issue response

Marshaled array used for sending signed tokens back to the user. This message is appended to the response body by the edge after a valid CAPTCHA is submitted.

- `<signed-tokens>` is an array of compressed elliptic curve point, as above, that have been 'signed' by the edge. In the VOPRF model the 'signed' point is essentially a commitment to the edge's private key

- `<proof>` is a base64 encoded JSON struct containing the necessary information for carrying out a DLEQ proof verification. In particular it contains base64 encodings of compressed elliptic curve points G,Y,P,Q along with response values S and C for streamlining the proof verification. See [below](#nizk-proofs-of-discrete-log-equality) for more details.

- `<M>` and `<Z>` are base64 encoded compressed elliptic curve points 

- `<batch-proof>` is a base64 encoded JSON struct of the form:<sup>2</sup>

	```
	{
		"proof":"<proof>",
		"M":"<M>",
		"Z":"<Z>",
	}
	```

<sup>2</sup> Other [VRF implementations](https://datatracker.ietf.org/doc/draft-goldbe-vrf/?include_text=1) use different notation to us. We have tried to coincide as much as possible with these works.

- `<Batch-DLEQ-Resp>`:
	
	`"batch-proof=" || <batch-proof>` 

- Issue response:
	
	`"signatures=" || <signed-tokens> || <Batch-DLEQ-Resp>`

#### Redemption request (privacy pass)

JSON struct sent in a request header to bypass CAPTCHA pages.

- `<token>` is an original token generated by the plugin before.

- `<shared-point>` is the corresponding unblinded, signed point received from the edge. This point is SEC1 encoded.

- `<host>` is the contents of the host header of the original request.

- `<path>` is the HTTP path of the original request.

- `HMAC()` is a HMAC function that uses SHA256

- `<derived-key>` is the derived key output by:
	
	`HMAC("hash_derive_key", <token>, <shared-point>)`

- `<request-binding>` is the output of the following:

	`HMAC("hash_request_binding", <derived-key>, <host>, <path>)`

- `<Redeem-JSON-struct>` (or privacy pass):

	```
	{
		"type":"Redeem",
		"contents":"<request-binding>"
	}
	```

- Header:

	`"challenge-bypass-token":"<Redeem-JSON-struct>"`


#### Redemption response

Server response header used if errors occur when verifying the privacy pass.

- `<error-resp>` is the error value returned by the privacy pass verifier. Takes the value 5 or 6, where 5 is an edge-side connection error and 6 is a pass verification error.

- Header: 

	`"CF-Chl-Bypass-Resp":"<error-resp>"`

### DLEQ handling

The DLEQ proofs are not currently handled by the extension. In a future version we plan to introduce this functionality. Moreover, the edge private key commitments are baked into the extension config so the deanonymisation potential is reduced for now.

## Overview of protocol

We give a short, cryptographic overview of the protocol written by George Tankersley. As mentioned above, our construction is based on the concept of a VOPRF based closely on the ROM realization of 2HashDH-NIZK from the [JKK14] with the addition of a batch NIZK proof.

### Notation 

We have tried to ensure that our notation coincides with the notation that is used to describe the ECVRF construction of [Goldberg et al.](https://tools.ietf.org/pdf/draft-goldbe-vrf-01.pdf). However, we have diverged at points since our construction contains extra features; such as oblivious evaluation and batch DLEQ proofs.

### Overview

The solution that we develop here is a protocol between a user, a challenger and an edge server. The edge server proxies user requests for a protected origin and refers the user to the challenger if the request is deemed to be (potentially) malicious. The challenger serves a CAPTCHA to the user. If the user solves the CAPTCHA, then the challenger issues a batch of signed tokens to the user. A user possessing signed tokens may attempt to redeem them with the edge instead of solving a challenge. If the edge verifies that a redemption pass contains a token signed by the challenger that has not already been spent, then the edge allows the connection through to the origin.

In the specific case of Cloudflare, the challenger and the edge are the same party. Furthermore, our edge "rewards" the user with a single-domain clearance cookie that allows the user to visit the origin for a period of time without being challenged again.


### Preliminaries

- A signature on a message is a publicly verifiable authentication tag that certifies that the message has been signed by the holder of the private half of a public/private keypair.
- A blind signature is a signature scheme where the contents of the message are obscured ("blinded") before signing, such that the signer does not know what it is signing. A party who knows how the message was obscured (the "blinding factor") can unblind both the message and the signature to produce a valid signature for the original message. The most widely-known example of a blind signature is Chaum's blind RSA scheme.
- A message authentication code ("MAC") on a message is a keyed authentication tag that can be only be created and verified by the holder of the secret key.
- A pseudorandom function is a function whose output cannot be efficiently distinguished from random output. This is a general class of functions; concrete examples include hashes and encryption algorithms.
- An oblivious pseudorandom function ("OPRF") is a generalization of blind signatures. Per Jarecki, it's a two-party protocol between sender S and receiver R for securely computing a pseudorandom function `f_x(·)` on key `x` contributed by S and input `t` contributed by R, in such a way that receiver R learns only the value `f_x(t)` while sender S learns nothing from the interaction.
    - In this protocol, the edge is the "sender" holding `x` and the inputs `t` are the tokens. So the clients don't learn our key and we don't learn the real token values until they're redeemed.
- Furthermore, a verifiable OPRF is one where the sender supplies a proof that the function was evaluated correctly.


### Protocol description

We detail a 'blind-signing' protocol written by George Tankersley using an OPRF to contruct per-pass shared keys for a MAC over each redemption request. This hides the token values themselves until redemption and obviates the need for public key encryption. This protocol subsumes the blind-RSA protocol that was described in earlier releases of the protocol specification.

Given a group setting and three hashes `H_1`, `H_2`, `H_3` we build a commitment to a random token using a secret key x held by the edge servers. `H_1` is a hash into the group and `H_2`, `H_3` are hashes to bitstrings `{0, 1}^λ` where `λ` is a security parameter (we use SHA256).

We assume the edge has published a public key `Y = xG` for the current epoch.


Token issuance looks like this:

1. User generates a random token `t` and a blinding factor `r`

2. User calculates `T = H_1(t)` and `P = rT`

3. User sends `P` to the server along with the CAPTCHA solution

4. Edge validates solution with the challenger and computes `Q = xP = xrT`

5. Edge generates a proof `D` showing that `DLEQ(Q/P == Y/G)`

6. Edge sends `(Q, D)` to client

7. User checks the proof `D` against the previously-known key commitment `H` to establish that the edge is using a consistent key.

8. User unblinds `Q` to calculate `N = (-r)Q = xT` and stores `(t, N)`

Now both the edge and the user can calculate `H_2(t, N)` as a shared key.


Redemption looks like this:

1. User calculates request binding data `R` for the request they want to make

2. User chooses an unspent token `t` to redeem and retrieves `(t, N)`

3. User calculates a shared key `sk = H_2(t, N)`

4. User sends a pass `(t, MAC_{sk}(R))` to the edge along with the HTTP request

5. Edge recalculates `R` from observed request data

6. Edge checks the double-spend list for `t`

7. Edge calculates `T = H_1(t)`, `N = xT` and `sk = H_2(t, N)`

8. Edge checks that `MAC_{sk}(R)` matches the user-supplied value

9. If MAC is valid, edge forwards the request and stores a record of `t`

In the current protocol, "request binding data" is the Host header and requested HTTP path.


### NIZK proofs of discrete-log equality

In issuance step (5.) above, we call for a zero-knowledge proof of the equality of a discrete logarithm (our edge key) with regard to two different generators.

The protocol naturally provides `Q = xP` in the edge response. To ensure that the edge has not used unique `x` value to tag users, we require them to publish a public key, `Y = xG`. If `P`, `G` are orthogonal we can use a Chaum-Pedersen proof [CP93] to prove in zero knowledge that `log_G(Y) == log_P(Q)`. We note this as `DLEQ(Q/P == Y/G)`.

The proof follows the standard non-interactive Schnorr pattern. For a group of prime order `q` with orthogonal generators `P`, `G`, public key `Y`, and point `Q`:

1. Prover chooses a random nonce

        k <--$-- Z/qZ

2. Prover commits to the nonce with respect to both generators

        A = kG, B = kP

3. Prover constructs the challenge

        c = H_3(G,Y,P,Q,A,B)

4. Prover calculates response

        s = k - cx (mod q)

5. Prover sends (c, s) to the verifier

6. Verifier recalculates commitments

        A' = sG + cY
        B' = sP + cQ

7. Verifier hashes

        c' = H_3(G,H,P,Q,A',B')

   and checks that `c == c'`.

If all users share a consistent view of the tuple `(Y, G)` for each key epoch, they can all prove that the tokens they have been issued share the same anonymity set with respect to `k`. One way to ensure this consistent view is to pin a key in each copy of the client and use software update mechanisms for rotation. A more flexible way is to pin a reference that allows each client to fetch the latest version of the key from a trusted location; we examine this possibility in Appendix A. We currently use the former method but plan to migrate to the latter in the near future.


### Batch Requests

In practice, the issuance protocol operates over sets of tokens rather than just one. A system parameter, `m`, determines how many tokens a user is allowed to request per valid CAPTCHA solution. Consequently, users generate `(t_1, t_2, ... , t_m)` and `(r_1, r_2, ... , r_m)`; send `(P_1, P_2, ... , P_m)` to the edge; and receive `(Q_1, Q_2 ... , Q_m)` in response.

Generating an independent proof of equality for each point implies excess overhead in both computation and bandwidth consumption. Therefore, we employ a batch proof to show consistent key usage for an entire set of tokens at once.  The proof is a parallelized Schnorr protocol for the common-exponent case taken from [Hen14] and adapted for non-interactivity:

Given `(G, Y, q)`; `(P_1,...,P_m)`, `(Q_1, ... ,Q_m)`; `Q_i = k(P_i)` for i = 1...m

1. Prover calculates a seed using a Fiat-Shamir transform:

        z = H_3(G, Y, P_1, ... , P_m, Q_1, ... , Q_m)

2. Prover initializes PRNG(z) and samples from it to non-interactively generate

        c_1, ... , c_m <--$-- Z/qZ.

3. Prover generates composite group elements M and Z

        M = (c_1*P_1) + (c_2*P_2) + ... + (c_m*P_m)
        Z = (c_1*Q_1) + (c_2*Q_2) + ... + (c_m*Q_m)

4. Prover sends proof

        (c, s) <-- DLEQ(Z/M == Y/G)

5. Verifier recalculates the PRNG seed from protocol state, generates the composite elements, and checks that `c' == c` as in the single-element proof above.

We can see why this works in a reduced case.

For `(P_1, P_2)`, `(Q_1, Q_2)`, and `(c_1, c_2)`:

    Q_1 = x(P_1)
    Q_2 = x(P_2)
    (c_1*Q_1) = c_1(x*P_1) = x(c_1*P_1)
    (c_2*Q_2) = c_2(x*P_2) = x(c_2*P_2)
    (c_1*Q_1) + (c_2*Q_2) = x[(c_1*P_1) + (c_2*P_2)]

So the composite points will have the same discrete log relation x as the underlying individual points.

### Attacks

#### Tagging by the edge

The major risk for users is the lack of validation. There's no way for the user to know if they have been given a bad/tagged `Q` value until they attempt to redeem, which might be a linkable operation.

The basic attack works by using a unique `k` value for each batch of issued tokens. Later, the edge can try validating redemptions with each key to link the request to both the issuance request and all other redemptions from the same batch. Structured choices of key (e.g. sequential) allow these bulk checks to be relatively efficient.

We assume that the proof of consistent discrete logarithm is sufficient to guard against this and other key-related edge-side tagging attacks.  Alternatively or additionally, if the edge publishes historical key values then auditors who save their signed token results can check for honesty retroactively.

What else the user needs to validate remains an open question.

#### Stockpiling of passes

The major risk to the edge is that a malicious user might somehow acquire enough privacy passes to launch a service attack, for instance by paying people to solve CAPTCHAs and stockpile the resulting passes.

We mitigate this in-protocol in two ways. First, by limiting the number of passes that a user can request per challenge solution. Secondly, and more effectively, by enabling fast key rotation by the edge. The edge declares an epoch for which passes will be valid, and at the end of that epoch rotates the key it uses to sign and validate passes. This has the effect of invalidating all previously-issued passes and requiring a stockpiling attacker to solve challenges close to the time they want to launch an attack, rather than waiting indefinitely.

The process of key rotation is simple: the edge generates a new private key and, via some appropriately public process, a fresh generator `G`. Its public key is then `H = kG`, which it publishes as `(H, G)` or just `H` (see Appendix A).

We mitigate this risk out-of-protocol by applying further arbitrary processing to the requests (for instance, using a WAF or rate limiting) such that even an attacker in possession of many passes cannot effectively damage the origins.

### Appendix A: Tor-specific public key publication

A better way to publish H is to run a long-lived Tor relay with the public key placed in some of the descriptor fields. The descriptor will be included in the Tor network consensus and thus queryable by any Tor client with control port access - which includes Tor Browser. The descriptor is signed and addressed by a public key under our control that will develop a reputation weighting in the consensus over time. This gives us a reasonably trusted publication mechanism that, by protocol necessity, provides a consistent view to all participants in the Tor network while allowing us to update the values at any time.

In this scheme, client software need only pin a Tor relay fingerprint and the challenger can rotate keys as often as necessary to mitigate stockpiling problems.

We can further reduce the bookkeeping burden on clients while increasing the trustworthiness of our public keys by deriving the public key generator G from the consensus shared randomness values.


### Appendix B: Benefits vs blind RSA

- Simpler, faster primitives
- 10x savings in pass size (~256 bits using P-256 instead of ~2048)
- The only thing edge to manage is a private scalar. No certificates.
- No need for public-key encryption at all, since the derived shared key used to calculate each MAC is never transmitted and cannot be found from passive observation without knowledge of the edge key or the user's blinding factor.
- Easier key rotation. Instead of managing certificates pinned in TBB and submitted to CT, we can use the DLEQ proofs to allow users to positively verify they're in the same anonymity set with regard to k as everyone else.

## Blog post

See the Cloudflare blog post (to be written)

## IETF draft

See the spec [here](https://github.com/cloudflare/challenge-bypass-specification).

## Server-side release

See the accompanying server-side [release](https://github.com/cloudflare/challenge-bypass-server).

## References

[CP93] Chaum, Pedersen. Wallet Databases with Observers. CRYPTO'92

[Hen14] Ryan Henry. Efficient Zero-Knowledge Proofs and Applications, August 2014.

[JKK14] Jarecki, Kiayias, Krawczyk. Round-Optimal Password-Protected Secret Sharing and T-PAKE in the Password-Only model. https://eprint.iacr.org/2014/650.pdf

[JKKX16] Jarecki, Kiayias, Krawczyk, Xu. Highly-Efficient and Composable Password-Protected Secret Sharing. https://eprint.iacr.org/2016/144.pdf


