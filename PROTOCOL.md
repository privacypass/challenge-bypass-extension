# Overview of protocol

We give a short, cryptographic overview of the protocol written by George Tankersley. Our construction is based on the concept of a Verifiable, Oblivious Pseudorandom Function (VOPRF) related closely to the ROM realization of 2HashDH-NIZK from the [JKK14] with the addition of a batch NIZK proof.

## Notation 

We have tried to ensure that our notation coincides with the notation that is used to describe the ECVRF construction of [Goldberg et al.](https://tools.ietf.org/pdf/draft-goldbe-vrf-01.pdf). However, we have diverged at points since our construction contains extra features; such as oblivious evaluation and batch DLEQ proofs. We use CAPTCHA as a catch-all term for some form of proof-of-work internet challenge. 

## Introduction

The solution that we develop here is a protocol between a user, a challenger and an edge server. The edge server proxies user requests for a protected origin and refers the user to the challenger if the request is deemed to be (potentially) malicious. The challenger serves a CAPTCHA to the user. If the user solves the CAPTCHA, then the challenger issues a batch of signed tokens to the user. A user possessing signed tokens may attempt to redeem them with the edge instead of solving a challenge. If the edge verifies that a redemption pass contains a token signed by the challenger that has not already been spent, then the edge allows the connection through to the origin.


## Preliminaries

- A message authentication code ("MAC") on a message is a keyed authentication tag that can be only be created and verified by the holder of the secret key.
- A pseudorandom function is a function whose output cannot be efficiently distinguished from random output. This is a general class of functions; concrete examples include hashes and encryption algorithms.
- An oblivious pseudorandom function ("OPRF") is a generalization of blind signatures. Per Jarecki, it's a two-party protocol between sender S and receiver R for securely computing a pseudorandom function `f_x(·)` on key `x` contributed by S and input `t` contributed by R, in such a way that receiver R learns only the value `f_x(t)` while sender S learns nothing from the interaction.
    - In this protocol, the edge is the "sender" holding `x` and the inputs `t` are the tokens. So the clients don't learn our key and we don't learn the real token values until they're redeemed.
- Furthermore, a verifiable OPRF is one where the sender supplies a proof that the function was evaluated correctly.


## Protocol description

We detail a 'blind-signing' protocol written by the Privacy Pass team using an OPRF to construct per-pass shared keys for a MAC over each redemption request. This hides the token values themselves until redemption and obviates the need for public key encryption. This protocol subsumes the blind-RSA protocol that was described in earlier releases of the protocol specification.

Given a group setting and three hashes `H_1`, `H_2`, `H_3` we build a commitment to a random token using a secret key x held by the edge servers. `H_1` is a hash into the group and `H_2`, `H_3` are hashes to bitstrings `{0, 1}^λ` where `λ` is a security parameter (we use SHA256).

We assume the edge has published a public key `Y = xG` for the current epoch and some long-term generator `G` (we use `H` instead in the code but `Y` here to differentiate from the hash functions that we use). Here we also the term 'user' synonymously with 'plugin' for operations that are carried out on the client-side.


Token issuance looks like this:

1. User generates a random token `t` and a blinding factor `r`

2. User calculates `T = H_1(t)` and `M = rT`

3. User sends `M` to the server along with the CAPTCHA solution

4. Edge validates solution with the challenger and computes `Z = xM = xrT`

5. Edge generates a proof `D` showing that `DLEQ(Z/M == Y/G)`

6. Edge sends `(Z, D)` to client

7. User checks the proof `D` against the sent tokens and the previously-known key commitment `Y` to establish that the edge is using a consistent key.

8. User unblinds `Z` to calculate `N = (1/r)Z = xT` and stores `(t, N)`


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


## NIZK proofs of discrete-log equality

In issuance step (5.) above, we call for a zero-knowledge proof of the equality of a discrete logarithm (our edge key) with regard to two different generators.

The protocol naturally provides `Z = xM` in the edge response. To ensure that the edge has not used unique `x` value to tag users, we require them to publish a public key, `Y = xG`. Now we can use knowledge of `G,Y,M,Z` to construct a Chaum-Pedersen proof [CP93] proving in zero knowledge that `log_G(Y) == log_M(Z)` (i.e. that the same key is used for the pinned epoch as for 'signing' the tokens). We note this as `DLEQ(Z/M == Y/G)`.

The proof follows the standard non-interactive Schnorr pattern. For a group of prime order `q` with orthogonal generators `M`, `G`, public key `Y`, and point `Z`:

1. Prover chooses a random nonce

        k <--$-- Z/qZ

2. Prover commits to the nonce with respect to both generators

        A = kG, B = kM

3. Prover constructs the challenge

        c = H_3(G,Y,M,Z,A,B)

4. Prover calculates response

        s = k - cx (mod q)

5. Prover sends (c, s) to the verifier

6. Verifier recalculates commitments

        A' = sG + cY
        B' = sM + cZ

7. Verifier hashes

        c' = H_3(G,Y,M,Z,A',B')

   and checks that `c == c'`.

If all users share a consistent view of the tuple `(G, Y)` for each key epoch, they can all prove that the tokens they have been issued share the same anonymity set with respect to `x`. One way to ensure this consistent view is to pin the same accepted commitments in each copy of the client and use software update mechanisms for rotation. A more flexible way is to pin a reference that allows each client to fetch the latest version of the key from a trusted location; we examine this possibility [below](#tor-specific-public-key-publication). We currently use the former method but plan to migrate to the latter in the near future. This means that we will pin commitments for each key that will be accepted for signing in the extension directly (see config.js). 

## Batch Requests

In practice, the issuance protocol operates over sets of tokens rather than just one. A system parameter, `m`, determines how many tokens a user is allowed to request per valid CAPTCHA solution. Consequently, users generate `(t_1, t_2, ... , t_m)` and `(r_1, r_2, ... , r_m)`; send `M_1, M_2, ... , M_m)` to the edge; and receive `(Z_1, Z_2 ... , Z_m)` in response.

Generating an independent proof of equality for each point implies excess overhead in both computation and bandwidth consumption. Therefore, we employ a batch proof to show consistent key usage for an entire set of tokens at once.  The proof is a parallelized Schnorr protocol for the common-exponent case taken from [Hen14] and adapted for non-interactivity:

Given `(G, Y, q)`; `(M_1,...,M_m)`, `(Z_1, ... ,Z_m)`; `Z_i = x(M_i)` for i = 1...m

1. Prover calculates a seed using a Fiat-Shamir transform:

        z = H_3(G, Y, M_1, ... , M_m, Z_1, ... , Z_m)

2. Prover initializes PRNG(z) and samples from it to non-interactively generate

        c_1, ... , c_m <--$-- Z/qZ.

3. Prover generates composite group elements M and Z

        M = (c_1*M_1) + (c_2*M_2) + ... + (c_m*M_m)
        Z = (c_1*Z_1) + (c_2*Z_2) + ... + (c_m*Z_m)

4. Prover sends proof<sup>1</sup>

        (c, s) <-- DLEQ(Z/M == Y/G)

5. Verifier recalculates the PRNG seed from protocol state, generates the composite elements, and checks that `c' == c` as in the single-element proof above.

<sup>1</sup>: In the actual instantiation of the protocol we also send the values of `M` and `Z` for both the batch and DLEQ proofs. The client then recomputes the values of `M` and `Z` themselves using the tokens in the response and checks that these values are equal before verifying the proof.

We can see why this works in a reduced case for `(M_1, M_2)`, `(Z_1, Z_2)`, and `(c_1, c_2)`:

    Z_1 = x(M_1)
    Z_2 = x(M_2)
    (c_1*Z_1) = c_1(x*M_1) = x(c_1*M_1)
    (c_2*Z_2) = c_2(x*M_2) = x(c_2*M_2)
    (c_1*Z_1) + (c_2*Z_2) = x[(c_1*M_1) + (c_2*M_2)]

So the composite points will have the same discrete log relation x as the underlying individual points.

## Attacks

We detail two potential attack vectors for a malicious edge/client and proposed mitigations.

### Tagging by the edge

The major risk for users is the lack of validation. There's no way for the user to know if they have been given a bad/tagged `Z` value until they attempt to redeem, which might be a linkable operation.

The basic attack works by using a unique `x` value for each batch of issued tokens. Later, the edge can try validating redemptions with each key to link the request to both the issuance request and all other redemptions from the same batch. Structured choices of key (e.g. sequential) allow these bulk checks to be relatively efficient.

We assume that the proof of consistent discrete logarithm is sufficient to guard against this and other key-related edge-side tagging attacks.  Alternatively or additionally, if the edge publishes historical key values then auditors who save their signed token results can check for honesty retroactively.

What else the user needs to validate remains an open question.

### Stockpiling of passes

The major risk to the edge is that a malicious user might somehow acquire enough privacy passes to launch a service attack, for instance by paying people to solve CAPTCHAs and stockpile the resulting passes.

We mitigate this in-protocol in two ways. First, by limiting the number of passes that a user can request per challenge solution. Secondly, and more effectively, by enabling fast key rotation by the edge. The edge declares an epoch for which passes will be valid, and at the end of that epoch rotates the key it uses to sign and validate passes. This has the effect of invalidating all previously-issued passes and requiring a stockpiling attacker to solve challenges close to the time they want to launch an attack, rather than waiting indefinitely. In practice, we could also use a 'sliding window approach' so that tokens from the last epoch are not immediately invalidated, this will make epoch transitions smoother for clients. Note here though that we leak a bit of anonymity with respect to the set of clients that are using tokens signed by one of the keys that are valid.

The process of key rotation is simple: the edge generates a new private key and, via some appropriately public process, a fresh generator `G` (we can also use a fixed generator). The public key is then computed as `Y = xG`, and the pair `(Y, G)` or just `Y` (see [below](#tor-specific-public-key-publication)) is then published.

We mitigate this risk out-of-protocol by applying further arbitrary processing to the requests (for instance, using a WAF or rate limiting) such that even an attacker in possession of many passes cannot effectively damage the origins.

### Token exhaustion
Privacy Pass uses a finite list of low-entropy characteristics to determine whether a token should be redeemed or not. In the case of Cloudflare CAPTCHAs, the extension looks for the presence of a HTTP response header and particular status code. Alternative methods that check the HTML tags of a challenge page could also be used. Unfortunately, this means that it is easy to recreate the characteristics that are required by the extension to sanction a redemption. 

To view the attack at its most powerful, consider a sub-resource that manages to embed itself widely on many webpages with high visitation that is able to trigger token redemptions. Such a resource would be able to drain the extension of all its tokens by triggering redemptions until all the tokens were used. While it is unclear why such an attack would be useful, it is important to acknowledge that it is indeed possible to carry out and would thus render the usage of Privacy Pass useless if the sub-resource was especially prevalent.

We mitigate this loosely by preventing token redemptions occurring for the same URL in quick succession (until some action has occurred such as the browser window closing or the tokens being cleared). This prevents a sub-resource from continually draining tokens after each spend, it also spreads out the redemptions considerably. While this does not prevent the attack from occurring outright, it makes it quite expensive to launch and also non-trivial to carry out. Notice that the sub-resource would have to schedule a page reload each time the extension is adjudged to have cleared the set of URLs that have been interacted with.

#### Tor-specific public key publication

A better way to publish H is to run a long-lived Tor relay with the public key placed in some of the descriptor fields. The descriptor will be included in the Tor network consensus and thus queryable by any Tor client with control port access - which includes Tor Browser. The descriptor is signed and addressed by a public key under our control that will develop a reputation weighting in the consensus over time. This gives us a reasonably trusted publication mechanism that, by protocol necessity, provides a consistent view to all participants in the Tor network while allowing us to update the values at any time.

In this scheme, client software need only pin a Tor relay fingerprint and the challenger can rotate keys as often as necessary to mitigate stockpiling problems.

## References

[CP93] Chaum, Pedersen. Wallet Databases with Observers. CRYPTO'92

[Hen14] Ryan Henry. Efficient Zero-Knowledge Proofs and Applications, August 2014.

[JKK14] Jarecki, Kiayias, Krawczyk. Round-Optimal Password-Protected Secret Sharing and T-PAKE in the Password-Only model. https://eprint.iacr.org/2014/650.pdf