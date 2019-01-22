# Deterministic methods for hashing bytes to elliptic curve points

A central portion of our design relies on deterministically hashing bytes to a
uniformly random point on an elliptic curve (we currently use the NIST P256
curve). There are two methods that we use that are controlled via the
"`hash-to-curve`" config option.

It is important that the hash-to-curve algorithm is identical in both the server
and client implementations.

## Hash-and-increment

The method that is currently used in Privacy Pass v1.0 is the
`hash-and-increment` method. Essentially this method works by hashing a
sequence of bytes (the bytes are slightly modified to match Golang's point
generation procedure) and checking if the result can be decompressed into a
point on P-256. If this is successful then we can continue, otherwise we try
again using the result of the previous iteration up to 10 times before failing.

It is obvious that this provides a probabilistic (and non-negligible) chance of
failure and so this method of hashing is suboptimal. See
[here](https://github.com/privacypass/challenge-bypass-extension/blob/alxdavids/h2c/addon/scripts/crypto.js#L156-L195)
for more details.

## Affine SSWU method

In Privacy Pass v1.1 we will move to supporting both the previous
`hash-and-increment` method, and a new method that we call "affine SSWU". The
affine SSWU method always returns a elliptic curve point and thus has zero chance
of failure. The method used is the simplified version of SWU, which was proposed by
Brier et al. based on the previous work of Shallue, Woestijne and Ulas (hence SSWU).
It is known as "affine" since it generates curve points in the affine
representation rather than the Jacobian representation.

The algorithm is described below. The input is a field element `t` that is
obtained by hashing the input bytes into 𝔽_p using SHA256. The output is a coordinate
pair (x,y) for a curve point on the elliptic curve E(𝔽_p). Note that this is an
optimized version of the simplified SWU method described
[here](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/). We use
this optimized version as it reduces the number of exponentiations and
inversions (modulo p) that are required.

```
CONSTANTS: A,B such that E: y^2=x^3+Ax+B, A ≠ 0, and p=3 mod 4.
INPUT: t ∈ 𝔽_p such that t ∉ {−1,0,1}.
OUTPUT: (x,y) ∈ E(𝔽_p).
 1. u  = −t^2
 2. t0 = u^2+u
 3. t0 = 1/t0
 4. x  = (1+t0)*(−B/A)
 5. g  = x^2
 6. g  = g+A
 7. g  = g*x
 8. g  = g+B
 9. y  = g^((p+1)/4)
10. t0 = y^2
11. IF t0 ≠ g THEN
12. x  = u*x
13. y  = (−1)^((p+1)/4)*u*t*y
14. ENDIF
15. RETURN (x,y)
```
