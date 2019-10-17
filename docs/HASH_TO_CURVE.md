# Deterministic methods for hashing bytes to elliptic curve points

A central portion of our design relies on deterministically hashing bytes to a
uniformly random point on an elliptic curve (we currently use the NIST P256
curve). There are two methods that we use that are controlled via the
`hash-to-curve` config option.

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
failure and so this method of hashing is suboptimal.

## Affine SSWU method

In the new release of Privacy Pass we will move to supporting both the previous
`hash-and-increment` method, and a new method that we call "affine SSWU". The
affine SSWU method always returns a elliptic curve point and thus has zero chance
of failure. The method used is the simplified version of SWU, which was proposed by Brier et al. based on the previous work of Shallue, Woestijne and Ulas (hence SSWU).
It is known as "affine" since it generates curve points in the affine
representation rather than the Jacobian representation.

The algorithm is described in <https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/>. The input is a field element `t` that is obtained by hashing the input bytes into GF(p) using the output of a random oracle (we use the hash function SHA-256). The output is a coordinate pair (x,y) for a curve point on the  elliptic curve E(GF(p)).
