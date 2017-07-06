challenge-bypass-extension
===============================

This Firefox extension allows a user to bypass challenge pages provided by Cloudflare using the blind tokens protocol described in the [btd repo](https://github.com/cloudflare/btd). The functionality has not yet (06 July 2017) been enabled beyond testing colos.

The protocol has received extensive review and testing, but this extension is a work in progress and is NOT intended to be the canonical implementation of a bypass client. Someone who actually knows JavaScript should probably write that one.

To be sure it works in Tor Browser, this code was developed against Firefox ESR. It uses WebExtensions, so it may also work in Chrome.

Cryptography is implemented using [SJCL](https://github.com/bitwiseshiftleft/sjcl). Third-party implementers should note that the outputs of the hash-to-curve, key derivation, and point encoding functions must match their Go equivalents exactly (see [btd](https://github.com/cloudflare/btd/tree/master/crypto)).
