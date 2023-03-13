## Setting Up Chrome Extension

In a terminal:

```sh
$ git clone https://github.com/armfazh/challenge-bypass-extension --branch = declNetReq
$ nvm use 18 // it should work with Node v16+.
$ npm ci
$ npm run build
```

In Chrome:

1. Remove all extensions of Privacy pass. current public extension is v3.0.5.

1. We will install extension v4.0.0 which has **manifest v3 AND has no UI**.

1. Load the extension from the source code.

1. Open the Service worker & Devtools of a blank tab.

1. Navigate to https://demo-origin.pat-issuer.cloudflare.com/type2 As you can see, we must specify type=2.

1. The behaviour expected is that browser first receives a 401 error, which is catched by the extension and then a reload that brings the body 'Token OK'.
