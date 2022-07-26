# Privacy Pass Extension

[![Privacy Pass](https://github.com/privacypass/challenge-bypass-extension/actions/workflows/action.yml/badge.svg)](https://github.com/privacypass/challenge-bypass-extension/actions)

**The Privacy Pass protocol is now being standardised by the
[privacypass](https://datatracker.ietf.org/wg/privacypass/about/) IETF
working group. All contributions are welcome! See the [GitHub
page](https://github.com/ietf-wg-privacypass) for more details.**

The Privacy Pass browser extension implements the Privacy Pass protocol
for providing a private authentication mechanism during web browsing.
Privacy Pass is currently supported by Cloudflare to allow users to
redeem validly signed tokens instead of completing CAPTCHA solutions.
The extension is compatible with
[Chrome](https://chrome.google.com/webstore/detail/privacy-pass/ajhmfdgkijocedmfjonnpjfojldioehi)
and
[Firefox](https://addons.mozilla.org/firefox/addon/privacy-pass/)
(v48+). An example server implementation that is compatible with this
extension is available
[here](https://github.com/privacypass/challenge-bypass-server).

The protocol we use is based on a realization of a 'Verifiable,
Oblivious Pseudorandom Function' (VOPRF) first established by [Jarecki
et al.](https://eprint.iacr.org/2014/650.pdf). We
also detail the entire protocol and results from this deployment in a
[research
paper](https://content.sciendo.com/view/journals/popets/2018/3/article-p164.xml)
that appeared at PETS 2018 (Issue 3).

In October 2021, we announced a new major version (v3) as mentioned in the
[blog post](https://blog.cloudflare.com/privacy-pass-v3) which makes the code
base more resilient, extensible, and maintainable.

## Build Instruction

```sh
$ npm ci
$ npm run build
```

After that, the `dist` folder will contain all files required by the extension.

## Development Installation

### Firefox

-   Build by following the [Build Instruction](#build-instruction).
-   Open Firefox and go to `about:debugging#/runtime/this-firefox`.
-   Click on 'Load Temporary Add-on' button.
-   Select `manifest.json` from `dist` folder.
-   Check extension logo appears in the top-right corner and 0 passes
    are stored (by clicking on it).
-   Go to a web page supporting Privacy Pass where internet challenges
    are   displayed (e.g. <https://captcha.website>)
-   Solve CAPTCHA and check that some passes are stored in the extension
    now.
    -   captcha.website cannot be bypassed (this is only for gaining
        passes)
-   Go to a new website supporting Privacy Pass that ordinarily displays
    a challenge.
-   Check that the website is displayed correctly without human
    interaction (more than one pass may be spent).
    -   No interaction with a CAPTCHA page should occur, for instance.

### Chrome

-   Build by following the [Build Instruction](#build-instruction).
-   Open Chrome and go to `chrome://extensions`.
-   Turn on the Developer mode on the top-right corner.
-   Click on 'Load unpacked' button.
-   Select the `dist` folder.
-   Check extension logo appears in the top-right corner and follow
    the same instruction as in Firefox. (If you cannot see the extension logo,
    it's probably just not pinned to the toolbar yest)

## Test Instruction
```sh
$ npm ci
$ npm test
```

## Directory Structure

- `public`: Contains all the assets which are neither the business logic files nor the style sheets
- `src`: Contains all the business logic files and the style sheets
  - `background`: The business logic for the extension background process
      - `listeners`: Contains all the listeners which listen on all the events happened in the browser
          - `tabListener.ts`: The listeners which listen on all the tab related events [API](https://developer.chrome.com/docs/extensions/reference/tabs/)
          - `webRequestListener.ts`: The listeners which listen on all the web request related events [API](https://developer.chrome.com/docs/extensions/reference/webRequest/)
      - `providers`: Contains the provider-specific code of all the Privacy Pass providers in the extension. Currently we have only Cloudflare and hCaptcha
      - `voprf.js`: Legacy crypto code which is still in Vanilla JavaScript
      - `voprf.d.ts`: TypeScript declaration file for the legacy crypto code
      - `tab.ts`: Tab class to represent a tab and encapsulate everything which is Tab specific
      - `token.ts`: Token class to represent a token and contain all the code related to tokens
  - `popup`: The web app for the popup in the browser toolbar
      - `components`: Contains all the React components
      - `styles`: Contains all the style sheets which are shared among the React components
      - `types.d.ts`: Global Typescript declaration

## Cryptography

Cryptography is implemented using the elliptic-curve library
[SJCL](https://github.com/bitwiseshiftleft/sjcl) and compression of
points is done in accordance with the standard SEC1. This work uses the
NIST standard P256 elliptic curve for performing operations. Third-party
implementers should note that the outputs of the hash-to-curve, key
derivation, and point encoding functions must match their Go equivalents
exactly for interaction with our server implementation. More information
about this will be provided when the edge implementation is
open-sourced.

## Acknowledgements

The creation of the Privacy Pass protocol was a joint effort by the team
made up of George Tankersley, Ian Goldberg, Nick Sullivan, Filippo
Valsorda and Alex Davidson.

We would also like to thank Eric Tsai for creating the logo and
extension design, Dan Boneh for helping us develop key parts of the
protocol, as well as Peter Wu and Blake Loring for their helpful code
reviews. We would also like to acknowledge Sharon Goldberg, Christopher
Wood, Peter Eckersley, Brian Warner, Zaki Manian, Tony Arcieri, Prateek
Mittal, Zhuotao Liu, Isis Lovecruft, Henry de Valence, Mike Perry,
Trevor Perrin, Zi Lin, Justin Paine, Marek Majkowski, Eoin Brady, Aaran
McGuire, and many others who were involved in one way or another and
whose efforts are appreciated.

## FAQs

### What do I have to do to acquire new passes?

*   Click "Get More Passes" in the extension pop-up (or navigate to
    <https://captcha.website>).
*   Solve the CAPTCHA that is presented on the webpage
*   Your extension should be populated with new passes.

### Are passes stored after a browser restart?

Depending on your browser settings, the local storage of your browser
may be cleared when it is restarted. Privacy Pass stores passes in local
storage and so these will also be cleared. This behavior may also be
observed if you clear out the cache of your browser.

## Known Issues

### Extensions that modify user-agent or headers.

There is a [conflict resolution|https://developer.chrome.com/docs/extensions/reference/webRequest/#conflict-resolution] happening when more than one extension tries
to modify the headers of a request. According to documentation,
the more recent installed extension is the one that can update
headers, while others will fail.

Compounded to that, Cloudflare will ignore clearance cookies when the
user-agent request does not match the one used when obtaining the
cookie.

### hCaptcha support.

As of version 3.x.x, support for hCaptcha tokens is paused. Only
Cloudflare CAPTCHAs are supported by this extension.
