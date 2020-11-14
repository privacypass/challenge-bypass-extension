# Challenge Bypass Extension

**The Privacy Pass protocol is now being standardised by the
[privacypass](https://datatracker.ietf.org/wg/privacypass/about/) IETF
working group. All contributions are welcome! See the [GitHub
page](https://github.com/ietf-wg-privacypass) for more details.**

[![CircleCI](https://circleci.com/gh/privacypass/challenge-bypass-extension.svg?style=svg)](https://circleci.com/gh/privacypass/challenge-bypass-extension)

The Privacy Pass browser extension implements the Privacy Pass protocol
for providing a private authentication mechanism during web browsing.
Privacy Pass is currently supported by Cloudflare to allow users to
redeem validly signed tokens instead of completing CAPTCHA solutions.
The extension is compatible with
[Chrome](https://chrome.google.com/webstore/detail/privacy-pass/ajhmfdgkijocedmfjonnpjfojldioehi)
and
[Firefox](https://addons.mozilla.org/en-US/firefox/addon/privacy-pass/)
(v48+). An example server implementation that is compatible with this
extension is available
[here](https://github.com/privacypass/challenge-bypass-server).

The protocol we use is based on a realization of a 'Verifiable,
Oblivious Pseudorandom Function' (VOPRF) first established by [Jarecki
et al.](https://eprint.iacr.org/2014/650.pdf). For a technical
description of the protocol see the [PROTOCOL.md](docs/PROTOCOL.md). We
also detail the entire protocol and results from this deployment in a
[research
paper](https://content.sciendo.com/view/journals/popets/2018/3/article-p164.xml)
that appeared at PETS 2018 (Issue 3).

__The protocol has received extensive review, but this extension is a
work-in-progress and we regard all components as beta releases. In
particular in v1.0 of the extension some features are not fully
implemented (e.g. DLEQ proof verification).__

__We hope to address a significant number of existing issues in a future
release of the extension. Users can also install the latest branch of
master into their browser to use a newer version.__

We welcome contributions from the wider community. Also feel free to
notify us of any issues that occur. Pull requests and reviews are
welcome and encouraged.

- [Challenge Bypass Extension](#challenge-bypass-extension)
  - [Stable Releases](#stable-releases)
  - [Quickstart](#quickstart)
  - [Useful Documentation](#useful-documentation)
  - [Development](#development)
    - [Firefox](#firefox)
    - [Chrome](#chrome)
  - [Plugin Overview](#plugin-overview)
  - [Team](#team)
  - [Design](#design)
  - [Cryptography](#cryptography)
  - [Acknowledgements](#acknowledgements)
  - [FAQs](#faqs)
    - [What do I have to do to acquire new passes?](#what-do-i-have-to-do-to-acquire-new-passes)
    - [Are passes stored after a browser restart?](#are-passes-stored-after-a-browser-restart)
    - [Are passes stored after a browser
      restart?](#are-passes-stored-after-a-browser-restart)

## Stable Releases

Download the latest stable release of the extension:
-   [Chrome](https://chrome.google.com/webstore/detail/privacy-pass/ajhmfdgkijocedmfjonnpjfojldioehi)
-   [Firefox](https://addons.mozilla.org/en-US/firefox/addon/privacy-pass/)

## Quickstart

```sh
$ git clone https://github.com/privacypass/challenge-bypass-extension.git
$ cd challenge-bypass-extension
$ git submodule update --init
$ make install
$ make sjcl
$ make build
$ make test-all
```

## Useful Documentation

Documentation for the protocol, workflow and extension components.

*   [Protocol](docs/PROTOCOL.md)
*   [Extension implementation](docs/EXT_PROTOCOL_IMPL.md)
*   [Configuration options](docs/CONFIG.md)
*   [Supported hash-to-curve algorithms](docs/HASH_TO_CURVE.md)

## Development

*   Directory:
    -   `src`: The source files that are used for establishing the
        extension.
        -   `ext`: Source files that are specific to the extension.
        -   `crypto`: External source files that provide cryptographic
            functionality.
            -   `sjcl`: Cryptographic library submodule.
            -   `keccak`: Browserified implementation of Keccak taken
                from <https://github.com/cryptocoinjs/keccak>.
    -   `addon`: Extension directory.
    -   `test`: Test scripts for using the jest integration test
        framework.
    -   `docs`: Documentation.
-   Commands:
    -   `make install`: Installs all dependencies.
    -   `make sjcl`: Configures and builds the SJCL source code.
    -   `make build`: Builds all source files and compiles them into
        unminified source file at `addon/build.js`.
    -   `make test`: Builds all source files (except
        `src/ext/listeners.js`) into a single file and then runs the
        jest testing framework on this file.
    -   `make test-all`: Same as `make test` and runs the sjcl tests.
    -   `make lint`: Lints the source files.
    -   `make dist`: Package the extension files into a `ext.zip` file.

### Firefox

-   Run [Quickstart](#quickstart) instructions.
-   Open Firefox and go to `about:debugging`.
-   Click on 'Load Temporary Add-on' button.
-   Select `manifest.json` from `addon/` folder.
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

Same as above, except the extension should be loaded at
`chrome://extensions` instead.

## Plugin Overview

The following script files are used for the workflow of Privacy Pass and
are found in `addon/` folder. They are compiled into a single file
(`build.js`) that is then loaded into the browser.

*   src/ext/
    -   listeners.js: Initialises the listener functions that are used
        for the webRequest and webNavigation frameworks.
    -   background.js: Determines the bulk of the browser-based workflow
        for Privacy Pass. Decides whether to initiate the token issuance
        and redemption phases of the protocols.
    -   browserUtils.js: General utility functions that are used by
        background.js. We separate them so that we separate the specific
        browser API calls from the actual workflow.
    -   config.js: Config file that decides the workflow for Privacy
        Pass.
    -   token.js: Token generation and storage procedures.
    -   issuance.js: Specific functions for handling token issuance
        requests from the extension and corresponding server responses.
    -   redemption.js: Specific functions for construction redemption
        requests.
*   src/crypto/
    -   local.js: Wrapper for extension-specific cryptographic
        operations.
    -   sjcl/: Local copy of SJCL library.
    -   keccak/: Local implementation of the Keccak hash function (taken
        from <https://github.com/cryptocoinjs/keccak>).

Files for testing are found in `test/` folder. Some functions from the
extension files are mocked during test execution. The tests are run on a
separate file in `addon/test.js` that has the same contents as
`build.js` but with the HTTP listeners removed.

## Team

*   [Alex Davidson](https://alxdavids.xyz)
*   [Ian Goldberg](https://cs.uwaterloo.ca/~iang/)
*   [Nick Sullivan](https://github.com/grittygrease)
*   [George Tankersley](https://gtank.cc)
*   [Filippo Valsorda](https://github.com/filosottile)

## Design

*   [Eric Tsai](https://github.com/eetom)

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
