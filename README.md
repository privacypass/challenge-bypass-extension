# Deprecated

#### This version of Privacy Pass extension is not currently under active development. More [details below](#deprecation).

---

[![github release](https://img.shields.io/github/release/privacypass/challenge-bypass-extension.svg)](https://github.com/privacypass/challenge-bypass-extension/releases/)
[![Privacy Pass](https://github.com/privacypass/challenge-bypass-extension/actions/workflows/action.yml/badge.svg)](https://github.com/privacypass/challenge-bypass-extension/actions)
[![License](https://img.shields.io/badge/License-BSD_3--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)

# Privacy Pass Extension

![Privacy Pass logo](./public/icons/128/gold.png)

This browser extension implements the client-side of the Privacy Pass protocol providing unlinkable cryptographic tokens. For example, these tokens can be used on Cloudflare-protected websites to redeem a token instead of solving a CAPTCHA.

Home page: **[https://privacypass.github.io][pp-home]**

## Installation

| **[Chrome][chrome-store]** | **[Firefox][firefox-store]** |
| -- | -- |
| [![chrome logo](./public/icons/browser/chrome.png)][chrome-store] | [![firefox logo](./public/icons/browser/firefox.png)][firefox-store] |

## How it works?

**Privacy Pass Providers:**  🟩 [Cloudflare][cf-url]  🟩 [hCaptcha][hc-url]

[pp-home]: https://privacypass.github.io/
[cf-url]: https://issuance.privacypass.cloudflare.com/
[hc-url]: https://www.hcaptcha.com/privacy-pass/
[chrome-store]: https://chrome.google.com/webstore/detail/privacy-pass/ajhmfdgkijocedmfjonnpjfojldioehi/
[firefox-store]: https://addons.mozilla.org/firefox/addon/privacy-pass/

**Get tokens**
 - Click on the extension icon, and click on top of one of the **providers**.
 - One page will open with a CAPTCHA to be solved.
 - Solve successfully the CAPTCHA and the extenison will get some tokens.

**Use tokens**
 - When a page shows a CAPTCHA from one of the **providers**, and if the extension has tokens, the browser uses a token to pass the provider's challenge without any interaction.
 - Otherwise, the user must solve the CAPTCHA, which grants some tokens for future use.

See [FAQs](#faqs) and [Known Issues](#known-issues) section: if something is not working as expected.

---

## Installing from Sources

We recommend to install the extension using the official browser stores listed in [Installation](#Installation) section above. If you want to compile the sources or your browser is not supported, you can install the extension as follows.

### Building

```sh
git clone https://github.com/privacypass/challenge-bypass-extension
nvm use 16
npm ci
npm run build
```

Once these steps complete, the `dist` folder will contain all files required to load the extension.

### Running Tests

```sh
nvm use 16
npm ci
npm test
```

### Manually Loading Extension

#### Firefox

1. Open Firefox and navigate to [about:debugging#/runtime/this-firefox/](about:debugging#/runtime/this-firefox/)
1. Click on 'Load Temporary Add-on' button.
1. Select `manifest.json` from the `dist` folder.
1. Check extension logo appears in the top-right corner of the browser.

#### Chrome

1. Open Chrome and navigate to [chrome://extensions/](chrome://extensions/)
1. Turn on the 'Developer mode' on the top-right corner.
1. Click on 'Load unpacked' button.
1. Select the `dist` folder.
1. Check extension logo appears in the top-right corner of the browser.
1. If you cannot see the extension logo, it's likely not pinned to the toolbar.

#### Edge

-   Open Edge and navigate to [edge://extensions/](edge://extensions/)
-   Turn on the 'Developer mode' on the left bar.
-   Click on 'Load unpacked' button in the main panel.
-   Select the `dist` folder.
-   The extension will appear listed in the main panel.
-   To see the extension in the bar, click in the puzzle icon and enable it, so it gets pinned to the toolbar.
---

### Highlights

**2018** -- The Privacy Pass protocol is based on a _Verifiable, Oblivious Pseudorandom Function_ (VOPRF) first established by [Jarecki et al. 2014](https://eprint.iacr.org/2014/650.pdf). The details of the protocol were published at [PoPETS 2018](https://doi.org/10.1515/popets-2018-0026) paper authored by Alex Davidson, Ian Goldberg, Nick Sullivan, George Tankersley, and Filippo Valsorda.

**2019** -- The captcha provider [hCaptcha](https://www.hcaptcha.com/privacy-pass) announced support for Privacy Pass, and the [v2](https://github.com/privacypass/challenge-bypass-extension/tree/2.0.0) version was released.

**2020** -- The CFRG (part of IRTF/IETF) started a [working group](https://datatracker.ietf.org/wg/privacypass/about/) seeking for the standardization of the Privacy Pass protocol.

**2021** -- In this [blog post](https://blog.cloudflare.com/privacy-pass-v3), we announced the [v3](https://github.com/privacypass/challenge-bypass-extension/tree/v3.0.0) version of this extension, which makes the code base more resilient, extensible, and maintainable.

**2022** -- The Privacy Pass protocol can also use RSA blind signatures.

<strong id="deprecation">2024</strong> -- The Privacy Pass protocol standardisation has diverged from the original PoPETS version, which this extension implements. To keep up with the protocol, CAPTCHA providers moved to this new version, and ended their support for PoPETS flavour. This repository remains as a relic of the past, but is not supported by any CAPTCHA providers. Cloudflare maintains [Silk - Privacy Pass client](https://github.com/cloudflare/pp-browser-extension) which forked this repository to provide IETF standard support.

#### Acknowledgements

The creation of the Privacy Pass protocol was a joint effort by the team made up of George Tankersley, Ian Goldberg, Nick Sullivan, Filippo Valsorda, and Alex Davidson.

The Privacy Pass team would like to thank Eric Tsai for creating the logo and extension design, Dan Boneh for helping us develop key parts of the protocol, as well as Peter Wu and Blake Loring for their helpful code reviews. We would also like to acknowledge Sharon Goldberg, Christopher Wood, Peter Eckersley, Brian Warner, Zaki Manian, Tony Arcieri, Prateek Mittal, Zhuotao Liu, Isis Lovecruft, Henry de Valence, Mike Perry, Trevor Perrin, Zi Lin, Justin Paine, Marek Majkowski, Eoin Brady, Aaran McGuire, Suphanat Chunhapanya, Armando Faz Hernández, Benedikt Wolters, Maxime Guerreiro, and many others who were involved in one way or another and whose efforts are appreciated.

---

## FAQs

#### What do I have to do to acquire new passes?

1. Click "Get More Passes" in the extension pop-up.
1. Solve the CAPTCHA that is presented on the webpage.
1. Your extension should be populated with new passes.

#### Are passes stored after a browser restart?

Depending on your browser settings, the local storage of your browser may be cleared when it is restarted. Privacy Pass stores passes in local storage and so these will also be cleared. This behavior may also be observed if you clear out the cache of your browser.

---

## Known Issues

#### Extensions that modify user-agent or headers

There is a [conflict resolution](https://developer.chrome.com/docs/extensions/reference/webRequest/#conflict-resolution) happening when more than one extension tries to modify the headers of a request. According to documentation, the more recent installed extension is the one that can update headers, while others will fail.

Compounded to that, Cloudflare will ignore clearance cookies when the user-agent request does not match the one used when obtaining the cookie.

#### hCaptcha support

As of version 3.0.4, support for hCaptcha tokens has been re-enabled. Note: even though an hCaptcha captcha consumes one token from the extension, it is still possible that the user must solve an interactive captcha. This behaviour depends on the logic used by the captcha provider, and does not indicate a malfunctioning of the PrivacyPass extension.
