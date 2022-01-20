### ES6 Polyfills

* adds [core-js](https://github.com/zloirock/core-js) to both the [background](../../../public/manifest.json) and [popup](../../../public/popup.html) pages
  - using a local copy of a recent browser build, which was saved from [cdnjs](https://cdnjs.com/libraries/core-js)
* only needed to add support for very old browsers, which do not understand features that have since been added to the javascript (aka: ecmascript) scripting language
  - for Chrome, this is only recommended for extensions packed in CRX2 format
