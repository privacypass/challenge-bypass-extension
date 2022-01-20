#!/usr/bin/env bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

"${DIR}/build/build.sh"
"${DIR}/pack extensions/chromium/crx3/pack_crx3_with_openssl.sh"
"${DIR}/pack extensions/firefox/pack_xpi_with_zip.sh"

"${DIR}/inject ES6 polyfills/inject_es6_polyfills.sh"
"${DIR}/pack extensions/chromium/crx2/pack_crx2_with_openssl.sh"
