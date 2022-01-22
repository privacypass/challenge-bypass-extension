#!/usr/bin/env bash

# ------------------------------------------------------------------------------
# configuration

# 'USE_OPENSSL' determines how CRX2 and CRX3 extensions are built
#   - any non-empty value will use:
#       OpenSSL
#   - an empty value will use:
#       2x different versions of Chrome
#       1x older for CRX2: <  64.0.3242.0
#       1x newer for CRX3: >= 64.0.3242.0
USE_OPENSSL='1'

# ------------------------------------------------------------------------------

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

"${DIR}/build/build.sh"
if [ -n "$USE_OPENSSL" ];then
  "${DIR}/pack extensions/chromium/crx3/pack_crx3_with_openssl.sh"
else
  "${DIR}/pack extensions/chromium/crx3/pack_crx3_with_chrome.sh"
fi
"${DIR}/pack extensions/firefox/pack_xpi_with_zip.sh"

"${DIR}/inject ES6 polyfills/inject_es6_polyfills.sh"
if [ -n "$USE_OPENSSL" ];then
  "${DIR}/pack extensions/chromium/crx2/pack_crx2_with_openssl.sh"
else
  "${DIR}/pack extensions/chromium/crx2/pack_crx2_with_chrome.sh"
fi
