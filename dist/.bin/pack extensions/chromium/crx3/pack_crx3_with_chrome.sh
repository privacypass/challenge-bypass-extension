#!/usr/bin/env bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

source "${DIR}/../../../.env/constants.sh"
source "${DIR}/../../../.env/chrome_crx3.sh"
source "${DIR}/../.common/pack_crx_with_chrome.sh"

crx_path="${DIR}/../../../../${ext_name}"

if [ -f "${crx_path}.crx" ];then
  mv "${crx_path}.crx" "${crx_path}.crx3.crx"
fi
