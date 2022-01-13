#!/usr/bin/env bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# ------------------------------------------------------------------------------
# configuration

CHROME_HOME='/c/PortableApps/Google Chrome/97.0.4692.71/App/Chrome-bin'
CHROME_HOME='/c/PortableApps/SRWare Iron/85.0.4350.0/Iron'
PATH="${CHROME_HOME}:${PATH}"

# ------------------------------------------------------------------------------
# bootstrap

function main {
  cd "${DIR}/../.."
  cwd=$(realpath .)
  ext_dir="${cwd}/PrivacyPass"
  ext_key="${cwd}/PrivacyPass.pem"

  if [ -f "$ext_key" ];then
    chrome "--pack-extension=${ext_dir}" "--pack-extension-key=${ext_key}"
  else
    chrome "--pack-extension=${ext_dir}"
  fi
}

main
