#!/usr/bin/env bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

source "${DIR}/../../.env/constants.sh"

if [ -z "$ext_name" ];then
  echo 'script configuration is invalid:'
  echo 'missing name of browser extension'
  exit 1
fi

# ------------------------------------------------------------------------------
# bootstrap

function main {
  cd "${DIR}/../../.."
  cwd=$(pwd -P)

  xpi_file="${cwd}/${ext_name}.xpi"

  cd "$ext_name"

  # https://extensionworkshop.com/documentation/publish/package-your-extension/#package-linux
  zip -r -FS "$xpi_file" *
}

main
