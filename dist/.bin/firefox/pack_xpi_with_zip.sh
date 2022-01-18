#!/usr/bin/env bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# ------------------------------------------------------------------------------
# bootstrap

function main {
  cd "${DIR}/../.."
  cwd=$(pwd -P)
  ext_name='PrivacyPass'
  xpi_file="${cwd}/${ext_name}.xpi"

  cd "$ext_name"

  # https://extensionworkshop.com/documentation/publish/package-your-extension/#package-linux
  zip -r -FS "$xpi_file" *
}

main
