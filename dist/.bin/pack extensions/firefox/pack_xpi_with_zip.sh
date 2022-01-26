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

  ext_dir="${cwd}/${ext_name}"
  ext_xpi="${cwd}/${ext_name}.xpi"

  if [ ! -d "$ext_dir" ];then
    echo 'Extension directory does not exist.'
    echo 'Perhaps the Typescript compiler build failed?'
    exit 1
  fi

  cd "$ext_dir"

  # https://extensionworkshop.com/documentation/publish/package-your-extension/#package-linux
  zip -r -FS "$ext_xpi" *
}

main
