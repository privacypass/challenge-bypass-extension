#!/usr/bin/env bash

if [ -z "$ext_name" ];then
  echo 'script configuration is invalid:'
  echo 'missing name of browser extension'
  exit 1
fi

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# ------------------------------------------------------------------------------
# bootstrap

function main {
  cd "${DIR}/../../../.."
  cwd=$(realpath .)
  ext_dir="${cwd}/${ext_name}"
  ext_key="${cwd}/${ext_name}.pem"

  if [ -f "$ext_key" ];then
    chrome --disable-gpu --disable-software-rasterizer "--pack-extension=${ext_dir}" "--pack-extension-key=${ext_key}"
  else
    chrome --disable-gpu --disable-software-rasterizer "--pack-extension=${ext_dir}"
  fi
}

main
