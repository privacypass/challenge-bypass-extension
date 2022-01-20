#!/usr/bin/env bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

source "${DIR}/../../../.env/constants.sh"
source "${DIR}/../../../.env/openssl.sh"

if [ -z "$ext_name" ];then
  echo 'script configuration is invalid:'
  echo 'missing name of browser extension'
  exit 1
fi

# ------------------------------------------------------------------------------
# Source:  http://code.google.com/p/chromium/issues/attachmentText?id=15059&aid=-2305436989939443553&name=crxmake.sh
# Purpose: Pack a Chromium extension directory into crx2 format
#   notes: all temporary files are created in the cwd.
#          the final crx is created adjacent to the input extension directory.

function byte_swap {
  # Take "abcdefgh" and return it as "ghefcdab"
  echo "${1:6:2}${1:4:2}${1:2:2}${1:0:2}"
}

function pack_crx2 {
  if test $# -ne 2; then
    echo "Usage: crxmake.sh <extension dir> <pem path>"
    exit 1
  fi

  ext_dir=$1
  ext_key=$2
  crx="${ext_dir}.crx2.crx"
  name=$(basename "$ext_dir")
  pub="${name}.pub"
  sig="${name}.sig"
  zip="${name}.zip"

  if [ ! -d "$ext_dir" ];then
    echo 'error: extension directory path does not exist'
    exit 1
  fi

  if [ ! -f "$ext_key" ];then
    echo 'error: pem file path does not exist'
    exit 1
  fi

  echo "writing ${name}.crx2.crx"

  # preparation: remove previous crx
  rm -f "$crx"

  # preparation: remove all previous temporary files in the cwd
  rm -f "$pub" "$sig" "$zip"

  # cleanup: remove all temporary files in the cwd
  trap 'rm -f "$pub" "$sig" "$zip"' EXIT

  # zip up the crx dir
  cwd=$(pwd -P)
  (cd "$ext_dir" && zip -qr -9 -X "${cwd}/${zip}" .)

  # signature
  openssl sha1 -sha1 -binary -sign "$ext_key" < "$zip" > "$sig"

  # public key
  openssl rsa -pubout -outform DER < "$ext_key" > "$pub" 2>/dev/null

  crmagic_hex='4372 3234' # Cr24
  version_hex='0200 0000' # 2
  pub_len_hex=$(byte_swap $(printf '%08x\n' $(ls -l "$pub" | awk '{print $5}')))
  sig_len_hex=$(byte_swap $(printf '%08x\n' $(ls -l "$sig" | awk '{print $5}')))
  (
    echo "${crmagic_hex} ${version_hex} ${pub_len_hex} ${sig_len_hex}" | xxd -r -p
    cat "$pub" "$sig" "$zip"
  ) > "$crx"

  echo 'success: crx2 Chrome extension has been packed'
}

# ------------------------------------------------------------------------------
# bootstrap

function main {
  cd "${DIR}/../../../.."
  cwd=$(pwd -P)
  ext_dir="${cwd}/${ext_name}"
  ext_key="${cwd}/${ext_name}.pem"

  TMP="${DIR}/temp"
  [ -d "$TMP" ] && rm -rf "$TMP"
  mkdir "$TMP"

  cd "$TMP"
  pack_crx2 "$ext_dir" "$ext_key"

  # cleanup: remove temporary directory
  cd "$DIR"
  rm -rf "$TMP"
}

main
