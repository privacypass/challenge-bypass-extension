#!/usr/bin/env bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# ------------------------------------------------------------------------------
# configuration

OPENSSL_HOME='/c/PortableApps/OpenSSL/1.1.0'
PATH="${OPENSSL_HOME}:${PATH}"

# ------------------------------------------------------------------------------
# Source:  https://stackoverflow.com/a/18709204
# Purpose: Pack a Chromium extension directory into crx format
#   notes: all temporary files are created in the cwd.
#          the final crx is created adjacent to the input extension directory.

function pack_crx3 {
  if test $# -ne 2; then
    echo "Usage: crxmake.sh <extension dir> <pem path>"
    exit 1
  fi

  ext_dir=$1
  ext_key=$2
  crx="${ext_dir}.crx"
  name=$(basename "$ext_dir")
  pub="${name}.pub"
  sig="${name}.sig"
  zip="${name}.zip"
  tosign="${name}.presig"
  binary_crx_id="${name}.crxid"

  echo "writing '${name}.crx'"

  # preparation: remove previous crx
  rm -f "$crx"

  # preparation: remove all previous temporary files in the cwd
  rm -f "$pub" "$sig" "$zip" "$tosign" "$binary_crx_id"

  # cleanup: remove all temporary files in the cwd
  trap 'rm -f "$pub" "$sig" "$zip" "$tosign" "$binary_crx_id"' EXIT

  # zip up the crx dir
  cwd=$(pwd -P)
  (cd "$ext_dir" && zip -qr -9 -X "${cwd}/${zip}" .)

  #extract crx id
  openssl rsa -in "$ext_key" -pubout -outform der | openssl dgst -sha256 -binary -out "$binary_crx_id"
  truncate -s 16 "$binary_crx_id"

  #generate file to sign
  (
    # echo "$crmagic_hex $version_hex $header_length $pub_len_hex $sig_len_hex"
    printf "CRX3 SignedData"
    echo "00 12 00 00 00 0A 10" | xxd -r -p
    cat "$binary_crx_id" "$zip"
  ) > "$tosign"

  # signature
  openssl dgst -sha256 -binary -sign "$ext_key" < "$tosign" > "$sig"

  # public key
  openssl rsa -pubout -outform DER < "$ext_key" > "$pub" 2>/dev/null

  crmagic_hex='43 72 32 34' # Cr24
  version_hex='03 00 00 00' # 3
  header_length='45 02 00 00'
  header_chunk_1='12 AC 04 0A A6 02'
  header_chunk_2='12 80 02'
  header_chunk_3='82 F1 04 12 0A 10'
  (
    echo "${crmagic_hex} ${version_hex} ${header_length} ${header_chunk_1}" | xxd -r -p
    cat "$pub"
    echo "$header_chunk_2" | xxd -r -p
    cat "$sig"
    echo "$header_chunk_3" | xxd -r -p
    cat "$binary_crx_id" "$zip"
  ) > "$crx"

  echo 'success: crx3 Chrome extension has been packed'
}

# ------------------------------------------------------------------------------
# bootstrap

function main {
  cd "${DIR}/../.."
  cwd=$(pwd -P)
  ext_dir="${cwd}/PrivacyPass"
  ext_key="${cwd}/PrivacyPass.pem"

  TMP="${DIR}/temp"
  [ -d "$TMP" ] && rm -rf "$TMP"
  mkdir "$TMP"

  cd "$TMP"
  pack_crx3 "$ext_dir" "$ext_key"

  # cleanup: remove temporary directory
  cd "$DIR"
  rm -rf "$TMP"
}

main
