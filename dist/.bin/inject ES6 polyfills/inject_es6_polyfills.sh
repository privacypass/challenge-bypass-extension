#!/usr/bin/env bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

source "${DIR}/../.env/constants.sh"
source "${DIR}/../.env/build.sh"

if [ -z "$ext_name" ];then
  echo 'script configuration is invalid:'
  echo 'missing name of browser extension'
  exit 1
fi

ext_dir="${DIR}/../../${ext_name}"

if [ ! -d "$ext_dir" ];then
  echo 'Extension directory does not exist.'
  echo 'Perhaps the Typescript compiler build failed?'
  echo 'Quitting without making any changes.'
  exit 1
fi

cd "$ext_dir"

if [ -d 'lib' ];then
  echo '"lib" directory already exists in extension directory.'
  echo 'Has polyfill has already been injected?'
  echo 'Quitting without making any changes.'
  exit 1
fi

cp -r "${DIR}/lib" .

function perform_file_search_replace {
  filepath="$1"
  old_text="$2"
  new_text="$3"
  flags="$4"

  perl -pi.bak -e "s|${old_text}|${new_text}|${flags}" "$filepath"
  [ -f "${filepath}.bak" ] && rm -f "${filepath}.bak"
}

filepath='manifest.json'
old_text='"background.js"'
new_text='"lib/core-js.js", "background.js"'
flags=''
perform_file_search_replace "$filepath" "$old_text" "$new_text" "$flags"

filepath='popup.html'
old_text='<script'
new_text='<script src="lib/core-js.js"></script><script'
flags=''
perform_file_search_replace "$filepath" "$old_text" "$new_text" "$flags"
