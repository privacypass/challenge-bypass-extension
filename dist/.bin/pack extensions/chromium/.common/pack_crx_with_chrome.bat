@echo off

if not defined ext_name (
  echo script configuration is invalid:
  echo missing name of browser extension
  exit /b 1
)

cd /D "%~dp0..\..\..\.."

set ext_dir="%cd%\%ext_name%"
set ext_key="%cd%\%ext_name%.pem"

if not exist %ext_dir% (
  echo Extension directory does not exist.
  echo Perhaps the Typescript compiler build failed?
  exit /b 1
)

if exist %ext_key% (
  chrome --disable-gpu --disable-software-rasterizer --pack-extension=%ext_dir% --pack-extension-key=%ext_key%
) else (
  chrome --disable-gpu --disable-software-rasterizer --pack-extension=%ext_dir%
)
