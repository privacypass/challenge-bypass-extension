@echo off

if not defined ext_name (
  echo script configuration is invalid:
  echo missing name of browser extension
  exit /b 1
)

cd /D "%~dp0..\..\..\.."

set ext_dir="%cd%\PrivacyPass"
set ext_key="%cd%\PrivacyPass.pem"

if exist %ext_key% (
  chrome --pack-extension=%ext_dir% --pack-extension-key=%ext_key%
) else (
  chrome --pack-extension=%ext_dir%
)
