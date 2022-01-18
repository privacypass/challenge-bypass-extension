@echo off

set CHROME_HOME=C:\PortableApps\Google Chrome\97.0.4692.71\App\Chrome-bin
set CHROME_HOME=C:\PortableApps\SRWare Iron\85.0.4350.0\Iron
set PATH=%CHROME_HOME%;%PATH%

cd /D "%~dp0..\.."

set ext_dir="%cd%\PrivacyPass"
set ext_key="%cd%\PrivacyPass.pem"

if exist %ext_key% (
  chrome --pack-extension=%ext_dir% --pack-extension-key=%ext_key%
) else (
  chrome --pack-extension=%ext_dir%
)
