@echo off

call "%~dp0..\..\.env\constants.bat"
call "%~dp0..\..\.env\7zip.bat"

if not defined ext_name (
  echo script configuration is invalid:
  echo missing name of browser extension
  exit /b 1
)

cd /D "%~dp0..\..\.."

set ext_dir="%cd%\%ext_name%"
set ext_xpi="%cd%\%ext_name%.xpi"

if not exist %ext_dir% (
  echo Extension directory does not exist.
  echo Perhaps the Typescript compiler build failed?
  exit /b 1
)

cd %ext_dir%

rem :: https://sevenzip.osdn.jp/chm/cmdline/index.htm
rem :: https://sevenzip.osdn.jp/chm/cmdline/commands/add.htm
7z a -tzip %ext_xpi% -r .

if not defined BUILD_ALL (
  echo.
  pause
)
