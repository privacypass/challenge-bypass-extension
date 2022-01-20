@echo off

call "%~dp0..\..\.env\constants.bat"
call "%~dp0..\..\.env\7zip.bat"

if not defined ext_name (
  echo script configuration is invalid:
  echo missing name of browser extension
  exit /b 1
)

cd /D "%~dp0..\..\.."

set xpi_file="%cd%\%ext_name%.xpi"

cd "%ext_name%"

rem :: https://sevenzip.osdn.jp/chm/cmdline/index.htm
rem :: https://sevenzip.osdn.jp/chm/cmdline/commands/add.htm
7z a -tzip %xpi_file% -r .

if not defined BUILD_ALL (
  echo.
  pause
)
