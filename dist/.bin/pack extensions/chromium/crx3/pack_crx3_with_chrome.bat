@echo off

call "%~dp0..\..\..\.env\constants.bat"
call "%~dp0..\..\..\.env\chrome_crx3.bat"
call "%~dp0..\.common\pack_crx_with_chrome.bat"

set crx_path=%~dp0..\..\..\..\%ext_name%

if exist "%crx_path%.crx" (
  ren "%crx_path%.crx" "%ext_name%.crx3.crx"
)

if not defined BUILD_ALL (
  echo.
  pause
)
