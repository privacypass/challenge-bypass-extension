@echo off

set BUILD_ALL=1

call "%~dp0.\build\build.bat"
call "%~dp0.\pack extensions\chromium\crx3\pack_crx3_with_chrome.bat"
call "%~dp0.\pack extensions\firefox\pack_xpi_with_7zip.bat"

call "%~dp0.\inject ES6 polyfills\inject_es6_polyfills.bat"
call "%~dp0.\pack extensions\chromium\crx2\pack_crx2_with_chrome.bat"

echo.
pause
