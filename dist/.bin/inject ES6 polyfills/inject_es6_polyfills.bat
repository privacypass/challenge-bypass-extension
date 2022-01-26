@echo off
setlocal enabledelayedexpansion

call "%~dp0..\.env\constants.bat"
call "%~dp0..\.env\build.bat"

if not defined ext_name (
  echo script configuration is invalid:
  echo missing name of browser extension
  exit /b 1
)

set ext_dir="%~dp0..\..\%ext_name%"

if not exist %ext_dir% (
  echo Extension directory does not exist.
  echo Perhaps the Typescript compiler build failed?
  echo Quitting without making any changes.
  exit /b 1
)

cd /D %ext_dir%

if exist "%cd%\lib" (
  echo "lib" directory already exists in extension directory.
  echo Has polyfill has already been injected?
  echo Quitting without making any changes.
  exit /b 1
)

xcopy /E /I /Q "%~dp0.\lib" "lib"

set filepath=manifest.json
set "old_text="background.js""
set "new_text="lib/core-js.js", "background.js""
set flags=
call :perform_file_search_replace "%filepath%" "!old_text!" "!new_text!" "%flags%"

set filepath=popup.html
set "old_text=<script"
set "new_text=<script src="lib/core-js.js"></script><script"
set flags=
call :perform_file_search_replace "%filepath%" "!old_text!" "!new_text!" "%flags%"

goto :done

:perform_file_search_replace
  set filepath=%~1
  set old_text=%2
  set new_text=%3
  set flags=%~4

  rem :: trim double-quotes from text without using shell because ~N variable expansion breaks when string contains certain special characters
  set old_text=!old_text:~1,-1!
  set new_text=!new_text:~1,-1!

  rem :: https://stackoverflow.com/a/1258256
  rem ::   add backslash to escape double-quotes in text, or perl won't see them
  set old_text=!old_text:"=\"!
  set new_text=!new_text:"=\"!

  perl -pi.bak -e "s|!old_text!|!new_text!|%flags%" "%filepath%"

  if exist "%filepath%.bak" del "%filepath%.bak"
  goto :eof

:done

if not defined BUILD_ALL (
  echo.
  pause
)

endlocal
