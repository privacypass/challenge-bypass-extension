@echo off

call "%~dp0.\.env\build.bat"

cd /D "%~dp0..\.."

call npm run test

if not defined BUILD_ALL (
  echo.
  pause
)
