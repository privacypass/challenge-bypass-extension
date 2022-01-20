@echo off

call "%~dp0..\.env\%~nx0"

cd /D "%~dp0..\..\.."

call npm run build

if not defined BUILD_ALL (
  echo.
  pause
)
