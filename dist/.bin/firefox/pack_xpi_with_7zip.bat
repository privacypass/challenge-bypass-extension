@echo off

set ZIP7_HOME=C:\PortableApps\7-Zip\16.02\App\7-Zip64
set PATH=%ZIP7_HOME%;%PATH%

cd /D "%~dp0..\.."

set ext_name=PrivacyPass
set xpi_file="%cd%\%ext_name%.xpi"

cd "%ext_name%"

rem :: https://sevenzip.osdn.jp/chm/cmdline/index.htm
rem :: https://sevenzip.osdn.jp/chm/cmdline/commands/add.htm
7z a -tzip %xpi_file% -r .
