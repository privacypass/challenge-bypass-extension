@echo off

rem :: ================================
rem :: version of Chrome >= 64.0.3242.0
rem :: ================================
rem ::   https://sourceforge.net/projects/portableapps/files/Google%20Chrome%20Portable/
rem ::   https://sourceforge.net/projects/portableapps/files/Google%20Chrome%20Portable/GoogleChromePortable64_97.0.4692.71_online.paf.exe/download
set CHROME_HOME=C:\PortableApps\Google Chrome\97.0.4692.71\App\Chrome-bin
rem ::   https://sourceforge.net/projects/portableapps/files/Iron%20Portable/
rem ::   https://sourceforge.net/projects/portableapps/files/Iron%20Portable/IronPortable_85.0.4350.0.paf.exe/download
set CHROME_HOME=C:\PortableApps\SRWare Iron\85.0.4350.0\App\Iron
rem ::   http://download1.srware.net/old/
rem ::   http://download1.srware.net/old/iron/win/85/IronPortable64.exe
set CHROME_HOME=C:\PortableApps\SRWare Iron\85.0.4350.0\Iron

set PATH=%CHROME_HOME%;%PATH%
