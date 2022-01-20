#!/usr/bin/env bash

# ================================
# version of Chrome >= 64.0.3242.0
# ================================
#   https://sourceforge.net/projects/portableapps/files/Google%20Chrome%20Portable/
#   https://sourceforge.net/projects/portableapps/files/Google%20Chrome%20Portable/GoogleChromePortable64_97.0.4692.71_online.paf.exe/download
CHROME_HOME='/c/PortableApps/Google Chrome/97.0.4692.71/App/Chrome-bin'
#   https://sourceforge.net/projects/portableapps/files/Iron%20Portable/
#   https://sourceforge.net/projects/portableapps/files/Iron%20Portable/IronPortable_85.0.4350.0.paf.exe/download
CHROME_HOME='/c/PortableApps/SRWare Iron/85.0.4350.0/App/Iron'
#   http://download1.srware.net/old/
#   http://download1.srware.net/old/iron/win/85/IronPortable64.exe
CHROME_HOME='/c/PortableApps/SRWare Iron/85.0.4350.0/Iron'

export PATH="${CHROME_HOME}:${PATH}"
