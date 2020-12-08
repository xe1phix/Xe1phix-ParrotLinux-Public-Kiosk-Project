#!/bin/sh
## -------------------------------------------- ##
##  [+] Xe1phix-Compiling-Firetools-v3.2.sh
## ------------------------------------------- ##



##-========================================================================================-##
##              [+] Setting up a compilation environment - Debian/Ubuntu Build:
##-========================================================================================-##
sudo apt-get install build-essential qt5-default qt5-qmake qtbase5-dev-tools libqt5svg5 git


##-========================================================================================-##
##                [+] Setting up a compilation environment - CentOS 7 Build:
##-========================================================================================-##
sudo yum install gcc-c++ qt5-qtbase-devel qt5-qtsvg.x86_64 git



##-============================-##
##   [+] Compile & Install:
##-============================-##
git clone  https://github.com/netblue30/firetools
cd firetools



##-=======================================================-##
##   [+] Compiling & Installing The Debian/Ubuntu Build:
##-=======================================================-##
./configure



##-===================================================-##
##   [+] Compiling & Installing The CentOS 7 Build:
##-===================================================-##
./configure --with-qmake=/usr/lib64/qt5/bin/qmake



##-=====================================================-##
##   [+] Make + Make-Install The Debian/Ubuntu Build:
##-=====================================================-##
make
sudo make install-strip

