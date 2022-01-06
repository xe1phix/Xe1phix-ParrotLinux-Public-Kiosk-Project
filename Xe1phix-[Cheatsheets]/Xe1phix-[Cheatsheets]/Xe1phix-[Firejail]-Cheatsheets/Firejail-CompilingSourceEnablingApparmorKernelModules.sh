#!/bin/sh


Compile and install


## ================================================================================== ##
echo "Cloning The Firejail Github Repo..."
## ================================================================================== ##
git clone https://github.com/netblue30/firejail.git


## ================================================================================== ##
echo "Moving To That Directory..."
## ================================================================================== ##
cd firejail


## ================================================================================== ##
echo "Initiate Firejail Setup Using The Make Compiler..."
## ================================================================================== ##
./configure && make && sudo make install-strip


## ================================================================================== ##
echo "Load The Apparmor Kernel Module, Then Compile Into Firejail Source..."
## ================================================================================== ##
./configure --prefix=/usr --enable-apparmor


## ================================================================================== ##
echo "The Apparmor Profile Needs To Be Loaded Into The Kernel..."
## ================================================================================== ##
aa-enforce firejail-default















┌─[root@parrot]─[/home/xe1phix/firejail]
└──╼ #./configure --prefix=/usr --enable-apparmor
checking for gcc... gcc
checking whether the C compiler works... yes
checking for C compiler default output file name... a.out
checking for suffix of executables... 
checking whether we are cross compiling... no
checking for suffix of object files... o
checking whether we are using the GNU C compiler... yes
checking whether gcc accepts -g... yes
checking for gcc option to accept ISO C89... none needed
checking for a BSD-compatible install... /usr/bin/install -c
checking for ranlib... ranlib
checking how to run the C preprocessor... gcc -E
checking for grep that handles long lines and -e... /bin/grep
checking for egrep... /bin/grep -E
checking for ANSI C header files... yes
checking for sys/types.h... yes
checking for sys/stat.h... yes
checking for stdlib.h... yes
checking for string.h... yes
checking for memory.h... yes
checking for strings.h... yes
checking for inttypes.h... yes
checking for stdint.h... yes
checking for unistd.h... yes
checking sys/apparmor.h usability... yes
checking sys/apparmor.h presence... yes
checking for sys/apparmor.h... yes
checking for main in -lpthread... yes
checking pthread.h usability... yes
checking pthread.h presence... yes
checking for pthread.h... yes
checking linux/seccomp.h usability... yes
checking linux/seccomp.h presence... yes
checking for linux/seccomp.h... yes
configure: creating ./config.status
config.status: creating Makefile
config.status: creating src/lib/Makefile
config.status: creating src/fcopy/Makefile
config.status: creating src/fnet/Makefile
config.status: creating src/firejail/Makefile
config.status: creating src/firemon/Makefile
config.status: creating src/libtrace/Makefile
config.status: creating src/libtracelog/Makefile
config.status: creating src/firecfg/Makefile
config.status: creating src/ftee/Makefile
config.status: creating src/faudit/Makefile
config.status: creating src/fseccomp/Makefile

Configuration options:
   prefix: /usr
   sysconfdir: /etc
   seccomp: -DHAVE_SECCOMP
   <linux/seccomp.h>: -DHAVE_SECCOMP_H
   apparmor: -DHAVE_APPARMOR
   global config: -DHAVE_GLOBALCFG
   chroot: -DHAVE_CHROOT
   bind: -DHAVE_BIND
   network: -DHAVE_NETWORK
   user namespace: -DHAVE_USERNS
   X11 sandboxing support: -DHAVE_X11
   whitelisting: -DHAVE_WHITELIST
   private home support: -DHAVE_PRIVATE_HOME
   file transfer support: -DHAVE_FILE_TRANSFER
   overlayfs support: -DHAVE_OVERLAYFS
   git install support: 
   busybox workaround: no
   EXTRA_LDFLAGS: -lapparmor 
   fatal warnings: 
   Gcov instrumentation: 


