#!/bin/sh

/usr/lib/rpm/rpmrc

/etc/rpmrc			# changes here affect RPM configuration on a global scope

~/.rpmrc			# change here are on per user bases


RPM --showrc		# displays rpm configuration file (rpmrc)
rpm -nodeps			# install without worrying about dependancies
rpm -qd				# list all the documentation fi les contained in the package
rpm -qlc			# List configurations files by an rpm package

rpm -Kv *.rpm		# check package signature while displaying progess indicator
rpm -iv *.rpm		# install package while displaying progess indicator
rpm -Vv *.rpm


rpm --checksig bash
rpm --verify --group “Amusements/Games”
rpm --verify --all

­rpm -b				# builds a binary package given a src code and config file
rpm -p				# queries the uninstalled RPM package file
rpm -a				# Queries or verifies all packages
rpm -f				# Queries or verifies the package that owns the file
rpm -l              # list packages in redhat
rpm -K				# check package signature
rpm -F				# ­F or ­­freshen update already installed packages
rpm –v 				# Display a progress indicator while the package is installed.


rpm -q --changelog rpm | less		# look through the changelog of the package

­­rpm --rebuild 		# builds a binary package given a RPM source
­­rpm --rebuilddb		# rebuilds the RPM DB to fix errors
rpm ­­--root <Dir>	# modifies the linux system having a root folder located at dir
rpm --­­force			# forces installation of a package even when it means overwriting existing files or packages
rpm --test			# Checks for dependencies, conflicts and other problems without actually installing the package

rpm --prefix <path> # Sets the installation dir to path
rpm -qi				# displays package info
rpm -ql				# Displays the files contained in the package
rpm -qR				# displays the packages and files on which this one depends

rpm ‐ql package‐name               # list the files for INSTALLED package
rpm ‐qlp package.rpm               # list the files inside package


rpm -qa --qf “%{GROUP}\n” | sort -u
rpm2cpio pam-1.1.8-2.fc20.x86_64.rpm | cpio -i -v --make-directories




rpm -qpi openssh-3.4p1-2.i386.rpm | grep Version

rpm -qi kernel-source | grep Version


rpm -qa					## List the packages that have been installed on the system:
rpm -qd at				## List the documentation files in a package:
rpm -qc at				## List configuration files or scripts in a package:
rpm -qf /etc/fstab		## Determine what package a particular file was installed from.

rpm -ql kernel-source			## For an installed package, enter query mode and use the -l option along with the package name:
rpm -qf /etc/aliases			## Those that are package members look like this:
rpm -qa | grep kernel			## List Installed Packages With Kernel in the name

rpm -qlp kernel-source-1.3.0-1.i386.rpm		## List the files contained in a package:



rpm --showrc
-d, --docfiles
              List only documentation files (implies -l).

rpm -q --requires
rpm -q --provides
rpm -q --changelog httpd | less
rpm --querytags | less

/etc/yum.conf
/etc/yum.repos.d/
cat /etc/yum.repos.d/*.repo
/var/cache/yum
yum
yum check­update		# checks to see whether updates are available
yum upgrade			# works like update with the ­­obsoletes flag set
yum list			# displays info about the package
yum list available
yum list installed
yum list all


yum provides		# displays information about packages
yum whatprovides	# that provide a specified program or feature
yum search			# searches package names, summaries, packagers and descriptions for a specified keyword

yum info ­ 			# displays info about a package
yum clean ­ 			# cleans up the Yum cache directory
yum clean metadata
yum clean packages
yum shell ­ 			# enters the yum shell mode


yum resolvedep­ 			# displays packages matching the specified dependency
yum localinstall­ 		# install the specified local RPM files, using your yum repositories to resolve dependencies
yum deplist­ 			# display dependencies of the specified package
yum deplist emacs | less

yum localupdate­ 		# updates the system using the specified local RPM files, using your yum repositories to resolve dependencies
yumdownloader firefox

yum history
yum history info 96

yum grouplist | less
yum groupinstall LXDE


