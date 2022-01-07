#!/bin/bash
#
# Install grsecurity from source, Debian version
#
# Author:  Rickard Bennison <rickard@0x539.se>
# License: WTFPL, see http://www.wtfpl.net/txt/copying/
# Version: 1.4.2
# Release: 2015-03-15
#

gpg_bash_lib_input_key_import_dir="/usr/share/whonix/grsecurity-installer-keys.d"
source "/usr/lib/gpg-bash-lib/source_all"

POLICY_STRING="Installed"

# Make sure apt-get calls are truly non-interactive
export DEBIAN_FRONTEND=noninteractive

if [ -z `which gcc` ]; then
  POLICY_STRING="Candidate"
fi

BAD_OPTIONS=(
	'PAX_MEMORY_UDEREF It causes kernel-panic in VirtualBox/VMWare guest mode' 
	'PAX_KERNEXEC It causes kernel-panic in VirtualBox/VMWare guest mode'
	'PAX_MPROTECT No infrastructure for applying MPROTECT exceptions in Debian: most software will not work'
	'PAX_MEMORY_SANITIZE Disabling slightly improves performance in VirtualBox gust mode'
	'PAX_MEMORY_STACKLEAK Disabling slightly improves performance in VirtualBox gust mode'
)

OK_OPTIONS=(
	'GRKERNSEC Grsecurity is not enabled, \e[01;31myou are wasting your time\e[0m'
	'PAX_PAGEEXEC Improves perfomance on vitrual machines'
)

GCC_VERSION=`LANGUAGE=C apt-cache policy gcc | grep "$POLICY_STRING:" | cut -c 16-18`

BUILDTOOLS="build-essential bin86 kernel-package libncurses5-dev zlib1g-dev gcc-${GCC_VERSION}-plugin-dev bc"

if [ `whoami` != "root" ]; then
	echo "This script needs to be run as root!"
	exit 1
fi

if [ -z /etc/debian_version ]; then
	echo "This script is made for Debian environments!"
	exit 1
fi

clear

echo "Welcome to the automagic grsecurity Whonix Installer

We will be working from /usr/src so make sure to have at least
4 GB of free space on the partition where /usr/src resides.

The installation will be carried out in the following steps:
1. Fetch the current version from grsecurity.net
2. Letting you choose which version you would like to install
3. Install the following debian packages if needed:
	 ${BUILDTOOLS} curl xz-utils
4. Download the kernel source from www.kernel.org
5. Download the grsecurity patch from grsecurity.net
6. Verify the downloads with shipped keys and extract the kernel
7. Apply the grsecurity kernel patch to the kernel source
8. Copy the current kernel configuration from /boot
9. Configure the kernel by
	a) selecting a shipped configuration file
	b) running 'make nconfig' if the current kernel doesn't support grsecurity
	c) running 'make oldconfig' if the current kernel supports grsecurity
10. Checking user configuration file
11. Compile the kernel into a debian package
12. Install the debian package

"

DOWNLOAD_STABLE=1
DOWNLOAD_STABLE2=1
DOWNLOAD_TESTING=1

if [ -f latest_stable_patch ]; then
	STABLE_MTIME=`expr $(date +%s) - $(date +%s -r latest_stable_patch)`

	if [ $STABLE_MTIME -gt 3600 ]; then
		rm latest_stable_patch
	else
		DOWNLOAD_STABLE=0
	fi
fi

if [ -f latest_stable2_patch ]; then
	STABLE2_MTIME=`expr $(date +%s) - $(date +%s -r latest_stable2_patch)`

	if [ $STABLE2_MTIME -gt 3600 ]; then
		rm latest_stable2_patch
	else
		DOWNLOAD_STABLE2=0
	fi
fi

if [ -f latest_test_patch ]; then
	TESTING_MIME=`expr $(date +%s) - $(date +%s -r latest_test_patch)`

	if [ $TESTING_MIME -gt 3600 ]; then
		rm latest_test_patch
	else
		DOWNLOAD_TESTING=0
	fi
fi

if [ -z `which curl` ]; then
	echo "==> Installing curl ..."
	apt-get -y -qq install curl &> /dev/null
	if [ $? -eq 0 ]; then echo "OK"; else echo "Failed"; exit 1; fi
fi

function secure_download {
	curl --progress-bar --remote-name --tlsv1 --proto =https $1
}

echo "==> Checking current versions of grsecurity ..."

if [ $DOWNLOAD_STABLE -eq 1 ]; then
	secure_download https://grsecurity.net/latest_stable_patch
fi

if [ $DOWNLOAD_STABLE2 -eq 1 ]; then
	secure_download https://grsecurity.net/latest_stable2_patch
fi

if [ $DOWNLOAD_TESTING -eq 1 ]; then
	secure_download https://grsecurity.net/latest_test_patch
fi

STABLE_VERSIONS=`cat latest_stable_patch | sed -e 's/\.patch//g' | sed -e 's/grsecurity-//g'`
STABLE2_VERSIONS=`cat latest_stable2_patch | sed -e 's/\.patch//g' | sed -e 's/grsecurity-//g'`
TESTING_VERSIONS=`cat latest_test_patch | sed -e 's/\.patch//g' | sed -e 's/grsecurity-//g'`

COUNTER=0

for x in ${STABLE_VERSIONS} ${STABLE2_VERSIONS}; do

	let COUNTER=COUNTER+1

	GRSEC=`echo ${x} | sed -e 's/-/ /g' | awk '{print $1}'`
	KERNEL=`echo ${x} | sed -e 's/-/ /g' | awk '{print $2}'`
	REVISION=`echo ${x} | sed -e 's/-/ /g' | awk '{print $3}'`

	VERSIONS[$COUNTER]=${x}-stable

	echo "==> $COUNTER. grsecurity version ${GRSEC} for kernel ${KERNEL}, revision ${REVISION} (stable version)"
done

for x in ${TESTING_VERSIONS}; do

	let COUNTER=COUNTER+1

	GRSEC=`echo ${x} | sed -e 's/-/ /g' | awk '{print $1}'`
	KERNEL=`echo ${x} | sed -e 's/-/ /g' | awk '{print $2}'`
	REVISION=`echo ${x} | sed -e 's/-/ /g' | awk '{print $3}'`

	VERSIONS[$COUNTER]=${x}-testing

	echo "==> $COUNTER. grsecurity version ${GRSEC} for kernel ${KERNEL}, revision ${REVISION} (testing version)"
done


echo -n "==> Please make your selection: [1-$COUNTER]: "

read SELECTION


DATA=${VERSIONS[$SELECTION]}
VERSION=`echo $DATA | sed -e 's/-/ /g' | awk '{print $1}'`
KERNEL=`echo $DATA | sed -e 's/-/ /g' | awk '{print $2}'`
REVISION=`echo $DATA | sed -e 's/-/ /g' | awk '{print $3}'`
BRANCH=`echo $DATA | sed -e 's/-/ /g' | awk '{print $4}'`
GRSEC=`echo $VERSION-${KERNEL}-${REVISION}`
KERNEL_BRANCH=`echo ${KERNEL} | cut -c 1`

if [ "${BRANCH}" == "testing" ]; then
	TESTING=y
else
	TESTING=n
fi


echo -n "==> Remove build tools after install? (${BUILDTOOLS}): [y/N] "
read UNINSTALL


echo "==> Installing grsecurity ${BRANCH} version $VERSION using kernel version ${KERNEL} ... "

echo -n "==> Installing packages needed for building the kernel ... ";
apt-get -y -qq install ${BUILDTOOLS} xz-utils &> /dev/null
if [ $? -eq 0 ]; then echo "OK"; else echo "Failed"; exit 1; fi

cd /usr/src

if [ -h linux ]; then
	rm linux
fi

if [ ! -f linux-${KERNEL}.tar.xz ] && [ ! -f linux-${KERNEL}.tar ]; then
	echo "==> Downloading kernel version ${KERNEL} ... "

	if [ ${KERNEL_BRANCH} -eq 2 ]; then
		secure_download https://www.kernel.org/pub/linux/kernel/v2.6/longterm/v2.6.32/linux-${KERNEL}.tar.xz
		secure_download https://www.kernel.org/pub/linux/kernel/v2.6/longterm/v2.6.32/linux-${KERNEL}.tar.sign
	elif [ ${KERNEL_BRANCH} -eq 3 ]; then
		secure_download https://www.kernel.org/pub/linux/kernel/v3.0/linux-${KERNEL}.tar.xz
		secure_download https://www.kernel.org/pub/linux/kernel/v3.0/linux-${KERNEL}.tar.sign
	elif [ ${KERNEL_BRANCH} -eq 4 ]; then
		secure_download https://www.kernel.org/pub/linux/kernel/v4.x/linux-${KERNEL}.tar.xz
		secure_download https://www.kernel.org/pub/linux/kernel/v4.x/linux-${KERNEL}.tar.sign
	fi

		echo -n "==> Extracting linux-${KERNEL}.tar ... "
		unxz linux-${KERNEL}.tar.xz
	if [ $? -eq 0 ]; then echo "OK"; else echo "Failed"; exit 1; fi
fi

echo -n "==> Verifying linux-${KERNEL}.tar ... "

gpg_bash_lib_input_sig_file="$PWD/linux-${KERNEL}.tar.sign"
gpg_bash_lib_input_data_file="$PWD/linux-${KERNEL}.tar"

gpg_bash_lib_function_main_verify
trap - ERR

if [ "$gpg_bash_lib_output_validsig_status" = 'true' ]; then echo "OK"; else echo "Failed"; exit 1; fi

if [ ! -f grsecurity-${GRSEC}.patch ]; then
	echo "==> Downloading grsecurity patch version ${GRSEC} ... "

	if [ "${TESTING}" == "y" ]; then
		secure_download https://grsecurity.net/test/grsecurity-${GRSEC}.patch
		secure_download https://grsecurity.net/test/grsecurity-${GRSEC}.patch.sig
	else
		secure_download https://grsecurity.net/stable/grsecurity-${GRSEC}.patch
		secure_download https://grsecurity.net/stable/grsecurity-${GRSEC}.patch.sig
	fi
fi

echo -n "==> Verifying grsecurity-${GRSEC}.patch ... "
gpg_bash_lib_input_sig_file="$PWD/grsecurity-${GRSEC}.patch.sig"
gpg_bash_lib_input_data_file="$PWD/grsecurity-${GRSEC}.patch"

gpg_bash_lib_function_main_verify
trap - ERR

if [ "$gpg_bash_lib_output_validsig_status" = 'true' ]; then echo "OK"; else echo "Failed"; exit 1; fi

if [ ! -d linux-${KERNEL} ]; then
	echo -n "==> Unarchiving linux-${KERNEL}.tar ... "
	tar xf linux-${KERNEL}.tar
	if [ $? -eq 0 ]; then echo "OK"; else echo "Failed"; exit 1; fi
fi

if [ ! -d linux-${KERNEL}-grsec ]; then
	mv linux-${KERNEL} linux-${KERNEL}-grsec
fi

ln -s linux-${KERNEL}-grsec linux
cd linux

patch --silent -p1 --forward --dry-run < ../grsecurity-${GRSEC}.patch &> /dev/null

if [ $? -eq 0 ]; then
	echo -n "==> Applying patch ... "
	patch --silent -p1 --forward < ../grsecurity-${GRSEC}.patch
	if [ $? -eq 0 ]; then echo "OK"; else echo "Failed"; exit 1; fi
else
	echo "==> Patch seems to already been applied, skipping ..."
fi


# Fix http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=638012
#
# the lguest directory seems to be moving around quite a bit, as of 3.3.something
# it resides under the tools directory. The best approach should be to just search for it 
if [ ! -s Documentation/lguest ]; then
	if [ ${KERNEL_BRANCH} -eq 3 ] || [ ${KERNEL_BRANCH} -eq 4 ]; then
		cd Documentation
		find .. -name lguest.c | xargs dirname | xargs ln -s
		cd ..
	fi
fi

cp /boot/config-`uname -r` .config
is_set() {
	grep -q "CONFIG_$2=y" .config
}

if ! is_set GRKERNSEC; then
	echo "==> Current kernel doesn't seem to be running grsecurity. Running 'make nconfig'"
	make nconfig
else
	echo -n "==> Current kernel seems to be running grsecurity. Running 'make oldconfig' ... "
	yes "" | make oldconfig &> /dev/null
	if [ $? -eq 0 ]; then echo "OK"; else echo "Failed"; exit 1; fi
fi

DO_CHECK=y
while [ "${DO_CHECK}" == 'y' ]; do
	echo "==> Checking kernel configuration ..."

	for OPTION in "${OK_OPTIONS[@]}"; do
		OPT_NAME=${OPTION%% *}
		OPT_TEXT=${OPTION#* }
		( ! is_set "${CONFIG}" "${OPT_NAME}" ) && echo -e "Option ${OPT_NAME} is disabled and recommended to be enabled (${OPT_TEXT})"
	done

	for OPTION in "${BAD_OPTIONS[@]}"; do
		OPT_NAME=${OPTION%% *}
		OPT_TEXT=${OPTION#* }
		is_set "${CONFIG}" "${OPT_NAME}" && echo -e "Option ${OPT_NAME} is enabled and recommended to be disabled (${OPT_TEXT})"
	done


	DO_CHECK=n
	echo -n "==> Would you like to reconfigure kernel? [y/N] "
	read DO_CHECK
	[ "${DO_CHECK}" == 'y' ] && make nconfig
done

echo -n "==> Building kernel ... "

NUM_CORES=`grep -c ^processor /proc/cpuinfo`

make-kpkg clean &> /dev/null
if [ $? -eq 0 ]; then echo -n "phase 1 OK ... "; else echo "Failed"; exit 1; fi

make-kpkg --jobs=${NUM_CORES} --initrd --revision=${REVISION} kernel_image kernel_headers &> /dev/null
if [ $? -eq 0 ]; then echo "phase 2 OK ... "; else echo "Failed"; exit 1; fi

cd ..

# If we reinstall the same kernel, we have to clean-up DKMS-built modules, otherwise they will not be rebuilt on kernel package installation
echo "==> Cleaning old kernel modules ... "
find /var/lib/dkms/ /lib/modules/ -name "*${KERNEL}*grsec*" -exec rm -r {} \+ &>/dev/null

echo -n "==> Installing kernel ... "
dpkg -i linux-{image,headers}-${KERNEL}-grsec_${REVISION}_*.deb &> /dev/null
if [ $? -eq 0 ]; then echo "OK"; else echo "Failed"; exit 1; fi


echo -n "==> Cleaning up ... "
rm linux-${KERNEL}.tar linux-${KERNEL}.tar.sign grsecurity-${GRSEC}.patch grsecurity-${GRSEC}.patch.sig
if [ $? -eq 0 ]; then echo "OK"; else echo "Failed"; exit 1; fi

if [ "${UNINSTALL}" == "y" ]; then
	echo -n "==> Removing build tools ... "
	apt-get -y -qq remove ${BUILDTOOLS} &> /dev/null
	if [ $? -eq 0 ]; then echo "OK"; else echo "Failed"; exit 1; fi
fi
