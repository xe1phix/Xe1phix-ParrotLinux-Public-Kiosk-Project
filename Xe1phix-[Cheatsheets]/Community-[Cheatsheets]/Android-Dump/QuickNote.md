Xe1phix-Other Session ID:
0578e38ef8ef39846277390e5326f95db2f917633321f1e41eff5b338050870479


Xe1phix-Other Tox ID:
DF4B8EE892F0AD9D27873F2F86F049C712F8139992CCF5F060B525D37F4A4818EB7D3B067D43


Xe1phix-Other Briar ID:
briar://acr6tqknwky6mlzbjx5fpkffwu4k53r7y2fd6qczrvmufh2siduww



Hunter.io API Key:
4a4bb6033fa91ade62737eea47514034267c5de2


IPStack API Access Key:
07097318a8d4094ee4226209e0a9dc14


NetworksDB API Key:
e7b3b9df-440b-4448-ac37-67661e86d8ec


PulseDive API key: 
9b4fa2bb951c86b5b89fdcc1eecf62ada141bbc476bc44b8a629536570c07387


FullHunt API Key:
7c8a026e-7903-4df7-a9ff-90472e622d9d



Neutrino API:
User ID: xe1phix

Neutrino Root API Key:  
lkB8argt9ODLBmUa6Lq4Z8QMpm1StBi3BPYSopSYoa5TsHva

Neutrino Production API Key:
Ik7nPv23zktyW9ROMNPKLl9jpdCYS4ToASawya2kSq9uwfJ0




Clearbit API Key:







Hello Russell (and PLUG),
I am a Linux Engineer, I have studied Linux for 12yr now.
I have given talks at 9 InfoSec conferences over the years.
I recently remastered an old talk I gave years ago titled:
"How To Create A Persistent, LUKS Encrypted USB With A LUKS Killswitch Using Parrot Linux"
I rewrote it for BSides this year, but I think it would be a great talk to give at a PLUG meetup as well.

Here is the CFP for the talk:

## ----------------------------------------------------------------------------------- #

In this presentation, I will cover:

> Securely wipe files/device partitions (6 different methods).
> Format the USB device with Parrot Linux hybrid ISO.
> Create an Ext3 filesystem on the persistent partition.
> Create LUKS encrypted container on the persistent partition.
> Create a mount point, and mount the new LUKS encrypted partition.
> Dump the header information of a LUKS device.
> Add a nuke slot to the LUKS header.
> Create a binary backup of the LUKS header and keyslot area.
> Encrypt the LUKS header with OpenSSL for secure storage.
> Decrypt the LUKS header with OpenSSL for secure storage.
> Erase all LUKS key slots on persistant partition.
> Restore LUKS header from binary backup file.

## ----------------------------------------------------------------------------------- ##

Here are the slides:
https://gitlab.com/xe1phix/ParrotSecWiki/-/blob/InfoSecTalk/Xe1phix-InfoSec-Talk-Materials/How-To-Create-A-%5BPersistent%5D-%5BLUKS-Encrypted%5D-USB-Device-With-%5BParrot-Linux%5D-v2-%5BBSidesPDX%5D-2023/How-To-Create-A-%5BPersistent%5D-%5BLUKS-Encrypted%5D-USB-Device-With-%5BParrot-Linux%5D-v2-%5BSlides%5D/Xe1phix-_Encrypted-Persistent-USB-NukeSlot_-Slides-_v15.7.84_.pdf


If you aren't interested in this talk, 
I have several completed talks on hand:
> Secure Linux VPNs - Mullvad (Wireguard, OpenVPN) + ProtonVPN
> Encrypting files with friends using GnuPG
> Intro to Linux filesystems (ZFS, Btrfs, XFS, and Ext4)
> Secure Linux sandboxes using Firejail and AppArmor
> Securing IRC using Firejail, AppArmor, Wireguard, OpenVPN, CertFP (SASL + TLS), Irc2P, and Tor

Talks in development:
(75%+ completion, could complete by Oct meetup)
> Intro to Linux Anonymity Networks - Using I2P (I2PSnark, Irc2P,  I2PMail, IMule), and Tor (TorBrowser, Whonix, OnionShare, Ricochet, Briar, and Session)
> Pentesting IPv6 - (Using the THC-Hydra IPv6 Attack Toolkit)
> Secure Linux Firewalls - (Using IPTables, PFSense, IPSet, and FWSnort)
> Secure Android Messaging - (Using Session, Briar, aTox, Telegram, and Element)
> Secure Android Networking - (Using Mullvad, Wireguard, OpenVPN, ProtonVPN, and TorBrowser)
> Linux Forensic Analysis - using Sleuthkit (fls, ils, icat, mmls, etc), dc3dd, dcdldd, Foremost, ddrescue, and  guymager
> Linux Metadata Forensics - Analysis, anonymization, and  manipulation (Exiftool, Exifprobe, Exiv2, etc)
> Linux PDF Forensics (pdf-parser, hachoir, peepdf, pdfid, etc)
> Securing Linux Kernel Modules - (Using Modprobe and kernel module parameters)
> Hardening Linux Sysctl Settings - (Securing SysFS options)

Thank you for considering my presentation
You can contact me at markrobertcurry@protonmail.com



Ching
10:10


What he desires is non desire


Your smoothing the water with flat irons




Hello Russell,
I'm very flexible on which month I give the presentation. 

It would depend on which talk you would be most interested in me giving.
If you pick the 

 "How To Create A Persistent, LUKS Encrypted USB With A LUKS Killswitch
> Using Parrot Linux"



----
Share via Tcpdump Sniffing

    Sniff anything on one interface:

tcpdump -i <interface>

    Filtering on host (source/destination/any):

tcpdump -i <interface> host <IP>
tcpdump -i <interface> src host <IP>
tcpdump -i <interface> dst host <IP>
tcpdump -i <interface> ether host <MAC>
tcpdump -i <interface> ether src host <MAC>
tcpdump -i <interface> ether dst host <MAC>

    Filtering on port (source/destination/any):

tcpdump -i <interface> port <port>
tcpdump -i <interface> src port <port>
tcpdump -i <interface> dst port <port>

    Filtering on network (e.g. network=192.168)

tcpdump -i <interface> net <network>
tcpdump -i <interface> src net <network>
tcpdump -i <interface> dst net <network>

    Protocol filtering

tcpdump -i <interface> arp
tcpdump -i <interface> ip
tcpdump -i <interface> tcp
tcpdump -i <interface> udp
tcpdump -i <interface> icmp

    Condition usage example

tcpdump -i <interface> '((tcp) and (port 80) and ((dst host 192.168.1.254) or (dst host 192.168.1.200)))'

    Disable name resolution

tcpdump -i <interface> -n

    Make sure to capture whole packet (no truncation)

tcpdump -i <interface> -s 0

    Write full pcap file

tcpdump -i <interface> -s 0 -w capture.pcap

    Show DNS traffic

tcpdump -i <interface> -nn -l udp port 53

    Show HTTP User-Agent & Hosts

tcpdump -i <interface> -nn -l -A -s1500 | egrep -i 'User-Agent:|Host:'

    Show HTTP Requests & Hosts

tcpdump -i <interface> -nn -l -s 0 -v | egrep -i "POST /|GET /|Host:"

    Show email recipients

tcpdump -i <interface> -nn -l port 25 | egrep -i 'MAIL FROM\|RCPT TO'

    Show FTP data

tcpdump -i <interface> -nn -v port ftp or ftp-data

    Show all passwords different protocols

tcpdump -i wlan0 port http or port ftp or port smtp or port imap or port pop3 or port telnet -l -A | egrep -i -B5 'pass=|pwd=|log=|login=|user=|username=|pw=|passw=|passwd=|password=|pass:|user:|username:|password:|login:|pass |user '

S

----
[githubusercontent](


https://gist.githubusercontent.com/roycewilliams/b17feea61f39a96d75031930180ef6a6/raw/962bef9fdae8eed973f405bae7a34d735e9f2bfe/roycewilliams-github-starred.md





----
Share via 
Skip to content
Sign up

Wh1t3Fox /
WiFi_Auditor
Public

Code
Issues

More
OS Installation
Jump to bottom
Craig West edited this page Feb 5, 2021 · 3 revisions
Pages 5

Home
Hardware
OS Installation

    [0] Introduction
    Overview
    Caveats
    [1] Set up the Raspberry Pi's EEPROM to support USB booting.
    [2] Install 64 bit Archlinux onto the SD card.
    [3] Install packages required for the special setup.
    Setup Wifi
    Configure wpa_supplicant
    Configure systemd service
    [4] Swap out the stable U-Boot for the release candidate.
    [5] Configure dropbear to allow early SSH access during boot.
    [6] Update the initramfs to support btrfs, full USB boot and full disk encryption.
    [7] Prepare the USB device.
    [8] Prepare the boot.txt with the correct kernel command line arguments.
    [9] Clone the system.
    [10] Finish!

Software Installation

    WiFi Tools

Clone this wiki locally

H/T to XSystem for the initial write-up
[0] Introduction
Overview

In this guide you will learn how to set up a Raspberry Pi 4 Model B with the following features:

    64 bit Archlinux ARM (AArch64)
    Full USB Boot
        This allows you to ditch the SD card entirely and boot from a thumb drive or SSD connected through a SATA-to-USB adapter.
    Full Disk Encryption + SSH Unlock
        This applies to the root filesystem, not the boot partition.
        You will be able to unlock the system locally using monitor and keyboard or remotely by connecting to the Pi through an SSH connection we will set up.

Caveats

As the guide is written right now, it is assumed you are using the ethernet port for networking. With the way the initramfs will be set up, the onboard WiFi interface is not detected anymore. I believe this can be fixed, but I haven't been able to do that yet.
[1] Set up the Raspberry Pi's EEPROM to support USB booting.

You need to update the Pi's EEPROM in order for it to support full USB booting.

Since the EEPROM is a piece of memory directly integrated on the Pi's SoC this change will persist even if you swap out all storage media attached to the Pi. If you have already done this for your Pi, you can skip this section altogether.

There are already a number of guides out on the web on how to accomplish this, so I will keep this section brief.

Install the latest version of Raspberry Pi OS (Yes, Raspberry Pi OS, not Archlinux) onto your SD card.

    Refer to the official guides for more information on this: https://www.raspberrypi.org/software/
    Note that Raspberry Pi OS Lite is sufficient, a desktop environment is not required.
    Remember to place an empty file called 'ssh' into the boot partition if you'd like to use a headless setup. More info here: https://www.raspberrypi.org/documentation/remote-access/ssh/README.md

Once you're up and running, update your system:

sudo apt update
sudo apt full-upgrade

Edit the configuration file governing what firmware updates you receive:

sudo nano /etc/default/rpi-eeprom-update

In this file the FIRMWARE_RELEASE_STATUS variable should currently be set to critical.
Change it to stable in order to receive the latest updates. The file should then look like this:

FIRMWARE_RELEASE_STATUS="stable"

Update the firmware of the Pi:

sudo rpi-eeprom-update -d -a

If required, perform a system reboot now.

At the time of writing (5 Feb 2021), the updated VL805 EEPROM version reads '000138a1'.

Now that the EEPROM has been updated, you can shut down the system. The installation of Raspberry Pi OS is no longer needed and will be replaced with Arch in the next step.
[2] Install 64 bit Archlinux onto the SD card.

AArch64 Installation on the Archlinux ARM website: https://archlinuxarm.org/platforms/armv8/broadcom/raspberry-pi-4

Archwiki's Installation page for guidance: https://wiki.archlinux.org/index.php/installation_guide
[3] Install packages required for the special setup.

The following packages are required:
Package 	Description
dosfstools 	Required to set up a vfat partition on the USB drive.
rsync 	Will be used to clone the prepared system to the USB drive and to transfer files between the Pi and your third system from which you will remotely unlock the Pi.
unzip 	What it says on the tin, really. Used to decompress zip-archives.
base-devel 	Required to build user packages.
uboot-tools 	Required to update the U-Boot boot script.
mkinitcpio-utils 	See below.
mkinitcpio-netconf 	See below.
mkinitcpio-dropbear 	These three packages set up networking and an SSH shell during boot to allow remotely unlocking the root filesystem.
wpa_supplicant 	Used for connecting to WiFi

To install all of them at once, run:

pacman -S dosfstools rsync unzip base-devel \
    uboot-tools mkinitcpio-utils mkinitcpio-netconf mkinitcpio-dropbear wpa_supplicant

Setup Wifi

Install mkinitcpio-wifi for being able to unlock the RPi without ethernet. This can be done using an AUR helper, like yay, or manually building the PKGBUILD. https://aur.archlinux.org/packages/mkinitcpio-wifi/

git clone https://aur.archlinux.org/yay.git
cd yay && makepkg -si
yay -S mkinitcpio-wifi

Configure wpa_supplicant

wpa_passphrase <ESSID> <PASSPHRASE> >> /etc/wpa_supplicant/wpa_supplicant.conf
cp /etc/wpa_supplicant/wpa_supplicant.conf /etc/wpa_supplicant/initcpio.conf # initcpio.conf is used for the bootloader connection

Configure systemd service

cp wireless-network@.service from this repo to /etc/systemd/system/ and enable the service

systemctl daemon-reload
systemctl enable wireless-network@wlan0.service

Revert to traditional interface names

ln -s /dev/null /etc/udev/rules.d/80-net-setup-link.rules

I did this because when my Pi was booting the interface names would change. Having 3 Wifi dongles attached with changing names became annoying. Also for the bootloader WiFi connection wlanX naming is required.
[4] Swap out the stable U-Boot for the release candidate.

To boot the generic / mainline 64 bit Linux kernel, Archlinux uses a bootloader called Das U-Boot.

At the time of writing, the version of the bootloader supplied in the repositories does not support full USB booting. There is, however, a release candidate available that supports full USB booting.

We will now download the package files of the u-boot package installed on the Pi, modify them so that they install the release-candidate instead of the stable version, and then swap out the bootloader on the Pi.

First, acquire the package files for the package uboot-raspberrypi.
These can be found here: https://github.com/archlinuxarm/PKGBUILDs/tree/master/alarm/uboot-raspberrypi

You can use a tool like DownGit in order to download just the specific folder of the repository:

    Visit https://downgit.github.io/
    Paste the link to the specific folder given above.
    Download the zip archive.

You now need to transfer the zip archive to the Pi. (Assuming you performed the steps above on a third system and not on the Pi itself.) This can for instance be achieved using rsync over ssh:

# Perform this on the third host, assuming the Pi's username and hostname
# are still called 'alarm' and the Pi is connected to the same network.
rsync uboot-raspberrypi.zip alarm@alarm:/home/alarm/

Once the zip archive is available on the Pi, unzip it and change into the directory:

# Make sure you are not root, as root cannot / should not install user packages.
# Change into the home directory, if not already.
cd
# Unzip the archive. All files are already contained within a folder within the archive.
unzip uboot-raspberrypi.zip
# Change into the directory.
cd uboot-raspberrypi

Next, we need to perform some edits on the PKGBUILD in order to use the release candidate instead of the stable version.

vim PKGBUILD

Perform the following three replacements:
Variable 	Before 	After
pkgname 	uboot-raspberrypi 	uboot-raspberrypi-rc
pkgver 	2020.07 	2021.01rc5
First value in md5sums 	a3206df1c1b97df7a4ddcdd17cb97d0c 	eb2c658ecd8f31dfa7f625ca337a140c

The PKGBUILD should then look something like this:

# U-Boot: Raspberry Pi
# Maintainer: Kevin Mihelich <kevin@archlinuxarm.org>

buildarch=12

pkgname=uboot-raspberrypi-rc
pkgver=2021.01rc5
pkgrel=2
pkgdesc="U-Boot for Raspberry Pi"
arch=('armv7h' 'aarch64')
url='http://www.denx.de/wiki/U-Boot/WebHome'
license=('GPL')
backup=('boot/boot.txt' 'boot/boot.scr' 'boot/config.txt')
makedepends=('bc' 'dtc' 'git')
conflicts_armv7h=('linux-raspberrypi')
_commit=f4b58692fef0b9c16bd4564edb980fff73a758b3
source=("ftp://ftp.denx.de/pub/u-boot/u-boot-${pkgver/rc/-rc}.tar.bz2"
        "https://github.com/raspberrypi/firmware/raw/${_commit}/boot/bcm2710-rpi-3-b.dtb"
        "https://github.com/raspberrypi/firmware/raw/${_commit}/boot/bcm2710-rpi-3-b-plus.dtb"
        "https://github.com/raspberrypi/firmware/raw/${_commit}/boot/bcm2710-rpi-cm3.dtb"
        "https://github.com/raspberrypi/firmware/raw/${_commit}/boot/bcm2711-rpi-4-b.dtb"
        '0001-rpi-increase-space-for-kernel.patch'
        'boot.txt.v2'
        'boot.txt.v3'
        'mkscr')
md5sums=('eb2c658ecd8f31dfa7f625ca337a140c'
         '0c56f6b8fde06be1415b3ff85b5b5370'
         'e4b819439961514c7441473d4733a1b4'
         '38cab92f98944f0492c5320cf8b36870'
         '04f2dd06c65cd7ad2932041cbe220a13'
         '728c4a0a542db702b8d88ffe1994660c'
         '69e883f0b8d1686b32bdf79684623f06'
         'be8abe44b86d63428d7ac3acc64ee3bf'
         '021623a04afd29ac3f368977140cfbfd')

# ...

Now, build the package but do not install it just yet:

# Make sure you are cd'd into the PKGBUILD's directory.
makepkg -s

This should install the necessary build-dependencies, download the release candidate and build the bootloader.

Now we're going to swap the stable bootloader with the release-candidate. Make sure to perform both steps in a single session (i.e. don't reboot the system inbetween), as your system is briefly left with no bootloader.

# Uninstall the stable bootloader.
sudo pacman -R uboot-raspberrypi
# Afterwards, while still in the uboot-raspberrypi directory,
# install our freshly built release-candidate.
makepkg -si

makepkg -si will inform you the package has already been built, and will simply proceed to install it.

DO NOT REBOOT YET.

I had issues connecting to the internet via lan after a reboot, so proceed with the setup.
[5] Configure dropbear to allow early SSH access during boot.

These steps are simply adapted from gea0's guide for the Pi 3 which was already linked in the beginning: https://gist.github.com/gea0/4fc2be0cb7a74d0e7cc4322aed710d38

Set up an RSA SSH key on the system from which you would like to remotely unlock your pi:

ssh-keygen -t rsa -b 4096 -a 100 -f ~/.ssh/pi_unlock_key

Transfer it to the pi:

rsync ~/.ssh/pi_unlock_key.pub alarm@alarm:/home/alarm/
ssh-copy-id -i ~/.ssh/pi_unlock_key.pub alarm@alarm

Additionally, set up the configuration on this host system:

vim ~/.ssh/config
--------------------------------------------------------------------------------
Host h4kb0x
  HostName 192.168.2.34
  User root
  IdentityFile ~/.ssh/pi_unlock_key

The IP used for the HostName will be set as a static IP on the Pi

The user has to be root because this is the user used to connect during the early unlock stage. This doesn't mean that we enable actual root access over ssh for the booted system.

The next steps will now be performed on the Pi and not the host used for unlocking.

Make the copied key dropbear's root key.

sudo mv ~/pi_unlock_key.pub /etc/dropbear/root_key

Finally, regenerate the RSA host key with the -m PEM option. This is due to a bug in dropbear which will cause errors in the next section when running the dropbear-hook during mkinitcpio.

cd /etc/ssh
sudo rm ssh_host_rsa_key*
sudo rm ssh_host_dsa_key*
sudo rm ssh_host_ecdsa_key*
# Regenerate it with the '-m PEM' option.
sudo ssh-keygen -t rsa -b 4096 -f ssh_host_rsa_key -N "" -m PEM < /dev/null
sudo ssh-keygen -t ecdsa -f ssh_host_dsa_key -N "" -m PEM < /dev/null
sudo ssh-keygen -t ecdsa  -f ssh_host_ecdsa_key -N "" -m PEM < /dev/null

Now that dropbear is set up, we can move on to the initramfs.
[6] Update the initramfs to support btrfs, full USB boot and full disk encryption.

We will now perform a number of changes to the system's initramfs in order to ensure support for the three essential features (btrfs, usb boot and disk encryption + SSH unlock) during boot.

Edit mkinitcpio.conf:

sudo vim /etc/mkinitcpio.conf

We now need to add two additional modules:
module 	description
pcie_brcmstb 	Necessary to allow booting from a USB device.
broadcom 	The netconf-hook would get stuck during boot if I didn't add this module. It's therefore a necessary module for remotely unlocking the machine.

Also add the following binary:
binary 	description
/usr/lib/libgcc_s.so.1 	Decryption would otherwise fail with the error that pthread_cancel is not available when using the encryptssh hook.
wpa_passphrase 	Pre-computes PSK entries for network configuration blocks of a wpa_supplicant.conf file
wpa_supplicant 	Supports connecting to WiFi network

Finally, we need the following additional hooks:
hooks 	insert after 	description
keyboard keymap 	autodetect 	Loads the keyboard early in order to allow entry of the passphrase using monitor and keyboard.
sleep wifi netconf dropbear encryptssh 	block 	The five hooks necessary to set up early networking, the ssh shell and encryption. sleep ensures all devices are online before setting up networking.

Your /etc/mkinitcpio.conf should then look something like this:

# ...
MODULES=(pcie_brcmstb broadcom)

# ...
BINARIES=(/usr/lib/libgcc_s.so.1 wpa_passphrase wpa_supplicant)

# ...
FILES=()

# ...
HOOKS=(base udev autodetect keyboard keymap modconf block sleep wifi netconf dropbear encryptssh filesystems fsck)

Now, rebuild the initramfs:

sudo mkinitcpio -P

[7] Prepare the USB device.

We will now set up the USB device using full-disk encryption.

Note that you should now perform some special steps on the USB drive to ensure full security, which often involves overriding either the entire drive or the second partition with random bytes or zero bytes.
It may also be advisable to perform a SATA Secure Erase on the drive before partitioning.

Instead of providing all the details here, you are strongly advised to consider the corresponding page on the Archwiki before proceeding: https://wiki.archlinux.org/index.php/Dm-crypt/Drive_preparation

Now, on to the actual partitioning of the drive. Plug in the USB device to the pi and identify it with sudo fdisk -l. It will probably have been assigned the /dev/sda-identifier. Once identified, reformat it similarly to the installation guide:

sudo fdisk /dev/sda
# Create a new MBR table.
o
# Create a new primary boot partition.
n
[Enter] (picks the default 'p')
[Enter] (picks the default '1')
[Enter] (picks the default '2048')
+200M
# Set its type correctly.
t
c
# Create the second partition, which we will encrypt momentarily.
n
[Enter] (picks the default 'p')
[Enter] (picks the default '2')
[Enter] (picks the default first sector)
[Enter] (picks the default last sector)
# Print the pending changes and ensure everything looks good.
p
# Apply and exit.
w

Next, set up the appropriate filesystems and encryption:

# Set up the correct filesystem for the boot partition.
sudo mkfs.vfat /dev/sda1
# Set up encryption on the second partition.
sudo cryptsetup luksFormat -c aes-xts-plain64 -s 512 -h sha512 --use-random -i 1000 /dev/sda2
sudo cryptsetup luksOpen /dev/sda2 root
# And format the ext4 filesystem for it.
sudo mkfs.ext4 /dev/mapper/root

[8] Prepare the boot.txt with the correct kernel command line arguments.

For now, create a copy of the boot.txt and then edit this copy.

sudo cp /boot/boot.txt{,.new}
sudo vim /boot/boot.txt.new

Get UUID for /dev/sda2

root@raspberrypi:/home/pi# blkid | grep 'sda2'
/dev/sda2: UUID="142d95da-817d-4ad7-90c9-ce99a5e63ba3" TYPE="crypto_LUKS" PARTUUID="f8095a2e-02"

In it, comment out the line that reads part uuid ... by placing a #-symbol in front of it.

Next, we will focus our attention on the setenv-line that defines the command line arguments of the kernel. Replace the section that reads root=PARTUUID=${uuid} with the following:

ip=192.168.2.144::192.168.2.34:255.255.255.0:h4kb0x:wlan0:none cryptdevice=UUID=142d95da-817d-4ad7-90c9-ce99a5e63ba3:root root=/dev/mapper/root

The first argument tells the netconf-hook how exactly it is supposed to set up networking. This is the place where the hostname we defined earlier during ssh configuration comes into play. Generally, the ip argument has the following pattern:

ip=<client-ip>:<server-ip>:<gateway-ip>:<netmask>:<hostname>:<device>:<autoconf>:<dns0-ip>:<dns1-ip>

For more information and further examples on how to set this up, refer to the corresponding section in the Archwiki: https://wiki.archlinux.org/index.php/Mkinitcpio#Using_net

In my example I have explicitly set the hostname to h4kb0x and told netconf to autoconfigure wlan0 interface using a static IP.

The next two arguments set up full disk encryption, using /dev/sda2 as the encrypted blockdevice and mapping it to /dev/mapper/root.

The boot.txt.new should then look something like this:

# After modifying, run ./mkscr

# Set root partition to the second partition of boot device
#part uuid ${devtype} ${devnum}:2 uuid

setenv bootargs console=ttyS1,115200 console=tty0 ip=192.168.2.144::192.168.2.34:255.255.255.0:h4kb0x:wlan0:none cryptdevice=UUID=142d95da-817d-4ad7-90c9-ce99a5e63ba3:root root=/dev/mapper/root rw rootwait smsc95xx.macaddr="${usbethaddr}"

# ...

Note: We will run ./mkscr later, which will apply the changes. If applied now, you wouldn't be able to reboot the system anymore.
[9] Clone the system.

We will now clone our prepared system to the USB drive.

First, mount both partitions of the USB drive. One way to achieve this can look like this:

# Create a new folder in your home-directory for this.
mkdir ~/pi-setup
cd ~/pi-setup
# Create folders for the two partitions.
mkdir usb-boot
mkdir usb-root
# Identify the disks.
sudo fdisk -l
# Assuming your USB drive was detected as /dev/sda
# Open the encrypted partition
sudo cryptsetup luksOpen /dev/sda2 root
# Mount both USB partitions
sudo mount /dev/sda1 usb-boot/
sudo mount /dev/mapper/root usb-root/

Note: Double check that you mounted the right partitions in the right folders. It is easy to make a mistake here, and you may corrupt the bootstrap-system we've set up so far with the next few commands if you're not careful.

Now, actually clone the system.

sudo rsync --info=progress2 -axHAX /boot/ usb-boot/
sudo rsync --info=progress2 -axHAX / usb-root/
# Ensure the cache is empty.
sudo sync

Now, we need to perform two final adjustments.

First, adjust the fstab of the cloned system by replacing /dev/mmcblk1p1 with PARTUUID=<ID>:

root@h4kb0x:/home/alarm# blkid | grep 'sda1'
/dev/sda1: SEC_TYPE="msdos" UUID="2CCF-0B28" TYPE="vfat" PARTUUID="f8095a2e-01"

sudo vim usb-root/etc/fstab
--------------------------------------------------------------------------------
PARTUUID=f8095a2e-01 /boot vfat  defaults  0 0

Secondly, apply the changes we made to the bootloader.

cd ~/pi-setup/usb-boot
sudo mv boot.txt.new boot.txt
sudo ./mkscr

Finally, unmount the two partitions.

cd ~/pi-setup
sudo umount usb-boot usb-root
sudo cryptsetup close root

And that's it. Shutdown your system and remove the SD card.
[10] Finish!

Now, connect the USB drive and only the USB drive to the Pi and power it on.

You should now be able to unlock the Pi locally through both monitor and keyboard as well as remotely via ssh by connecting to the Pi from your other host with the host-config that we've set up:

ssh h4kb0x

Footer
© 2023 GitHub, Inc.
Footer navigation

    Terms
    Privacy
    Security
    Status
    Docs
    Contact GitHub
    Pricing
    API
    Training
    Blog
    About

OS Installation · Wh1t3Fox/WiFi_Auditor Wiki · GitHub

----
https://maltronics.com/products/malduino-w

https://github.com/Cr4sh?tab=repositories

https://github.com/Shiva108/CTF-notes

https://github.com/maksyche/pentest-everything

https://tryhackme.com/path/outline/pentesting

https://github.com/The-Viper-One/Pentest-Everything/tree/Main/everything/everything-linux

https://tryhackme.com/room/vulnversity

https://github.com/mubix/post-exploitation

https://github.com/mubix/post-exploitation-wiki

https://github.com/NullArray/AutoSploit

https://github.com/GTFOBins/GTFOBins.github.io

https://github.com/Ebazhanov/linkedin-skill-assessments-quizzes

https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/osint.md

https://github.com/0xsyr0?tab=repositories

----
## ----------------------------------------- ##
Privacy is fundamental to a well-functioning society, 
## ----------------------------------------- ##
This is because it allows:
--> Societal norms, ethics, and laws to be safely discussed and challenged. 
## ----------------------------------------- ##
--> Its absence leads to a society experiencing:
## ----------------------------------------- ##
--> Repression of external (AND! internal) forms of thought
## ----------------------------------------- ##
--> Intellectually disrupted social  consciousness 
## ----------------------------------------- ##
--> And a Withering public discourse 
## ----------------------------------------- ##
##  [?] A fear of  communal exchange of ideas.
## ----------------------------------------- ##
##  [?] A healthy society is contingent upon: shared thought discussion.
## ----------------------------------------- ##
--> Which only serves the malevolent. 
## ----------------------------------------- ##
A free and open society, therefore:

## ----------------------------------------- ##
--> Cannot flourish, and develop.
## ----------------------------------------- ##
--> Nor can a truly free society exist 
without the the fundamental human right to privacy. 
## ----------------------------------------- ##
--> Without the majority of society understanding the crucial nessessity of privacy
## ----------------------------------------- ##
## The societal impact ???? 
## ----------------------------------------- ##
--> Privacy has been irrefutability proven:
## ----------------------------------------- ##
##. (over and over again)
## ----------------------------------------- ##
in thoroughly vetted, 
and professionally ¿¿¿¿¿ 
##  and professionally critiqued 
##.sociology studies.
## ----------------------------------------- ##
That privacy is a foundational, 
## ----------------------------------------- ##
That privacy is an alsolutely fundamemtal tenant of society.
## ----------------------------------------- ##
And a noticeable infringement 
on these human liberties, 
## ----------------------------------------- ##
encroachment on these human liberties, 
has deep seeded ¿¿¿¿
## ----------------------------------------- ##
##  a foundational tenant of society 
## ----------------------------------------- ##
That is why privacy is paramount.
## ----------------------------------------- ##
And that is why we strive to make 
internet censorship and 
mass surveillance ineffective. 
## ----------------------------------------- ##

----
Keyoxide Keyoxide (Verify decentralized cryptographic identities on the go)
https://f-droid.org/packages/org.keyoxide.keyoxide/