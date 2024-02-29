


if [[ `id -u` = '0' ]];
	then
		SUDO=''
	else 
		SUDO='sudo'
fi


if ! [[ `id | grep sudo` || `id -u` = '0' ]]; 
	then
		echo "Not root and not in the sudo group. Exiting." 
		echo
		exit
fi








sed -i 's/SHELL=.*/SHELL=\/bin\/false/' "$USERADD"

sed -i 's/PATH=.*/PATH=\"\/usr\/local\/bin:\/usr\/bin:\/bin"/' /etc/environment


## Set permissions for admin user's home directory.
chmod 700 "/home/$ADMINUSER"




systemd-delta --no-pager


sed -ie '/\s\/home\s/ s/defaults/defaults,noexec,nosuid,nodev/' /etc/fstab
echo "none /tmp tmpfs rw,noexec,nosuid,nodev 0 0" >> /etc/fstab
	else
sed -ie '/\s\/tmp\s/ s/defaults/defaults,noexec,nosuid,nodev/' /etc/fstab

echo "none /run/shm tmpfs rw,noexec,nosuid,nodev 0 0" >> /etc/fstab
## Bind /var/tmp to /tmp to apply the same mount options during system boot
echo "/tmp /var/tmp none bind 0 0" >> /etc/fstab
## Temporarily make the /tmp directory executable before running apt-get and remove execution flag afterwards. This is because
## sometimes apt writes files into /tmp and executes them from there.
echo -e "DPkg::Pre-Invoke{\"mount -o remount,exec /tmp\";};\nDPkg::Post-Invoke {\"mount -o remount /tmp\";};" >> /etc/apt/apt.conf.d/99tmpexec
chmod 644 /etc/apt/apt.conf.d/99tmpexec


echo "APT::Periodic::AutocleanInterval \"7\";" >> /etc/apt/apt.conf.d/10periodic
chmod 644 /etc/apt/apt.conf.d/10periodic




echo "tmpfs /tmp tmpfs defaults,nosuid,nodev,mode=1777,size=100M 0 0" >> /etc/fstab
echo "/tmp /var/tmp tmpfs defaults,nosuid,nodev,bind,mode=1777,size=100M 0 0" >> /etc/fstab













## Creating mountpoint at %s" "$mountpoint
(umask 077; mkdir "$mountpoint")

## Changing ownership of the mountpoint to %s:%s" "$SUDO_UID" "$SUDO_GID
chown "$SUDO_UID":"$SUDO_GID" "$mountpoint"

## Removing permissions for group and others
chmod -R go-rwx "$mountpoint"

## Mounting volume to %s" "$mountpoint
mount -u "$SUDO_UID" -m 700 -o noatime,nosuid,nobrowse "$ramdisk_path" "$mountpoint"
undo="umount \"$mountpoint\"


## Configure su execution...
dpkg-statoverride --update --add root adm 4750 /bin/su


## Configuring home directories and shell access..."
sed -ie '/^DIR_MODE=/ s/=[0-9]*\+/=0700/' /etc/adduser.conf
sed -ie '/^UMASK\s\+/ s/022/077/' /etc/login.defs


echo "[$i] Passwords and authentication"
sed -i 's/^password[\t].*.pam_cracklib.*/password\trequired\t\t\tpam_cracklib.so retry=3 maxrepeat=3 minlen=14 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1 difok=4/' /etc/pam.d/common-password
sed -i 's/try_first_pass sha512.*/try_first_pass sha512 remember=24/' /etc/pam.d/common-password
sed -i 's/nullok_secure//' /etc/pam.d/common-auth



# Disable shell access for new users (not affecting the existing admin user).
sed -ie '/^SHELL=/ s/=.*\+/=\/usr\/sbin\/nologin/' /etc/default/useradd
sed -ie '/^DSHELL=/ s/=.*\+/=\/usr\/sbin\/nologin/' /etc/adduser.conf

echo "[$i] Cron and at"
echo root > /etc/cron.allow
echo root > /etc/at.allow

echo "[$i] Ctrl-alt-delete"
sed -i 's/^exec.*/exec \/usr\/bin\/logger -p security.info \"Ctrl-Alt-Delete pressed\"/' /etc/init/control-alt-delete.conf








echo sshd : ALL : ALLOW$'\n'ALL: LOCAL, 127.0.0.1 > /etc/hosts.allow
echo ALL: PARANOID > /etc/hosts.deny

echo "[$i] /etc/login.defs"
sed -i 's/^LOG_OK_LOGINS.*/LOG_OK_LOGINS\t\tyes/' /etc/login.defs
sed -i 's/^UMASK.*/UMASK\t\t077/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t\t1/' /etc/login.defs
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t\t30/' /etc/login.defs
sed -i 's/DEFAULT_HOME.*/DEFAULT_HOME no/' /etc/login.defs
sed -i 's/USERGROUPS_ENAB.*/USERGROUPS_ENAB no/' /etc/login.defs
sed -i 's/^# SHA_CRYPT_MAX_ROUNDS.*/SHA_CRYPT_MAX_ROUNDS\t\t10000/' /etc/login.defs


echo "[$i] /etc/security/limits.conf"
echo * hard maxlogins 10 >> /etc/security/limits.conf
echo * hard core 0$'\n'* soft nproc 100$'\n'* hard nproc 150$'\n\n'# End of file >> /etc/security/limits.conf

echo "[$i] Adduser / Useradd" 
sed -i 's/DSHELL=.*/DSHELL=\/bin\/false/' /etc/adduser.conf 
sed -i 's/SHELL=.*/SHELL=\/bin\/false/' /etc/default/useradd
sed -i 's/^# INACTIVE=.*/INACTIVE=35/' /etc/default/useradd

echo "[$i] Root access"
sed -i 's/^#+ : root : 127.0.0.1/+ : root : 127.0.0.1/' /etc/security/access.conf
echo console > /etc/securetty


echo "[$i] .rhosts"
for dir in `cat /etc/passwd | awk -F ":" '{print $6}'`;
do
        find $dir -name "hosts.equiv" -o -name ".rhosts" -exec rm -f {} \; 2> /dev/null
        if [[ -f /etc/hosts.equiv ]];
                then
                rm /etc/hosts.equiv
        fi
done



echo "[$i] Remove users"
for users in games gnats irc news uucp; 
do 
	sudo userdel -r $users 2> /dev/null
done



echo "[$i] Remove suid bits"
for p in /bin/fusermount /bin/mount /bin/ping /bin/ping6 /bin/su /bin/umount /usr/bin/bsd-write /usr/bin/chage /usr/bin/chfn /usr/bin/chsh /usr/bin/mlocate /usr/bin/mtr /usr/bin/newgrp /usr/bin/pkexec /usr/bin/traceroute6.iputils /usr/bin/wall /usr/sbin/pppd;
do 
	oct=`stat -c "%a" $p |sed 's/^4/0/'`
	ug=`stat -c "%U %G" $p`
	dpkg-statoverride --remove $p 2> /dev/null
	dpkg-statoverride --add $ug $oct $p 2> /dev/null
	chmod -s $p
done

for SHELL in `cat /etc/shells`; do
	if [ -x $SHELL ]; then
		$SUDO chmod -s $SHELL
	fi
done


echo "[$i] Running Aide, this will take a while"
aideinit --yes
cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db


































## Set some AppArmor profiles to enforce mode.

aa-enforce /etc/apparmor.d/usr.bin.firefox
aa-enforce /etc/apparmor.d/usr.sbin.avahi-daemon
aa-enforce /etc/apparmor.d/usr.sbin.dnsmasq
aa-enforce /etc/apparmor.d/bin.ping
aa-enforce /etc/apparmor.d/usr.sbin.rsyslogd



echo -e "Configuring system auditing..."
if [ ! -f /etc/audit/rules.d/tmp-monitor.rules ]; then
## Monitor changes and executions within /tmp
-w /tmp/ -p wa -k tmp_write
-w /tmp/ -p x -k tmp_exec > /etc/audit/rules.d/tmp-monitor.rules
fi


if [ ! -f /etc/audit/rules.d/admin-home-watch.rules ]; then
## Monitor administrator access to /home directories

-a always,exit -F dir=/home/ -F uid=0 -C auid!=obj_uid -k admin_home_user" > /etc/audit/rules.d/admin-home-watch.rules
fi
augenrules
systemctl restart auditd.service




## Configure the settings for the "Welcome" popup box on first login.
echo -e "Configuring user first login settings...}"
mkdir -p "/home/$ENDUSER/.config"
echo yes > "/home/$ENDUSER/.config/gnome-initial-setup-done"
chown -R "$ENDUSER:$ENDUSER" "/home/$ENDUSER/.config"
sudo -H -u "$ENDUSER" ubuntu-report -f send no



echo "[$i] Auditd"
sed -i 's/^space_left_action =.*/space_left_action = email/' /etc/audit/auditd.conf
curl -s $AUDITD_RULES > /etc/audit/audit.rules
sed -i 's/^GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX="audit=1"/' /etc/default/grub
curl -s $AUDITD_RULES > /etc/audit/audit.rules
update-grub 2> /dev/null











## Lockdown Gnome screensaver lock settings


## Lockdown Gnome screensaver lock settings
echo -e "${HIGHLIGHT}Configuring Gnome screensaver lock settings...${NC}"
mkdir -p /etc/dconf/db/local.d/locks
echo "[org/gnome/desktop/session]
idle-delay=600

[org/gnome/desktop/screensaver]
lock-enabled=1
lock-delay=0 > /etc/dconf/db/local.d/00_screensaver-lock

/org/gnome/desktop/session/idle-delay
/org/gnome/desktop/screensaver/lock-enabled
/org/gnome/desktop/screensaver/lock-delay > /etc/dconf/db/local.d/locks/00_screensaver-lock

dconf update



sudo -H -u "$ENDUSER" dbus-launch gsettings set $GConfProperty false


# Fix some permissions in /var that are writable and executable by the standard user.
chmod o-w /var/tmp


grep "user-db:user" /etc/dconf/profile/user
grep "system-db:local" /etc/dconf/profile/user


dconf update




























openssl dgst -${HASH} ${TARGET_FILE} | cut -d ' ' -f 2

FILE}.sig
FILE}.asc


.(asc|sig)

for HASH in SHA512 SHA256 SHA1 MD5; do
for SUMFILE in "${TARGET_DIR}"/"${HASH}"*; do

"$(basename $SUMFILE .txt).asc"
"$(basename $SUMFILE .txt).sig"


"
  --keyserver hkps://sks.openpgp-keyserver.de \
  --keyserver-options ca-cert-file="$(dirname $0)/sks-keyservers.netCA.pem" \
  --keyserver-options no-honor-keyserver-url \
--trust-model=always"

export GNUPGHOME=~/

if [[ ! -d ${GNUPGHOME} ]]; then
    mkdir -m 0700 -d ${GNUPGHOME}

if gpg ${OPTIONS} ${EXTRA_OPTIONS} --verify "${TARGET_SIG}" "${TARGET_FILE}"; then
  echo "VERIFIED"
else
  err "WARNING FAGGOT!"
fi




wget ftp://ftp.mozilla.org/pub/mozilla.org/firefox/releases/34.0/SHA512SUMS 
wget ftp://ftp.mozilla.org/pub/mozilla.org/firefox/releases/34.0/SHA512SUMS.asc 
wget ftp://ftp.mozilla.org/pub/mozilla.org/firefox/releases/34.0/linux-x86_64/en-US/firefox-34.0.tar.bz2

verify.sh firefox-34.0.tar.bz2



SHA512SUM*, SHA256SUM*, SHA1SUM*



## You must have gnupg-curl installed to fetch keys over HKPS


SSH_AUTH_SOCK=$HOME/.gnupg/S.gpg-agent.ssh
setenv SSH_AUTH_SOCK $HOME/.gnupg/S.gpg-agent.ssh

$HOME/.gnupg/gpg-agent.conf

enable-ssh-support
pinentry-program /usr/local/bin/pinentry



$HOME/.gnupg/scdaemon.conf
disable-ccid


export GNUPGHOME="$SECUREDIR/gnupg-home"
(umask 077; mkdir -p "$GNUPGHOME")

## Generating master key and encryption subkey for "%s" <%s>' "$key_name" "$key_email"

gpg_output=$(gpg --command-fd 0 --status-fd 2 --no-tty --gen-key --batch 2>&1 << EOF

%no-protection
Key-Type: RSA
Key-Length: 4096
Key-Usage: ,
Name-Real: $key_name
Name-Email: $key_email
Expire-Date: 1y
Subkey-Type: RSA
Subkey-Length: 4096
Subkey-Usage: encrypt
%commit
EOF


## Generating master key and encryption subkey for "John Doe" <jd@example.com>
## Key ID is 


## Exporting private keys"
gpg --armor --output "$EXPORTDIR/$key_id.private.asc" \
    --export-options export-backup --export-secret-keys "$key_id"

## Exporting public keys"
gpg --armor --output "$EXPORTDIR/$key_id.public.asc" --export "$key_id"


# Change the GnuPG home dir, so that you can interact with the keys you just created
export GNUPGHOME=$PWD/secure/gnupg-home

# Make sure there is no gpg-agent running
gpgconf --kill gpg-agent


## Generating revocation certificate"
revcert_path="$EXPORTDIR/$key_id-revocation-certificate.asc"

gpg --command-fd 0 --status-fd 2 --no-tty \
    --armor --output "$EXPORTDIR/$key_id-revocation-certificate.asc" \
    --gen-revoke "$key_id"


gpg --armor --export E22FE7692F473FA12F2BAB164046979C50C10E97

## Get your public SSH key with:
gpg --export-ssh-key E22FE7692F473FA12F2BAB164046979C50C10E97


### git signing ###
commit.gpgSign = true
push.gpgSign = if-asked


gpg --import secure/export/E22FE7692F473FA12F2BAB164046979C50C10E97.public.asc




# Full fingerprint for FPF Authority Signing Key.
signing_pubkey="F81962A54902300F72ECB83AA1FC1F6AD2D09049"

# Signing Keys
2224 5C81 E3BA EB41 38B3  6061 310F 5612 00F4 AD77 # SecureDrop Release Signing Key
F819 62A5 4902 300F 72EC  B83A A1FC 1F6A D2D0 9049 # FPF Authority Signing Key


# Write detached signature file.
gpg --armor --detach-sign \
    --output "${gpgsync_signature_file}" \
    -u "${signing_pubkey}" \
    "${gpgsync_fingerprints_file}"

# Sanity-checking: signature must be valid.
gpg --verify "${gpgsync_signature_file}" "${gpgsync_fingerprints_file}"



gpg --symmetric --cipher-algo AES256 --s2k-digest-algo SHA512 <file-to-encrypt>


/var/run/user/$(id -u)/gnupg/S.gpg-agent



gpgconf --reload scdaemon
/usr/bin/pkill -x -INT gpg-agent


gpg-agent \
        	--daemon \
        	--enable-ssh-support \
        	--log-file "/dev/stdout"


gpg --card-status


gpg --encrypt --recipient your-email --armor ~/.otpkeys


    otpkey=`grep ^$1 "$otpkeys_path" | cut -d":" -f 2 | sed "s/ //g"`
else 
    otpkey=`gpg --batch --decrypt "$otpkeys_path" 2> /dev/null | grep "^$1:" | cut -d":" -f 2 | sed "s/ //g"`


oathtool --totp -b "$otpkey"

gpg --export-secret-key $KEYID | paperkey --output-type raw | base64 > $KEYNAME


for f in x*; do cat $f | head -c -1 | qrencode -o qr-$f.png; done


ykksm-checksum --database dbi:mysql:ykksm --db-user user --db-passwd pencil


echo "Generating new key..."
yubico-piv-tool  -s 9a -A RSA2048 -a generate | pbcopy

echo "Generating self signed certificate..."
pbpaste | yubico-piv-tool -s 9a -S '/CN=Smart card certificate/' -P 123456 -a verify -a selfsign | pbcopy
echo $?

yubico-piv-tool 

yubico-piv-tool 

yubico-piv-tool 

yubico-piv-tool 

yubico-piv-tool 

echo "Importing certificate..."
pbpaste | yubico-piv-tool -s 9a -a import-certificate
echo $?












GITVERSION=$(git describe --tags --always)

gpg --keyring $PROG_DIR/f-droid.org-signing-key.gpg --no-default-keyring --trust-model always

curl -L https://f-droid.org/$FDROID_APK > $TMP_DIR/$FDROID_APK
curl -L https://f-droid.org/${FDROID_APK}.asc > $TMP_DIR/${FDROID_APK}.asc

curl -L https://f-droid.org/repo/$DL_APK > $TMP_DIR/$FDROID_APK
curl -L https://f-droid.org/repo/${DL_APK}.asc > $TMP_DIR/${FDROID_APK}.asc

$GPG --verify $TMP_DIR/${FDROID_APK}.asc






ssh git@gitlab.example.com 2fa_recovery_codes









if ! grep '^APT::Get::AllowUnauthenticated' /etc/apt/apt.conf.d/* ; then
    echo 'APT::Get::AllowUnauthenticated "false";' >> /etc/apt/apt.conf.d/01-vendor-ubuntu
fi

if ! grep '^Unattended-Upgrade::Remove-Unused-Dependencies;' /etc/apt/apt.conf.d/50unattended-upgrades; then
    sed -i 's/.*Unattended-Upgrade::Remove-Unused-Dependencies.*/Unattended-Upgrade::Remove-Unused-Dependencies "true";/' /etc/apt/apt.conf.d/50unattended-upgrades
  fi



  TMPCONF=$(mktemp --tmpdir ntpconf.XXXXX)

  if [[ -z "$NTPSERVERPOOL" ]]; then
    NTPSERVERPOOL="0.ubuntu.pool.ntp.org 1.ubuntu.pool.ntp.org 2.ubuntu.pool.ntp.org 3.ubuntu.pool.ntp.org pool.ntp.org"
  fi


for s in $(dig +noall +answer +nocomments $NTPSERVERPOOL | awk '{print $5}'); do
    if [[ $NUMSERV -ge $SERVERS ]]; then
      break
    fi

nslookup "$s"|grep "name = " | awk '{print $4}'|sed 's/.$//'

for s in $(echo "$NTPSERVERPOOL" | awk '{print $(NF-1),$NF}')

systemctl restart systemd-timesyncd


echo "Setting time zone to $TIMEDATECTL"
    timedatectl set-timezone "$TIMEDATECTL"

systemctl status systemd-timesyncd --no-pager






lsof -i${1} -s${1}:LISTEN -P -n | grep ":${2} "); else FIND=$(lsof -i${1} -P -n | grep ":${2} "); fi



$(lshw -quiet -class system 2> /dev/null | awk '{ if ($1=="product:") { print $2 }}')


lscpu | grep -i "^Hypervisor Vendor" | awk -F: '{ print $2 }' | sed 's/ //g'


# lxc environ detection
grep -qa 'container=lxc' /proc/1/environ

cat /proc/1/cgroup 2> /dev/null | grep -i docker


## found LXC in environnement
grep -qa 'container=lxc' /proc/1/environ



SSH_KEY_FILES="ssh_host_ed25519_key.pub ssh_host_ecdsa_key.pub ssh_host_dsa_key.pub ssh_host_rsa_key.pub"


# Create host ID when a MAC address was not found
SSH_KEY_FILES="ssh_host_ed25519_key.pub ssh_host_ecdsa_key.pub ssh_host_dsa_key.pub ssh_host_rsa_key.pub"

HOSTID=$(cat /etc/ssh/${I} | ${SHA1SUMBINARY} | awk '{ print $1 }')


DBUS creates ID as well with dbus-uuidgen and is stored in /var/lib/dbus-machine-id (might be symlinked to /etc/machine-id)
sMACHINEIDFILE="/etc/machine-id"
head -1 ${sMACHINEIDFILE} | grep "^[a-f0-9]"



 | shasum -a 256 | awk '{ print $1 }'
 
 
 
 sysctl -n kern.uuid
 
 
 
ip addr show 2> /dev/null | egrep "link/ether " | head -1 | awk '{ print $2 }' | tr '[:upper:]' '[:lower:]')
ip addr show eth0 2> /dev/null | egrep "link/ether " | head -1 | awk '{ print $2 }' | tr '[:upper:]' '[:lower:]')
ifconfig 2> /dev/null | grep "^eth0" | grep -v "eth0:" | grep HWaddr | awk '{ print $5 }' | tr '[:upper:]' '[:lower:]')

 
 
 
 
 
 # If using openssl, use the best hash type it supports
        if [ ! "${OPENSSLBINARY}" = "" ]; then
            OPENSSL_HASHLIST=$(openssl dgst -h 2>&1)
            for OPENSSL_HASHTYPE in sha256 sha1 md5 ; do
                if echo "${OPENSSL_HASHLIST}" | grep "^-${OPENSSL_HASHTYPE} " >/dev/null ; then
                    break
                fi
            done
        fi
 

/proc/1/cmdline

echo ${FILENAME} | awk -F/ '{ print $NF }'

awk '/(^\/|init)/ { print $1 }' /proc/1/cmdline



sys/firmware/efi/efivars

sys/firmware/efi/efivars/SecureBoot-*

od -An -t u1 ${FILE} | awk '{ print $5 }'





echo "set superusers=\"sysadmin\"" >> /etc/grub.d/40_custom
echo -e "$PASS\n$PASS" | grub-mkpasswd-pbkdf2 | tail -n1 | awk -F" " '{print "password_pbkdf2 sysadmin " $7}' >> /etc/grub.d/40_custom
sed -ie '/echo "menuentry / s/echo "menuentry /echo "menuentry --unrestricted /' /etc/grub.d/10_linux
sed -ie '/^GRUB_CMDLINE_LINUX_DEFAULT=/ s/"$/ module.sig_enforce=yes"/' /etc/default/grub
echo "GRUB_SAVEDEFAULT=false" >> /etc/default/grub
update-grub









## Checking for presence GRUB conf file (/boot/grub/grub.conf or /boot/grub/menu.lst)"
if [ -f /boot/grub/grub.conf -o -f /boot/grub/menu.lst ]; then

if [ -f /boot/grub/grub.conf ]; then 
        GRUBCONFFILE="/boot/grub/grub.conf"; 
    else 
        GRUBCONFFILE="/boot/grub/menu.lst"; 
    fi
fi


if [ -f /boot/grub/grub.cfg ]; then
    GRUBCONFFILE="/boot/grub/grub.cfg"
elif [ -f /boot/grub2/grub.cfg ]; then
    GRUBCONFFILE="/boot/grub2/grub.cfg"
fi


grep 'password --md5' ${GRUBCONFFILE} | grep -v '^#')
grep 'password --encrypted' ${GRUBCONFFILE} | grep -v '^#')
grep 'set superusers' ${GRUBCONFFILE} | grep -v '^#')
grep 'password_pbkdf2' ${GRUBCONFFILE} | grep -v '^#')
grep 'grub.pbkdf2' ${GRUBCONFFILE} | grep -v '^#')

## Checking password option LILO:
egrep 'password[[:space:]]?=' ${LILOCONFFILE} | grep -v "^#")











systemctl --full --type=service | awk '{ if ($4=="running") { print $1 } }' | awk -F. '{ print $1 }')

systemctl --full --type=service

list-unit-files --type=service | sort -u | awk '{ if ($2=="enabled") { print $1 } }' | awk -F. '{ print $1 }')

systemctl list-unit-files --type=service


chkconfig --list | egrep '3:on|5:on' | awk '{ print $1 }')


chkconfig --list



/usr/lib/systemd/system/rescue.service

## checking presence sulogin for single user mode"
egrep "^ExecStart=.*sulogin" /usr/lib/systemd/system/rescue.service)




## Description : Check CPU options and support (PAE, No eXecute, eXecute Disable)
## More info   : pae and nx bit are both visible on AMD and Intel CPU's if supported

## Checking CPU support (NX/PAE)"

FIND_PAE_NX=$(grep " pae " /proc/cpuinfo | grep " nx ")
FIND_PAE=$(grep " pae " /proc/cpuinfo)
FIND_NX=$(grep " nx " /proc/cpuinfo)


## CPU support: PAE and/or NoeXecute supported
## CPU support: No PAE or NoeXecute supported

## Use a PAE enabled kernel when possible to gain native No eXecute/eXecute Disable support"


## Checking the default I/O kernel scheduler"
LINUX_KERNEL_IOSCHED=$(${GREPTOOL} "CONFIG_DEFAULT_IOSCHED" ${LINUXCONFIGFILE} | awk -F= '{ print $2 }' | sed s/\"//g)




if [ -f /etc/security/limits.conf ]; then

grep -v "^#" /etc/security/limits.conf | grep -v "^$" | awk '{ if ($1=="*" && $2=="soft" && $3=="core" && $4=="1") { print "soft core enabled" } }')
grep -v "^#" /etc/security/limits.conf | grep -v "^$" | awk '{ if ($1=="*" && $2=="hard" && $3=="core" && $4=="1") { print "hard core enabled" } }')


## Checking sysctl value of fs.suid_dumpable"
sysctl fs.suid_dumpable 2> /dev/null | awk '{ if ($1=="fs.suid_dumpable") { print $3 } }')


KERNELS=$(${LSBINARY} /boot/vmlinuz* | grep -v rescue | sed 's/vmlinuz-//' | sed 's/generic.//' | sed 's/huge.//' | sed 's/\.[a-z].*.//g' | sed 's/-[a-z].*.//g' | sed 's./boot/..' | sed 's/-/./g' | sort -n -k1,1 -k2,2 -k3,3 -k4,4 -k5,5 -k6,6 -t \.)



lsmod | awk '{ print $1 }' | grep "^ip*_tables"


proc/net/ip_tables_names
proc/net/ip6_tables_names

/boot/config-$(uname -r)



iptables -t ${TABLE} --numeric --list | egrep  -z -o -w  '[A-Z]+' | tr -d '\0' | awk -v t=${TABLE} 'NR%2 {printf "%s %s ",t, $0 ; next;}1')

iptables --list --numeric 2> /dev/null | egrep -v "^(Chain|target|$)" | ${WCBINARY} -l | ${TRBINARY} -d ' ')


iptables --list --numeric --line-numbers --verbose | awk '{ if ($2=="0") print $1 }' | ${XARGSBINARY})

iptables --list --numeric --line-numbers --verbose

## Description : Check nftables kernel module
lsmod | awk '{ print $1 }' | grep "^nf*_tables")


NFT_RULES_LENGTH=$(${NFTBINARY} export json 2> /dev/null | wc -c)



grep loghost /etc/inet/hosts | grep -v "^#"

getent hosts loghost | grep loghost




SYSLOGD_CONF="/etc/syslog-ng/syslog-ng.conf"
        else
SYSLOGD_CONF="/etc/syslog.conf"
            
egrep "@[a-zA-Z0-9]|destination\s.+(udp|tcp).+\sport" ${SYSLOGD_CONF} | grep -v "^#" | grep -v "[a-zA-Z0-9]@")




DESTINATIONS=$(grep "^destination" ${SYSLOGD_CONF} | egrep "(udp|tcp)" | grep "port" | awk '{print $2}')
for DESTINATION in ${DESTINATIONS}; do
grep "log" | grep "source" | egrep "destination\(${DESTINATION}\)")


## parsing directories from /etc/newsyslog.conf file"
awk '/^\// { print $1 }' /etc/newsyslog.conf | sed 's/\/*[a-zA-Z_.-]*$//g' | sort -u)
        
## parsing files from /etc/newsyslog.conf file"
awk '/^\// { print $1 }' /etc/newsyslog.conf | sort -u)
        
        
        
        
egrep "(sha1sum|sha256sum|sha512sum)" ${AUDIT_FILE}
        
egrep "(apt-key adv)" ${AUDIT_FILE}| sed 's/RUN apt-key adv//g'| sed 's/--keyserver/Key Server:/g' | sed 's/--recv/Key Value:/g'
        
#            GOOD=$("${DIGBINARY}" +short +time=1 $SIGOKDNS)
#            BAD=$("${DIGBINARY}" +short +time=1 $SIGFAILDNS)
        
        
/etc/passwd | egrep -v '^#|^root:|^(\+:\*)?:0:0:::' | cut -d ":" -f1,3 | grep ':0')

grep -v '^#' ${PASSWD_FILE} | cut -d ':' -f3 | sort | uniq -d)


 | egrep -v '^#|/sbin/nologin|/usr/sbin/nologin


## Checking for non unique group ID's in /etc/group"
grep -v '^#' /etc/group | grep -v '^$' | awk -F: '{ print $3 }' | sort | uniq -d)



## Checking password file consistency (pwck)
pwck -q -r 2> /dev/null; echo $?


if [ -f /etc/login.defs ]; then
UID_MIN=$(grep "^UID_MIN" /etc/login.defs | awk '{print $2}')

UID_MIN="1000"; fi

awk -v UID_MIN="${UID_MIN}" -F: '($3 >= UID_MIN && $3 != 65534) || ($3 == 0) { print $1","$3 }' /etc/passwd)


## checking sudoers file (${SUDOERS_FILE}) permissions"
ls -l ${SUDOERS_FILE} | cut -c 2-10

"rw-------" -o "${FIND}" = "rw-rw----" -o "${FIND}" = "r--r-----" ]; then




## Checking PASS_MIN_DAYS option in /etc/login.defs"

grep "^PASS_MIN_DAYS" /etc/login.defs | awk '{ if ($1=="PASS_MIN_DAYS") { print $2 } }')

## Checking PASS_MAX_DAYS option in /etc/login.defs "
grep "^PASS_MAX_DAYS" /etc/login.defs | awk '{ if ($1=="PASS_MAX_DAYS") { print $2 } }')


## checking presence sulogin for single user mode"
egrep "^[a-zA-Z0-9~]+:S:(respawn|wait):/sbin/sulogin" /etc/inittab)
egrep "^su:S:(respawn|wait):/sbin/sulogin" /etc/inittab)

## checking presence sulogin for single user mode"
grep "^SINGLE=/sbin/sulogin" /etc/sysconfig/init)





egrep "^ExecStart=" ${FILE} | grep "sulogin")



grep umask ${FILE} | sed 's/^[ \t]*//' | grep -v "^#" | awk '{ print $2 }'

if [ "${MASK}" = "077" -o "${MASK}" = "027" -o "${MASK}" = "0077" -o "${MASK}" = "0027" ]; then


grep "^UMASK" /etc/login.defs | awk '{ print $2 }'

## Default umask in /etc/login.defs could not be found and defaults usually to 022, which could be more strict like 027



grep "umask" /etc/login.conf | sed 's/#.*//' | sed -E 's/^[[:cntrl:]]//' | grep -v '^$' | awk -F: '{ print $2}' | awk -F= '{ if ($1=="umask") { print $2 }}')

## Umask in /etc/login.conf could be more strict like 027"



## Checking FAILLOG_ENAB option in /etc/login.defs "
grep "^FAILLOG_ENAB" /etc/login.defs | awk '{ if ($1=="FAILLOG_ENAB") { print $2 } }')

## Configure failed login attempts to be logged in /var/log/faillog"



awk '/^domain/ { print $2 }' /etc/resolv.conf)

awk '/^search/ { print $2 }' /etc/resolv.conf)


grep "^options" /etc/resolv.conf | awk '{ print $2 }')



## using domain name from FQDN hostname (${FQDN})"
DOMAINNAME=$(echo ${FQDN} | awk -F. '{print $2}')
                




 # Description : Check PowerDNS authoritative status
grep "^master=yes" ${POWERDNS_AUTH_CONFIG_LOCATION})
grep "^slave=yes" ${POWERDNS_AUTH_CONFIG_LOCATION})


## checking sysctl for kern.domainname"
sysctl -a 2>&1 | grep "^kern.domainname" | awk -F: '{ print $2 }' | sed 's/ //g' | grep -v "^$")


awk '{ print $1, $2 }' /etc/hosts | egrep -v '^(#|$)' | egrep "[a-f0-9]" | sort | ${UNIQBINARY} -d)

egrep -v '^(#|$|^::1\s|localhost)' /etc/hosts | grep -i hostname)

egrep -v '^(#|$)' /etc/hosts | egrep '^(localhost|::1)\s' | grep -w hostname)

getent hosts localhost | awk '{print $1}' | sort | tr -d '\n')



iptables -L 2>&1 | grep fail2ban
## Checking for Fail2ban iptables chain





        SSHOPS="AllowTcpForwarding:NO,LOCAL,YES:=\
                ClientAliveCountMax:2,4,16:<\
                ClientAliveInterval:300,600,900:<\
                Compression:NO,,YES:=\
                FingerprintHash:SHA256,MD5,:=\
                GatewayPorts:NO,,YES:=\
                IgnoreRhosts:YES,,NO:=\
                LoginGraceTime:120,240,480:<\
                LogLevel:VERBOSE,INFO,:=\
                MaxAuthTries:2,4,6:<\
                MaxSessions:2,4,8:<\
                PermitRootLogin:(NO|PROHIBIT-PASSWORD|WITHOUT-PASSWORD),,YES:=\
                PermitUserEnvironment:NO,,YES:=\
                PermitTunnel:NO,,YES:=\
                Port:,,22:!\
                PrintLastLog:YES,,NO:=\
                StrictModes:YES,,NO:=\
                TCPKeepAlive:NO,,YES:=\
                UseDNS:NO,,YES:=\
                VerifyReverseMapping:YES,,NO:=\
                X11Forwarding:NO,,YES:=\
                AllowAgentForwarding:NO,,YES:="


SSHOPS="${SSHOPS} UsePrivilegeSeparation:SANDBOX,YES,NO:=  Protocol:2,,1:="

${SSHOPS} Protocol:2

${SSHOPS} UsePrivilegeSeparation:SANDBOX,YES,NO:="


egrep -i "^AllowUsers" ${SSH_DAEMON_OPTIONS_FILE} | awk '{ print $2 }')

egrep -i "^AllowGroups" ${SSH_DAEMON_OPTIONS_FILE} | awk '{ print $2 }')


echo "[$i] /etc/ssh/sshd_config"
echo $'\n'## Groups allowed to connect$'\n'AllowGroups $SSH_GRPS >> /etc/ssh/sshd_config"
sed -i 's/^LoginGraceTime 120/LoginGraceTime 20/' /etc/ssh/sshd_config
sed -i 's/^PermitRootLogin without-password/PermitRootLogin no/' /etc/ssh/sshd_config
bash -c "echo ClientAliveInterval 900 >> /etc/ssh/sshd_config"
bash -c "echo ClientAliveCountMax 0 >> /etc/ssh/sshd_config"
bash -c "echo PermitUserEnvironment no >> /etc/ssh/sshd_config"
bash -c "echo Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc >> /etc/ssh/sshd_config"
/etc/init.d/ssh restart





## OpenVPN-Virtual-Appliance-Admin-URLS.txt

##-============================================-##
##          Access Server Admin Web UI:
##-============================================-##
https://vmware_appliance_ip_address:943/admin


##-==============================================================-##
## Appliance Management Interface:
##-==============================================================-##
## Use the Appliance Management Interface to reboot, 
## shut down or change the network settings of the appliance.
##-==============================================================-##
https://vmware_appliance_ip_address:5480

##-=======================================-##
##          Client Web Server:
##-=======================================-##
## Use the Admin Web UI to configure 
## the OpenVPN Access Server settings.
##-=======================================-##
https://vmware_appliance_ip_address:5480


make a root cert for signing intermediate CAs:

./certool --dir epki/root --cn "EPKI Root Test" --type ca


Make the intermediate CA:

./certool --dir epki/root --type intermediate --serial 1 --cn "EPKI Intermediate" --name inter
cp epki/root/inter.crt epki/ca.crt
cp epki/root/inter.key epki/ca.key
cat epki/root/ca.crt epki/ca.crt >epki/cabundle.crt

Make a certificate/key pair for the OpenVPN server:

./certool --dir epki --type server --serial 1 --cn server

Make a tls_auth key for the OpenVPN server:

./certool --dir epki --tls_auth

Generate Diffie Hellman parameters for the OpenVPN server:

openssl dhparam -out epki/dh.pem 2048


Load the files we just generated into the Access Server config database:

./confdba -mk external_pki.ta_key --value_file epki/ta.key
./confdba -mk external_pki.ca_crt --value_file epki/cabundle.crt
./confdba -mk external_pki.server_crt --value_file epki/server.crt
./confdba -mk external_pki.server_key --value_file epki/server.key
./confdba -mk external_pki.dh_pem --value_file epki/dh.pem

Configure remote certificate usage to netscape ("ns"):

./confdba -mk external_pki.remote_cert_usage -v ns

Configure use of the X509 "role" attribute for declaration of auto-login permission:

./confdba -mk external_pki.autologin_x509_spec -v "role,,AUTOLOGIN"


certool will generate the file epki/etest.p12 which contains the cert/key pair:

./certool --dir epki --type client --serial 2 --cn etest --cabundle epki/cabundle.crt --pkcs12 --prompt


generate an autologin cert/key pair for etest. The generated cert/key will be in the file epki/etestauto.p12:

./certool --dir epki --type client --serial 3 --cn etest --name etestauto --cabundle epki/cabundle.crt --pkcs12 --prompt role=AUTOLOGIN
./sacli --user etest --key prop_autologin --value true UserPropPut


Make a tls_auth key for the OpenVPN server and load it into the Access Server configuration:

cd /usr/local/openvpn_as/scripts
mkdir epki
./certool --dir epki --tls_auth
./confdba -mk external_pki.ta_key --value_file epki/ta.key

Generate Diffie Hellman parameters for the OpenVPN server and load them into the Access Server configuration:

openssl dhparam -out epki/dh.pem 2048
./confdba -mk external_pki.dh_pem --value_file epki/dh.pem


import the CA certificate, server certificate, and server private key (all specified in PEM format) into the Access Server:

./confdba -mk external_pki.ca_crt --value_file <CA_CERT_BUNDLE>
./confdba -mk external_pki.server_crt --value_file <SERVER_CERT_FILE>
./confdba -mk external_pki.server_key --value_file <SERVER_PRIVATE_KEY_FILE>


Netscape certificate type (a netscape de-facto standard that is well-supported, but shunned by purists). Configure as follows:

    ./confdba -mk external_pki.remote_cert_usage -v ns

    X509 explicit/extended key usage based on RFC3280 TLS rules. Configure as follows:

    ./confdba -mk external_pki.remote_cert_usage -v eku



enable split CA mode:

./confdba -mk external_pki.remote_cert_usage -v split

Next, replace the following line (from above):

./confdba -mk external_pki.ca_crt --value_file <CA_CERT_BUNDLE>

with:

./confdba -mk external_pki.server_ca_crt --value_file <SERVER_CA_CERT_BUNDLE>
./confdba -mk external_pki.client_ca_crt --value_file <CLIENT_CA_CERT_BUNDLE>



disabling the external_pki.cn_username_requirement boolean key:

./sacli -k external_pki.cn_username_requirement -v false ConfigPut


set the store to "both":

./sacli --user __DEFAULT__ --key cli_cert_store --value "both" UserPropPut












create a private key and certificate signing request (4096 bits SHA256):
openssl req -out server.csr -new -newkey rsa:4096 -sha256 -nodes -keyout server.key

Decrypt a passphrase protected private key with OpenSSL:

openssl rsa -in server.key -out decrypted.key


cd /usr/local/openvpn_as/scripts/
./certool -d /usr/local/openvpn_as/etc/web-ssl --type ca --unique --cn "OpenVPN Web CA"
./certool -d /usr/local/openvpn_as/etc/web-ssl --type server --remove_csr --sn_off --serial 1 --name server --cn vpn.exampletronix.com
./sacli start

cd /usr/local/openvpn_as/scripts/
./sacli --key "cs.priv_key" ConfigDel
./sacli --key "cs.ca_bundle" ConfigDel
./sacli --key "cs.cert" ConfigDel
./sacli start


To set the interface name that the OpenVPN daemons should listen on:

./sacli --key "vpn.daemon.0.server.ip_address" --value <INTERFACE> ConfigPut
./sacli --key "vpn.daemon.0.listen.ip_address" --value <INTERFACE> ConfigPut
./sacli start

To set a specific port for the UDP OpenVPN daemons:

./sacli --key "vpn.server.daemon.udp.port" --value <PORT_NUMBER> ConfigPut
./sacli start

To set a specific port for the TCP OpenVPN daemons:

./sacli --key "vpn.server.daemon.tcp.port" --value <PORT_NUMBER> ConfigPut
./sacli start

To restore the default so it listens to all interfaces and ports TCP 443 and UDP 1194:

./sacli --key "vpn.daemon.0.server.ip_address" --value "all" ConfigPut
./sacli --key "vpn.daemon.0.listen.ip_address" --value "all" ConfigPut
./sacli --key "vpn.server.daemon.udp.port" --value "1194" ConfigPut
./sacli --key "vpn.server.daemon.tcp.port" --value "443" ConfigPut
./sacli start


To disable multi-daemon mode and use only 1 TCP daemon:

./sacli --key "vpn.server.daemon.enable" --value "false" ConfigPut
./sacli --key "vpn.daemon.0.listen.protocol" --value "tcp" ConfigPut
./sacli --key "vpn.server.port_share.enable" --value "true" ConfigPut
./sacli start

To disable multi-daemon mode and use only 1 UDP daemon:

./sacli --key "vpn.server.daemon.enable" --value "false" ConfigPut
./sacli --key "vpn.daemon.0.listen.protocol" --value "udp" ConfigPut
./sacli --key "vpn.server.port_share.enable" --value "false" ConfigPut
./sacli start


Restore the default of using multi-daemon mode, with the amount of processes same as CPU cores (recommended):

./sacli --key "vpn.server.daemon.enable" --value "true" ConfigPut
./sacli --key "vpn.daemon.0.listen.protocol" --value "tcp" ConfigPut
./sacli --key "vpn.server.port_share.enable" --value "true" ConfigPut
./sacli --key "vpn.server.daemon.tcp.n_daemons" --value "`./sacli GetNCores`" ConfigPut
./sacli --key "vpn.server.daemon.udp.n_daemons" --value "`./sacli GetNCores`" ConfigPut
./sacli start


Reset web services, service forwarding, and OpenVPN daemons to default ports and listen on all interfaces:

./sacli --key "admin_ui.https.ip_address" --value "all" ConfigPut
./sacli --key "admin_ui.https.port" --value "943" ConfigPut
./sacli --key "cs.https.ip_address" --value "all" ConfigPut
./sacli --key "cs.https.port" --value "943" ConfigPut
./sacli --key "vpn.server.port_share.enable" --value "true" ConfigPut 
./sacli --key "vpn.server.port_share.service" --value "admin+client" ConfigPut
./sacli --key "vpn.daemon.0.server.ip_address" --value "all" ConfigPut
./sacli --key "vpn.daemon.0.listen.ip_address" --value "all" ConfigPut
./sacli --key "vpn.server.daemon.udp.port" --value "1194" ConfigPut
./sacli --key "vpn.server.daemon.tcp.port" --value "443" ConfigPut
./sacli start


Change maximum amount of active incoming VPN tunnels:

./sacli --key "vpn.server.max_clients" --value <NUMBER> ConfigPut
./sacli start

On the primary node adjust the VHID:

./sacli --key "ucarp.vhid" --value <NUMBER> ConfigPut
service openvpnas restart


Define extra parameters for Access Server to pass to UCARP:

./sacli --key "ucarp.extra_parms" --value <PARAMETERS> ConfigPut
service openvpnas restart


Override up/down scripts with new scripts (make sure to create them of course):

./sacli --key "ucarp.extra_parms" --value "--upscript /root/up --downscript /root/down" ConfigPut
service openvpnas restart

And to revert to the default scripts:

./sacli --key "ucarp.extra_parms" ConfigDel
service openvpnas restart


Disable NAT for outgoing public traffic (enabled by default):

./sacli --key "vpn.server.nat" --value "false" ConfigPut
./sacli start

Re-enable NAT (restore default):

./sacli --key "vpn.server.nat" ConfigDel
./sacli start

Specify interface/address for outgoing NAT:

./sacli --key "vpn.server.routing.snat_source.N" <INTERFACE-ADDRESS>
./sacli start


For example NAT eth2 traffic via 1.2.3.4:

./sacli --key "vpn.server.routing.snat_source.0" --value "eth2:1.2.3.4" ConfigPut
./sacli start

Or NAT eth0 traffic via the eth0:4 address:

./sacli --key "vpn.server.routing.snat_source.0" --value "eth0:4" ConfigPut
./sacli start

Or NAT ens192 traffic using a range of public IPs from 76.49.27.18 to 76.49.27.22:

./sacli --key "vpn.server.routing.snat_source.0" --value "ens192:76.49.27.18:76.49.27.22" ConfigPut
./sacli start

Multiple rules can be specified for multiple interfaces, for example:

./sacli --key "vpn.server.routing.snat_source.0" --value "eth0:76.49.27.18:76.49.27.22" ConfigPut
./sacli --key "vpn.server.routing.snat_source.1" --value "eth1:3" ConfigPut
./sacli start


To make Access Server add rules after existing ones (append instead of prepend):

./sacli --key "iptables.append" --value "True" ConfigPut
./sacli start

Restore default behavior:

./sacli --key "iptables.append" ConfigDel
./sacli start


Example for disabling one of the three above settings:

./sacli --key "iptables.vpn.disable.filter" --value "True" ConfigPut
./sacli start

Restoring the value to its default:

./sacli --key "iptables.vpn.disable.filter" ConfigDel
./sacli start


Switch to Layer 2 bridging mode:

./sacli --key "vpn.general.osi_layer" --value "2" ConfigPut
./sacli start

Restore to Layer 3 routing mode:

./sacli -key "vpn.general.osi_layer" ConfigDel
./sacli start


Enable UDP multicast and IGMP traffic passthrough:

./sacli --key "vpn.routing.allow_mcast" --value "true" ConfigPut
./sacli start

Restore the default setting:

./sacli --key "vpn.routing.allow_mcast" ConfigDel
./sacli start




    iptables -A INPUT -i tap0 -j ACCEPT
    iptables -A INPUT -i br0 -j ACCEPT
    iptables -A FORWARD -i br0 -j ACCEPT







## Create a crontab entry that updates your hosts file every night at midnight:
crontab -e

0 0 * * * wget https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts -O /etc/hosts



https://github.com/StevenBlack/hosts





generate 10 new credentials:

sudo yhsm-generate-keys -D /etc/yubico/yhsm/keys.json --key-handle 1 --start-public-id interncccccc -c 10


We now have 10 randomly generated credentials which are encrypted and stored in /var/cache/yubikey-ksm/aeads/1/

## decrypt one of them and program a YubiKey with it:
sudo yhsm-decrypt-aead --aes-key 000102030405060708090a0b0c0d0e0f --key-handle 1 --format yubikey-csv /var/cache/yubikey-ksm/aeads/


The output lists all 10 of our YubiKey credentials in decrypted form. 


## We pick one of the credentials and program a YubiKey with it. 
## In my case, one of the credentials looked like this:
8,interncccccc,9949741dc5c7,60d82797fbcab4c0ef08e79cfdc54a94,000000000000,,,,,,


## The relevant parts are:
Public ID: interncccccc
Private ID: 9949741dc5c7
Secret AES Key: 60d82797fbcab4c0ef08e79cfdc54a94


## use ykpersonalize to program a YubiKey with the credential:
ykpersonalize -1 -ofixed=interncccccc -ouid=9949741dc5c7 -a60d82797fbcab4c0ef08e79cfdc54a94


## The KSM is correctly decrypting OTPs from the YubiKey.
curl http://localhost:8002/wsapi/decrypt?otp=interncccccctkbngftibfuvvbihrdjguvnrcdihejut
OK counter=0001 low=5d6e high=cb use=00


## Testing the Validation server
curl "http://localhost/wsapi/2.0/verify?id=1&nonce=0123456789abcdef&otp=internccccccvunvcnjucfjefvfkbbjunhutdhucbclt"
h=WLaajHlUqayhltxLgT8uIy/Wza0=
t=2016-10-31T15:07:44Z0785
otp=internccccccvunvcnjucfjefvfkbbjunhutdhucbclt
nonce=0123456789abcdef
sl=0
status=OK





## generate more client ID’s using the ykval-gen-clients command:
ykval-gen-clients --urandom 5


## export existing clients by using the ykval-export-clients command:
sudo ykval-export-clients


yubico-piv-tool --full-help

yubico-piv-tool --action=

yubico-piv-tool --action=generate
yubico-piv-tool --action=set-mgm-key
yubico-piv-tool --action=import-key
yubico-piv-tool --action=import-certificate
yubico-piv-tool --action=request-certificate
yubico-piv-tool --action=set-chuid
yubico-piv-tool --action=
yubico-piv-tool --action=
yubico-piv-tool --action=
yubico-piv-tool --action=
yubico-piv-tool --action=
yubico-piv-tool --action=
yubico-piv-tool --action=
yubico-piv-tool --action=
yubico-piv-tool --action=
yubico-piv-tool --action=



--algorithm=RSA2048
--algorithm=RSA4096

--hash=SHA512
--hash=SHA256


--key-format=PEM
--key-format=PKCS12
--key-format=DER
--key-format=SSH

--password=

## The subject to use for certificate request
## The subject must be written as: /CN=host.example.com/OU=test/O=example.com/
--subject=


## Serial number of the self-signed certificate
--serial=

## Time (in days) until the self-signed certificate expires (default=‘365’)
--valid-days=





	

## Format of data for write/read object (possible values="hex", "base64", "binary" default=‘hex’)
--format=$ENUM


## Generate a new ECC-P256 key on device in slot 9a, will print the public key on stdout:
yubico-piv-tool -s9a -AECCP256 -agenerate


## Generate a certificate request with public key from stdin
yubico-piv-tool -s9a -S'/CN=foo/OU=test/O=example.com/' -averify -arequest


## Generate a self-signed certificate with public key from stdin
yubico-piv-tool -s9a -S'/CN=bar/OU=test/O=example.com/' -averify -aselfsign


## Import a certificate from stdin:
yubico-piv-tool -s9a -aimport-certificate


## Set a random chuid, import a key and import a certificate from a PKCS12 file, into slot 9c:
yubico-piv-tool -s9c -itest.pfx -KPKCS12 -aset-chuid -aimport-key -aimport-cert

## Import a certificate which is larger than 2048 bytes and thus requires compression in order to fit:

openssl x509 -in cert.pem -outform DER | gzip -9 > der.gz
yubico-piv-tool -s9c -ider.gz -KGZIP -aimport-cert

## Change the management key used for administrative authentication:
yubico-piv-tool -aset-mgm-key

## Delete a certificate in slot 9a, with management key being asked for:
yubico-piv-tool -adelete-certificate -s9a -k

## Show some information on certificates and other data:
yubico-piv-tool -astatus

## Read out the certificate from a slot and then run a signature test:
yubico-piv-tool -aread-cert -s9a
yubico-piv-tool -averify-pin -atest-signature -s9a

## Import a key into slot 85 (only available on YubiKey 4) 
## set the touch policy (also only available on YubiKey 4):
yubico-piv-tool -aimport-key -s85 --touch-policy=always -ikey.pem






#Configure Yubikey
sudo ykpersonalize -2 -ochal-resp -ochal-hmac -ohmac-lt64 -oserial-api-visible


touch /etc/pam.d/yubikey
    echo "auth [success=1 default=ignore] pam_succeed_if.so quiet user notingroup yubikey" | sudo tee --append /etc/pam.d/yubikey
    echo "auth required pam_yubico.so mode=challenge-response chalresp_path=/var/yubico" | sudo tee --append /etc/pam.d/yubikey


#Modify PAM Common Auth to Reference Yubikey PAM
sudo sed -i '3s/^/@include yubikey\n/' /etc/pam.d/common-auth


#Set Current User up for Yubikey (securely)
ykpamcfg -2 -v




#Setup USB (Yubikey) permissions
#wget "https://raw.githubusercontent.com/Yubico/yubikey-personalization/master/69-yubikey.rules" -O /tmp/69-yubikey.rules
#wget "https://raw.githubusercontent.com/Yubico/yubikey-personalization/master/70-yubikey.rules" -O /tmp/70-yubikey.rules

#sudo mv /tmp/69-yubikey.rules /etc/udev/rules.d/69-yubikey.rules
#sudo mv /tmp/70-yubikey.rules /etc/udev/rules.d/70-yubikey.rules







SQUID_DAEMON_CONFIG_LOCS="/etc /etc/squid /etc/squid3 /usr/local/etc/squid /usr/local/squid/etc"
    
    


## Check running processes
${PSBINARY} ax | egrep "(squid|squid3) " | grep -v "grep"



## check if a setuid/setgid bit is found
${FINDBINARY} ${SQUIDBINARY} \( -perm 4000 -o -perm 2000 \) -print)


## Checking all specific defined options in ${SQUID_DAEMON_CONFIG}"
grep -v "^#" ${SQUID_DAEMON_CONFIG} | grep -v "^$" | awk '{gsub("\t"," ");print}' | sed 's/ /!space!/g')


${SQUID_DAEMON_CONFIG} -type f -a \( -perm -004 -o -perm -002 -o -perm -001 \))

## Result: file ${SQUID_DAEMON_CONFIG} is world readable, writable or executable and could leak information or passwords"


grep "^auth_param" ${SQUID_DAEMON_CONFIG} | awk '{ print $2 }')

## Description : Check external Squid authentication
grep "^external_acl_type" ${SQUID_DAEMON_CONFIG}

## Report "squid_external_acl_type=TRUE"


## checking ACLs
grep "^acl " ${SQUID_DAEMON_CONFIG} | sed 's/ /!space!/g')

$(echo ${ITEM} | sed 's/!space!/ /g')
## Found ACL: ${ITEM}
## Report "squid_acl=${ITEM}"


## checking ACL Safe_ports http_access option"
grep "^http_access" ${SQUID_DAEMON_CONFIG} | grep "Safe_ports")


## Check if Squid has been configured to restrict access to all safe ports"
## Checking ACL 'Safe_ports' http_access option
## checking ACL safe ports"
grep "^acl Safe_ports port" ${SQUID_DAEMON_CONFIG} | awk '{ print $4 }')

grep -w "^acl Safe_ports port ${ITEM}" ${SQUID_DAEMON_CONFIG})


## Checking ACL 'Safe_ports' (port ${ITEM})"


# Description : Check reply_body_max_size value
## checking option reply_body_max_size
grep "^reply_body_max_size " ${SQUID_DAEMON_CONFIG} | sed 's/ /!space!/g')


## Configure Squid option reply_body_max_size to limit the upper size of requests."

grep "^httpd_suppress_version_string " ${SQUID_DAEMON_CONFIG} | grep " on")






## After booting into REMnux and making sure that it has Internet access, 
## run the following command to install SIFT on it:
wget --quiet -O - https://raw.github.com/sans-dfir/sift-bootstrap/master/bootstrap.sh | sudo bash -s -- -

## Install Sift (I installed v3)
wget quiet -O https://raw.github.com/sans-dfir/sift-bootstrap/master/bootstrap.sh | sudo bash

## Install REMnux
wget --quiet -O https://remnux.org/get-remnux.sh | sudo bash

wget --quiet -O - https://remnux.org/get-remnux.sh | sudo bash



echo postfix postfix/main_mailer_type select Internet Site | debconf-set-selections
echo postfix postfix/mailname string `hostname -f` | debconf-set-selections









dd if=/dev/zero of=./crypto.img bs=1M count=512
losetup /dev/loop1 ./crypto.img



## import the public GPG key that is used to sign the packages:
wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg|apt-key add -


echo "deb http://build.openvpn.net/debian/openvpn/<version> <osrelease> main" > /etc/apt/sources.list.d/openvpn-aptrepo.list

echo "deb http://build.openvpn.net/debian/openvpn/testing jessie main" > /etc/apt/sources.list.d/openvpn-aptrepo.list

echo "deb http://build.openvpn.net/debian/openvpn/release/2.3 wheezy main" > /etc/apt/sources.list.d/openvpn-aptrepo.list


apt-key list

/etc/apt/trusted.gpg
--------------------
pub   2048R/E158C569 2011-08-03 [expires: 2020-07-25]
uid                  Samuli Seppänen (OpenVPN Technologies, Inc) <samuli@openvpn.net>
sub   2048R/F5699905 2011-08-03 [expires: 2020-07-25]


https://community.openvpn.net/openvpn/wiki/AllFileSignatures
https://openvpn.net/index.php/open-source/documentation/sig.html

Security mailing list GPG key:
https://swupdate.openvpn.net/community/keys/security-key-2018.asc

Fingerprint F554 A368 7412 CFFE BDEF E0A3 12F5 F7B4 2F2B 01E7


List of all signing keys

Here's a complete list of the GPG signing keys:

    James Yonan's PGP key (for 1.5.0 -> 2.3_alpha1, key ID 1FBF51F3, fingerprint C699 B264 0C6D 404E 6454 A9AD 1D0B 4996 1FBF 51F3)
    Samuli Seppänen's old PGP key (2.3_alpha2 and later, key ID 198D22A3, fingerprint 0330 0E11 FED1 6F59 715F 9996 C29D 97ED 198D 22A3)
    Samuli Seppänen's new PGP key (2,3.15 Windows installers, 2.4.1, 2.4.2: key ID 40864578 , fingerprint 6D04 F8F1 B017 3111 F499 795E 2958 4D9F 4086 4578)
    Security mailing list GPG key (2.3.15 tarballs, 2.3.16+, 2.4.3+, key ID 2F2B01E7, fingerprint F554 A368 7412 CFFE BDEF E0A3 12F5 F7B4 2F2B 01E7) 

















































































echo "[$i] Aide"
sed -i 's/^Checksums =.*/Checksums = sha512/' /etc/aide/aide.conf









































        
        
        
        
        
        
        
        
        
        
        
        
        













echo "[$i] Blacklisting kernel modules"
echo >> /etc/modprobe.d/blacklist.conf
for mod in dccp sctp rds tipc net-pf-31 bluetooth usb-storage;
do 
	echo install $mod /bin/false >> /etc/modprobe.d/blacklist.conf
done
























































https://github.com/netblue30/firetunnel

https://github.com/dyne/tinfoil

https://github.com/drduh/YubiKey-Guide

