#!/usr/bin/env bash
#
# We assume the system is installed with:
# 
# 1. Minimal software
# 2. No root user login
# 3. The following partitions:
#	   /
#	   /boot
#	   /home
#	   /var
#	   /var/log
#	   /var/log/audit 
#	   /var/tmp
#	   swap
# 4. Completely stock install. No configuration after installation
# 5. No security profiles installed.
# 6. The machine will be administered by a subnet under the subdomain `admin`
#    in the same general domain as this machine.*
# 7. The gateway has a fqdn in both this and the admin subdomains with the same
#    short host name.*
#
# * Only the `ADMIN_NET=` line depends on these. Feel free to override it.


set -euxo pipefail

################################################################################
### CONFIGURATION PARAMETERS ###################################################
################################################################################

## Email Alerts

# using gmail as an example
declare SMTP_SERVER=smtp.gmail.com
declare SMTP_PORT=587
declare SMTP_ACCOUNT= #myself@gmail.com
declare SMTP_PASSWD= #thepassword
declare RECIPIENT="${SMTP_ACCOUNT}" #or use separate accounts for sending and receiving alerts

## Optional (1 is yes)

declare INSTALL_COCKPIT=1
declare INSTALL_NETDATA=1


################################################################################
### INITIAL SNAPSHOT ###########################################################
################################################################################

## Tagging Volumes
declare VG=$(sudo vgs -o vg_name --no-headings)

# os partitions
sudo lvchange \
  --addtag "local" \
  --addtag "os" \
  ${VG}/root
sudo lvchange \
  --addtag "local" \
  --addtag "os" \
  ${VG}/var
sudo lvchange \
  --addtag "local" \
  --addtag "os" \
  ${VG}/var_tmp

# log partitions
sudo lvchange \
  --addtag "local" \
  --addtag "log" \
  ${VG}/var_log
sudo lvchange \
  --addtag "local" \
  --addtag "log" \
  ${VG}/var_log_audit

# user storage
sudo lvchange \
  --addtag "local" \
  --addtag "user" \
  ${VG}/home

# swap
sudo lvchange --addtag "local" \
  ${VG}/swap

unset VG

## Taking Snapshot

# if centos
! grep -q "NAME=Fedora" /etc/os-release &&
{ # tags
  TIMESTAMP="$(date +"%Y-%m-%d-%H-%M-%S")"
  KERNEL="$(uname -r)"
  DESCRIPTION="initial_snapshot"

  # take the snapshots
  while read -r LV; do
    sudo lvcreate -s -l 50%ORIGIN \
      --addtag "${TIMESTAMP}" \
      -n "${LV##*/}_${TIMESTAMP}" \
      "${LV}"
  done <<< "$(sudo lvs --noheadings -o lv_path @os)"

  sudo lvchange \
    --addtag "local" \
    --addtag "os" \
    --addtag "${KERNEL}" \
    --addtag "${DESCRIPTION}" \
    "@${TIMESTAMP}"

  # clean up
  unset LV TIMESTAMP KERNEL DESCRIPTION
} ||
grep -q "NAME=Fedora" /etc/os-release


################################################################################
### HOST NAME ##################################################################
################################################################################

# register short hostname and FQDN in /etc/hosts
sudo cp -a /etc/hosts \
  /etc/.hosts.default~

printf "$(hostname -i |
  grep -o "[0-9]\{1,3\}\(\.[0-9]\{0,3\}\)\{3\}")\t$(hostname -f) $(hostname -s)\n" |
  sudo tee -a /etc/hosts >/dev/null

# this is necessary for some reason as systemd is defiantly attached to
# `localhost`
sudo hostnamectl set-hostname "$(hostname -f)"


################################################################################
### PACKAGE MANAGER ############################################################
################################################################################

# dnf config
sudo cp -a /etc/dnf/dnf.conf \
  /etc/dnf/.dnf.conf.default~
sudo sed -i -E 's/(installonly_limit=)3/\110/' \
  /etc/dnf/dnf.conf
echo "deltarpm=1" |
  sudo tee -a /etc/dnf/dnf.conf >/dev/null
echo "repo_gpgcheck=1" |
  sudo tee -a /etc/dnf/dnf.conf >/dev/null
echo "localpkg_gpgcheck=1" |
  sudo tee -a /etc/dnf/dnf.conf >/dev/null

grep -q "NAME=Fedora" /etc/os-release || #no epel on fedora
{ # epel
  sudo dnf -yq install epel-release &&

  # epel doesn't support gpg signed metadata, also, it is problematic to make a
  # backup of the default config here, so we don't
  sudo sed -i -E "s/(^enabled=[0,1]$)/\1\nrepo_gpgcheck=0/g" \
    /etc/yum.repos.d/epel*
}

sudo dnf -yq check-update ||
[ $? == 100 ] #exits 100 when updates are available

# update
sudo dnf -yq update

# automatic security updates
sudo dnf -yq install dnf-automatic
sudo systemctl enable dnf-automatic.timer

sudo cp -a /etc/dnf/automatic.conf \
  /etc/dnf/.automatic.conf.default~
sudo sed -i -E 's/(apply_updates = )no/\1yes/' \
  /etc/dnf/automatic.conf
sudo sed -i -E 's/(upgrade_type = )default/\1security/' \
  /etc/dnf/automatic.conf
sudo sed -i -E 's/(random_sleep = )0/\13600/' \
  /etc/dnf/automatic.conf
sudo sed -i -E 's/(emit_via = )stdio/\1command_email/' \
  /etc/dnf/automatic.conf
sudo sed -i -E 's/(email_from = )root@example.com/\1dnf/' \
  /etc/dnf/automatic.conf

sudo systemctl start dnf-automatic.timer


################################################################################
### EMAIL ALERTS ###############################################################
################################################################################

# using gmail as an example
# SMTP_SERVER= #smtp.gmail.com
# SMTP_PORT= #587
# SMTP_ACCOUNT= #myself@gmail.com
# SMTP_PASSWD= #thepassword
# RECIPIENT="${SMTP_ACCOUNT}" #or use separate accounts for sending and receiving alerts

# install postfix
sudo dnf -yq install postfix cyrus-sasl-plain
sudo systemctl enable postfix

# configure smtp credentials
sudo touch /etc/postfix/sasl_passwd
sudo chmod 600 /etc/postfix/sasl_passwd
echo "[${SMTP_SERVER}]:${SMTP_PORT} ${SMTP_ACCOUNT}:${SMTP_PASSWD}" |
  sudo tee /etc/postfix/sasl_passwd >/dev/null
sudo postmap /etc/postfix/sasl_passwd

# configure `postfix`
sudo cp -a /etc/postfix/main.cf \
  /etc/postfix/.main.cf.default~
sudo sed -i -E "s/(^inet_interfaces = ).*/\1$(hostname)/" \
  /etc/postfix/main.cf
sudo sed -i -E "s/(^inet_protocols = ).*/\1ipv4/" \
  /etc/postfix/main.cf
echo "relayhost = [${SMTP_SERVER}]:${SMTP_PORT}
smtp_use_tls = yes
smtp_sasl_auth_enable = yes
smtp_sasl_security_options = noanonymous
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd" |
  sudo tee -a /etc/postfix/main.cf >/dev/null

# by default, postfix will come up before we have an IP and will fail if `inet_interfaces` is set to anything but `all
# this is the fix per https://bugs.centos.org/view.php?id=13323
sudo mkdir /usr/lib/systemd/system/postfix.service.d
echo "[Unit]
After=network-online.target" |
  sudo tee /usr/lib/systemd/system/postfix.service.d/online.conf >/dev/null
sudo systemctl daemon-reload

# configure aliases
sudo cp -a /etc/aliases \
  /etc/.aliases.default~
echo "root: $(whoami)
$(whoami): ${RECIPIENT}" |
  sudo tee -a /etc/aliases >/dev/null
sudo newaliases

# start postfix
sudo systemctl start postfix

# send test alert
echo "Subject: $(hostname -f) - Email Alerts Configured
$(hostname -f) has been configured to send email alerts to this address." |
  sendmail -F "Alert" root

# clean up
unset SMTP_SERVER SMTP_PORT SMTP_ACCOUNT SMTP_PASSWD RECIPIENT


################################################################################
### BOOT LOADER ################################################################
################################################################################

## Install Bootloader to All RAID Members

# install grub to all drives in `/boot` mdraid
[ -d /sys/block/md ] &&
{ # loop through boot drives and install grub
  while read -r BOOT_DRIVE; do
    sudo grub2-install "${BOOT_DRIVE}"
  done <<< "$(sudo mdadm -QD \
                "$(mount | grep "/boot" | awk '{ print $1 }')" |
                tail -n +2 |
                grep -o "/dev/[[:alpha:]]*")"

  # clean up
  unset BOOT_DRIVE
} || [ ! -d /sys/block/md ] # allow to fail if no mdraid is present

## Harden Grub

# generate random username
sudo dnf -yq install words
GRUB_USER="$(shuf -n 1 /usr/share/dict/words | tr [A-Z] [a-z])"
GRUB_PW="$(shuf -n 3 /usr/share/dict/words | tr '\n' '-' | sed 's/-$//')"

# set username and password for grub config
sudo sed -i s/root/"${GRUB_USER}"/g /etc/grub.d/01_users #or whatever username
sudo dnf -yq install expect
sudo expect -c "spawn grub2-setpassword
expect \"word:\"
exp_send \"${GRUB_PW}\\r\"
expect \"word:\"
exp_send \"${GRUB_PW}\\r\""
sudo grub2-mkconfig -o "/etc/$(readlink /etc/grub2.cfg)" #for bios booting
sudo grub2-mkconfig -o "/etc/$(readlink /etc/grub2-efi.cfg)" || : #for efi booting

echo "==========================================================================
=== GRUB CREDENTIALS =====================================================
==========================================================================
= USER: ${GRUB_USER}
= PASSWORD: ${GRUB_PW}
=
= Credentials will be displayed again up completion of onboarding.
=========================================================================="


################################################################################
### STORAGE ####################################################################
################################################################################

## Schedule RAID Scrubbing

[ -d /sys/block/md ] &&
{ # write cron script
  echo '#!/usr/bin/env bash

  for MD in /sys/block/md*; do
    echo "check" > "${MD}/md/sync_action"
    [ cat "${MD}/md/mismatch_cnt -gt 0 ] &&
      echo "Subject: $(hostname -f) - MD RAID Corruption
  $(cat ${MD}/md/mismatch_cnt) mismatches found on ${MD}." |
    sendmail -F "mdraid" root
  done' |
    sudo tee /etc/cron.weekly/md_scrub >/dev/null

  # make it executable
  sudo chmod +x /etc/cron.weekly/md_scrub
} || [ ! -d /sys/block/md ]

## Install and Configure SMART Monitoring

# install smartmontools
sudo dnf -yq install smartmontools
sudo systemctl enable smartd

# configure short test between 1-2AM daily
# and long test between 3-4AM Saturdays on all SMART-enabled drives
sudo cp -a /etc/smartmontools/smartd.conf \
  /etc/smartmontools/.smartd.conf.default~
echo "DEVICESCAN -a -o on -S on -n standby,q -s (S/../.././01|L/../../6/03) -W 4,35,40 -m root" |
  sudo tee -a /etc/smartmontools/smartd.conf >/dev/null

# enable and start smartd
sudo systemctl start smartd

## Harden Mount Options

# add nosuid and nodev options to /home
sudo sed -i -E "s/(\/home.*)defaults/\1nosuid,nodev/" \
  /etc/fstab

# systemd should be made aware of this change
sudo systemctl daemon-reload

# remount to apply new options
sudo mount -o remount /home

## Disable USB Storage

# disable usb-storage in running config
sudo modprobe -r usb-storage

# prevent it from being loaded at boot
echo "install usb-storage /bin/true" |
  sudo tee /etc/modprobe.d/usb-storage.conf >/dev/null


################################################################################
### NETWORK ####################################################################
################################################################################

sudo dnf -yq install bind-utils

echo "net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0" |
  sudo tee -a /etc/sysctl.d/99-sysctl.conf >/dev/null

sudo sysctl --system >/dev/null


################################################################################
### TIME #######################################################################
################################################################################

sudo cp -a /etc/chrony.conf \
  /etc/.chrony.conf.default~
sudo sed -i "s/ maxpoll [0-9]*//g" \
  /etc/chrony.conf
sudo sed -i "s/^server .*/& maxpoll 10/g" \
  /etc/chrony.conf

sudo systemctl restart chronyd


################################################################################
### FIREWALL ###################################################################
################################################################################

# name zone after lowest domain level
declare ZONE="$(hostname -d | cut -d '.' -f 1)"

# use interface associated with the fqdn -- fqdn must be resolving properly
declare FQDN_INTERFACE="$(nmcli -g GENERAL.DEVICE,IP4.ADDRESS device show |
            grep -B 1 \
              "$(host -4 -t A "$(hostname -f)" |
                awk '{ print $NF }')" |
                head -n 1)"

# reverse dns lookup the default gateway to find short hostname of the gateway
# lookup the ip of the gateway on the admin subdomain
# set the variable to the /24 of that ip
declare ADMIN_NET="$(host \
  "$(host $(ip route |
        grep default |
        awk '{ print $3 }') |
      head -n 1 |
      awk '{ print $NF }' |
      cut -d "." -f 1).admin.$(hostname -d |
        sed 's/^[[:alnum:]]*\.//')" |
    awk '{ print $NF }' |
    sed 's/[[:digit:]]*$//')0/24"
    
# we'll create our own zone that corresponds to our vlan/subnet config
sudo firewall-cmd --permanent --new-zone="${ZONE}"
sudo firewall-cmd --permanent --zone="${ZONE}" \
  --set-short="Server Default Gateway"
sudo firewall-cmd --permanent --zone="${ZONE}" \
  --set-description="The server's default gateway provides services and management access."
sudo firewall-cmd --permanent --zone="${ZONE}" \
  --set-target=DROP

# allow ssh and ping from admin subnet
sudo firewall-cmd --permanent --zone="${ZONE}" \
  --add-rich-rule="rule family=ipv4 source address=${ADMIN_NET} service name=ssh accept"
sudo firewall-cmd --permanent --zone="${ZONE}" \
  --add-rich-rule="rule family=ipv4 source address=${ADMIN_NET} icmp-type name=echo-request accept"

# add interface associated with the server's fqdn to the new zone
sudo firewall-cmd --permanent --zone="${ZONE}" \
  --add-interface="${FQDN_INTERFACE}"

# default zone for new interfaces should be `drop`
sudo firewall-cmd --set-default-zone=drop

# apply changes
sudo firewall-cmd --complete-reload


################################################################################
### ANTIVIRUS ##################################################################
################################################################################

# install and enable
sudo dnf -yq install clamd clamav clamav-update
sudo systemctl enable clamd@scan

# archive default configs
sudo cp -a /etc/freshclam.conf \
  /etc/.freshclam.conf.default~
sudo cp -a /etc/sysconfig/freshclam \
  /etc/sysconfig/.freshclam.default~
sudo cp -a /etc/clamd.d/scan.conf \
  /etc/clamd.d/.scan.conf.default~

# configure freshclam
sudo sed -i -E 's/#(LogFileMaxSize[[:space:]]).*/\12M/' \
  /etc/freshclam.conf
sudo sed -i -E 's/#(LogTime[[:space:]]).*/\1yes/' \
  /etc/freshclam.conf
sudo chgrp -R virusgroup /var/lib/clamav
sudo chmod g+s /var/lib/clamav

# configure scan
sudo sed -i -E 's/(^Example)/#\1/' \
  /etc/clamd.d/scan.conf
sudo sed -i -E 's/#(LogFile[[:space:]]).*/\1\/var\/log\/clamd.scan/' \
  /etc/clamd.d/scan.conf
sudo sed -i -E 's/#(LogFileMaxSize[[:space:]]).*/\12M/' \
  /etc/clamd.d/scan.conf
sudo sed -i -E 's/#(LogTime[[:space:]]).*/\1yes/' \
  /etc/clamd.d/scan.conf
sudo sed -i -E 's/#(LocalSocket[[:space:]])/\1/' \
  /etc/clamd.d/scan.conf
sudo sed -i -E 's/#(LocalSocketGroup[[:space:]])/\1/' \
  /etc/clamd.d/scan.conf
sudo sed -i -E 's/#(LocalSocketMode[[:space:]])/\1/' \
  /etc/clamd.d/scan.conf
sudo sed -i -E 's/#(ExcludePath[[:space:]])/\1/g' \
  /etc/clamd.d/scan.conf
sudo sed -i "s/^#VirusEvent.*/VirusEvent printf \"Subject: $(hostname -f) VIRUS ALERT\\\nFOUND: %v\" | \/usr\/sbin\/sendmail -F \"clamd\" root/" \
  /etc/clamd.d/scan.conf
sudo sed -i -E 's/#(DetectPUA[[:space:]]).*/\1yes/' \
  /etc/clamd.d/scan.conf
sudo touch /var/log/clamd.scan
sudo chown clamscan:clamscan /var/log/clamd.scan

# selinux
sudo setsebool -P antivirus_can_scan_system 1
sudo setsebool -P clamd_use_jit 1

# download definiton and start clamd
sudo freshclam
sudo systemctl start clamd@scan


################################################################################
### USERS ######################################################################
################################################################################

## General User Configuration

# change minimum uid/gid from 1000 to 5000
sudo sed -i -E "s/(^[U,G]ID_MIN[[:space:]]*)1000$/\15000/g" \
  /etc/login.defs

# configure umask
sudo cp -a /etc/bashrc \
  /etc/.bashrc.default~
sudo sed -i 's/umask.*/umask 027/' \
  /etc/bashrc #only want to replace the first instance

# set password strength rules
echo "difok = 4
minlen = 10
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
maxrepeat = 3" |
  sudo tee /etc/security/pwquality.conf >/dev/null

echo "if [ $UID -gt 199 ] && [ "`id -gn`" = "`id -un`" ]; then
  umask 027
fi" |
  sudo tee /etc/profile.d/custom.sh >/dev/null

# add sysadmin to appropriate groups
sudo gpasswd -a "$(whoami)" systemd-journal
sudo gpasswd -a "$(whoami)" adm

# login message
echo "
WARNING: Unauthorized access to this information system will be prosecuted to the fullest extent of the law.
" | sudo tee /etc/issue >/dev/null

# timeouts
echo "TMOUT=600" | sudo tee /etc/profile.d/timeout.sh >/dev/null
echo "FAIL_DELAY 4" | sudo tee -a /etc/login.defs >/dev/null

# Authentication

# install `sssd`
sudo dnf -yq install sssd
sudo systemctl enable sssd

# configure sssd for local authentication
sudo touch /etc/sssd/sssd.conf
sudo chmod 600 /etc/sssd/sssd.conf
echo "[domain/local]
id_provider = files

[sssd]
domains = local
services = nss, pam, ssh, sudo" |
  sudo tee /etc/sssd/sssd.conf >/dev/null

# start `sssd`
sudo systemctl start sssd

# enable `sssd` `authselect` profile
sudo authselect select sssd \
  --force \
  without-nullok #\
#  with-faillock #faillock optional, cockpit has a tendency to lock you out

# Remote Access

# ssh
declare FQDN_IP="$(host "$(hostname -f)" | awk '{ print $NF }')"

sudo cp -a /etc/ssh/sshd_config \
  /etc/ssh/.sshd_config.default~
sudo sed -i -E \
  "s/^#(ListenAddress[[:space:]])[[:digit:]].*/\1${FQDN_IP}/" \
  /etc/ssh/sshd_config
sudo sed -i -E 's/^#(ClientAliveCountMax[[:space:]])[0-9]*/\10/' \
  /etc/ssh/sshd_config
sudo sed -i -E 's/^#(ClientAliveInterval[[:space:]])[0-9]*/\1600/' \
  /etc/ssh/sshd_config
sudo sed -i -E 's/^#(Banner[[:space:]]).*/\1\/etc\/issue/' \
  /etc/ssh/sshd_config
sudo sed -i -E 's/^(GSSAPIAuthentication[[:space:]]).*/\1no/' \
  /etc/ssh/sshd_config
sudo sed -i -E 's/^(PermitRootLogin[[:space:]]).*/\1no/' \
  /etc/ssh/sshd_config

# similarly to `postfix`, when `ListenAddress` is configured for `ssh`, it
# starts before we have an address and fails unlike `postfix`, `sshd` will make
# additional attempts to start and eventually succeed but to keep the logs
# cleaner, we can make a change to the unit file
sudo mkdir /usr/lib/systemd/system/sshd.service.d
echo "[Unit]
After=network-online.target" |
  sudo tee /usr/lib/systemd/system/sshd.service.d/online.conf >/dev/null
sudo systemctl daemon-reload

sudo systemctl restart sshd


################################################################################
### AUDITING ###################################################################
################################################################################

## General Configuration

# backup default config
sudo cp -a /etc/audit/auditd.conf \
  /etc/audit/.auditd.conf.default~

# set max log size to 700MB (based on default 5-log roatation and our 4GB partition for `/var/log/audit`)
sudo sed -i -E 's/(max_log_file = ).*/\1700/' \
  /etc/audit/auditd.conf

# try email alert when free space is critical (by default an earlier alert is sent to syslog)
sudo sed -i -E 's/(admin_space_left_action = ).*/\1EMAIL/' \
  /etc/audit/auditd.conf

# halt system if log partition becomes full (this should never happen)
sudo sed -i -E 's/(disk_full_action = ).*/\1HALT/' \
  /etc/audit/auditd.conf

# half system if log partition has disk errors
sudo sed -i -E 's/(disk_error_action = ).*/\1HALT/' \
  /etc/audit/auditd.conf

# restart `auditd` (`systemctl` command do not work by design)
grep -q "NAME=Fedora" /etc/os-release || #fedora will not load new rules until reboot
sudo service auditd restart

## Rules

# base rules
sudo cp /usr/share/doc/audit/rules/10-base-config.rules \
  /etc/audit/rules.d/

# since we're using number-prefixed rules, we want to comment out all lines in
# the default rules even though they are identical to our base rules
sudo sed -i 's/^-/#-/g' \
  /etc/audit/rules.d/audit.rules

# login uid rules
sudo cp /usr/share/doc/audit/rules/11-loginuid.rules \
  /etc/audit/rules.d/

# forbid 32-bit
sudo cp /usr/share/doc/audit/rules/21-no32bit.rules \
  /etc/audit/rules.d/

# ignore ntp
sudo cp /usr/share/doc/audit/rules/22-ignore-chrony.rules \
  /etc/audit/rules.d/

# this is necessary for some reason
sudo sed -i "s/-Fuid=chrony/-Fuid=$(id -u chrony)/g" \
  /etc/audit/rules.d/22-ignore-chrony.rules

# operating system protection profile (ospp)
sudo cp /usr/share/doc/audit/rules/30-ospp-v42.rules \
  /etc/audit/rules.d/

# `rmdir` appears to have been omitted
sudo sed -i -E 's/(unlink,unlinkat,rename,renameat)/rmdir,\1/g' \
  /etc/audit/rules.d/30-ospp-v42.rules

# our minimum uid is 5000, not 1000
sudo sed -i 's/auid>=1000/auid>=5000/g' \
  /etc/audit/rules.d/30-ospp-v42.rules

# additional security (stig)
sudo cp /usr/share/doc/audit/rules/30-stig.rules \
  /etc/audit/rules.d/

# our minimum uid is 5000, not 1000
sudo sed -i 's/auid>=1000/auid>=5000/g' \
  /etc/audit/rules.d/30-stig.rules

# enable optional rules
sudo sed -i 's/^#-w/-w/g' \
  /etc/audit/rules.d/30-stig.rules

# `/etc/sysconfig/network` appears to have been omitted
sudo sed -i -E 's/(^-w \/etc\/hostname.*system-locale$)/\1\
-w \/etc\/sysconfig\/network -p wa -k system-locale/' \
  /etc/audit/rules.d/30-stig.rules

# configure privileged rules
sed 's/^#//g' /usr/share/doc/audit/rules/31-privileged.rules |
  sed 's/priv\.rules/\/etc\/audit\/rules.d\/31-privileged.rules/g' |
  sudo bash

# admin home folder
sudo cp /usr/share/doc/audit/rules/32-power-abuse.rules \
  /etc/audit/rules.d/

# code injection
sudo cp /usr/share/doc/audit/rules/42-injection.rules \
  /etc/audit/rules.d/

# kernel modules
sudo cp /usr/share/doc/audit/rules/43-module-load.rules \
  /etc/audit/rules.d/

# lock out
# once enabled, no more changes can be made without rebooting
sudo cp /usr/share/doc/audit/rules/99-finalize.rules \
  /etc/audit/rules.d/

sudo sed -i 's/^#-e/-e/' \
  /etc/audit/rules.d/99-finalize.rules

# load the rules
sudo augenrules --load

# configure auditing in `GRUB`
echo 'GRUB_CMDLINE_LINUX="${GRUB_CMDLINE_LINUX} audit=1"' |
  sudo tee -a /etc/grub.d/40_custom >/dev/null
sudo dnf -yq install grubby
sudo grubby --update-kernel=ALL --args="audit=1"
sudo grub2-mkconfig -o "/etc/$(readlink /etc/grub2.cfg)" #for bios booting
sudo grub2-mkconfig -o "/etc/$(readlink /etc/grub2-efi.cfg)" || : #for efi booting


################################################################################
### COCKPIT (OPTIONAL) #########################################################
################################################################################

[ ${INSTALL_COCKPIT} == 1 ] &&
{ # install and enable
  sudo dnf -yq install cockpit cockpit-pcp cockpit-packagekit cockpit-storaged

  grep -q "NAME=Fedora" /etc/os-release && #fedora only
  { sudo dnf -yq install cockpit-selinux
    sudo dnf -yq remove cockpit-dashboard
  } || ! grep -q "NAME=Fedora" /etc/os-release


  sudo systemctl enable cockpit.socket

  # allow admins to access cockpit
  sudo firewall-cmd --permanent --zone="${ZONE}" \
    --add-rich-rule="rule family=ipv4 source address=${ADMIN_NET} service name=cockpit accept"

  # apply changes
  sudo firewall-cmd --reload

  sudo systemctl start cockpit.socket
  
  # clear cockpit motd
  sudo cp -a /etc/motd.d/cockpit \
    /etc/motd.d/.cockpit.default~
  echo | sudo tee /etc/motd.d/cockpit >/dev/null
  
} || [ ! ${INSTALL_COCKPIT} == 1 ]


################################################################################
### NETDATA (OPTIONAL) #########################################################
################################################################################

[ ${INSTALL_NETDATA} == 1 ] &&
{ # install and enable
  sudo dnf -yq install netdata
  sudo systemctl enable netdata

  # configure netdata
  sudo sed -i -E "s/(bind to = ).*/\1$(hostname -f)/" \
    /etc/netdata/netdata.conf
  sudo sed -i -E "s/#(use_fqdn=).*/\1'YES'/" \
    /etc/netdata/conf.d/health_alarm_notify.conf

  # allow admins to access netdata
  sudo firewall-cmd --permanent --zone="${ZONE}" \
    --add-rich-rule="rule family=ipv4 source address=${ADMIN_NET} port port=19999 protocol=tcp accept"

  # apply changes
  sudo firewall-cmd --reload

  # start netdata
  sudo systemctl start netdata
} || [ ! ${INSTALL_NETDATA} == 1 ]


################################################################################
### MISCELLANEOUS ##############################################################
################################################################################

# disable ctrl-alt-del
sudo systemctl mask ctrl-alt-del.target || #centos
sudo rm /etc/systemd/system/ctrl-alt-del.target #fedora

# disable kernel dumps
sudo systemctl disable kdump.service || : #fails if not present
sudo systemctl stop kdump.service || : #fails if not present


################################################################################
### LOCK DOWN ##################################################################
################################################################################

## Configure `aide`

# install and initialize `aide`
sudo dnf -yq install aide

# changes to `aide.conf`
cp -a /etc/aide.conf \
  /etc/.aide.conf.default~
  
sudo sed '/^\/var\/log LOG$/ a/var/log/lastlog
/^\/var\/log\/lastlog LSPP/ d' \
  /etc/.aide.conf.default~

echo '#!/usr/bin/env bash

aide --init >/dev/null &&

rm /var/lib/aide/aide.db.gz &&
mv /var/lib/aide/aide.db.new.gz  \
  /var/lib/aide/aide.db.gz

exit $?' |
  sudo tee /etc/cron.daily/zz-aide-init >/dev/null

sudo chmod +x /etc/cron.daily/zz-aide-init

# netdata log rotates daily and changed inode, so we ignore
[ ${INSTALL_NETDATA} == 1 ] &&
{ sudo sed '/# Ditto/ a!/var/log/netdata/error.log*' \
    /etc/.aide.conf.default~
} || [ ! ${INSTALL_NETDATA} == 1 ]

# initialize aide database
/etc/cron.daily/zz-aide-init

# make cron job
echo '#!/usr/bin/env bash

aide --check >/dev/null && exit 0

echo "Subject: $(hostname -f) - AIDE Integrity Check
$(aide --update)" |
  sendmail -F "aide" root

exit 0' |
  sudo tee /etc/cron.daily/00-aide-check >/dev/null

sudo chmod +x /etc/cron.daily/00-aide-check

## Configure `selinux` for Admin User

# we need policycoreutils-python-utils to use the semanage command
sudo dnf -yq install policycoreutils-python-utils

# set our user context to staff
sudo semanage login -a -s staff_u -rs0:c0.c1023 "$(whoami)"

# set appropriate context on our home folder
sudo restorecon -FR /home/$(whoami)

# create empty sudoers file
sudo touch /etc/sudoers.d/"$(whoami)"
sudo chmod 440 /etc/sudoers.d/"$(whoami)"

# allow sudo to escalate us to sysadm
# doing this will lock us out of sudo until a new session is established so we
# issue a reboot as well

sudo shutdown -r +1

echo "$(whoami) ALL=(ALL) TYPE=sysadm_t ROLE=sysadm_r ALL" |
  sudo tee /etc/sudoers.d/$(whoami) >/dev/null &&

echo "==========================================================================
=== GRUB CREDENTIALS =====================================================
==========================================================================
= USER: ${GRUB_USER}
= PASSWORD: ${GRUB_PW}
=========================================================================="

# clean up
unset ADMIN_NET INSTALL_COCKPIT INSTALL_NETDATA GRUB_USER GRUB_PW FQDN_IP \
  FQDN_INTERFACE ZONE

history -c

rm -- "$0" #delete this script

exit 0
