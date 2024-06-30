#!/usr/bin/env zsh
# WARNING: THIS SCRIPT WILL AGGRESSIVELY DESTROY ALL DATA ON ALL DRIVES
# ON THIS SYSTEM!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#
# This script assumes 3 drives (sda sdb and sdc) are present and the
# first 2 are identical in size. The majority of the operating system
# is installed onto a mirror of sda and sdb. Home is installed on sdc.
########################################################################

declare adm_user='o0-o'

# Subnet with ssh access in cidr notation
# If left blank, current ssh connetion is used with /24
declare adm_net= #10.0.0.0/8

# Leave blank to use reverse dns
declare hostname='adm3'

# Values can be selinux apparmor or blank
declare mandatory_access_control='apparmor'

# Example: a mirror for esp (for future use), boot, swap, root and a
# dedicated drive for home
declare -a boot_swap_root_mirror=( '/dev/sda' '/dev/sdb' )
declare home='/dev/sdc'


########################################################################
# PRELIMINARY ##########################################################
########################################################################

set -euo pipefail
setopt +o nomatch
trap -- 'echo "FAIL: ${pipestatus[@]}"' "ERR"

# Interactive password entry
while [ ! "${password-1}" = "${password_confirm-2}" ]; do
  printf  '%s: '    "Create a password for user ${adm_user}"
  read    -s        password
  printf  '\n%s: '  'Retype the password'
  read    -s        password_confirm
  print   '\n'
done
unset password_confirm

set -x

# NTP
timedatectl set-ntp true

# Check SSH connection for adm_net
: ${adm_net:=$( ss  --no-header                                     \
                    --options state established '( sport = :ssh )'  |
                awk '{print $5}'                                    |
                sed --expression 's|[0-9]*:.*|0/24|;q'                )}

# Check reverse dns for hostname
: ${hostname:=$(  dig -x "$( hostname -i )" +noall +answer            |
                  awk '/\.$/ { print substr($NF, 1, length($NF)-1) }'   )}


########################################################################
# RESET STORAGE ########################################################
########################################################################

# Unmount everything but live environment
declare notypes='nooverlay,noproc,nosysfs,nodevtmpfs,notmpfs,noiso9660'
declare notypes="${notypes},nodevpts,nocgroup2"
umount    --force --recursive '/mnt' || :
umount    --force --all \
          --types "${notypes}"  || :
# Turn off swap
swapoff   --all

# Deactivate all LVM logical volumes
lvchange  --yes --activate 'n'  \
          $( lvs  --noheadings --rows --options 'lv_path' ) || :

# Forcefully remove all LVM physical volumes
pvremove  --yes --force --force \
          $( pvs  --noheadings --rows --options 'pv_name' ) || :

# Close all LUKS containers
lsblk --noheadings        \
      --list              \
      --output NAME,TYPE  |
tac                       |
grep "crypt$"             |
while read -r crypt; do
  cryptsetup close "${crypt% *}"
done

# Remove all md devices
for md in '/dev/md'?*; do
  umount --lazy   "${md}"                             || :
  echo idle > "/sys/block/${md##*/}/md/sync_action"   || :
  echo none > "/sys/block/${md##*/}/md/resync_start"  || :
  mdadm --stop    "${md}"                             || :
  mdadm --remove  "${md}"                             || :
done
lsblk --noheadings  \
      --list        \
      --output NAME |
tac                 |
while read -r dev; do
  mdadm --misc --force --zero-superblock "/dev/${dev}"  || :
done

# Clear partitions
for drive in "${boot_swap_root_mirror[@]}" "${home}"; do
  sgdisk  --zap-all "${drive}"
done


########################################################################
# PARTITION ############################################################
########################################################################

# Create partitions for boot mirror, swap mirror and root mirror, create
# both biosboot and esp partitions to keep future options open
for drive in "${boot_swap_root_mirror[@]}"; do
  sgdisk  --zap-all                                                   \
          --new             '1:0:+1M'                                 \
          --typecode        '1:ef02'                                  \
          --change-name     '1:biosboot'                              \
          --partition-guid  '1:21686148-6449-6E6F-744E-656564454649'  \
          --new             '2:0:+550M'                               \
          --typecode        '2:ef00'                                  \
          --change-name     '2:ESP'                                   \
          --new             '3:0:+8G'                                 \
          --typecode        '3:fd00'                                  \
          --change-name     '3:boot_mirror_part'                      \
          --new             '4:0:+4G'                                 \
          --typecode        '4:fd00'                                  \
          --change-name     '4:swap_mirror_part'                      \
          --new             '5:0:-100M'                               \
          --typecode        '5:fd00'                                  \
          --change-name     '5:root_mirror_part'                      \
          "${drive}"
done

# Create partition for home (luks)
sgdisk  --zap-all                   \
        --new         '1:0:-100M'   \
        --typecode    '1:8309'      \
        --change-name '1:home_part' \
        "${home}"


########################################################################
# RAID #################################################################
########################################################################

# Create mirror for boot
yes                                                   |
mdadm --create                                        \
      --force                                         \
      --level         '1'                             \
      --metadata      '1.0'                           \
      --bitmap        'internal'                      \
      --homehost      "${hostname%%.*}"               \
      --raid-devices  "${#boot_swap_root_mirror[@]}"  \
      '/dev/md/boot_mirror'                           \
      "${boot_swap_root_mirror[@]/%/3}"               ||
[ "${pipestatus[2]}" = 0 ]

# Create mirror for swap
yes                                                   |
mdadm --create                                        \
      --force                                         \
      --level         '1'                             \
      --metadata      '1.2'                           \
      --bitmap        'internal'                      \
      --homehost      "${hostname%%.*}"               \
      --raid-devices  "${#boot_swap_root_mirror[@]}"  \
      '/dev/md/swap_mirror'                           \
      "${boot_swap_root_mirror[@]/%/4}"               ||
[ "${pipestatus[2]}" = 0 ]
shred --zero  --size '20MiB'  '/dev/md/swap_mirror'

# Create mirror for root
yes                                                   |
mdadm --create                                        \
      --force                                         \
      --level         '1'                             \
      --metadata      '1.2'                           \
      --bitmap        'internal'                      \
      --homehost      "${hostname%%.*}"               \
      --raid-devices  "${#boot_swap_root_mirror[@]}"  \
      '/dev/md/root_mirror'                           \
      "${boot_swap_root_mirror[@]/%/5}"               ||
[ "${pipestatus[2]}" = 0 ]


########################################################################
# ENCRYPTION ###########################################################
########################################################################

# Prep
for dev in '/dev/md/boot_mirror' '/dev/md/root_mirror' "${home}1"; do

  yes 'YES'                                   |
  cryptsetup  open  --type      'plain'       \
                    --key-file  '/dev/random' \
                    "${dev}"                  \
                    'container'               ||
  [ "${pipestatus[2]}" = 0 ]
  # Uncomment when you do it for real
#  dd  if='/dev/zero'              \
#      of='/dev/mapper/container'  \
#      bs='1M'                     \
#      status='progress'           || : # Exit 1 expected
  while ! cryptsetup close 'container'; do; done

done

# Key file
dd  if='/dev/urandom' \
    of='luks.key'     \
    bs='512'          \
    count='1'
chmod '600' 'luks.key'

# Boot
yes 'YES'                                       |
cryptsetup  luksFormat  --type      'luks1'     \
                        --key-file  'luks.key'  \
                        '/dev/md/boot_mirror'   ||
[ "${pipestatus[2]}" = 0 ]
cryptsetup  open        --key-file  'luks.key'  \
                        '/dev/md/boot_mirror'   \
                        'boot_luks'

# Root
yes 'YES'                                       |
cryptsetup  luksFormat  --key-file  'luks.key'  \
                        '/dev/md/root_mirror'   ||
[ "${pipestatus[2]}" = 0 ]
cryptsetup  open        --key-file  'luks.key'  \
                        '/dev/md/root_mirror'   \
                        'root_luks'

# Home
yes 'YES'                                       |
cryptsetup  luksFormat  --key-file  'luks.key'  \
                        "${home}1"              ||
[ "${pipestatus[2]}" = 0 ]
cryptsetup  open        --key-file  'luks.key'  \
                        "${home}1"              \
                        'home_luks'


########################################################################
# LVM ##################################################################
########################################################################

# Boot
pvcreate  --yes                   \
          --force --force         \
          '/dev/mapper/boot_luks'
vgcreate  'boot_vg'               \
          '/dev/mapper/boot_luks'
lvcreate  --size    '4G'     \
          --name    'boot_lv' \
          --addtag  'os'      \
          'boot_vg'

# Root
pvcreate  --yes                   \
          --force --force         \
          '/dev/mapper/root_luks'
vgcreate  'root_vg'               \
          '/dev/mapper/root_luks'
lvcreate  --size    '24G'     \
          --name    'root_lv' \
          --addtag  'os'      \
          'root_vg'
# Var
lvcreate  --size    '16G'     \
          --name    'var_lv'  \
          --addtag  'os'      \
          'root_vg'
# Log
lvcreate  --size    '8G'          \
          --name    'var_log_lv'  \
          --addtag  'log'         \
          'root_vg'

# Home
pvcreate  --yes                   \
          --force --force         \
          '/dev/mapper/home_luks'
vgcreate  'home_vg'               \
          '/dev/mapper/home_luks'
lvcreate  --extents '67%FREE' \
          --name    'home_lv' \
          --addtag  'local'   \
          --addtag  'user'    \
          'home_vg'


########################################################################
# FILE SYSTEMS #########################################################
########################################################################

# ESP
for drive in "${boot_swap_root_mirror[@]}"; do
  mkfs.vfat -F '32'     \
            -n 'ESP'    \
            "${drive}2"
done

# Boot
mkfs.ext4 -FF -L  'boot'                \
          '/dev/mapper/boot_vg-boot_lv'

# Root
mkfs.ext4 -FF -L  'root'                \
          '/dev/mapper/root_vg-root_lv'

# Var
mkfs.ext4 -FF -L  'var'                 \
          '/dev/mapper/root_vg-var_lv'

# Log
mkfs.ext4 -FF -L  'var_log'                 \
          '/dev/mapper/root_vg-var_log_lv'

# Home
mkfs.ext4 -FF -L  'home'                \
          '/dev/mapper/home_vg-home_lv'

# Chroot mount
mount   '/dev/mapper/root_vg-root_lv'     '/mnt'
mkdir                                     '/mnt/boot'
mount   --options 'rw,relatime,nodev,nosuid'              \
        '/dev/mapper/boot_vg-boot_lv'     '/mnt/boot'
mkdir                                     '/mnt/var'
mount   --options 'rw,relatime,nodev'                     \
        '/dev/mapper/root_vg-var_lv'      '/mnt/var'
mkdir                                     '/mnt/var/log'
mount   --options 'rw,relatime,nodev,nosuid,noexec'       \
        '/dev/mapper/root_vg-var_log_lv'  '/mnt/var/log'
mkdir                                     '/mnt/home'
mount   --options 'rw,relatime,nodev,nosuid'              \
        '/dev/mapper/home_vg-home_lv'     '/mnt/home'


########################################################################
# MINIMAL OS INSTALL/CONFIG ############################################
########################################################################

# Install the base OS
declare pacs=(  'base' 'base-devel'
                'linux-hardened' 'linux-firmware'
                'grub' 'mkinitcpio'
                'mdadm' 'lvm2'                    )
grep  --quiet "GenuineIntel"  \
      '/proc/cpuinfo'         &&
pacs+=( 'intel-ucode' )       || :
pacstrap  '/mnt'  "${pacs[@]-}"

# Configure mdadm
mdadm --detail  \
      --scan    >> '/mnt/etc/mdadm.conf'
printf  'MAILADDR root\n' >> '/mnt/etc/mdadm.conf'

# Configure luks
# Transfer keys to chroot
cp  --archive  'luks.key' '/mnt/etc/'
# Add swap and home to crypttab
printf  '%s\t%s\t%s\t%s\n'                                                \
        'swap'                                                            \
        "$( find  -L        '/dev/disk'           \
                  -samefile '/dev/md/swap_mirror' |
            head  --lines   '1'                     )"                    \
        '/dev/urandom'                                                    \
        'swap,cipher=aes-xts-plain64,size=256'                            \
        'home_luks'                                                       \
        "UUID=$( blkid --match-tag 'UUID' --output 'value' "${home}1" )"  \
        '/etc/luks.key'                                                   \
        'luks,discard'                                  >> '/mnt/etc/crypttab'
# Add boot and root to initramfs
printf  '%s\t%s\t%s\t%s\n'                          \
        'boot_luks'                                 \
        "UUID=$(  blkid --match-tag 'UUID'    \
                        --output    'value'   \
                        '/dev/md/boot_mirror'   )"  \
        '/etc/luks.key'                             \
        'luks,discard'                              \
        'root_luks'                                 \
        "UUID=$(  blkid --match-tag 'UUID'    \
                        --output    'value'   \
                        '/dev/md/root_mirror'   )"  \
        '/etc/luks.key'                             \
        'luks,discard'                        >> '/mnt/etc/crypttab.initramfs'

# Configure fstab
genfstab  '/mnt'  >>  '/mnt/etc/fstab'
# Swap is re-encrypted each boot via crypttab
printf  '%s\t%s\t%s\t%s\t%s\t%s\n'  \
        '/dev/mapper/swap'          \
        'none'                      \
        'swap'                      \
        'defaults'                  \
        '0'                         \
        '0'                         >>  '/mnt/etc/fstab'

# Time
arch-chroot '/mnt'  hwclock --systohc
arch-chroot '/mnt'  ln  --symbolic                              \
                        --force                                 \
                        '/usr/share/zoneinfo/America/New_York'  \
                        '/etc/localtime'

# Locale
sed --in-place                            \
    --expression '/#en_US.UTF-8/ s/^#//'  \
    '/mnt/etc/locale.gen'
printf  'LANG=%s.%s'  \
        'en_US'       \
        'UTF-8'       > '/mnt/etc/locale.conf'
printf  'KEYMAP=%s' \
        'us'        > '/mnt/etc/vconsole.conf'

arch-chroot '/mnt'  locale-gen

# Network
cp  --archive                   \
    '/etc/systemd/network/'*    \
    '/mnt/etc/systemd/network/'

# Hostname
printf  '%s' "${hostname}"  > '/mnt/etc/hostname'
printf  '%s\t%s'      \
        '127.0.1.1'   \
        "${hostname}" >>  '/mnt/etc/hosts'

# GPG
install --mode      '700'                   \
        --directory '/mnt/etc/skel/.gnupg'
printf  'keyserver hkps://keyserver.ubuntu.com\n' >\
        '/mnt/etc/skel/.gnupg/dirmngr.conf'
cp  '/mnt/etc/skel/.gnupg/dirmngr.conf' \
    '/mnt/root/.gnupg/'

# Create temporary user for AUR/makepkg
sed --in-place                                                            \
    --expression  '/^#\{,1\}MAKEFLAGS/ s/.*/MAKEFLAGS="-j'"$(nproc)"'"/p' \
    '/mnt/etc/makepkg.conf'
declare maker="z$( uuidgen | cut --delimiter '-' --fields '1' )"
declare maker_home="/home/${maker}"
arch-chroot '/mnt'  useradd --create-home           \
                            --user-group            \
                            --shell       '/bin/sh' \
                            "${maker}"

# Create a simple script to install AURs
pacstrap  '/mnt'  git
declare aur_installer="${maker_home}/install_aur.sh"
printf  '%s\n'                                                      \
        '#!/usr/bin/env bash'                                       \
        'set -euxo pipefail'                                        \
        'git clone "https://aur.archlinux.org/${1}.git"  \'         \
        '          "${HOME}/${1}"'                                  \
        'cd "${HOME}/${1}"'                                         \
        'makepkg --noconfirm --syncdeps --needed --clean --install --skippgpcheck' \
        'cd "../"'                                                  \
        'rm --force --recursive "${HOME}/${1}"'                     >\
        "/mnt${aur_installer}"
chmod '+x' "/mnt${aur_installer}"

declare -a first_boot_early=()
declare -a first_boot_late=()


########################################################################
# USER #################################################################
########################################################################

# Sudo
printf  '%s\n' '%adm ALL=(ALL) ALL' > '/mnt/etc/sudoers.d/adm'

# Prevent password being printed in trace
set +x

# Create admin user
arch-chroot '/mnt'  useradd --create-home                                     \
                            --user-group                                      \
                            --groups      'adm,systemd-journal'               \
                            --shell       '/bin/sh'                           \
                            --password $(openssl passwd -crypt "${password}") \
                            "${adm_user}"

# Add password to luks
yes "${password}"                                                       |
arch-chroot '/mnt'  cryptsetup  luksAddKey  --key-file  '/etc/luks.key' \
                                            '/dev/md/boot_mirror'       ||
[ "${pipestatus[2]}" = 0 ]
yes "${password}"                                                       |
arch-chroot '/mnt'  cryptsetup  luksAddKey  --key-file  '/etc/luks.key' \
                                            '/dev/md/root_mirror'       ||
[ "${pipestatus[2]}" = 0 ]
yes "${password}"                                                       |
arch-chroot '/mnt'  cryptsetup  luksAddKey  --key-file  '/etc/luks.key' \
                                            "${home}1"                  ||
[ "${pipestatus[2]}" = 0 ]

# Re-enable trace
set -x


########################################################################
# HARDENING ############################################################
########################################################################

# What to install
declare -a pacs=( 'firewalld' )
declare -a keys=()
declare -a aurs=()

# Install SELinux
[ "${mandatory_access_control-}" = 'selinux' ]    &&
{ aurs+=( 'aide-selinux' )
  printf  '%s\n'                            \
          "${maker} ALL=(ALL) NOPASSWD:ALL" >\
          '/mnt/etc/sudoers.d/maker'
  printf  '%s\n'                                                          \
          '#!/usr/bin/env bash'                                           \
          'set -euxo pipefail'                                            \
          'sed --expression '"'"'/^BUILDENV/ s/check/!check/'"'"'  \'     \
          '     "/etc/makepkg.conf"                        >\'            \
          '     "${HOME}/.makepkg.conf"'                                  \
          'sudo pacman --sync --noconfirm git devtools'                   \
          'git clone  "https://github.com/archlinuxhardened/selinux"  \'  \
          '            "${HOME}/selinux"'                                 \
          'cd "${HOME}/selinux"'                                          \
          './recv_gpg_keys.sh'                                            \
          './build_and_install_all.sh'                                    \
          'cd "../"'                                                      \
          'rm --force                       \'                            \
          '   --recursive "${HOME}/selinux"'                              \
          'rm "${HOME}/.makepkg.conf"'                                    >\
          "/mnt${maker_home}/install_selinux.sh"
  chmod '+x' "/mnt${maker_home}/install_selinux.sh"
  declare gcl="${gcl-}security=selinux selinux=1 "
  arch-chroot '/mnt' su "${maker}" --command "${maker_home}/install_selinux.sh"
  arch-chroot '/mnt'  semanage login  --add                   \
                                      --seuser  'staff_u'     \
                                      "${adm_user}"
  sed --in-place                                              \
      --expression  's/ALL$/TYPE=sysadm_t ROLE=sysadm_r ALL/' \
      '/mnt/etc/sudoers.d/wheel'
  rm  "/mnt${maker_home}/install_selinux.sh"
  first_boot_early+=( '/usr/bin/restorecon -v -r /' )
}                                                 ||
[ ! "${mandatory_access_control-}" = 'selinux' ]

# Or Install App Armor
[ "${mandatory_access_control-}" = 'apparmor' ] &&
{ pacs+=( 'apparmor' )
  declare gcl="${gcl-}apparmor=1 lsm=lockdown,yama,apparmor "
}                                                 ||
[ ! "${mandatory_access_control-}" = 'apparmor' ]

# AIDE
printf  '%s' "${aurs[@]}" |
fgrep 'aide-selinux'      ||
{ aurs+=( 'aide' )
  keys+=( '18EE86386022EF57' )
}
declare aide_db='/var/lib/aide/aide.db.gz'
declare aide_db_new='/var/lib/aide/aide.db.new.gz'
first_boot_early+=( '/usr/bin/aide --verbose --init'
                    "/usr/bin/mv ${aide_db_new} ${aide_db}" )

# Install pacman packages
pacstrap  '/mnt'  ${pacs[@]-}

# Install AUR packages
printf  '%s %s\n'                                     \
        "${maker} ALL=(ALL)"                          \
        'NOPASSWD:/usr/bin/makepkg, /usr/bin/pacman'  >\
        '/mnt/etc/sudoers.d/maker'
for key in ${keys[@]}; do
  arch-chroot '/mnt'  su "${maker}" --command "gpg --recv-keys ${key}"
done
for aur_pkg in "${aurs[@]}"; do
  arch-chroot '/mnt'  su "${maker}" --command "${aur_installer} ${aur_pkg}"
done

# Firewall
# Manually configuring nftables is too much work :(
declare zone='default_gateway'
declare gw_if="$( ip route show default                               |
                  sed --expression 's/^.*dev \([[:alnum:]]*\).*$/\1/'   )"
first_boot_late+=(  'firewall-cmd  --permanent                     \'
                    "              --new-zone    '${zone}'         \\"
                    '              --set-short   "Default Gateway" \'
                    '              --set-target  "DROP"'
                    'ip  -brief link             |'
                    'cut --delimiter " "         \'
                    '    --fields    "1"         |'
                    'grep  --invert-match "^lo"  |'
                    'while read -r iface; do'
                    '  firewall-cmd  --permanent               \'
                    '                --zone          "drop"    \'
                    '                --add-interface "${iface}"'
                    'done'
                    'firewall-cmd  --permanent                     \'
                    '              --zone              "drop"      \'
                    "              --remove-interface  '${gw_if}'"
                    'firewall-cmd  --permanent                           \'
                    "              --zone          '${zone}'             \\"
                    '              --add-rich-rule "rule               \'
                    '                              family=ipv4         \'
                    '                              source              \'
                    "                              address=${adm_net}  \\"
                    '                              service             \'
                    '                              name=ssh            \'
                    '                              accept"               \'
                    '              --add-rich-rule "rule               \'
                    '                              family=ipv4         \'
                    '                              source              \'
                    "                              address=${adm_net}  \\"
                    '                              icmp-type           \'
                    '                              name=echo-request   \'
                    '                              accept"'
                    'firewall-cmd  --permanent                 \'
                    "              --zone          '${zone}'   \\"
                    "              --add-interface '${gw_if}'"
                    'firewall-cmd  --set-default-zone  "drop"'
                    'firewall-cmd  --reload'                                  )


########################################################################
# ADDITIONAL SOFTWARE ##################################################
########################################################################

# What to install
declare -a pacs=( 'linux-lts' 'man-db' 'pkgfile'
                  'perl' 'tcl' 'expect' 'python3' 'ruby'
                  'go' 'jre-openjdk-headless'
                  'postfix' 'smartmontools'
                  'dmidecode' 'ipmitool' 'strace'
                  'zsh' 'tmux' 'neovim'                   )
declare -a keys=( '3FEF9748469ADBE15DA7CA80AC2D62742012EA22' ) #1password
declare -a aurs=( 'yay' '1password-cli' )

# Install pacman packages
pacstrap  '/mnt'  ${pacs[@]-}
# Boot into linux-hardened by default
sed --in-place                                \
    --expression  '/GRUB_DEFAULT=/ s/=.*/=2/' \
    '/mnt/etc/default/grub'

# Install AUR packages
printf  '%s %s\n'                                     \
        "${maker} ALL=(ALL)"                          \
        'NOPASSWD:/usr/bin/makepkg, /usr/bin/pacman'  >\
        '/mnt/etc/sudoers.d/maker'
for key in ${keys[@]}; do
  arch-chroot '/mnt'  su "${maker}" --command "gpg --recv-keys ${key}"
done
for aur_pkg in "${aurs[@]}"; do
  arch-chroot '/mnt'  su "${maker}" --command "${aur_installer} ${aur_pkg}"
done

# Update package search data
arch-chroot '/mnt'  yay --files --refresh
arch-chroot '/mnt'  pkgfile --update

# Update sysadmin
arch-chroot '/mnt'  usermod --shell '/bin/zsh'  \
                            "${adm_user}"
sed --in-place                                \
    --expression  '/#root:[[:space:]]*you/ a\
root:\t\t'"${adm_user}"                       \
    '/mnt/etc/postfix/aliases'
arch-chroot '/mnt'  newaliases

# Configure smartd short test between 1-2AM daily and long test between
# 3-4AM Saturdays on all SMART-enabled drives
printf  '%s (%s) - %s\n'                            \
        'DEVICESCAN -a -o on -S on -n standby,q -s' \
        'S/../.././01|L/../../6/03'                 \
        '-W 4,35,40 -m root'                        >>\
        '/mnt/etc/smartd.conf'


########################################################################
# ANTIVIRUS ############################################################
########################################################################

pacstrap  '/mnt'  clamav
arch-chroot '/mnt' su "${maker}" --command "${aur_installer} python-fangfrisch"

arch-chroot '/mnt' freshclam
arch-chroot '/mnt' sudo --user 'clamav'                                       \
                   fangfrisch initdb --conf '/etc/fangfrisch/fangfrisch.conf'
declare ALERT_CMD='{ echo "Subject: $(hostname -f) '
declare ALERT_CMD="${ALERT_CMD}"'CLAMAV ALERT:%v"; '
declare ALERT_CMD="${ALERT_CMD}"'log show --predicate '
declare ALERT_CMD="${ALERT_CMD}'"'(process == "clamd")'"' "
declare ALERT_CMD="${ALERT_CMD}"'--info --last 1m '
declare ALERT_CMD="${ALERT_CMD}"'--style syslog; } | '
declare ALERT_CMD="${ALERT_CMD}"'/usr/sbin/sendmail -F clamd root'
sed --in-place                                                  \
    --expression  '/^Example/                 s/^/#/'           \
    --expression  '/^#LogSyslog/              s/^#//'           \
    --expression  '/^#LocalSocket[[:space:]]/ s/^#//'           \
    --expression  '/^#LocalSocketMode/        s/^#//'           \
    --expression  '/^#ExcludePath/            s/^#//'           \
    --expression  '/^# Default: scan all/ a\
ExcludePath ^/dev/'                                             \
    --expression  's/^#\(MaxDirectoryRecursion\).*/\1 0/'       \
    --expression  's@^#\(VirusEvent\).*$@\1 '"${ALERT_CMD}"'@'  \
    --expression  '/^#ExitonOOM/              s/^#//'           \
    '/mnt/etc/clamav/clamd.conf'
printf  '%s\n'                                            \
        '[Unit]'                                          \
        'Description=Weekly Virus Scan'                   \
        'Requires=clamav-clamdscan.service'               \
        ''                                                \
        '[Timer]'                                         \
        'OnCalendar=weekly'                               \
        'Unit=clamav-clamdscan.service'                   \
        'RandomizedDelaySec=60m'                          \
        'Persistent=true'                                 \
        ''                                                \
        '[Install]'                                       \
        'WantedBy=timers.target'                          >\
        '/mnt/etc/systemd/system/clamav-clamdscan.timer'
printf  '%s\n'                                              \
        '[Unit]'                                            \
        'Description=Virus Scan'                            \
        ''                                                  \
        '[Service]'                                         \
        'Type=simple'                                       \
        'ExecStart=/usr/bin/clamdscan --multiscan /'        \
        ''                                                  \
        '[Install]'                                         \
        'WantedBy=multi-user.target'                        >\
        '/mnt/etc/systemd/system/clamav-clamdscan.service'


########################################################################
# DESKTOP ENVIRONMENT ##################################################
########################################################################

# This is proof-of-concept only at this point and will need much more
# work to be a functional desktop environment.

# What to install
declare -a pacs=( 'xorg-server' 'xorg-xinit' 'xorg-xrandr'
                  'awesome' 'neofetch'
                  'alacritty' 'vlc' 'nautilus' 'sushi' 'remmina'  )
arch-chroot '/mnt'  command -v ssh >/dev/null || pacs+=( 'openssh' )
#selinux installs conflicting openssh package
declare -a keys=( )
declare -a aurs=( 'nerd-fonts-meslo'
                  'ipmiview' 'brave-bin' 'firefox-esr-bin'  )

# Install pacman packages
pacstrap  '/mnt'  "${pacs[@]-}"

# Install AUR packages
printf  '%s %s\n'                                     \
        "${maker} ALL=(ALL)"                          \
        'NOPASSWD:/usr/bin/makepkg, /usr/bin/pacman'  >\
        '/mnt/etc/sudoers.d/maker'
for key in ${keys[@]-}; do
  arch-chroot '/mnt'  su "${maker}" --command "gpg --recv-keys ${key}"
done
for aur_pkg in "${aurs[@]}"; do
  arch-chroot '/mnt'  su "${maker}" --command "${aur_installer} ${aur_pkg}"
done

# Enable unprivileged user namespace for browser sandboxing
printf  'kernel.unprivileged_userns_clone=1'  >\
        '/mnt/etc/sysctl.d/00-local-userns.conf'

# Configure Awesome
sed --expression  '/^twm/ { s/^.*$/exec awesome/; q; }' \
    '/mnt/etc/X11/xinit/xinitrc'                        >\
    "/mnt/home/${adm_user}/.xinitrc"
arch-chroot '/mnt'  chown "${adm_user}" "/home/${adm_user}/.xinitrc"
declare awe_cfg="/home/${adm_user}/.config/awesome"
arch-chroot '/mnt'  su "${adm_user}" --command "mkdir --parents '${awe_cfg}'"


########################################################################
# SERVICES #############################################################
########################################################################

# First boot scripts
# Early (before network)
printf  '%s\n'                                                      \
        '#!/usr/bin/env bash'                                       \
        'set -euxo pipefail'                                        \
        "export PATH='/usr/bin:/usr/sbin:/bin:/sbin'"               \
        "${first_boot_early[@]-}"                                   \
        '/usr/bin/systemctl disable first-boot-early.service'       \
        '/usr/bin/rm /etc/systemd/system/first-boot-early.service'  \
        '/usr/bin/rm ${0}'                                          >>\
        '/mnt/usr/local/bin/first-boot-early'
chmod '+x' '/mnt/usr/local/bin/first-boot-early'
printf  '%s\n'                                              \
        '[Unit]'                                            \
        'Description=First Boot Early Configuration'        \
        'After=sysinit.target'                              \
        ''                                                  \
        '[Service]'                                         \
        'Type=oneshot'                                      \
        'ExecStart=/usr/local/bin/first-boot-early'         \
        'TimeoutSec=600'                                    \
        'StandardOutput=journal+console'                    \
        'StandardError=journal+console'                     \
        ''                                                  \
        '[Install]'                                         \
        'WantedBy=network.target'                           >\
        '/mnt/etc/systemd/system/first-boot-early.service'
# Late (after firewalld)
printf  '%s\n'                                                    \
        '#!/usr/bin/env bash'                                     \
        'set -euxo pipefail'                                      \
        "export PATH='/usr/bin:/usr/sbin:/bin:/sbin'"             \
        "${first_boot_late[@]-}"                                  \
        '/usr/bin/systemctl disable first-boot-late.service'      \
        '/usr/bin/rm /etc/systemd/system/first-boot-late.service' \
        '/usr/bin/rm ${0}'                                        >>\
        '/mnt/usr/local/bin/first-boot-late'
chmod '+x' '/mnt/usr/local/bin/first-boot-late'
printf  '%s\n'                                            \
        '[Unit]'                                          \
        'Description=First Boot Late Configuration'       \
        'After=firewalld.service'                         \
        ''                                                \
        '[Service]'                                       \
        'Type=oneshot'                                    \
        'ExecStart=/usr/local/bin/first-boot-late'        \
        'StandardOutput=journal+console'                  \
        'StandardError=journal+console'                   \
        ''                                                \
        '[Install]'                                       \
        'WantedBy=multi-user.target'                      >\
        '/mnt/etc/systemd/system/first-boot-late.service'

# Allow some enable to fail in case you've commented out a section above
arch-chroot '/mnt'  systemctl enable first-boot-early.service
arch-chroot '/mnt'  systemctl enable first-boot-late.service
arch-chroot '/mnt'  systemctl enable systemd-networkd.service
arch-chroot '/mnt'  systemctl enable systemd-resolved.service
arch-chroot '/mnt'  systemctl enable apparmor.service         || :
arch-chroot '/mnt'  systemctl enable firewalld.service        || :
arch-chroot '/mnt'  systemctl enable sshd                     || :
arch-chroot '/mnt'  systemctl enable postfix.service          || :
arch-chroot '/mnt'  systemctl enable smartd.service           || :
arch-chroot '/mnt'  systemctl enable clamav-freshclam.service || :
arch-chroot '/mnt'  systemctl enable clamav-daemon.service    || :
arch-chroot '/mnt'  systemctl enable fangfrisch.timer         || :
arch-chroot '/mnt'  systemctl enable clamav-clamdscan.timer   || :


########################################################################
# BOOTLOADER AND INIT ##################################################
########################################################################

# mkinitcpio
declare files='/etc/luks.key'
declare hooks='base systemd autodetect keyboard sd-vconsole modconf block'
declare hooks="${hooks} mdadm_udev sd-encrypt sd-lvm2 filesystems fsck"
sed --in-place                                          \
    --expression  '/^FILES/   s|(.*)$|('"${files}"')|'  \
    --expression  '/^HOOKS/   s/(.*)$/('"${hooks}"')/'  \
    --expression  '/^#COMPRESSION="zstd"/ a\
COMPRESSION="cat"'                                          \
        '/mnt/etc/mkinitcpio.conf'
arch-chroot '/mnt'  mkinitcpio  --allpresets

# dracut
# dracut wasn't functional for me, will try again in the future
#pacstrap  '/mnt'  dracut
#arch-chroot '/mnt'  su "${maker}" --command "${aur_installer} dracut-hooks"
#printf  '%s\n'  'hostonly="yes"'          \
#                'compress="cat"'          \
#                'hostonly_cmdline="yes"'  >\
#        '/mnt/etc/dracut.conf.d/00-default.conf'
#printf  '%s\n'  'install_items+="/etc/luks.key"' >\
#        '/mnt/etc/dracut.conf.d/10-luks.conf'
#reinstall kernels will regenerate initramfs
#pacstrap  '/mnt'  linux-hardened linux-lts

# Grub
declare gcl="${gcl-}audit=1 "
declare gcl="${gcl-}loglevel=3 "
declare gcl="${gcl-}quiet"
sed --in-place                                                            \
    --expression  '/GRUB_ENABLE_CRYPTODISK=/      s/^#//'                 \
    --expression  '/GRUB_CMDLINE_LINUX_DEFAULT=/  s|".*"$|"'"${gcl}"'"|'  \
    '/mnt/etc/default/grub'
printf  '%s\n'  'GRUB_DISABLE_SUBMENU=y'  >>\
        '/mnt/etc/default/grub'
# Install
for dev in "${boot_swap_root_mirror[@]}"; do
  arch-chroot '/mnt'  grub-install  --target  'i386-pc' \
                                    "${dev}"
done
# Set Password
printf  '%s\n%s\n%s\n%s'                                                      \
        "echo 'menuentry_id_option=\"--unrestricted \$menuentry_id_option\"'" \
        "echo 'export menuentry_id_option'"                                   \
        "echo 'set superusers=\"${adm_user}\"'"                               \
        "echo 'password_pbkdf2 ${adm_user} "                                 >\
        '/mnt/etc/grub.d/01_users'
set +x
arch-chroot '/mnt' su --command 'yes "'"${password}"'"  |
                                grub-mkpasswd-pbkdf2'     |
tail  --lines '1'                                         |
awk '{print $NF "'\''"}'                                  >>\
'/mnt/etc/grub.d/01_users'
set -x
chmod '0700' '/mnt/etc/grub.d/01_users'
# Generate config
arch-chroot '/mnt'  grub-mkconfig --output  '/boot/grub/grub.cfg'


########################################################################
## CLEAN UP ############################################################
########################################################################

# Delete temporary AUR/makepkg user
arch-chroot '/mnt'  userdel --force     \
                            --remove    \
                            "${maker}"
rm  '/mnt/etc/sudoers.d/maker' || :


########################################################################
## SNAPSHOT ############################################################
########################################################################

# Take a pre-boot snapshot of the OS
declare snap_time="$(date +"%Y-%m-%d-%H-%M-%S")"
lvs --noheadings            \
    --option      'lv_path' \
    '@os'                   |
while read -r lv; do
  declare size="$(  df  --block-size='1K'                             \
                        --exclude-type='tmpfs'                        \
                        --exclude-type='devtmpfs'                     \
                        --output='source,used'                        |
                    tail  --lines '+2'                                |
                    fgrep $(  lvs --noheadings                    \
                                  --option      'vg_name,lvname'  \
                                  --separator   '-'               \
                                  "${lv}"                           ) |
                    awk '{ print $2 }'                                  )K"
  lvcreate  --snapshot                            \
            --name      "${lv##*/}_${snap_time}"  \
            --size      "${size}"                 \
            --addtag    "${snap_time}"            \
            --addtag    "$(uname -r)"             \
            "${lv}"
done


########################################################################
## RECOVER #############################################################
########################################################################

# Copy this if you reboot into the installer and want to recover the OS
# It should do nothing in the context of this script
mount                                               |
grep  --quiet '/mnt'                                ||
{ declare home='/dev/sdc'                           &&
  cryptsetup  open  /dev/md/*root_mirror            \
                    'root_luks'                     &&
  sleep '1'                                         &&
  lvscan  --all                                     &&
  mount '/dev/root_vg/root_lv'    '/mnt'            &&
  mount '/dev/root_vg/var_lv'     '/mnt/var'        &&
  mount '/dev/root_vg/var_log_lv' '/mnt/var/log'    &&
  cryptsetup  open  --key-file '/mnt/etc/luks.key'  \
                    '/dev/md/'*'boot_mirror'        \
                    'boot_luks'                     &&
  cryptsetup  open  --key-file '/mnt/etc/luks.key'  \
                    "${home}1"                      \
                    'home_luks'                     &&
  lvscan  --all                                     &&
  mount '/dev/boot_vg/boot_lv'  '/mnt/boot'         &&
  mount '/dev/home_vg/home_lv'  '/mnt/home'
}
