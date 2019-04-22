#!/bin/bash
## Xe1phix-zfs-v*.*.sh     
##   	  

    
'##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##'
     [+] VDEVs (Virtual Block Devices)
     [+] COW (Copy-on-Write) Filesystem                                               
                                                   _________________________________________________________________________________________
     [+] Primary Cache (ARC)                       |_|_ _ _________________________________________________________________              |
                                                   |_|_____| [+]_Attribute_Details      |____________| [+]_Attribute_Value |_____________|
                                                     / #||-> Primary Cache (ARC) Method       |                            \ \ | |  / /
                                                    / /#||-> User Data + Metadata is Cached   |        primarycache=all     \ \| | / /
                                                   / / #||-> Metadata (Only) Is Cached        |   primarycache=metadata      \ | |/ /
                                              ____/ / /#||-> Neither User Nor Metadata Cached |       primarycache=none       \|_| /
                                        ##   (____}~===~{+}-===================================================================||=======~##
     [+] Secondary Cache (L2ARC)                  \ \ \#||-> User Data + Metadata is Cached.  |      secondarycache=all       /| | \
                                                   \ \ #||-> Metadata (Only) Is Cached        | secondarycache=metadata      / | |\ \
                                                    \ \#||-> Neither User Nor Metadata Cached |     secondarycache=none     / /| | \ \
                                                     \ #||  ________________________________ _|_ _________________________ /_/_|_|__\ \___
                                                      \#||_|________________________________|___|_________________________________________| 
                                                   


'##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##'
     [+] SHA256 Checksum Integrity Verification 
     [+] Deduplication
     [+] Ditto Blocks (Replicated Metadata)
     
'##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##'
     [+] ZFS Snapshots
         ▪ Sending a ZFS Snapshot
         ▪ Receiving a ZFS Snapshot
         ▪ Rolling Back a ZFS Snapshot
         ▪ Snapshot User Holds 
         ▪ ZFS Snapshot Diff Parser
         ▪ Rolling Snapshots                                ## @yesterday @today @friday @thursday @wednesday @tuesday
         ▪ Incremental Sending of Snapshot Streams          ## ZFS hole_birth Feature
     [+] ZFS Clones
'##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##'
     [+] ZFS Quotas (User & group)
         ▪ quota=
         ▪ refquota=
         ▪ userquota=
         ▪ groupquota=
     [+] Dataset Reservations
'##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##'

                    ##                                 |    |
'##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##'
     [+] ACL Inheritance
         ▪ ACL Inheritance Flags
     [+] Access Control Entries (ACEs)
         ▪ Trivial ACLs
         ▪ Non-Trivial ACLs
            ♦ ACL Entry Types
            ♦ ACL Access Privileges
     [+] Extended Attributes                            ## Enable xattr on Specified Dataset|       xattr |
     [+] ZFS User Delegating Permissions                ##   Annotate Datasets For Admin    |  dept:users |
       ------------------------------------------------ ##  FileSystem, Volumes, Snapshots  | ----------- |
     [+] Transaction Group Number                       ## ZFS Background Recording         | enabled_txg |
     [+] Trusted Extension on Datasets                  ## SELinux Labeled Privilege Zone   |    mlslabel |
     [+] Virus Scan Service                             ## Scan Files In Dir For Viruses    |       vscan |
     [+] ZFS Zone Restriction                           ## Dataset Managed Non-Global Zone  |       zoned |
     [+] Temporary Mount Points                         ## Temporary Mount Point Properties |       
     [+] Blocked Processes Execution                    ## (from within this file system)   |     exec=no |
     [+] Future Device Node Blocking                    ## Blocks Device Nodes From Opening | devices=off |        
       ------------------------------------------------ ## --- (on this file system.) ----- | ----------- |
     [+] Read-Only Datasets Modification                ## Prevents Dataset Modification    |    readonly |
     [+] Enable The Set-UID Bit                         ## Enable Set-UID Bit on Dataset    |   setuid=on |
'##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##'
     [+] Log - ZFS Intent Log (ZFS ZIL)
         ▪ Mirrored Log Devices
         ▪ Separate Intent Log Devices
     [+] ZFS Data Scrubbing and Resilvering
         ▪ Automatic Repair (scrubbing)
'##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##'
     [+] ZFS VDEVs RAIDs:
         ▪ Striped VDEVS
         ▪ Mirrored VDEVs
         ▪ Striped Mirrored VDEVs
     [+] RAID-Z Storage Pool:
         ▪ RAIDZ (4 Disks)
         ▪ Double-Parity RAID-Z | RAIDZ2 (5 Disks)
         ▪ Triple-Parity RAID-Z | RAIDZ3 (6 Disks - 3/6 Parity)
         ▪ Nested RAIDZ (8 Disks)
     [+] RAID-Z Virtual Devices (Loop)
'##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##'
     [+] Large ZFS Dataset Blocks | 128KB                                            ## allows record size on dataset to be set larger than 128KB
     [+] ZFS - Hybrid Block Pointer | Embedded Data Feature
     [+] Maximum 16 Exabyte File Size
     [+] Maximum 256 Quadrillion Zettabytes
     [+] Unlimited Dataset Creation
'##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##'
     [+] Compression (Applied to Individual Datasets)
         ▪ LZ4     (The latest and greatest - recommended)
         ▪ gzip-N  (Where N is 1 (fastest) - 9 (best compression ratio) - not recommended)
         ▪ LZJB    (Provides a good trade-off between speed and space)
'##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##'
     [+] I/O Statistics Display
     [+] ZFS Admin Web Console
     [+] Zpool History
'##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##'
 
 



zfs get all
zfs get all ZPool-ZFS/Scriptz
zfs get mounted,readonly,mountpoint,type
zfs get used,available,mountpoint
zfs get -H -o value compression 
zfs get -r -s local -o name,property,value all pool/home/bob
zfs get -o name,avail,used,usedsnap,usedds,usedrefreserv,usedchild -t filesystem,volume


zfs list -o mounted,name,used,avail,copies,rdonly,mountpoint,type
zfs list -o name,used,avail,aclmode,aclinherit,zoned,xattr,copies,checksum,compress,rdonly



zfs get -s local all
zfs get -s local all zfs/dir
zfs get -r -s temporary all zfs/dir
zfs get -H -o value -p used
zfs get -H -o name,value -r used
zfs get refquota,quota

df | awk 'NR==1||/zfs/'
df | awk 'NR==1||/(zfs|dir)/'


lsmod | awk 'NR==1||/zfs/'


zfs -o name,avail,used,usedsnap,usedds,usedrefreserv,usedchild -t filesystem,volume
zfs -t filesystem
zfs -t snapshot 
zfs -t volume
zfs -t all

zfs get -o name,property,value,received,source
zfs get -s local,default,inherited,temporary,received
zfs get -p


zpool history


zpool import
zfs mount ZPool-ZFS
mount | grep ZPool-ZFS
zfs set mountpoint=/mnt/ZPool-ZFS ZPool-ZFS
zpool import -d /mnt/ZPool-ZFS
zpool import -d /mnt/ZPool-ZFS ZPool-ZFS
zpool status -v


zfs mount | grep ZPool-ZFS
zfs mount ZPool-ZFS
mount -F zfs ZPool-ZFS/$Dir

zfs mount -o ro ZPool-ZFS
zfs mount -o remount,rw ZPool-ZFS

zfs unmount ZPool-ZFS/$dir/$dir/
zfs unmount -f ZPool-ZFS/$dir/$dir/
umount /mnt/ZPool-ZFS

zpool scrub ZPool-ZFS


zpool offline ZPool-ZFS sdc

umount ZPool-ZFS/$Dir




version=1 | 2 | current
snapdir=hidden | visible
logbias = latency | throughput
sharenfs=off
sharesmb=off
shareiscsi=off



echo "##-==============================-##"
echo "    [+] Nested Datasets             "
echo "##-==============================-##"

echo "##-==========================================-##"
echo "    [?] Datasets dont need to be isolated.      "
echo "##-==========================================-##"

echo "##-===========================================================-##"
echo "    [?] You can create nested datasets within each other.         "
echo "##-===========================================================-##"

echo "##-=================================================-##"
echo "##        This allows you to create namespaces,        "
echo "##      while tuning a nested directory structure,     "
echo "##              without affecting the other.           "
echo "##-=================================================-##"

echo "##-=================================================-##"
echo "    [?] If you want to compress zfs/log:              "
echo "    [?] but not on the parent zfs/ directory:         "
echo "##-=================================================-##"


## Consists of a ZIL header, which points to a list of records, 
## ZIL blocks and a ZIL trailer.


zfs create zfs/log
zfs set compression=on zfs/log          ## Enables or disables compression for a dataset.
zfs get compressratio zfs/log
zfs inherit -r compression zfs/log
zfs set exec=off zfs/log
zpool add zfs log /dev/sd -f



zpool create -f -m /mnt/ZPool-ZFS ZPool-ZFS /dev/sdd

zpool create -m /mnt/ZPool-ZFS ZPool-ZFS disk /dev/sdd

zpool create pool 

zfs create ZPool-ZFS/Xe1phixGitLab

zfs destroy -r ZPool-ZFS/Scripts

chmod -v -R ugo+rwx /mnt/ZPool-ZFS
chown -v -R xe1phix /mnt/ZPool-ZFS

zpool get all ZPool-ZFS

zpool set listsnapshots=on ZPool-ZFS

zfs list

zfs create -p ZPool-ZFS
zfs set mountpoint=/mnt/ZPool-ZFS ZPool-ZFS

chmod -v -R ugo+rwx /mnt/ZPool-ZFS/
chown -v -R xe1phix /mnt/ZPool-ZFS/
cd /mnt/ZPool-ZFS/
mkdir Xe1phixGitLab

zpool import -d /mnt/ZPool-ZFS
zpool import -d /mnt/ZPool-ZFS ZPool-ZFS
zpool import -a -R /mnt

zpool status -v

/mnt/zfspool    /srv/nfs4/music none    bind,defaults,nofail,x-systemd.requires=zfs-mount.service


zfs create ZPool-ZFS/Xe1phixGitLab
zfs create ZPool-ZFS/infosec
zfs create ZPool-ZFS/BrowntownAlpha
zfs create ZPool-ZFS/BrownTown
zfs create ZPool-ZFS/Audio
zfs create ZPool-ZFS/Scripts
zfs create ZPool-ZFS/Wordlists
zfs create ZPool-ZFS/OS

zfs create ZPool-ZFS/Torrents
zfs create ZPool-ZFS/Podcasts
zfs create ZPool-ZFS/'Quantum Physics'
zfs create ZPool-ZFS/Scripts{old}
zfs create ZPool-ZFS/Videos
zfs create ZPool-ZFS/'VirtualBox VMs'
zfs create ZPool-ZFS/ZBro
zfs create ZPool-ZFS/ManArchive
zfs create ZPool-ZFS/icons
zfs create ZPool-ZFS/'b {Archive}'


chgrp -hR xe1phix /mnt/ZPool-ZFS/Wordlists

chmod -v -R ugo+rwx /mnt/ZPool-ZFS && chown -v -R xe1phix /mnt/ZPool-ZFS

chmod -v ugo-x /mnt/ZPool-ZFS/Wordlists/
chmod -v ugo+rw /mnt/ZPool-ZFS/Wordlists/

chmod -v ugo-x /mnt/ZPool-ZFS/OS
chown -v -R xe1phix /mnt/ZPool-ZFS/OS

chmod -v ugo-x ZPool-ZFS/Pr0n
chown -v -R xe1phix ZPool-ZFS/Pr0n

chmod -v ugo-x ZPool-ZFS/Audio
chown -v -R xe1phix ZPool-ZFS/Audio

chmod -v ugo-x ZPool-ZFS/Scripts
chown -v -R xe1phix ZPool-ZFS/Scripts

chmod -v ugo-x ZPool-ZFS/infosec
chown -v -R xe1phix ZPool-ZFS/infosec

chmod -v ugo-x /mnt/ZPool-ZFS/OS
chown -v -R xe1phix /mnt/ZPool-ZFS/OS


chmod -v ugo-x /mnt/ZPool-ZFS/OS
chown -v -R xe1phix /mnt/ZPool-ZFS/OS


chmod -v ugo-x /mnt/ZPool-ZFS/OS
chown -v -R xe1phix /mnt/ZPool-ZFS/OS










zfs set checksum=sha256 ZPool-ZFS/Scripts

zfs set exec=off ZPool-ZFS/Scripts
zfs set compression=zls ZPool-ZFS/Scripts
zfs set zoned=on ZPool-ZFS/Scripts
zfs set acltype=posixacl ZPool-ZFS/Scripts
zfs set setuid=off ZPool-ZFS/Scripts
zfs set vscan=on ZPool-ZFS/Scripts
zfs allow -s ZPool-ZFS/Scripts
zfs allow cindys create,destroy,mount,snapshot tank/cindys


snapdir
aclmode
aclinherit



exec=off
zoned=on
aclmode=
aclinherit=
mlslabel=

zfs set sync=always



zfs set exec=off ZPool-ZFS/Xe1phixGitLab
zfs set zoned=on ZPool-ZFS/Xe1phixGitLab
zfs set exec=off ZPool-ZFS/BrowntownAlpha
zfs set copies=2 ZPool-ZFS/Xe1phixGitLab
zfs set exec=off ZPool-ZFS/Scripts
zfs set readonly=on ZPool-ZFS/Scripts
zfs set compression=on ZPool-ZFS/Scripts
zfs set zoned=on ZPool-ZFS/Scripts
zfs set compression=on ZPool-ZFS/Wordlists

zfs get compressratio

zfs set acltype=posixacl 



zpool set comment="Contact Xe1phix@mail.i2p" ZPool-ZFS
zpool get comment ZPool-ZFS

zfs set snapdir=visible ZPool-ZFS


zpool list 


zpool export -f 
unmount -f
--log-uberblocks
--fuse-mount-options
--enable-xattr

zfs userspace 
zfs userspace -n                ## Print numeric ID instead of user/group name.
-t                      ## Print the type
all,posixuser,smbuser,posixgroup,smbgroup

-o type,name,used,quota


zfs groupspace -t posixgroup




zfs allow perm|@setname[,...] filesystem|volume
zfs allow -s @setname perm|@setname

zonecfg add fs
zonecfg add dataset
zonecfg add device

zfs mount 
zfs unmount 




zpool get health ZPool-ZFS
zpool status -v ZPool-ZFS
zpool status -x
zpool status -T d 3 2

zpool history -l ZPool-ZFS
zpool history -i ZPool-ZFS

zpool status ZPool-ZFS
zpool get health ZPool-ZFS
zpool get health,free,allocated ZPool-ZFS
zpool get all ZPool-ZFS
zfs list -t all -o name,used,refer,written
zfs get used,available,compressratio ZPool-ZFS


zfs create -V 1G tank/swap
mkswap /dev/zvol/tank/swap
swapon /dev/zvol/tank/swap

zpool create -f -m /mnt/ZPool-ZFS ZPool-ZFS /dev/sdc
zfs set checksum=sha256 ZPool-ZFS                     ## Controls the checksum used to verify data integrity.
zfs get checksum

zfs set xattr=on ZPool-ZFS
zfs get xattr

zfs list -o name,avail,used,usedsnap,usedds,usedrefreserv,usedchild 
zfs list -o mountpoint,mounted,
zfs list -o name,mounted



zfs create ZPool-ZFS/Xe1phixGitLab
zfs get all ZPool-ZFS/Xe1phixGitLab

zfs set snapdir=visible ZPool-ZFS

sha256,verify


copies=2
compression=on
compression=lzjb


zfs snap ZPool-ZFS/Xe1phixGitLab@backup
zfs list -t snapshot


zfs snapshot -r ZPool-ZFS/Xe1phixGitLab@today
zfs clone ZPool-ZFS/Xe1phixGitLab@today ZPool-ZFS/Xe1phixGitLabBackup
zfs promote ZPool-ZFS/Xe1phixGitLabBackup
zfs rename 

## reverts the contents of ZPool-ZFS/Audio 
##   to the snapshot named yesterday
zfs rollback -r ZPool-ZFS/Xe1phixGitLab@yesterday
zfs snapshot -r ZPool-ZFS/Xe1phixGitLab@yesterday


zfs get -r all
zfs get -r -H all

name,property,value,source

echo "##-========================================================-##"
echo "    [+] the corruption will be automatically be repaired,     "
echo "        and noted in the status screen.                       "
echo "##-========================================================-##"

echo "##-============================================================-##"
echo "    [+] You can also initiate a manual scan                       "
echo "        of all data on the drive to check for corruption:         "
echo "##-============================================================-##"
zpool scrub zfs



echo "##-==========================================================-##"
echo "    [?] All storage is combined into a common pool              "
echo "    [?] That is then used to create one or more datasets.       "
echo "##-==========================================================-##"

echo "##-=====================================================================-##"
echo "    [?] The zfs daemon can import and mount zfs pools automatically.       "
echo "    [?] The daemon mounts the zfs pools reading the file:                  "
echo "##-=====================================================================-##"
/etc/zfs/zpool.cache

echo "##-====================================================-##"
echo "    [+] For each pool you want automatically              "
echo "        mounted by the zfs daemon execute:                "
echo "##-====================================================-##"
zpool set cachefile=/etc/zfs/zpool.cache ZPool-ZFS

zpool set cachefile=/var/lib/zfs/zpool.cache ZPool-ZFS

echo "##-====================================-##"
echo "    [+] Adaptive Replacement Cache        "
echo "##-====================================-##"

## add an L2ARC to your existing zpool, we might do:
zpool add ZPool-ZFS cache /tutorial/ssd


echo "##-====================================================-##"
echo "    [+] L2ARC is a caching "layer" between the RAM        "
echo "##-====================================================-##"
(very fast) and the disks (not so fast).


zfs create -b 512 -o xattr=on -o checksum=sha256 -V 12G /dev/sdd
fdisk /dev/tank/ext4

# mkfs.ext4 /dev/zd0p1
# mkfs.ext4 /dev/zd0p2
# mkdir /mnt/zd0p{1,2}
# mount /dev/zd0p1 /mnt/zd0p1
# mount /dev/zd0p2 /mnt/zd0p2

zfs mount ZPool-ZFS
zfs mount -o rw ZPool-ZFS/BrowntownAlpha
zfs mount -o remount,rw ZPool-ZFS/BrowntownAlpha
zfs mount -o remount,ro ZPool-ZFS/Scripts
zfs mount -O ZPool-ZFS/Xe1phixGitLab                   ## overlay mount
zfs unmount ZPool-ZFS/Scripts

zfs get all
zfs get all ZPool-ZFS

chmod -v ugo+rwx /mnt/ZPool-ZFS

zfs set compression=lzjb pool/ext4
zfs snapshot tank/ext4@001

zfs create ZPool-ZFS/log
zfs set exec=off ZPool-ZFS/log
zfs set compression=lz4 ZPool-ZFS/log
zfs get compressratio ZPool-ZFS/log
zfs set dedup=on ZPool-ZFS/test
zpool get dedupratio ZPool-ZFS
zfs set xattr=on ZPool-ZFS
zfs snapshot ZPool-ZFS/test@tuesday
zfs set compression=lzjb ZPool-ZFS/dir@friday

echo "##-=============================-##"
echo "    [+] Creating a bookmark:      "
echo "##-=============================-##"
zfs bookmark ZPool-ZFS/Xe1phixGitLab/GnuPG@snapshot zfs#bookmark
zfs bookmark ZPool-ZFS/Xe1phixGitLab@snapshot zfs#bookmark

echo "##-=============================================-##"
echo "    [+] list All bookmarks in the pool: "
echo "##-=============================================-##"
zfs list -t bookmark -r ZPool-ZFS




zfs get mountpoint 
zfs get mounted 

zfs set mountpoint=/mnt/ZPool-ZFS ZPool-ZFS/


zfs set mountpoint=legacy ZPool-ZFS/dir/dir
mount -F zfs ZPool-ZFS/dir/dir /mnt/ZPool-ZFS

zfs mount | grep ZPool-ZFS/dir
zfs mount ZPool-ZFS/dir/dir
mount -F zfs ZPool-ZFS/dir/dir

zfs mount -o ro ZPool-ZFS
zfs mount -o remount,rw ZPool-ZFS

zfs unmount ZPool-ZFS/dir/dir
zfs unmount -f ZPool-ZFS/dir/dir
umount /mnt/ZPool-ZFS




zfs set aclinherit=restricted
zfs set aclinherit=

zfs set compression=lzjb
zfs set compression=gzip

zfs set quota=50G ZPool-ZFS/$Dir

zfs set copies=2

zfs set exec=off ZPool-ZFS/Scripts
zfs set readonly=on ZPool-ZFS/
zfs set vscan=on ZPool-ZFS/
zfs set xattr=on ZPool-ZFS



zfs set snapdir=visible ZPool-ZFS/
zfs list -t snapshot
zfs list -r -t snapshot ZPool-ZFS

zfs clone ZPool-ZFS/test@tuesday ZPool-ZFS/tuesday
dd if=/dev/zero of=/tank/tuesday/random.img bs=1M count=100
zfs list -r ZPool-ZFS

zpool status
zpool status -v
zfs get all ZPool-ZFS
zfs list -o name,avail,used,usedsnap,usedds,usedrefreserv,usedchild 

zfs list -t filesystem,volume,all
modprobe zfs

/etc/modprobe.d/zfs.conf
## --------------------------------------------------------------------------------------------------------------- ##
    options scsi_mod scan=sync
## --------------------------------------------------------------------------------------------------------------- ##

/etc/fstab
## --------------------------------------------------------------------------------------------------------------------- ##
    /mnt/zfspool		/srv/nfs4/music		none	bind,defaults,nofail,x-systemd.requires=zfs-mount.service	0 0
## --------------------------------------------------------------------------------------------------------------------- ##


systemctl enable zfs.target
systemctl start zfs.target

systemctl enable zfs-import-cache
systemctl enable zfs-mount
systemctl enable zfs-import.target


echo "##-============================================-##"
echo "           [+] use ACL on a ZFS pool:             "
echo "##-============================================-##"
zfs set acltype=posixacl <nameofzpool>/<nameofdataset>
zfs set xattr=sa <nameofzpool>/<nameofdataset>
zfs set acltype=posixacl rpool/vztmp


zfs set dedup=verify
zfs set checksum=sha256,verify

zfs get checksum
zfs set checksum=sha256 tank

zfs set xattr=on ZPool-ZFS

zfs set mountpoint=/mnt/ZPool-ZFS ZPool-ZFS

zfs create ZPool-ZFS/log




zfs set compression=on ZPool-ZFS/
zfs create -o compression=gzip tank/test/one

-o feature@sha512=enabled
-o primarycache=metadata
-o logbias=throughput

zfs set quota=20G <nameofzpool>/<nameofdataset>/<directory>

zfs set sync=disabled <pool>/tmp


zpool add <pool> log <device-id>
zpool add <pool> log mirror <device-id-1> <device-id-2>


zfs set setuid=off <pool>/tmp
zfs set devices=off <pool>/tmp


zfs create -o setuid=off -o devices=off -o sync=disabled -o mountpoint=/tmp <pool>/tmp




systemctl mask tmp.mount


zfs create -o encryption=on -o keyformat=passphrase <nameofzpool>/<nameofdataset>

echo "##-=============================================================================-##"
echo "           [+] use a key instead of using a passphrase:	   				        "
echo "##-=============================================================================-##"

dd if=/dev/urandom of=/path/to/key bs=1 count=32
zfs create -o encryption=on -o keyformat=raw -o keylocation=file:///path/to/key <nameofzpool>/<nameofdataset>

echo "##-=============================================================================-##"
echo "           [+] manually load the keys and then mount the encrypted dataset:	   	"
echo "##-=============================================================================-##"

zfs load-key <nameofzpool>/<nameofdataset>      # load key for a specific dataset
zfs load-key -a                                   # load all keys
zfs load-key -r zpool/dataset                   # load all keys in a dataset


zpool import -l pool

echo "##-=============================================================================-##"
echo "           [+] automate this at boot with a custom systemd unit:	   				"
echo "##-=============================================================================-##"

/etc/systemd/system/zfs-key@.service

[Unit]
Description=Load storage encryption keys
DefaultDependencies=no
Before=systemd-user-sessions.service
Before=zfs-mount.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/bash -c 'systemd-ask-password "Encrypted storage password (%i): " | /usr/bin/zfs load-key zpool/%i'

[Install]
WantedBy=zfs-mount.service




echo "##-=============================================================================-##"
echo "                      [+] Create an encrypted home:                               "
echo "      (the two passwords, encryption and login, must be the same)	   				"
echo "##-=============================================================================-##"

zfs create -o compression=off -o dedup=off -o mountpoint=/home/<username> <zpool>/<username>
useradd -m <username>
passwd <username>
ecryptfs-migrate-home -u <username>

echo "##-=============================================================================-##"
echo "    [+] <log in user and complete the procedure with ecryptfs-unwrap-passphrase>	  "
echo "##-=============================================================================-##"



zfs snapshot ZPool-ZFS/project/production@today

zfs rollback -r ZPool-ZFS/home/anne@yesterday


zfs clone ZPool-ZFS/home/bob@yesterday ZPool-ZFS/clone

zfs inherit checksum ZPool-ZFS/home/bob ZPool-ZFS/home/anne


zfs allow cindys create,destroy,mount,snapshot 
zfs allow -s @pset create,destroy,snapshot,mount ZPool-ZFS/users

chmod A+user:cindys:add_subdirectory:allow /tank/cindys


zfs allow staff create,mount ZPool-ZFS/users

zfs allow -c destroy ZPool-ZFS/users



echo "##-=============================================================================-##"
echo "           [+] ZFS pools should be scrubbed at least once a week:	   				"
echo "##-=============================================================================-##"

zpool scrub ZPool-ZFS

echo "##-=============================================================================-##"
echo "           [+] automatic scrubbing once a week, add this to crontab:	   				"
echo "##-=============================================================================-##"

crontab -e



30 19 * * 5 zpool scrub ZPool-ZFS


## scrub every Sunday at 02:00 in the morning:
0 2 * * 0 /sbin/zpool scrub ZPool-ZFS



zpool get listsnapshots
zpool set listsnapshots=on ZPool-ZFS


ls /tank/home/cindy/.zfs/snapshot
zfs list -t snapshot -r ZPool-ZFS/dir

zfs list -r -t snapshot -o name,creation ZPool-ZFS/Xe1phixGitLab

zfs list -o space -r ZPool-ZFS

zfs snapshot ZPool-ZFS/Xe1phixGitLab@yesterday
zfs clone ZPool-ZFS/Xe1phixGitLab@yesterday

zfs snapshot ZPool-ZFS/Xe1phixGitLab@today
zfs clone ZPool-ZFS/Xe1phixGitLab@today

zfs clone ZPool-ZFS/Xe1phixGitLab@yesterday zfs/Xe1phixGitLab-backup

echo "##-=============================================================================-##"
echo "           [+] Create snapshots for all descendent file systems (-r ):	   		"
echo "##-=============================================================================-##"

zfs snapshot -r ZPool-ZFS/dir@snap1
zfs list -t snapshot -r ZPool-ZFS/dir

zfs set compression=on ZPool-ZFS/dir/dir@friday

zfs snapshot -r ZPool-ZFS/dir/dir@now
zfs hold -r keep ZPool-ZFS/dir/dir@now

zfs holds -r ZPool-ZFS/dir/dir@now
zfs release -r keep ZPool-ZFS/dir/dir@now
zfs destroy -r ZPool-ZFS/dir/dir@now

zfs rename ZPool-ZFS/dir/dir@snap1 ZPool-ZFS/dir/dir@today
zfs rename ZPool-ZFS/dir/dir@snap1 today
zfs rename -r ZPool-ZFS/home@yesterday @2daysago

zfs list -t snapshot -r ZPool-ZFS/dir






















echo "##-=================================-##"
echo "    [+] This is a local backup:        "
echo "##-=================================-##"
zfs snapshot ZPool-ZFS/myfiles@backup
zfs send ZPool-ZFS/myfiles@backup > /mnt/filesystem-backup


echo "##-=============================================-##"
echo "    [+] Restore the backup from the file:          "
echo "##-=============================================-##"
zfs receive -v ZPool-ZFS/myfiles < /mnt/filesystem-backup



echo "##-============================================-##"
echo "    [+] Copy that snapshot to a remote server:     "
echo "##-============================================-##"
zfs send ZPool-ZFS/myfiles@backup | ssh you@remoteserver zfs receive -v otherpool/myfiles


echo "##-=====================================================================-##"
echo "    [+] Its also possible to do incremental data (changes to snapshot):    "
echo "##-=====================================================================-##"
zfs send -i ZPool-ZFS/myfiles@backup ZPool-ZFS/myfiles@laterbackup | ssh you@remoteserver zfs receive -v otherpool/myfiles








zfs send ZPool-ZFS/test@tuesday | xz | openssl enc -aes-256-cbc -a -salt > /backup/test-tuesday.img.xz.asc


zfs send ZPool-ZFS/test@tuesday | xz > /backup/test-tuesday.img.xz


zfs receive ZPool-ZFS/test2 < /backup/test-tuesday.img


openssl enc -d -aes-256-cbc -a -in /storage/temp/testzone.gz.ssl | unxz | zfs receive ZPool-ZFS/test2


zfs send ZPool-ZFS/test@tuesday | zfs receive ZPool-ZFS/test


zfs send ZPool-ZFS/test@tuesday | ssh user@server.example.com "zfs receive ZPool-ZFS/test"














echo "##-=====================================================================-##"
echo "    [+] rename the zfs/olddata dataset "

to reflect that its an old copy of the data

zfs rename ZPool-ZFS/newdata ZPool-ZFS/olddata

zfs rename

zfs set quota=5G 


zfs get reservation
zfs set reservation=5G ZPool-ZFS/dir/dir
zfs set reservation=10G ZPool-ZFS/dir/dir


zfs set refreservation=10g ZPool-ZFS/dir/dir

zfs get reservation,refreserv 


zfs set dept:users=xe1phix ZPool-ZFS/user1
zfs set dept:users=log ZPool-ZFS/user2
zfs set dept:users=scripts ZPool-ZFS/user3
zfs set dept:users=scripts ZPool-ZFS/user3
zfs set dept:users=Pr0n ZPool-ZFS/Pr0n
zfs set dept:users=webm ZPool-ZFS/BrowntownAlpha/AnonOS/4chan/webm-2.0
BrowntownAlpha
OS
VirtualBox VMs
zfs set dept:users= ZPool-ZFS/Xe1phixGitLab/GnuPG
/Xe1phixGitLab/Xe1phix-Firejail

GnuPG-CryptoPartyWorkshop
Xe1phixGitLabProjects
ZPool-ZFS/Xe1phixGitLab/Xe1phixGitLabProjects/Stable/ParrotLinux-Public-Kios-Project
echo "##-===============================================================-##"
echo "           [+] clear a user property, use zfs inherit:       		"
echo "##-===============================================================-##"         
zfs inherit -r dept:users ZPool-ZFS



zfs get -r dept:users ZPool-ZFS/dir



echo "##-=====================================================================-##"
echo "    [+] Controls  whether regular files should be scanned for viruses 
when a file is opened and closed
vscan=on




echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"
echo "   		                                        "
echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"

echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=##"
echo "   		                                                                "
echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=##"
         




echo "##-================================================================================================-##"
echo "     [?] the contents of highly-compressible blocks are stored in the $Block_Pointer itself          "
echo "         (it contains the compresseed data, rather than a pointer to its location on disk).           "
echo "         Thus the space of the block (one sector, typically 512 bytes or 4KB)                         "
echo "         is saved, and no additional i/o is needed to read and write the data block.                  "
echo "##-================================================================================================-##"



echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"
echo "   		                   [+]  Deduplication                                   "
echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"
echo "##-===========================================================================-##"
echo "     [?] deduplication allows you to store the same data multiple times,         "
echo "              but only take up the space of a single copy.                       "
echo "## --------------------------------------------------------------------------- ##"
echo "     [?] Data can be deduplicated on the file, block, or byte level              "
echo "##-===========================================================================-##"


echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=##"
echo "   		                       File deduplication                                         "
echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=##"
echo "##-========================================================================================-##"
echo "      Each file is hashed with a cryptographic hashing algorithm, such as SHA-256.            "
echo "      If the hash matches for multiple files, rather than storing the new file on disk,       "
echo "      We reference the original file in the metadata.                                         "
echo "      If a single bytechanges in the file, the hashes will no longer match.                   "
echo "      This means we can no longer reference the whole file in the filesystem metadata.	    "
echo "##-========================================================================================-##"




echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=##"
echo "   		                          byte deduplication                                         "
echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=##"
echo "##-========================================================================================-##"
echo "            "
echo "            "
echo "            "
echo "            "
echo "            "
echo "##-========================================================================================-##"





echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"
echo "   		                                  block deduplication                                               "
echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"
echo "##-=========================================================================================================-##"
echo "      Block deduplication shares all the same blocks in a file, minus the blocks that are different.           "
echo "      This allows us to store only the unique blocks on disk, and reference the shared blocks in RAM.          "
echo "      because filesystems read and write data in block segments,                                               "
echo "      it makes the most sense to use block deduplication for a modern filesystem.                              "
echo "      The shared blocks are stored in whats called a "deduplication table".		                             "
echo "##-=========================================================================================================-##"




zfs set dedup=on 
zpool get dedupratio




echo "##-=========================================================-##"
echo "     [?] If youre paranoid about hash collisions,             "
echo "         you might want to use extra verification             "
echo "##-=========================================================-##"

zfs set dedup=verify ZPool-ZFS/
zfs set checksum=sha256,verify ZPool-ZFS/


parted /dev/sda mklabel gpt mkpart primary zfs 0 5G
parted /dev/sdb mklabel gpt mkpart primary zfs 0 5G
zpool add tank log mirror /dev/disk/by-id/ata-OCZ-REVODRIVE_OCZ-69ZO5475MT43KNTU-part1 /dev/disk/by-id/ata-OCZ-REVODRIVE_OCZ-9724MG8BII8G3255-part1


zpool add pool log mirror ata-OCZ-REVODRIVE_OCZ-33W9WE11E9X73Y41-part1 ata-OCZ-REVODRIVE_OCZ-X5RG0EIY7MN7676K-part
zpool add pool cache ata-OCZ-REVODRIVE_OCZ-33W9WE11E9X73Y41-part2 ata-OCZ-REVODRIVE_OCZ-X5RG0EIY7MN7676K-part2

zfs set secondarycache=metadata pool
zpool add -f pool cache usb-Kingston_DataTraveler_G3_0014780D8CEBEBC145E80163-0:0\


zpool add zfs cache ZPool-ZFS/
zpool add zfs log ZPool-ZFS/
zpool add zfs log mirror /tutorial/file7 /tutorial/file8


zpool set autoexpand=on

zfs rename ZPool-ZFS/Temp ZPool-ZFS/Pr0n
zfs destroy ZPool-ZFS/Scripts

zfs set copies=2 ZPool-ZFS/

zfs set compression=gzip

zfs umount ZPool-ZFS/

echo "##-===============================================================-##"
echo "              [+] To restore the backup from a file:	   				"
echo "##-===============================================================-##"
zfs receive -v mypool/myfiles < /mnt/filesystem-backup


echo "##-===============================================================-##"
echo "           [+] copy the snapshot to a remote server (offsite backup)."
echo "##-===============================================================-##"
zfs send ZPool-ZFS/myfiles@backup | ssh you@remoteserver zfs receive -v otherpool/myfiles



zpool create zfs_test mirror /var/lib/zfs_img/zfs0.img /var/lib/zfs_img/zfs1.img

echo "##-===============================================================-##"
echo "           [+] Create a pool with RAIDZ1 and three hard drives:	   "
echo "##-===============================================================-##"
zpool create zfs_test raidz1 /var/lib/zfs_img/zfs0.img /var/lib/zfs_img/zfs1.img /var/lib/zfs_img/zfs2.img


echo "##-=========================================================-##"
echo "     [+] create a pool with RAIDZ2 and four hard drives:	 "
echo "##-=========================================================-##"
zpool create zfs_test raidz2 /var/lib/zfs_img/zfs0.img /var/lib/zfs_img/zfs1.img /var/lib/zfs_img/zfs2.img /var/lib/zfs_img/zfs3.img


echo "##-============================================================-##"
echo "    [+] Create a STRIPED MIRRORED pool with four hard drives:		"
echo "##-============================================================-##"
zpool create zfs_test mirror /var/lib/zfs_img/zfs0.img /var/lib/zfs_img/zfs1.img mirror /var/lib/zfs_img/zfs2.img /var/lib/zfs_img/zfs3.img


echo "##-=====================================================================-##"
echo "    [+] To grow a mirror, expansion will need to be set on the pool.      "
echo "##-=====================================================================-##"
zpool set autoexpand=on ZPool-ZFS




zfs set snapdir=visible ZPool-ZFS/

zfs list -t snapshot -o name,creation


echo "##-=====================================================================-##"
echo "    [+] ZFS can clone snapshots to new volumes,                           "
echo "        so you can access the files from previous states individually:	"
echo "##-=====================================================================-##"
man zfs clone zfs_test/volume1@21082011 zfs_test/volume1_restore


zpool history


echo "##-=====================================================================-##"
echo "    [+] Monitor I/O activity on all zpools (refreshes every 6 seconds):	 "
echo "##-=====================================================================-##"

zpool iostat 6

zpool iostat ZPool-ZFS 2

zpool iostat -v

echo "##-=============================================-##"
echo "    [+] refreshes every 4 secs, 5 intervals:	    "
echo "##-=============================================-##"
zpool iostat ZPool-ZFS -v 4 5




zfs diff -e ZPool-ZFS/cindy@yesterday ZPool-ZFS/cindy@now


zfs diff -e -o size -o name ZPool-ZFS/cindy@yesterday ZPool-ZFS/cindy@now


zpool export ZPool-ZFS


zpool import


zpool create dozer mirror /file/a /file/b
zpool export dozer
zpool import -d /file
zpool import -d /file dozer

echo "##-============================================-##"
echo "    [+] Importing a Pool in Read-Only Mode	    "
echo "##-============================================-##"
zpool import -o readonly=on



zfs rollback ZPool-ZFS/home/cindy@tuesday
zfs rollback -r ZPool-ZFS/home/cindy@tuesday

zfs list -r -t snapshot -o name,creation tank/home/cindy

zfs snapshot ZPool-ZFS/Xe1phixGitLab@snap1
zfs snapshot ZPool-ZFS/Xe1phixGitLab@snap2

zfs diff ZPool-ZFS/Xe1phixGitLab@snap1 ZPool-ZFS/Xe1phixGitLab@snap2




echo "##-============================================================-##"
echo "    [+] Copy the partition table from /dev/sda to /dev/sdb:       "
echo "##-============================================================-##"
sgdisk --replicate=/dev/sdb /dev/sda


echo "##-==============================================================-##"
echo "    [?] Ensure the GUIDs are randomized otherwise the kernel        "
echo "        and ZFS will get really, really confused:                   "
echo "##-==============================================================-##"
sgdisk --randomize-guids /dev/sdb



zfs list -r ZPool-ZFS/



@eng (create, destroy, snapshot, mount, clone, promote, rename)
@simple (create, mount)


zfs allow staff create,mount ZPool-ZFS/home
zfs allow -c create,destroy ZPool-ZFS/home
zfs allow -c destroy,snapshot ZPool-ZFS/home

zfs allow -s @myset create,destroy,mount,snapshot,promote,clone,readonly ZPool-ZFS
zfs allow ZPool-ZFS
zfs allow staff @myset,rename ZPool-ZFS/home
zfs allow ZPool-ZFS/home

chmod A+group:staff:add_subdirectory:fd:allow ZPool-ZFS

zfs unallow cindy snapshot ZPool-ZFS/home/dir

zfs snapshot ZPool-ZFS/@today


zfs allow ZPool-ZFS
## -------------------------------------------------------------------##
## Permission sets:
##      @myset clone,create,destroy,mount,promote,readonly,snapshot
## Create time permissions:
##      create,destroy,mount
## Local+Descendent permissions:
##      group staff create,mount
## -------------------------------------------------------------------##
zfs unallow -s @myset ZPool-ZFS
zfs allow ZPool-ZFS


zfs list -o name,zoned,mountpoint -r

zpool get delegation ZPool-ZFS
zpool set delegation=on ZPool-ZFS

echo "##-=====================================================================-##"
echo "    [?] Controls whether a non-privileged user is granted access based     "
echo "        on the dataset permissions defined on the dataset.                 "
echo "##-=====================================================================-##"
delegation=on




chmod [options] A[index]{+|=}owner@ |group@
|everyone@:access-permissions/...[:inheritance-flags]:deny | allow file
chmod [options] A-owner@, group@,
everyone@:access-permissions/...[:inheritance-flags]:deny | allow file ...

chmod [options]
A[index]{+|=}user|group:name:access-permissions/...[:inheritance-flags]:deny | allow file
chmod [options] A-user|group:name:access-permissions/...[:inheritance-flags]:deny |
allow file ...


owner@, group@, everyone@

echo "##-=====================================================================-##"
echo "    [+] Identifies the ACL-entry-type for trivial ACL syntax.		         "
echo "##-=====================================================================-##"


echo "##-=====================================================================-##"
echo "    [+] user or group:ACL-entry-ID=username or groupname                   "
echo "##-----------------------------------------------------------------------##"
echo "    [+] Identifies the ACL-entry-type For explicit ACL syntax.             "
echo "##-----------------------------------------------------------------------##"
echo "    [+] The user and group ACL-entry-type must also contain                "
echo "##-----------------------------------------------------------------------##"
echo "    [+] the ACL-entry-ID, username or groupname		                     "
echo "##-=====================================================================-##"

access-permissions/.../ Identifies the access permissions that are granted or denied.

inheritance-flags       Identifies an optional list of ACL inheritance flags.

deny | allow            Identifies whether the access permissions are granted or denied




echo "#+===========+#                                                                                      "
echo " |           |-===================================================================================-##"
echo " |    owner@ |    The $Owner can $Read and $Modify the contents of the $file                         "
echo " |           |     (rw=read_data/write_data), (p=append_data)                                        "
echo " |-----------|-------------------------------------------------------------------------------------##"
echo " |           |     The $Owner can also $Modify the Files $Attributes such as                         "            
echo " |           |     [$Timestamps, Extended Attributes (xattr), and $ACLs]                             " 
echo " |           |     [a=Read_Attributes, W=Write_xattr, R=Read_xattr]                                  " 
echo " |           |     [A=Write_Attributes, c=Read_Acl, C=Write_Acl]                                     " 
echo " |-----------|-------------------------------------------------------------------------------------##"
echo " |           |     In addition, the $owner can $modify                                               " 
echo " |           |     the $ownership of the $file (o=write_owner).                                      " 
echo " |-=========-|-===================================================================================-##"
echo " |    group@ |    The group is granted $Read permissions to the $File (r=read_data)                  " 
echo " | =====     |     As well as the $files $attributes                                                 " 
echo " |      \___ |     (a=read_attributes, R=read_xattr, c=read_acl).                                    " 
echo " | ========= |-===================================================================================-##"
echo " | everyone@ |    Everyone who is not user or group is granted read permissions                      " 
echo " | ====      |    to the file and the files attributes                                               " 
echo " |     \_    |    (r=read_data, a=append_data, R=read_xattr, c=read_acl,and s=synchronize).          " 
echo " |       \__ |-===================================================================================-##"
echo "#+===========+#                                                                                       "





chmod A1=group@:read_data/write_data:allow file

    0:owner@:read_data/write_data/append_data/read_xattr/write_xattr/read_attributes/write_attributes/read_acl/write_acl/write_owner/synchronize:allow
    1:group@:read_data/write_data:allow
    2:everyone@:read_data/read_xattr/read_attributes/read_acl/synchronize:allow


chmod 644 file

    0:owner@:read_data/write_data/append_data/read_xattr/write_xattr/read_attributes/write_attributes/read_acl/write_acl/write_owner/synchronize:allow
    1:group@:read_data/read_xattr/read_attributes/read_acl/synchronize:allow
    2:everyone@:read_data/read_xattr/read_attributes/read_acl/synchronize:allow



echo "##-============================================================-##"
echo "    [+] read_data/execute permissions are added for the user		"
echo "##-============================================================-##"

chmod A+user:gozer:read_data/execute:allow test.dir

    0:user:gozer:list_directory/read_data/execute:allow
    1:owner@:list_directory/read_data/add_file/write_data/add_subdirectory/append_data/read_xattr/write_xattr/execute/delete_child/read_attributes/write_attributes/read_acl/write_acl/write_owner/synchronize:allow
    2:group@:list_directory/read_data/read_xattr/execute/read_attributes/read_acl/synchronize:allow
    3:everyone@:list_directory/read_data/read_xattr/execute/read_attributes/read_acl/synchronize:allow



echo "##-============================================================-##"
echo "    [+] read_data/execute permissions are removed for user		"
echo "##-============================================================-##"

chmod A0- test.dir

    0:owner@:list_directory/read_data/add_file/write_data/add_subdirectory/append_data/read_xattr/write_xattr/execute/delete_child/read_attributes/write_attributes/read_acl/write_acl/write_owner/synchronize:allow
    1:group@:list_directory/read_data/read_xattr/execute/read_attributes/read_acl/synchronize:allow
    2:everyone@:list_directory/read_data/read_xattr/execute/read_attributes/read_acl/synchronize:allow



echo "##-============================================================-##"
echo "    [+] ACL allow permissions are removed from everyone@		    "
echo "##-============================================================-##"

chmod A2- file

    0:owner@:read_data/write_data/append_data/read_xattr/write_xattr/read_attributes/write_attributes/read_acl/write_acl/write_owner/synchronize:allow
    1:group@:read_data/read_xattr/read_attributes/read_acl/synchronize:allow



echo "##-============================================-##"
echo "    [+] the existing ACL is replaced with         "
echo "        read_data/write_data permissions          "
echo "              for everyone@.		                "
echo "##-============================================-##"

chmod A=everyone@:read_data/write_data:allow file

    0:everyone@:read_data/write_data:allow



echo "##-=====================================================================-##"
echo "    [+] the existing ACL is replaced with read permissions for user		 "
echo "##-=====================================================================-##"

chmod A=user:gozer:read_data:allow file

    0:user:gozer:read_data:allow


chmod 655 file

    0:owner@:execute:deny
    1:owner@:read_data/write_data/append_data/read_xattr/write_xattr/read_attributes/write_attributes/read_acl/write_acl/write_owner/synchronize:allow
    2:group@:read_data/read_xattr/execute/read_attributes/read_acl/synchronize:allow
    3:everyone@:read_data/read_xattr/execute/read_attributes/read_acl/synchronize:allow




echo "##-=========================================================-##"
echo "    [+] read_data/write_data permissions are added             "
echo "        to files in the test2.dir directory.                   "
echo "        This is done for user gozer so that he has             "
echo "        read access on any newly created files.		         "
echo "##-=========================================================-##"

chmod A+user:gozer:read_data/write_data:file_inherit:allow test2.dir

    0:user:gozer:list_directory/read_data/add_file/write_data/execute:allow
    1:owner@:list_directory/read_data/add_file/write_data/add_subdirectory/append_data/read_xattr/write_xattr/execute/delete_child/read_attributes/write_attributes/read_acl/write_acl/write_owner/synchronize:allow
    2:group@:list_directory/read_data/read_xattr/execute/read_attributes/read_acl/synchronize:allow
    3:everyone@:list_directory/read_data/read_xattr/execute/read_attributes/read_acl/synchronize:allow




echo "##-========================================================-##"
echo "    [+] a non-trivial ACE of read_data/write_data/execute     "
echo "        is applied for user gozer on test.dir.		        "
echo "##-========================================================-##"

chmod A+user:gozer:read_data/write_data/execute:allow test.dir

    0:user:gozer:read_data/write_data:file_inherit:allow
    1:owner@:list_directory/read_data/add_file/write_data/add_subdirectory/append_data/read_xattr/write_xattr/execute/delete_child/read_attributes/write_attributes/read_acl/write_acl/write_owner/synchronize:allow
    2:group@:list_directory/read_data/read_xattr/execute/read_attributes/read_acl/synchronize:allow
    3:everyone@:list_directory/read_data/read_xattr/execute/read_attributes/read_acl/synchronize:allow




echo "##-=====================================================================-##"
echo "    [+] user gozer is granted read, write, and execute permissions        "
echo "        that are inherited for newly created files and directories.		"
echo "##-====================================================================-##"

chmod A+user:gozer:read_data/write_data/execute:file_inherit/dir_inherit:allow


    0:user:gozer:list_directory/read_data/add_file/write_data/execute:file_inherit/dir_inherit:allow
    1:owner@:list_directory/read_data/add_file/write_data/add_subdirectory/append_data/read_xattr/write_xattr/execute/delete_child/read_attributes/write_attributes/read_acl/write_acl/write_owner/synchronize:allow
    2:group@:list_directory/read_data/read_xattr/execute/read_attributes/read_acl/synchronize:allow
    3:everyone@:list_directory/read_data/read_xattr/execute/read_attributes/read_acl/synchronize:allow


echo "##-======================================================================-##"
echo "    [+] user gozer is granted read, write, and execute permissions          "
echo "        that are inherited for newly created files,                         "
echo "    [?] but are not propagated to subsequent contents of the directory.     "	
echo "##-======================================================================-##"

chmod A+user:gozer:read_data/write_data/execute:file_inherit/no_propagate:allow test4.dir

    0:user:gozer:list_directory/read_data/add_file/write_data/execute:file_inherit/no_propagate:allow
    1:owner@:list_directory/read_data/add_file/write_data/add_subdirectory/append_data/read_xattr/write_xattr/execute/delete_child/read_attributes/write_attributes/read_acl/write_acl/write_owner/synchronize:allow
    2:group@:list_directory/read_data/read_xattr/read_attributes/read_acl/synchronize:allow
    3:everyone@:list_directory/read_data/read_xattr/read_attributes/read_acl/synchronize:allow




echo "##-=====================================================================-##"
echo "    [+] ACL Inheritance With ACL Inherit Mode Set to Pass Through	   	"
echo "##-=====================================================================-##"

echo "##-============================================================-##"
echo "    [+] If the aclinherit property on the tank/cindy              "
echo "        file system is set to passthrough.                        "
echo "        then user gozer would inherit the ACL applied             "
echo "        on test4.dir for the newly created file                   "
echo "##-============================================================-##"




zfs set aclinherit=passthrough ZPool-ZFS/dir

0:user:gozer:read_data:allow
1:owner@:read_data/write_data/append_data/read_xattr/write_xattr/read_attributes/write_attributes/read_acl/write_acl/write_owner/synchronize:allow
2:group@:read_data/read_xattr/read_attributes/read_acl/synchronize:allow
3:everyone@:read_data/read_xattr/read_attributes/read_acl/synchronize:allow



echo "##-=====================================================================-##"
echo "    [+] ACL Inheritance With ACL Inherit Mode Set to Discard	   				"
echo "##-===============================================================-##"


zfs set aclinherit=discard tank/cindy
chmod A+user:gozer:read_data/write_data/execute:dir_inherit:allow test5.dir

0:user:gozer:list_directory/read_data/add_file/write_data/execute:dir_inherit:allow
1:owner@:list_directory/read_data/add_file/write_data/add_subdirectory/append_data/read_xattr/write_xattr/execute/delete_child/read_attributes/write_attributes/read_acl/write_acl/write_owner/synchronize:allow
2:group@:list_directory/read_data/read_xattr/execute/read_attributes/read_acl/synchronize:allow
3:everyone@:list_directory/read_data/read_xattr/execute/read_attributes/read_acl/synchronize:allow





aclinherit=discard | noallow | restricted | passthrough | passthrough-x

     noallow           only inherits inheritable ACL entries that specify "deny" permissions.

     restricted        removes  the write_acl  and  write_owner  
      (default)         permissions when the ACL entry is inherited.

     passthrough       inherits all inheritable ACL entries without any modifications 
                        made to the  ACL  entries  when  they  are inherited.
                    
     passthrough-x     Has the same meaning as passthrough, except that the 
                        owner@, group@, and everyone@ ACEs inherit the execute permission 
                        only if the file creation mode also requests the execute bit.


discard 		| does not inherit any ACL entries.
noallow 		| only inherits inheritable ACL entries that specify "deny" permissions.
restricted 		| (the default) removes the write_acl and  write_owner  perm
passthrough 	| inherits all inheritable ACL entries without any modifications made to the ACL entries
passthrough-x 	| owner@, group@, and everyone@ ACEs inherit  the  execute permission only if the file creation mode also requests the execute bit.




aclmode=discard | groupmask | passthrough

     discard       deletes all ACL entries that do not represent the mode of the file.
           
     groupmask     reduces user or group permissions. so that the ACL permissions 
      (default)     are reduced so perms arnt greater than !> owner permission bits. 

     passthrough   indicates that no changes are made to the ACL 
                    other than generating the necessary ACL entries to represent 
                    the  new mode of the file or directory.






zfs set aclinherit=noallow zfs/dir	   				"
echo "##-===============================================================-##"

chmod A+user:gozer:read_data:file_inherit:deny,user:lp:read_data:file_inherit:allow test6.dir


0:user:gozer:read_data:file_inherit:deny
1:user:lp:read_data:file_inherit:allow
2:owner@:list_directory/read_data/add_file/write_data/add_subdirectory/append_data/read_xattr/write_xattr/execute/delete_child/read_attributes/write_attributes/read_acl/write_acl/write_owner/synchronize:allow
3:group@:list_directory/read_data/read_xattr/execute/read_attributes/read_acl/synchronize:allow
4:everyone@:list_directory/read_data/read_xattr/execute/read_attributes/read_acl/synchronize:allow








mlslabel=label


echo "##-============================================================================-##"
echo "     [?] The  casesensitivity,  normalization,  and  utf8only  properties         "
echo "         are also new permissions that can be assigned to non-privileged users    "
echo "         by using the ZFS delegated administration feature.                       "
echo "##-============================================================================-##"
context=SELinux_User:SElinux_Role:Selinux_Type:Sensitivity_Level


echo "##-============================================================================-##"
echo "     [?] This flag sets the SELinux context for all files in the filesytem        "
echo "         under the mountpoint for that filesystem                                 "
echo "##-============================================================================-##"
fscontext=SELinux_User:SElinux_Role:Selinux_Type:Sensitivity_Level


echo "##-=====================================================================================-##"
echo "     [?] This  flag  sets  the  SELinux  context  for the filesytem being mounted.         "
echo "##-=====================================================================================-##"
defntext=SELinux_User:SElinux_Role:Selinux_Type:Sensitivity_Level


echo "##-====================================================================-##"
echo "     [?] This flag sets the SELinux context for unlabeled files.          "
echo "##-====================================================================-##"
rootcontext=SELinux_User:SElinux_Role:Selinux_Type:Sensitivity_Level


echo "##-==================================================================================-##"
echo "     [?] This flag sets the SELinux context for the root inode of the filesystem.       "
echo "##-==================================================================================-##"
overlay=on | off










echo "##-=====================================================================-##"
echo "    [+] Re-create the root pool.                   "
echo "##-============================================================-##"
                  
zpool create -f -o failmode=continue -R /a -m legacy -o cachefile= /etc/zfs/zpool.cache rpool c1t1d0s0



echo "##-=====================================================================-##"
echo "    [+] Restore the root pool snapshots.                   "
echo "##-============================================================-##"
                  
cat /mnt/rpool.snap1 | zfs receive -Fdu rpool


echo "##-=====================================================================-##"
echo "    [+] restore the actual root pool snapshots that are stored in a pool on a remote system                   "
echo "##-============================================================-##"
                  
ssh remote-system zfs send -Rb tank/snaps/rpool@snap1 | zfs receive -F rpool


echo "##-=====================================================================-##"
echo "    [+] Set the bootfs property on the root pool BE.                   "
echo "##-============================================================-##"
                  
zpool set bootfs=rpool/ROOT/zfsBE rpool


echo "##-=====================================================================-##"
echo "    [+] Shut down the system and boot failsafe mode.                   "
echo "##-============================================================-##"
                  
ok boot -F failsafe

echo "##-=====================================================================-##"
echo "    [+] Roll back each root pool snapshot.           "
echo "##-===============================================-##"
                  
zfs rollback rpool@snap1
zfs rollback rpool/ROOT@snap1
zfs rollback rpool/ROOT/s10zfsBE@snap1


## 
zfs set volsize=2G
zfs get volsize
zfs set volsize=8g rpool/swap


## 
zpool create dozer mirror /file/a /file/b
zpool export dozer
zpool import -d /file
zpool import -d /file dozer
zpool import -f dozer
zpool import -m dozer

zpool import -o readonly=on ZPool-ZFS
zpool scrub ZPool-ZFS
zpool status -x



zpool create pool mirror

add newpool log mirror

add tank mirror

zpool add -n zfs mirror $disk0 $disk1       ## perform a dry run
zpool add zfs mirror $disk0 $disk1


zpool create tank mirror c2t0d0 c2t1d0 c2t3d0 cache c2t5d0 c2t8d0


zpool create logz log mirror


mkfile 100m ZPool-ZFS/log/



echo "##-============================================================-##"
echo "       [+] You can access the ZFS Administration console          "
echo "                 through a secure web browser at:                 "
echo "##-============================================================-##"
https://system-name:6789/zfs

echo "##-============================================================-##"
echo "            [+] use the Solaris Management Console (smc)          "
echo "                    to manage ZFS storage pools                   "
echo "##-============================================================-##"
                  
/usr/sbin/smcwebserver start
/usr/sbin/smcwebserver enable








https://forums.freenas.org/index.php?threads/ecc-vs-non-ecc-ram-and-zfs.15449
https://docs.oracle.com/cd/E18752_01/html/819-5461/gbchx.html
https://arstechnica.com/information-technology/2014/02/ars-walkthrough-using-the-zfs-next-gen-filesystem-on-linux
http://docs.oracle.com/cd/E19253-01/819-5461/gevpg/index.html





