#LVM
pvdisplay
pvck
pvs
lvscan
lvdisplay
lvmdiskscan
vgchange
vgscan -a y
e4defrag -cv /path/to/myfiles (defrag folder )


$ sudo pvcreate /dev/sdb
$ sudo pvs
  PV         VG       Fmt  Attr PSize   PFree
  /dev/sda2  centos   lvm2 a--  <63.00g 4.00m
  /dev/sdb   vg_iscsi lvm2 a--  <30.00g    0
$ sudo pvdisplay
  --- Physical volume ---
  PV Name               /dev/sdb
  VG Name               vg_iscsi
  PV Size               30.00 GiB / not usable 4.00 MiB
  Allocatable           yes (but full)
  PE Size               4.00 MiB
  Total PE              7679
  Free PE               0
  Allocated PE          7679
  PV UUID               hG93NW-gvRB-njUP-pgj8-omRF-YzFe-rTMWOz

  --- Physical volume ---
  PV Name               /dev/sda2
  VG Name               centos
  PV Size               <63.00 GiB / not usable 3.00 MiB
  Allocatable           yes
  PE Size               4.00 MiB
  Total PE              16127
  Free PE               1
  Allocated PE          16126
  PV UUID               rFHI2D-fvZw-Mf2P-gKTC-ZTwt-vdiY-TEQc14
  
$ sudo vgcreate vg_iscsi /dev/sdb
$ sudo vgdisplay
  --- Volume group ---
  VG Name               vg_iscsi
  System ID
  Format                lvm2
  Metadata Areas        1
  Metadata Sequence No  2
  VG Access             read/write
  VG Status             resizable
  MAX LV                0
  Cur LV                1
  Open LV               0
  Max PV                0
  Cur PV                1
  Act PV                1
  VG Size               <30.00 GiB
  PE Size               4.00 MiB
  Total PE              7679
  Alloc PE / Size       7679 / <30.00 GiB
  Free  PE / Size       0 / 0
  VG UUID               j63noX-S9I0-5Gp0-3FPg-IZ23-oZNK-6qpb7X
$ sudo lvcreate -l 100%FREE -n lv_iscsi vg_iscsi
[vagrant@vg-suricata-30 ~]$ sudo lvscan
  ACTIVE            '/dev/vg_iscsi/lv_iscsi' [<30.00 GiB] inherit
  ACTIVE            '/dev/centos/swap' [2.00 GiB] inherit
  ACTIVE            '/dev/centos/home' [<20.01 GiB] inherit
  ACTIVE            '/dev/centos/root' [40.98 GiB] inherit
$ sudo lvdisplay
  --- Logical volume ---
  LV Path                /dev/vg_iscsi/lv_iscsi
  LV Name                lv_iscsi
  VG Name                vg_iscsi
  LV UUID                exEdIG-s2bK-vFEa-fD3X-dplu-q2W3-1rTXsE
  LV Write Access        read/write
  LV Creation host, time vg-suricata-30, 2019-12-18 12:35:56 +0000
  LV Status              available
  # open                 0
  LV Size                <30.00 GiB
  Current LE             7679
  Segments               1
  Allocation             inherit
  Read ahead sectors     auto
  - currently set to     8192
  Block device           253:3  

 $ sudo vgremove vg_iscsi
 $ sudo pvremove /dev/sdb
