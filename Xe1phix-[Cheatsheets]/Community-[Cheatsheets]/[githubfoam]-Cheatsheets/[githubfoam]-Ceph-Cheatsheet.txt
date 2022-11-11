ceph-deploy disk list ceph-server-01  -> To list the disks on a node
ceph-deploy disk zap osdserver1:sdb ->  zap a disk (delete its partition table) in preparation for use with Ceph

#Prepare OSDs
ceph-deploy osd prepare osdserver1:sdb:/dev/ssd
ceph-deploy osd prepare osdserver1:sdc:/dev/ssd
#Activate OSDs
ceph-deploy osd activate osdserver1:/dev/sdb1:/dev/ssd1
ceph-deploy osd activate osdserver1:/dev/sdc1:/dev/ssd2
#Create OSDs
ceph-deploy osd create osdserver1:sdb:/dev/ssd1

#Interactive Mode
ceph
ceph> health
ceph> status
ceph> quorum_status
ceph> mon_status

ceph health ->  Checking Cluster Health
ceph -w -> watch the cluster’s ongoing events
ceph -s ->  check a cluster’s status
ceph df ->check a cluster’s data usage and data distribution among pools

ceph osd stat -> check OSDs
ceph osd dump
ceph osd tree
ceph osd out {osd-num}
#Removing the OSD
ceph osd crush remove {name}
ceph auth del osd.{osd-num}


ceph mon stat
ceph mon dump
ceph quorum_status

ceph mds stat
ceph mds dump

ceph osd lspools-> list cluster’s pools