




mkdir -p /sys/fs/cgroup/freezer/sub
echo $$                                 ## Show PID of this shell
30655


## --------------------------------------------------------- ##
##  [+] create a child cgroup in the freezer hierarchy,
##      and put the shell into that cgroup:"
## --------------------------------------------------------- ##
sh -c 'echo 30655 > /sys/fs/cgroup/freezer/sub/cgroup.procs'

## --------------------------------------------------------- ##
cat /proc/self/cgroup | grep freezer
7:freezer:/sub



## ---------------------------------- ##
##    --> Create a new shell
##    --> inside of a new cgroup
##    --> mount the namespaces:
## --------------------------------- ##

unshare -Cm bash




cat /proc/self/mountinfo | grep freezer




##-============================================-##
##  [+] Inspect the '/proc/[pid]/cgroup'
##-============================================-##
## -------------------------------------------- ##
##   --> New shell process Spawned...
## 	     Created by unshare syscall()
## -------------------------------------------- ##



##-=====================================-##
##  [+] New shell process
##      Created by unshare syscall()"
## ===================================== ##
cat /proc/self/cgroup | grep freezer

## -------------------- ##"
	echo '7:freezer:/'
## -------------------- ##"




## ====================================================================== ##
##   [?] PID in the original cgroup namespace  (init,  with  PID  1):
## ====================================================================== ##
cat /proc/1/cgroup | grep freezer


echo -e "\n7:freezer:/.."

## ============================================= ##
##   [?] A process in a sibling cgroup (sub2):
## ============================================= ##

cat /proc/20124/cgroup | grep freezer

echo -e "\n7:freezer:/../sub2"










if [ $(id -u) -ne 0 ]; then
    unshare --user sleep 180 &
    userpid=$!;
    sudo $0 --userid $(id -u) --groupid $(id -g) --userpid $userpid "$@"
    exit 0;
fi





mount --bind $userpid/ns/user $usernspath

mount --bind $f ${root}${f}
mount --make-rprivate ${root}${f}


mount --bind /usr/bin/qemu-$arch $root/qemu-$arch





## create the mount ns with owning user ns
nsenter --user=$usernspath unshare --mount sleep 10 &

## timing problem here: need to allow nsenter time to begin executing
sleep 1

## can only mount on private propagation mount points
mount --make-rprivate $ctrl
mount --bind /proc/$!/ns/mnt $ctrl/$arch

## enter the mount ns with true root, not the user ns
nsenter --mount=$ctrl/$arch $0 --arch $arch --rootpath $rootpath in-ct
nsenter --mount=$ctrl/$arch --user=$ctrl/userns $0 --arch $arch --rootpath $rootpath in-ct-user




























