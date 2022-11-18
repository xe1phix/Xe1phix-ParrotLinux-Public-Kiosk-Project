# quota settings
sudo apt update ; sudo apt install quota -y
quota --version
find /lib/modules/`uname -r` -type f -name '*quota_v*.ko*'
sudo mount -o remount /
cat /proc/mounts | grep ' /
sudo quotacheck -ugm /
sudo quotaon -v /
sudo setquota -u member1 200M 240M 0 0 /
sudo quota -vs member1
sudo setquota -t 864000 864000 /
sudo repquota -s /
