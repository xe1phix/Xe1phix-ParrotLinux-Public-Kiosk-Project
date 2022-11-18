find the number of processing units (CPU) available on a system
nproc
nproc --all
echo "Threads/core: $(nproc --all)"

lscpu #the number of physical CPU cores
lscpu | egrep 'Model name|Socket|Thread|NUMA|CPU\(s\)'
lscpu -p

grep 'model name' /proc/cpuinfo | wc -l
grep 'cpu cores' /proc/cpuinfo | uniq
echo "CPU threads: $(grep -c processor /proc/cpuinfo)"
cat /proc/cpuinfo
grep -c ^processor /proc/cpuinfo 
cat /proc/cpuinfo | grep 'core id' #get the actual number of cores
getconf _NPROCESSORS_ONLN && echo "Number of CPU/cores online at $HOSTNAME: $(getconf _NPROCESSORS_ONLN)"
