#Process affinity is the scheduler property that helps to bind or unbind the process so that the process will run only with the allotted CPU
#Processor affinity, or CPU pinning or “cache affinity”, enables the binding and unbinding of a process or a thread to a central processing unit (CPU) or a range of CPUs

#According to the taskset command man pages, value f means "any CPU."
$ pidof rsync
$ taskset -p 2395 #use the PID to get CPU affinity, returns the current CPU affinity in a hexadecimal bit mask format
pid 2395's current affinity mask: f
$ taskset -cp 2395 #get the CPU range of a process
pid 2395's current affinity list: 0-3

$ taskset -c 0 vlc #start the VLC program on CPU core ID 0
taskset 0xa gedit #launch gedit with CPU affinity 0xa.

#If the server gets a reboot or the process is restarted, the PID changes
taskset -p 0x11 9030 #assign a process to cores 0 and 4
taskset -cp 0,4 9030 #assign a process to cores 0 and 4
taskset -cp 1 9030 # bound the process 9030 to run only on CPU 1, configuration is not permanent
