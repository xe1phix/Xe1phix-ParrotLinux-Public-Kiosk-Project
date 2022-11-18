
# priority levels between -20 and 19
nice -10 perl test.pl -> test.pl is launched with a nice value of 10 when the process is started
nice --10 perl test.pl -> Launch a Program with High Priority
nice #Checking default niceness,the default is 0 

# 0 for none, 1 for real-time, 2 for best-exertion, 3 for inactive
ionice -c 3 -p 1 #PID as 1 to be an idle I/O process
ionice -c 2 bash #run ‘bash’  as a best-effort program
ionice -p 3467 #examine the class and priority used by PID 3467
ionice -c 1 -n 3 -p 3467 
#set the I/O scheduling class to Idle,takes longer,no longer performance degradation
# for pid in $(pidof rsync); do ionice -c 3 -p $pid; done
----------------------------------------------------------------------------------------------------- 
renice -n -19 -p 3534 -> Change the Priority of a Running Process
#adding more virtual runtime to the process
#The OS thinks that the process has taken more virtual runtime time than other processes in the run queue.
#in the next cycle, the CPU gives less time to the process
#The process finishes late as it’s getting less time “on CPU”
renice +10 PID
#The OS thinks that the process hasn’t got enough “on CPU” time than other processes in the run queue
#in the next cycle, the CPU gives more “on CPU” time to that process as compared to other processes in the run queue.
renice -10 PID
/etc/security/limits.conf -> set the default nice value of a particular user or group
$ pidof rsync
$ renice +10 2395
2395 (process ID) old priority 0, new priority 10
