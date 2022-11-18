#Start a Linux Process or Command in Background
$ tar -czf home.tar.gz .
$ tar -tvf home.tar.gz # list the contents of a .tar file
$ bg
$ jobs
OR
$ tar -czf home.tar.gz . &
$ jobs
#Keep Linux Processes Running After Exiting Terminal
$ sudo rsync Templates/* /var/www/html/files/ &
$ jobs
$ disown  -h  %1
$ jobs
OR
$ nohup tar -czf iso.tar.gz Templates/* &
$ jobs
#Detach a Linux Processes From Controlling Terminal
firefox </dev/null &>/dev/null &

count & # count command running on the background
jobs
fg
bg
fg %#    #Replace the # with serial number of the job,bring any job in the foreground 
fg %2 #bring job 2 into the foreground
jobs -l
count 2> /dev/null &

$ tail -f temp.log  #Placing a Foreground Job into the Background,suspend the job with a Ctrl-Z,
^Z[1]+ Stopped tail -f temp.log  
$ bg # bg to place the suspended job in the background
$ jobs # list the jobs in the background


$ jobs -l # list job in the background, process id 105231
[1]+ 105231 Running 
$ fg 1 # bring job #1 in the foreground from the background, process id 105231
sudo rsync 

$ fg 1 #type ctrl+z to send the job #1 to the background, process id 105231
sudo rsync 
^Z
[1]+  Stopped 

$ jobs -l # list the job #1 in the background which is stopped, process id 105231
[1]+ 105231 Stopped 

$ bg 1 # run the job 1 in the background again, process id 105231
[1]+ sudo rsync 

$ jobs -l # list the job #1 in the background, process id 105231
[1]+ 105231 Running
