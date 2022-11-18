---------------------------------------------------------------------------------------------------
du -sh /* # list directory sizes under root / disk
du -sh /* | sort -h
du -m /some/path | sort -nr | head -n 20 #sorted list containing the 20 biggest dirs
for each in $(ls) ; do du -hs "$each" ; done
du --threshold=1M -h | sort -h #includes hidden dot folders (folders which start with .).
du -h | sort -h 3

du -bch #-b gives you the file size instead of disk usage, and -c gives a total at the end
du -ch | tail -1
du -sh /some/dir #the summary of a grand total disk usage size of an directory use the option “-s” 
du -sh /var/* |grep G
du -ah /home/tecmint # displays the disk usage of all the files and directories
du -kh /home/tecmint #the disk usage of a directory tree with its subtress in Kilobyte blocks. Use the “-k” (displays size in 1024 bytes units).
du -kh /home/tecmint #Megabytes (MB)
du -ch /home/tecmint #The “-c” flag provides a grand total usage disk space at the last line
du -ah --exclude="*.txt" /home/tecmint
du -ha --time /home/tecmint #the disk usage based on modification of time, use the flag “–time”

#The problem with du is that it adds up the size of the directory nodes as well,not to sum up only the file sizes.
# total size of files in a directory
du -h -c directory #listing path 
du -h -c directory|tail -1 #only total size 
$ du -sh /var/log/apt #only total size and listing 

#du prints actual disk usage rounded up to a multiple of (usually) 4 KB instead of logical file size
$ for i in {0..9}; do echo -n $i > $i.txt; done #create files 
$ ls *.txt
0.txt  1.txt  2.txt  3.txt  4.txt  5.txt  6.txt  7.txt  8.txt  9.txt
$ du -ch *.txt | tail -1
40K     total
$ ls -FaGl *.txt | printf "%'d\n" $(awk '{SUM+=$4}END{print SUM}')
10

du /var/* -shc --exclude=lib #--exclude to exclude any directory
du /var/ -h --exclude=lib --max-depth=1 #first-level sub-directories in the /var/ directory. 
 
$ du -ch /var/log/apt | tail -1 | cut -f 1
$ du -ac --bytes /var/log/apt
$ du -ac --bytes /var/log/apt | grep "log$" | awk '{ print; total += $1 }; END { print "total lobsters: ", total, " Bytes" }'
$ du -ac --bytes /var/log/apt | grep "log$" | awk '{ print; total += $1 }; END { print "total lobsters: ", total/1024, " KB" }'
$ du -ac --bytes /var/log/apt | grep "log$" | awk '{ print; total += $1 }; END { print "total lobsters: " total/1024/1024 " MB" }'
$ du /var/log/apt/*.log | awk '{ print; total += $1 }; END { print "total size: ",total }'
----------------------------------------------------------------------------------------------------
$ dir /var/log/apt #list directory contents
$ dir /var/log/apt | tee >( awk '{ total += $4 }; END { print total }' ) #list directory contents and total size 
$ dir /var/log/apt | awk '{ print; total += $4 }; END { print "total size: ",total }' #total size 

----------------------------------------------------------------------------------------------------
