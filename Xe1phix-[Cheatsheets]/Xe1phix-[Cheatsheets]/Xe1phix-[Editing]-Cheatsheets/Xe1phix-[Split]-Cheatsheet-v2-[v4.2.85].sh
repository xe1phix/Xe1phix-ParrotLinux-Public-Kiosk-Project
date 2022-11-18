# merge all files in the directory and split 
ls | xargs cat | tee file1 | split -5
# printing
pr -h "title" file1
list mounted file systems
$ cat /etc/mtab

split -l 4 index.txt split_file #Split file based on number of lines
split index.txt -l 4 --verbose
split -l 4 -a 4 index.txt #Change in suffix length. By default, the suffix length is 2
split -l 4 -d index.txt #change the split files suffix to numeric
split -l 4 index.txt split_index_ # create split output files with index suffix,
split -l 4 -e index.txt #Avoid zero-sized split files
split -n 3 index.txt #Create n chunks output files
split -n 2 index.txt #Split the file into two files of equal length
#split the file index.txt into separate files called indexaa, indexab, …..with each file containing 16 bytes of data
split -b 16 index.txt index 
split -b=1M -d  file.txt file --additional-suffix=.txt
split -b 10M -d  system.log system_split.log


~$ cat test.txt | wc -l
40
~$ split --numeric-suffixes=2 --additional-suffix=.txt -l 22 test.txt file
$ ls -lai file*
 2139 -rw-rw-r-- 1 vagrant vagrant 660 Mar 21 11:01 file02.txt
 5482 -rw-rw-r-- 1 vagrant vagrant 660 Mar 21 11:01 file03.txt
 5483 -rw-rw-r-- 1 vagrant vagrant 660 Mar 21 11:01 file04.txt
18296 -rw-rw-r-- 1 vagrant vagrant 220 Mar 21 11:01 file05.txt
$ cat file04.txt | wc -l
12
$ cat file05.txt | wc -l
4
