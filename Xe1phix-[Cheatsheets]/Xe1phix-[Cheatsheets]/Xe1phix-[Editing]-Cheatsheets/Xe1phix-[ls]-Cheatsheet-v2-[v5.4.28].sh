filecount=$(ls | wc -l)

# -a option shows all hidden files and directories (Those who start with .")
#the -F classify the results in files and folders,makes it more visual when a lot of files and directories with different extensions exist
ls -alF

ls -i About-TecMint #inode

The Bash shell feature that is used for matching or expanding specific types of patterns is called globbing
$ ls -l ????.txt #files whose names are four characters long
$ ls -l foot????.doc # files whose names are 8 characters long, first 4 characters are f, o, o and t and extension is doc
$ ls -l best.??? #all files with the name ‘test’ having any extension of three characters long


$ ls –lt #lists files in long listing format, and sorts files based on modification time, newest first
$ ls –lth
$ ls –ltr #list down files /folders sorted with modified time, -r reverse order
$ ls -ltr | grep "`date | awk '{print $2" "$3}'`" #todays date
$ ls -ltr | grep "$(date +"%b %e")"
$ ls -ltr | grep "Feb 18" #current date "Mar 22" # list files on specific dates
$ ls -ltr | awk '$6 == "Feb" && $7 >=15 && $7 <= 31 {print $6,$7,$8,$9}' # list files after Feb 15t
$ ls -ltr . | awk '$6 == "Feb" && $7 >=15 && $7 <= 31 {print $6,$7,$8,$9}' # list files after Feb 15t on specific directory

$ ls -lrt /var/log | awk '{ total += $5 }; END { print total }' # sum of file sizes

$ ls -FaGl /var/log/apt | printf "%'d\n" $(awk '{SUM+=$4}END{print SUM}') #total size 
$ ls -FaGl /var/log/apt | sudo tee /dev/stderr | printf "%'d\n" $(awk '{SUM+=$4}END{print SUM}') #list directory contents and total size 
$ ls -laUR /var/log/apt | grep -e "^\-" | tr -s " " | cut -d " " -f5 | awk '{sum+=$1} END {print sum}' #only sum up file sizes not the directory itself

# total size, sum of files listed
$ sumcol()
> {
>     awk "{sum+=\$$1} END {print sum}"
> }
$ ls -lrt /var/log/apt/ | sumcol 5

$ ls -l | grep 'Mar 22 12:27' | tr -s ' ' | cut -d ' ' -f9 | xargs rm -rf #delete files on specific date

#Listing of files in directory based on last modification time of file’s status information, or the 'ctime'
#list that file first whose any status information like: owner, group, permissions, size etc has been recently changed.
$ ls –lct #List Files Based on Last Modification Time 
$ ls –ltu #Listing of files in directory based on last access time, i.e. based on time the file was last accessed, not modified.

#Sorting Ouptut of ls -l based on Date
#based on 6th field month wise, then based on 7th field which is date, numerically
ls -l | sort -k6M -k7n 
ls -l | head -n 10 | sort -k6
ls -l | head -n 10| sort -k6M -k7n #based on 6th field month wise, then based on 7th field which is date

ls -lt --time=birth #sorted by creation/birth date time
ls -l --time=creation #sorted by creation/birth date time

$ ls -l *.pl #all files of ‘pl’ extension

$ ls -l [p-s]* #all files and folders whose name contains p or q or r or s
$ ls -l [1-5]* #all files and folders whose name starts with any digit from 1 to 5

$ ls -l {?????.sh,*st.txt} #files whose names are 5 characters long and the extension is ‘sh’ or the last two characters of the files are ‘st’ and the extension is ‘txt’
$ rm {*.doc,*.docx} #delete all files whose extensions are ‘doc’ or ‘docx’

$ ls a*+(.bash|.sh) #filenames which are starting with character ‘a’ and has the extension ‘bash’ or ‘sh’

ls -alt #list files in last modifed date order use the -t flag which is for 'time last modified'.
ls -altr #list files in last modifed date order use the -t flag which is for 'time last modified', reverse order
