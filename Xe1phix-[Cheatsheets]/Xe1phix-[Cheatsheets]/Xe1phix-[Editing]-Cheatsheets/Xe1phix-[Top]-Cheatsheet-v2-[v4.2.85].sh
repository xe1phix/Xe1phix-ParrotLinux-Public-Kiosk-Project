list user vagrant's full command line of processes
$ top -c -u vagrant
ignore idle processes
$ top -i -u vagrant
updated with 5 secs intervals, including child processes
$ top -u vagrant -c -d 5 -S
#determine which Plaso processes are running
top -p `ps -ef | grep log2timeline.py | grep python | awk '{ print $2 }' | tr '\n' ',' | sed 's/,$//'`

