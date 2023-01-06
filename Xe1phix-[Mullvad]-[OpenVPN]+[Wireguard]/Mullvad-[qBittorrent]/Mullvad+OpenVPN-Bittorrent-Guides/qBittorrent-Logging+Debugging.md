### Logging and debugging: ###
With the advent of systemd replacing upstart, logging also changed. qbittorrent doesn't have a straightforward logging facility. When it runs it outputs to syslog, but when it doesn't run, like if the disclaimer hasn't been answered yet, you won't see anything in the log files. The best way to see this is to impersonate the qbtuser and run qbittorent-nox to see if the disclaimer comes up again.

Another way of working around how qbittorrent logs/doesn't log is to modify the init script as a 'oneshot' command execution and pipe the output to a file such as `/var/log/qbittorrent.log`, but I haven't tried this yet. Possibly the process identifier will need to be specified as well as the stop command so that status and stop commands also work. This is still a work in progress and I'll update this guide when I have it working.

You can also view output of qbittorrent with journalctl:  

##-====================================================================-##
##  [+] Show the entire log in a pager that can be scrolled through:
##-====================================================================-##
journalctl -u qbittorrent.service


##-====================================================================-##
##  [+] Show the live version of the log file as things are happening:
##-====================================================================-##
journalctl -f -u qbittorrent.service
