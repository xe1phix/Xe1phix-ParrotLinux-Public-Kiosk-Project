
du --apparent-size --block-size=1

du -k . |xdu", "sudo du -k -x / |xdu

sort all
of the directories on your system by how much space they are using:

du -cb / | sort -n		## sort programs, then dir by space consumed


## ============================================================================= ##
du --exclude='*.o'
du -ks * | sort -n -r			## Sort everything by size in kilobytes
du -cs /home/* | sort -nr		## Show summary, sort results largest to smallest disk
du -csh /home/*					## human-readable output
du -Ss /etc				## but not in subdirectories beneath it:
du -csh				## du --total --summarize --human-readable
du -sh * 			## du --human-readable --summarize
## ============================================================================= ##
du -k || --block-size=1K		## equivalent to '--apparent-size --block-size=1K'
du -m || --block-size=1M		## equivalent to '--apparent-size --block-size=1M'
du -S || --separate-dirs		## for directories do not include size of subdirectories
du -P || --no-dereference		## dont follow any symbolic links (this is the default)
du -b || --bytes				## equivalent to '--apparent-size --block-size=1'
du -D || --dereference-args		## dereference only symlinks that are listed on the command line
## ============================================================================= ##

