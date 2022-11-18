 history file size setting
 $ cat /etc/profile
 $ echo $HISTSIZE
 $ echo $HISTFILE
 $ fc -l

 #Linux Command History with date and time, temporary
HISTTIMEFORMAT="%d/%m/%y %H:%M "
HISTTIMEFORMAT="%d/%m/%y %T "

export HISTSIZE=0 #Disable the usage of history using HISTSIZE
echo $HISTSIZE
echo $HISTFILE
export HISTCONTROL=ignoredups #Eliminate the continuous repeated entry from history using HISTCONTROL
export HISTIGNORE="pwd:ls:ls -ltr:" #Ignore specific commands from the history using HISTIGNORE
export HISTCONTROL=erasedups #Erase duplicates across the whole history using HISTCONTROL
export HISTCONTROL=ignorespace #Force history not to remember a particular command using HISTCONTROL
#  service httpd stop [Note that there is a space at the beginning of service,to ignore this command from history]

history -c #Clear all the previous history

# !ps #Execute previous command that starts with a specific word
# !4 #Execute a specific command from history
# !-1 #execute the second last command
# !! #run the last executed command, or press CTRL+P
# !dconf #re-run the last command with the keyword ‘dconf’ in it

