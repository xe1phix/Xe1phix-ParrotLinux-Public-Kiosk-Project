#!/bin/bash
#
# Copyright 2011 Alexandros Iosifidis, Dimitrios Michalakos
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

source firewall.sh

SSH_CONF_FILE='/etc/ssh/sshd_config'
SSH_PID_FILE='/var/run/sshd.pid'
SSH_PORT=${1-'22'}

# Configures and hardens the SSH daemon.
# Please note that Red Hat has a policy of backporting security patches from the latest releases into the current distribution version. Thus SSH daemon may seem outdated, while it is not. As long as the latest updates are applied to system, the SSH daemon will be fully patched.
# Please refer to http://wiki.centos.org/HowTos/Network/SecuringSSH for further reading on SSH security.
function ssh.configure {
   # Configure:
   sed -i -e "s|^\(#\?\)\(Port\)\(\s\+\)\(.*\)$|\2 $SSH_PORT|" $SSH_CONF_FILE #change SSH port
   sed -i -e "s|^\(#\?\)\(PermitRootLogin\)\(\s\+\)\(.*\)$|\2 no|" $SSH_CONF_FILE #disable root login
   sed -i -e "s|^\(#\?\)\(LoginGraceTime\)\(\s\+\)\(.*\)$|\2 1m|" $SSH_CONF_FILE #user has 1 minute to enter password, else connection is closed
   sed -i -e "s|^\(#\?\)\(MaxAuthTries\)\(\s\+\)\(.*\)$|\2 3|" $SSH_CONF_FILE #after 3 failed login attempts connection is closed
   sed -i -e "s|^\(#\?\)\(MaxSessions\)\(\s\+\)\(.*\)$|\2 3|" $SSH_CONF_FILE #max_sessions=3
   sed -i -e "s|^\(#\?\)\(IgnoreUserKnownHosts\)\(\s\+\)\(.*\)$|\2 yes|" $SSH_CONF_FILE
   sed -i -e "s|^\(#\?\)\(IgnoreRhosts\)\(\s\+\)\(.*\)$|\2 yes|" $SSH_CONF_FILE
   sed -i -e "s|^\(#\?\)\(HostbasedAuthentication\)\(\s\+\)\(.*\)$|\2 no|" $SSH_CONF_FILE
   sed -i -e "s|^\(#\?\)\(UseDNS\)\(\s\+\)\(.*\)$|\2 no|" $SSH_CONF_FILE
   sed -i -e "s|^\(#\?\)\(PermitEmptyPasswords\)\(\s\+\)\(.*\)$|\2 no|" $SSH_CONF_FILE
   sed -i \
-e "s|^\(#\?\)\(ClientAliveInterval\)\(\s\+\)\(.*\)$|\2 900|" \
-e "s|^\(#\?\)\(ClientAliveCountMax\)\(\s\+\)\(.*\)$|\2 0|" \
$SSH_CONF_FILE #after 15 minutes of inactivity user is kicked out
   sed -i -e "s|^\(#\?\)\(GSSAPIAuthentication\)\(\s\+\)\(.*\)$|\2 no|" $SSH_CONF_FILE
   sed -i -e "s|^\(#\?\)\(UsePAM\)\(\s\+\)\(.*\)$|\2 no|" $SSH_CONF_FILE
   sed -i -e "s|^\(#\?\)\(X11Forwarding\)\(\s\+\)\(.*\)$|\2 no|" $SSH_CONF_FILE
   sed -i -e "s|^\(#\?\)\(AllowTcpForwarding\)\(\s\+\)\(.*\)$|\2 no|" $SSH_CONF_FILE
   sed -i \
-e "s|^\(#\?\)\(LogLevel\)\(\s\+\)\(.*\)$|\2 INFO|" \
-e "s|^\(#\?\)\(SyslogFacility\)\(\s\+\)\(.*\)$|\2 AUTHPRIV|" \
$SSH_CONF_FILE #log messages of INFO level (or higher) in /var/log/secure
   sed -i -e "s|^\(#\?\)\(PidFile\)\(\s\+\)\(.*\)$|\2 $SSH_PID_FILE|" $SSH_CONF_FILE #set PID file
   sed -i -e "s|^\(#\?\)\(Subsystem\)\(\s\+\)\(sftp\)\(\s\+\)\(.*\)$|\2 \4 internal-sftp|" $SSH_CONF_FILE #set sftp subsystem to accept chroot jails
   sed -i -e '$!N; /^\(.*\)\n\1$/!P; D' $SSH_CONF_FILE #remove concurent duplicate lines
   chmod u=rw,g=,o= $SSH_CONF_FILE
   service sshd reload #restart service
   # Set firewall:
   firewall.allow tcp $SSH_PORT
   return 0 #done
}

# Imprisons the specified user in a SFTP chroot jail.
# $1 the user that will be emprisoned, i.e. 'betty'. {REQUIRED}
# $2 the directory that user will be emprisoned into, i.e. '/home/betty'. {REQUIRED}
# Please note that jail directory should be owned by root, otherwise chrooting won't work.
function ssh.add_jail {
   local user="$1"
   local jail="$2"
   # Make sure user is specified:
   if [ -z $user ] ; then #user not specified
      echo "The name of the user that will be imprisoned must be specified."
      return 1 #exit
   fi
   # Make sure jail is specified:
   if [ -z $jail ] ; then #jail not specified
      echo "The directory that user will be imprisoned into must be specified."
      return 1 #exit
   fi
   # Make sure user exists:
   if ! grep -iq "^$user" /etc/passwd ; then #user does not exist
      echo "The specified user \"$user\" does not exist."
      return 1 #exit
   fi
   # Make sure jail directory exists:
   if [ ! -d "$jail" ]; then
      echo "The specified chroot directory \"$jail\" does not exist."
      return 1 #exit
   fi
   # Make sure chroot jail does not already exist:
   sed -i -e "/^Match User \"$user\"$/,/^#End of Match$/d" $SSH_CONF_FILE #remove lines from "Match User $user" to the first "#End of Match"
   # Configure new chroot jail:
   echo -n \
"Match User \"$user\"
   ChrootDirectory $jail
   ForceCommand internal-sftp
   AllowTcpForwarding no
#End of Match
" >> $SSH_CONF_FILE
   service sshd reload #reload configuration
   return 0 #done
}

# Releases the specified user from her SFTP jail.
# $1 the user that will be released, i.e. 'mary'. {REQUIRED}
function ssh.remove_jail {
   local user="$1"
   # Make sure user is specified:
   if [ -z $user ] ; then #user not specified
      echo "The name of the user that will be released must be specified."
      return 1 #exit
   fi
   # Make sure chroot jail exists:
   if ! grep -iq "^Match User \"$user\"" $SSH_CONF_FILE ; then #chroot jail does not exists
      echo "Chroot jail could not be found for the user \"$user\"."
      return 0 # exit
   fi
   # Delete jail configuration:
   sed -i -e "/^Match User \"$user\"$/,/^#End of Match$/d" $SSH_CONF_FILE #remove lines from "Match User $user" to first "#End of Match"
   service sshd reload #reload configuration
   return 0 #done
}
