# ------------------------------------------------------------------
#
#    Copyright (C) 2002-2005 Novell/SUSE
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License published by the Free Software Foundation.
#
# ------------------------------------------------------------------
# vim:syntax=apparmor

#include <tunables/global>

/usr/bin/mlmmj-make-ml.sh {
  #include <abstractions/base>
  #include <abstractions/bash>
  #include <abstractions/consoles>
  #include <abstractions/nameservice>

  capability sys_admin,

  /usr/bin/mlmmj-make-ml.sh r,

  # some shell tools are needed
  /{usr/,}bin/domainname mix,
  /{usr/,}bin/hostname mix,
  /{usr/,}bin/bash mix,
  /{usr/,}bin/cp mixr,
  /{usr/,}bin/mkdir mixr,
  /{usr/,}bin/touch mixr,
  /usr/bin/which mixr,
  # if mkdir cant read the current work directory it jumps into /
  # allow reading that dir.
  / r,

  # skeleton data
  /usr/share/mlmmj/text.skel r,
  /usr/share/mlmmj/text.skel/** r,

  # spool dirs
  /var/spool r,
  /var/spool/mlmmj rw,
  /var/spool/mlmmj/** w,
}
