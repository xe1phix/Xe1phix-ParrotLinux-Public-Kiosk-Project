Display current libraries from the cache
# ldconfig -p | head -5
Display libraries from every directory
ldconfig -v | head
# cat /etc/ld.so.conf
------------------------------------------------------------------------------------------
# ldd (Unix) ldd (List Dynamic Dependencies)
ldd /bin/ls
# display unused direct dependencies
ldd -u /bin/ping
# more information
ldd -v /bin/ping


