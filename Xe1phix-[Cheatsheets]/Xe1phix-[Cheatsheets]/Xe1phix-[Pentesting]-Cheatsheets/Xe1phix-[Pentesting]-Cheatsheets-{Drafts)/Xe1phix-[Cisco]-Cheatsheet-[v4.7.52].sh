


## Cisco/Networking Commands

##  ? - Help
##  > - User mode
##  - Privileged mode

router(config)# - Global Configuration mode

## ----------------------------------------------------------- ##
##   [?] enable secret more secure than enable password.
## ----------------------------------------------------------- ##


For example, in the configuration command:

enable secret 5 $1$iUjJ$cDZ03KKGh7mHfX2RSbDqP.

## ----------------------------------------------------------- ##
The enable secret has been hashed with MD5, whereas in the command:
username jdoe password 7 07362E590E1B1C041B1E124C0A2F2E206832752E1A01134D
The password has been encrypted using the weak reversible algorithm.
## ----------------------------------------------------------- ##

## -------------------------------------------------- ##
##   [?] Change to privileged mode to view configs
## -------------------------------------------------- ##
cisco> enable

## ---------------------------------------- ##
# Change to global config mode to modify
## ---------------------------------------- ##
cisco# config terminal/config t


## ------------------------------------------------------------------ ##
##   [?] Gives you the router's configuration register (Firmware)
## ------------------------------------------------------------------ ##
cisco# show version


## ----------------------------------------------------------------------- ##
##   [?] Shows the router, switch, or firewall's current configuration
## ----------------------------------------------------------------------- ##
cisco# show running-config


## ----------------------------------------------------------- ##
##   [?] show the router's routing table
## ----------------------------------------------------------- ##
cisco# show ip route

## ----------------------------------------------------------- ##
##   [?] Dump config but obscure passwords
## ----------------------------------------------------------- ##
cisco# show tech-support
