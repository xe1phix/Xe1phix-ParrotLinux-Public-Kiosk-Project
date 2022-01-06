

## -------------------------------------- ##
##    [+]  Chmod Policy:          ##
## -------------------------------------- ##
bindfs --chmod-normal			##  Try to chmod the original files (the default).
bindfs --chmod-ignore			##  Have all chmods fail silently.
bindfs --chmod-deny				##  Have all chmods fail with 'permission denied'.
bindfs --chmod-filter=				##  Change permissions of chmod requests.
bindfs --chmod-allow-x			##  Allow changing file execute bits in any case.


##-=====================-##
##    [+]  XAttributes Policy:   ##
##-=====================-## ----------------------------------------------------------- ##
bindfs --xattr-ro						##   Let extended attributes be read-only
bindfs --xattr-rw						##   Let  extended  attributes  be  read-writ
												## ----------------------------------------------------------- ##

##-=======================-##
##    [+]  Other File Operations:  ##
##-=======================-## -------------------------------------------------------------------- ##
bindfs --delete-deny					##   Disallow deleting files.
bindfs --rename-deny					##   Disallow renaming files (within the mount).
													## -------------------------------------------------------------------- ##

##-======================-##
##    [+]  File Creation Policy:   ##
##-======================-## --------------------------------------------------------------------------- ##
bindfs --create-as-user			  ##   New files owned by creator (default for root). *
bindfs --create-as-mounter		  ##   New files owned by fs mounter (default for users).
bindfs --create-for-user=			  ##   New files owned by specified user. *
bindfs --create-for-group=		  ##   New files owned by specified group. *
bindfs --create-with-perms=	  ##   Alter permissions of new files.
												  ## --------------------------------------------------------------------------- ##

##-======================-##
##    [+]  Chown Policy:            ##  
##-======================-## ----------------------------------------------------------------------- ##
bindfs --chown-normal			  ##   Try to chown the original files (the default).
bindfs --chown-ignore			  ##   Have all chowns fail silently.
bindfs --chown-deny				  ##   Have all chowns fail with 'permission denied'.
												  ## ----------------------------------------------------------------------- ##


