#!/bin/bash


##-===============================================-##
##   [+] Print metadata associated to the rule
##-===============================================-##
yara --print-meta


##-===========================-##
##   [+] Print module data
##-===========================-##
yara --print-module-data


##-===============================================-##
##   [+] Print namespace associated to the rule
##-===============================================-##
yara --print-namespace/etc/snort/rules/


##-=================================-##
##   [+] Print rules statistics
##-=================================-##
yara --print-stats


##-========================================-##
##   [+] Print strings found in the file
##-========================================-##
yara --print-strings


##-==================================================-##
##   [+] Print length of strings found in the file
##-==================================================-##
yara --print-string-length


##-===============================================-##
##   [+] Print the tags associated to the rule
##-===============================================-##
yara --print-tags


##-===============================================-##
##   [+] Scan files in directories recursively
##-===============================================-##
yara --recursive


##-==============================================================-##
##   [+] RULES_FILE contains rules already compiled with yarac
##-==============================================================-##
yara --compiled-rules



##-===============================================================-##
##   [+] Apply rules on /$Dir/rules to all files on current dir
##-===============================================================-##
yara /$Dir/rules



##-=========================================================-##
##   [+] Apply rules on /foo/bar/rules to bazfile.
##   [+] Only reports rules tagged as Packer or Compiler.
##-=========================================================-##
yara -t Packer -t Compiler /$Dir/rules bazfile


##-====================================================================-##
##   [+] Scan all files in the /foo directory and its subdirectories.
##   [+] Rules are read from standard input.
##-====================================================================-##
cat /$Dir/rules | yara -r /foo


##-=============================================================-##
##   [+] Defines three external variables $Var $Var and $Var.
##-=============================================================-##
yara -d $Var=true -d $Var=5 -d $Var="my string" /$Dir/rules bazfile


##-===============================================-##
##   [+]
##-===============================================-##
## ------------------------------------------------------------------------------ ##
##   [?] Apply rules on /foo/bar/rules to bazfile
##   [?] while passing the content of cuckoo_json_report to the cuckoo module.
## ------------------------------------------------------------------------------ ##
yara -x cuckoo=cuckoo_json_report /$Dir/rules bazfile





##-==========================================-##
##   [+] Run yardoc on all our lib files:
##-==========================================-##
yardoc lib/**/*.rb


