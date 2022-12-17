
## ---------------------------------------------------------------------- ## 
##   [?] man pages are "flat" documents, meaning single files.
##   [?] info uses hypertext (like web pages) to help organize docs
## ---------------------------------------------------------------------- ## 
## 
## ---------------------------------------------------------------------- ## 
##  1 Executable programs or shell commands
##  2 System calls (functions provided by the kernel)
##  3 Library calls (functions within program libraries)
##  4 Special files
##  5 File formats and conventions
##  6 Games
##  7 Miscellaneous
##  8 System administration commands (usually only for root)
##  9 Kernel routines
## ---------------------------------------------------------------------- ## 


==================================
|| Dir 	||   Section Name
__________________________________
|| man1 ||  (1) User Commands
|| man2 ||  (2) System Calls
|| man3 ||  (3) Subroutines
|| man4 ||  (4) Devices
|| man5 ||  (5) File Formats
|| man6 ||  (6) Games
|| man7 ||  (7) Miscellaneous
|| man8 ||  (8) Sys. Admin
|| manl ||  (l) Local
==================================

apropos
whatis grep                        # Display a short info on the command or word 
whereis java                       # Search path and standard directories for word 


## ---------------------------------------------------------------------- ## 
man −f <cmd>	## This will list details associated with the command
man -w			## show location of man pages
man -a			## show all man pages for command
man -wa
man -d mkfifo	## use the debug (-d) option to man to watch as it constructs a manpath
## ---------------------------------------------------------------------- ## 


## ---------------------------------------------------------------------- ## 
/etc/manpath.config						## man-db configuration file.
/var/cache/man/index.(bt|db|dir|pag)	## An FHS compliant global index database cache.
/usr/man/index.(bt|db|dir|pag)			## A traditional global index database cache.
## ---------------------------------------------------------------------- ## 


## ---------------------------------------------------------------------- ## 
info --index-search=		        ## 
info --output=$FILE		            ## 
info --subnodes			            ## 
## ---------------------------------------------------------------------- ## 
info -w				                ## print physical
info --where		                ## location of
info --location		                ## Info file.
## ---------------------------------------------------------------------- ## 
info emacs buffers				    ## start at buffers node within emacs manual
info --show-options emacs		    ## start at node with emacs' command line options
## ---------------------------------------------------------------------- ## 
info --subnodes -o out.txt emacs	## dump entire manual to out.txt
## ---------------------------------------------------------------------- ## 



echo "## + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + ##"
echo "## ======================================================================================================= ##"
echo -e "\t\t || /usr/share/man 	|| 		## Directories contain manual pages ||"
echo "## ======================================================================================================= ##"
echo "## ------------------------------------------------------------------------------------------------------- ##"
echo "## /usr/share/man/<locale>/man[1-9]		## These directories contain manual pages for 
echo "## 										## the specific locale in source code form.
echo "## ------------------------------------------------------------------------------------------------------- ##"
echo "## ======================================================================================================= ##"
echo "## + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + ##"
echo
echo "## ======================================================================================================= ##"
echo -e "\t\t || /usr/local/info 	|| 		## Info pages associated with locally installed programs.
echo "## ======================================================================================================= ##"
echo -e "\t\t || /usr/local/man 	|| 		## Man pages associated with locally installed programs.
echo "## ======================================================================================================= ##"
echo -e "\t\t || /usr/share/info	||		## Info pages go here.
echo "## ======================================================================================================= ##"
echo -e "\t\t || /usr/share/locale	||		## Locale information goes here.
echo "## ======================================================================================================= ##"
echo -e "\t\t || /usr/share/man		||		## Manual pages subdirectories arranged by sections.
echo "## ======================================================================================================= ##"

