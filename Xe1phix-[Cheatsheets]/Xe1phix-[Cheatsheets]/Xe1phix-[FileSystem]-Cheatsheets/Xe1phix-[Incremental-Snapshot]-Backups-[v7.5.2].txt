## ---------------------------------------------------------- ##
##  [?] A Snapshot Backup is Considered A Hybrid Approach
## ---------------------------------------------------------- ##


##-======================================================================-##
##   1). A Full Data Backup is Made.
##   2). A Pointer Reference Table is Created. 
##   3). An Incremental Backup is Performed From Now On.
##-======================================================================-##

## ---------------------------------------------------------------------- ##
##  [?] Incremental Backup - Makes A Copy of Only Data That Has Been
##                           Modified Since The Last Backup Operation 
## ---------------------------------------------------------------------- ##
        
##-===========================================================================-##
##   4). New or Modified Data is Added or Updated Within The Backup Archive.
##-===========================================================================-##


##-=============================================================================================-##
##   5). A Pointer Reference Table, is Copied And Updated Each Time A Snapshot Backup is Made.  
##-=============================================================================================-##
## --------------------------------------------------------------------------------------------- ##
##  [?] (That File is: Xe1phixGitLab.snar)
## --------------------------------------------------------------------------------------------- ##



##-=================================================================================================-##
##  [?] In The Following Example, I'm Making A Snapshot Backup Using The Directory Location:
## ------------------------------------------------------------------------------------------------- ##
##      --> /run/media/public/2TB/Xe1phixGitLab/*   (ZuluMount mounts in the /run/media dir)
## ------------------------------------------------------------------------------------------------- ##
## 
## ------------------------------------------------------------------------------------------------- ##
##  [?] I Named The Backup File That The Data is Stored Inside of:
## ------------------------------------------------------------------------------------------------- ##
##      --> Xe1phixGithub.tar.xz
## 
## ------------------------------------------------------------------------------------------------- ##
##  [?] And Finally, I Named The Snapshot Pointer Reference File:
## ------------------------------------------------------------------------------------------------- ##
##      --> Xe1phixGitLab.snar
## 
##-=================================================================================================-##



## ------------------------------------------------------------------------------------------------- ##
##  [?] The Tar .snar File Extension - Contains Metadata Used To Create Full Incredmental Backups
## ------------------------------------------------------------------------------------------------- ##
##  [?] The Snapshot File Uses File Timestamps. 
##      So Tar Can Determine if A File Has Been Modified Since It Was Last Backed up.
## ------------------------------------------------------------------------------------------------- ##



## ------------------------------------------------------------------------------------------------- ##
##  [?] The -g Option - Creates A Snapshot File: (I Named Mine: Xe1phixGitLab.snar)
## ------------------------------------------------------------------------------------------------- ##
##  [?] The -J Option - Use xz Compression
## ------------------------------------------------------------------------------------------------- ##
##  [?] The -c Option - Creates A Tar Archive File
## ------------------------------------------------------------------------------------------------- ##
##  [?] The -v Option - Uses Verbose Reporting
## ------------------------------------------------------------------------------------------------- ##
##  [?] The -f Option - References A File
## ------------------------------------------------------------------------------------------------- ##
tar -g Xe1phixGitLab.snar -Jcvf Xe1phixGitLab.tar.xz /run/media/public/2TB/Xe1phixGitLab/*
tar -g Xe1phixTextbooks.snar -Jcvf Xe1phixTextbooks.tar.xz /run/media/public/2TB/BrowntownAlpha/textbooks/*
tar -g Exotic-Liability.snar -Jcvf Exotic-Liability.tar.xz /home/xe1phix/Podcasts/Exotic-Liability/*

tar -g Xe1phix-Xe1phixGitLab-Xe1phix-Hardened-ParrotSec-Kios-Projects-Production.snar -Jcvf ParrotSec-Projects-Production.tar.xz /home/xe1phix/Downloads/Xe1phixGitLab/Xe1phixGitLabProjects/Stable/ParrotLinux-Public-Kios-Project/Xe1phix-Hardened-ParrotKios-Projects-Production/*


## ---------------------------------------- ##
##  [+] List The Tar Archives Contents:
## ---------------------------------------- ##
tar -tf Xe1phixGitLab.tar.xz
tar -tf Xe1phixTextbooks.tar.xz
tar -tf Exotic-Liability.tar.xz
tar -tf ParrotSec-Projects-Production.tar.xz


## --------------------------------------------------------------------------------- ##
##  [?] The Metadata Within Xe1phixGithub.snar Lets The Tar Command 
##      Know When A File is New or Modified Since The Last Snapshot Backup. 
## --------------------------------------------------------------------------------- ##
##  [?] If The File is New or Modified, It is Appended To The 
##      Archived Snapshot Backup File (Xe1phixGithub.tar.xz) 
## --------------------------------------------------------------------------------- ##
tar -g /home/xe1phix/Xe1phixGithub.snar -Jcvf /home/xe1phix/Xe1phixGithub.tar.xz /run/media/public/2TB/Xe1phixGithub/*
tar -g /run/media/public/2TB/Xe1phixGithub.snar -Jcvf /run/media/public/2TB/Xe1phixGithub.tar.xz /run/media/public/2TB/Xe1phixGithub/*

tar -g /run/media/public/2TB/Xe1phixTextbooks.snar -Jcvf /run/media/public/2TB/Xe1phixTextbooks.tar.xz /run/media/public/2TB/BrowntownAlpha/textbooks/*
tar -g /home/xe1phix/Xe1phixTextbooks.snar -Jcvf /home/xe1phix/Xe1phixTextbooks.tar.xz /run/media/public/2TB/BrowntownAlpha/textbooks/*

tar -g /home/xe1phix/Podcasts/Exotic-Liability.snar -Jcvf /home/xe1phix/Podcasts/Exotic-Liability.tar.xz /home/xe1phix/Podcasts/Exotic-Liability/*





