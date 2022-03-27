#!/bin/sh
## #######
## ## Xe1phix-Chmod-Graphical-Mania.sh
## #######
## 
## 			I wasted far too much time creating these graphs.
## 		So feel free to distribute them among your linux peers.
## 









                     _____________
                     |	 |	 |	 |
                     | O | G | O |
                     | w | r | t |
                     | n | o | h |
                     | e | u | e |	 
                     | r | p | r |
_____________________|___|___|___|_
| chmod 0400 |______| -r-------- | 
| chmod 0600 |______| -rw------- | 
| chmod 0620 |______| -rw--w---- | 
| chmod 0644 |______| -rw-r--r-- | 
| chmod 0655 |______| -rw-r-xr-x | 
| chmod 0700 |______| -rwx------ | 
| chmod 0744 |______| -rwxr--r-- | 
| chmod 0720 |______| -rwx-w---- | 
| chmod 0755 |______| -rwxr-xr-x |
#####################|	 |	 |	 |
                     | O | G | O |
                     | w | r | t |
                     | n | o | h |
                     | e | u | e |	 
                     | r | p | r |
                     |___|___|___|

#####################################################
	Sample umask values and their effects
#####################################################
 Umask 	 Created files 			Created directories
#####################################################
| 000 |	0666 | (rw-rw-rw-) 	  | 0777 | (rwxrwxrwx)	|
| 002 |	0664 | (rw-rw-r--) 	  | 0775 | (rwxrwxr-x)	|
| 022 |	0644 | (rw-r--r--) 	  | 0755 | (rwxr-xr-x)	|
| 027 |	0640 | (rw-r-----) 	  | 0750 | (rwxr-x---)	|
| 077 |	0600 | (rw-------) 	  | 0700 | (rwx------)	|
| 277 |	0400 | (r--------) 	  | 0500 | (r-x------)	|
#####################################################





PERMISSION VALUES USING OCTAL DIGITS:

Permission Value 		Explanation
0444 					Read (r) permission for everyone.

0644 					Read (r) and write (w) permissions for the file owner. 
						Everyone else has read-only access to the file. 
						
0755 					Read (r), write (w), and execute (x) permissions for 
						the file owner and read (r) and execute (x) permissions
						to the file for everyone else.
						
2755 					Like 755 but also sets the set-GID bit. Security risk

1755 					Like 755 but also sets the sticky bit. Security risk









The + Means Extended Attributes, such as Access Control Lists (ACLs)
______________________________________________________________________
	-rw-rw-r--+ 



The t indicates that theres a sticky bit is set for that directory
drwxrwxr-t


the lowercase s indicates that the owner of the file also has execute permissions.
-rwsr-xr-x

allows the binary to run with the permissions of the owning group

-rwSr-xr-x



l (for a symbolic link)
b (for a block device)





||$ chmod 0710 ||     |-|rwx|--x|---|		  ||$ chmod u=|rwx|,g=x| 		||
||$ chmod 0720 ||     |-|rwx|-w-|---|		  ||$ chmod u=|rwx|,g=w			||
||$ chmod 0740 ||     |-|rwx|r--|---|		  ||$ chmod u=|rwx,g=|r			||
||$ chmod 0744 ||     |-|rwx|r--|r--|		  ||$ chmod a=|r,u+wx			||
||$ chmod 0755 ||     |-|rwx|r-x|r-x|		  ||$ chmod a=|rx,u+w			||
||$ chmod 0775 ||     |-|rwx|rwx|r-x|		  ||$ chmod a=|rwx,o-w			||
||$ chmod 0776 ||     |-|rwx|rwx|rw-|		  ||$ chmod a=|rwx,o-x			||
||$ chmod 0777 ||     |-|rwx|rwx|rwx|		  ||$ chmod a=|rwx				||
||$ chmod 2755 ||     |-|rwx|r-s|r-x|		  ||$ chmod a=|r,uo+x|,g+s,u+w	||
||$ chmod 2775 ||     |-|rwx|rws|r-x|		  ||$ chmod a=|r,uo+x,g+s,ug+w	||
||$ chmod 4420 ||     |-|r-S|-w-|---|		  ||$ chmod u=|r,u+S,g+w		||
||$ chmod 4655 ||     |-|rws|r-x|r-x|		  ||$ chmod a=|r,go+x,u+sw		||
||$ chmod 4755 ||     |-|rwS|r-x|r-x|		  ||$ chmod a=|r,go+x,u+w,g+S	||



||$ chmod 0710 ||	||$ chmod u=|rwx|,g=x| 		 ||     |-|rwx|--x|---|
||$ chmod 0720 ||	||$ chmod u=|rwx|,g=w		 ||     |-|rwx|-w-|---|
||$ chmod 0740 ||	||$ chmod u=|rwx,g=|r		 ||     |-|rwx|r--|---|
||$ chmod 0744 ||	||$ chmod a=|r,u+wx			 ||     |-|rwx|r--|r--|
||$ chmod 0755 ||	||$ chmod a=|rx,u+w			 ||     |-|rwx|r-x|r-x|
||$ chmod 0775 ||	||$ chmod a=|rwx,o-w		 ||     |-|rwx|rwx|r-x|
||$ chmod 0776 ||	||$ chmod a=|rwx,o-x		 ||     |-|rwx|rwx|rw-|
||$ chmod 0777 ||	||$ chmod a=|rwx			 ||     |-|rwx|rwx|rwx|
||$ chmod 2755 ||	||$ chmod a=|r,uo+x|,g+s,u+w ||     |-|rwx|r-s|r-x|
||$ chmod 2775 ||	||$ chmod a=|r,uo+x,g+s,ug+w ||     |-|rwx|rws|r-x|
||$ chmod 4420 ||	||$ chmod u=|r,u+S,g+w		 ||     |-|r-S|-w-|---|
||$ chmod 4655 ||	||$ chmod a=|r,go+x,u+sw	 ||     |-|rws|r-x|r-x|
||$ chmod 4755 ||	||$ chmod a=|r,go+x,u+w,g+S  ||     |-|rwS|r-x|r-x|










||	|-|---|---|---|	 ||		||$ chmod || 0000 ||	||$ chmod || ugo-a      		||				  
||	|-|--x|--x|--x|	 ||		||$ chmod || 0111 ||	||$ chmod || a=x 				||						  
||	|-|r--|---|---|	 ||		||$ chmod || 0400 ||	||$ chmod || u=r 				||  ||$ umask 277 ||      
||	|-|r--|r--|r--|	 ||		||$ chmod || 0444 ||	||$ chmod || a=r	 			||
||	|-|r-x|---|---|	 ||		||$ chmod || 0500 ||	||$ chmod || u=rx				||
||	|-|r-x|r-x|---|	 ||		||$ chmod || 0550 ||	||$ chmod || ug=rx				||
||	|-|rw-|---|---|	 ||		||$ chmod || 0600 ||	||$ chmod || u=rw 	 		  	||  ||$ umask 077 ||
||	|-|rw-|-w-|---|	 ||		||$ chmod || 0620 ||	||$ chmod || ug=w,u+r	  		||  ||$ umask 037 ||
||	|-|rw-|r--|---|  ||		||$ chmod || 0640 ||	||$ chmod || ug=r,u+w	 		||  ||$ umask 027 ||		
||	|-|rw-|r--|r--|  ||		||$ chmod || 0644 ||	||$ chmod || a=r,u+w	  		||  ||$ umask 022 ||
||	|-|rw-|r-x|r-x|  ||		||$ chmod || 0655 ||	||$ chmod || a=r,ug+x,u+w		||
||	|-|rw-|rw-|---|  ||		||$ chmod || 0660 ||  	||$ chmod || ug=rw 		 		||
||	|-|rw-|rw-|r--|  ||		||$ chmod || 0664 ||  	||$ chmod || a=r,ug+rw    		||  ||$ umask 002 ||     
||	|-|rw-|rw-|rw-|  ||		||$ chmod || 0666 ||  	||$ chmod || a=rw	 	 		||  ||$ umask 000 ||     
||	|-|rwx|---|---|	 ||		||$ chmod || 0700 ||	||$ chmod || u+rwx,go-rwx 		||	||  |-|rwx|--x|---|  ||		||$ chmod || 0710 ||		||$ chmod  || u=rwx,g=x			|| 
||  |-|rwx|-w-|---|  ||		||$ chmod || 0720 ||	||$ chmod || u=rwx,g=w			||
||  |-|rwx|r--|---|  ||		||$ chmod || 0740 ||	||$ chmod || u=rwx,g=r			||
||  |-|rwx|r--|r--|  ||		||$ chmod || 0744 ||	||$ chmod || a=r,u+wx		   ||
||  |-|rwx|r-x|r-x|  ||		||$ chmod || 0755 ||	||$ chmod || a=rx,u+w		   ||
||  |-|rwx|rwx|r-x|  ||		||$ chmod || 0775 ||	||$ chmod || a=rwx,o-w		   ||
||  |-|rwx|rwx|rw-|  ||		||$ chmod || 0776 ||	||$ chmod || a=rwx,o-x		   ||
||  |-|rwx|rwx|rwx|  ||		||$ chmod || 0777 ||	||$ chmod || a=rwx 			   || 
||  |-|rwx|r-s|r-x|  ||		||$ chmod || 2755 ||	||$ chmod || a=r,uo+x,g+s,u+w  || 
||  |-|rwx|rws|r-x|  ||		||$ chmod || 2775 ||	||$ chmod || a=r,uo+x,g+s,ug+w || 
||  |-|r-S|-w-|---|  ||		||$ chmod || 4420 ||	||$ chmod || u=r,u+S,g+w 	   || 
||  |-|rws|r-x|r-x|  ||		||$ chmod || 4655 ||	||$ chmod || a=r,go+x,u+sw 	   || 
||  |-|rwS|r-x|r-x|  ||		||$ chmod || 4755 ||	||$ chmod || a=r,go+x,u+w,g+S 	|| 


				  ________________
				   |A|	 |	 |	 |
				   |T|	 |	 |	 |
	   			   |T| O | G | O |	
				   |R| w | r | t |
			       |I| n | o | h |
				   |B| e | u | e |
			       |U| r | p | r |
				   |T|	 |	 |	 |
___________________|E|   |   |   |______________________________
				   | |   |   |   |
|$ chmod 0000      |-|---|---|---|        			  ||$ chmod ugo-a
|$ chmod 0111      |-|--x|--x|--x|        			  ||$ chmod a=x|
|$ chmod 0400      |-|r--|---|---|  ||$ umask 277     ||$ chmod u=|r 
|$ chmod 0444      |-|r--|r--|r--|        			  ||$ chmod a=|r
|$ chmod 0500      |-|r-x|---|---|        			  ||$ chmod u=|rx| 
|$ chmod 0550      |-|r-x|r-x|---|         			  ||$ chmod ug=|rx|
|$ chmod 0600      |-|rw-|---|---|  ||$ umask 077     ||$ chmod u=|rw
|$ chmod 0620      |-|rw-|-w-|---|        			  ||$ chmod ug=w,u+|r
|$ chmod 0640      |-|rw-|r--|---|  ||$ umask 027     ||$ chmod ug=|r,u+w				umask 0037
|$ chmod 0644      |-|rw-|r--|r--|  ||$ umask 022     ||$ chmod a=|r,u+w			
|$ chmod 0655      |-|rw-|r-x|r-x|        			  ||$ chmod a=|r,ug+x||,u+w
|$ chmod 0660      |-|rw-|rw-|---|        			  ||$ chmod ug=|rw
|$ chmod 0664      |-|rw-|rw-|r--|  ||$ umask 002     
|$ chmod 0666      |-|rw-|rw-|rw-|  ||$ umask 000     
|$ chmod 0700      |-|rwx|---|---|        			  ||$ chmod u+|rwx|,go-|rwx|
|$ chmod 0710      |-|rwx|--x|---|        			  ||$ chmod u=|rwx|,g=x| 
|$ chmod 0720      |-|rwx|-w-|---|        			  ||$ chmod u=|rwx|,g=w
|$ chmod 0740      |-|rwx|r--|---|        			  ||$ chmod u=|rwx,g=|r
|$ chmod 0744      |-|rwx|r--|r--|        			  ||$ chmod a=|r,u+wx
|$ chmod 0755      |-|rwx|r-x|r-x|        			  ||$ chmod a=|rx,u+w
|$ chmod 0775      |-|rwx|rwx|r-x|        			  ||$ chmod a=|rwx,o-w
|$ chmod 0776      |-|rwx|rwx|rw-|        			  ||$ chmod a=|rwx,o-x
|$ chmod 0777      |-|rwx|rwx|rwx|        			  ||$ chmod a=|rwx
|$ chmod 2755      |-|rwx|r-s|r-x|        			  ||$ chmod a=|r,uo+x|,g+s,u+w
|$ chmod 2775      |-|rwx|rws|r-x|        			  ||$ chmod a=|r,uo+x,g+s,ug+w
|$ chmod 4420      |-|r-S|-w-|---|        			  ||$ chmod u=|r,u+S,g+w
|$ chmod 4655      |-|rws|r-x|r-x|        			  ||$ chmod a=|r,go+x,u+sw
|$ chmod 4755      |-|rwS|r-x|r-x|        			  ||$ chmod a=|r,go+x,u+w,g+S
===================| |   |   |   |===========================================
				   |A|	 |	 |	 |
				   |T|	 |	 |	 |
	   			   |T| O | G | O |	
				   |R| w | r | t |
			       |I| n | o | h |
				   |B| e | u | e |
			       |U| r | p | r |
				   |T|   |	 |	 |
				   |E|   |   |   |
	               |_|___|___|___|


					|-|rws|r-x|r-x|
					|-|rwx|r-s|r-x|
					|-|rws|r-s|r-x|


| 000 |	0666 | (rw-rw-rw-) 	  

| 002 |	0664 | (rw-rw-r--) 	  
| 022 |	0644 | (rw-r--r--) 	  
| 027 |	0640 | (rw-r-----) 	  
| 077 |	0600 | (rw-------) 	  
| 277 |	0400 | (r--------) 	  


| 000 |	0666 | (rw-rw-rw-) 	  | 0777 |	(rwxrwxrwx)	|
| 002 |	0664 | (rw-rw-r--) 	  | 0775 |	(rwxrwxr-x)	|
| 022 |	0644 | (rw-r--r--) 	  | 0755 |	(rwxr-xr-x)	|
| 027 |	0640 | (rw-r-----) 	  | 0750 |	(rwxr-x---)	|
| 077 |	0600 | (rw-------) 	  | 0700 |	(rwx------)	|
| 277 |	0400 | (r--------) 	  | 0500 |	(r-x------)	|



type / owner / group / world

|T|
|Y|
|P|
|E|
|


Type is directory (d) or file (-).
read    (r)	 4
write   (w)	 2
execute (e)	 1


||                          ||                               ||                             ||
||==========================||===============================||=============================||
||  File Perm Attributes:   || User (Owner) File Permissions ||   Group File Permissions    ||
||==========================||===============================||=============================||
|| - = regular file         ||                               ||                             ||
|| b = block device file	||  r = read					 || r = read					||
|| c = char device file		||  w = write 					 || w = write				    ||	
|| d = directory			||  x = execute 				 || x = execute 			    ||
|| l = symbolic link		||  s = setUID and execute 		 || s = setGID and execute 	    ||
|| s = Unix domain socket	||  S = setUID and not execute 	 || S = setGID and not execute 	||
|| p = named pipe           ||                               ||                             ||
||                          ||                               ||                             ||
||==========================||===============================||=============================||
||                          ||                               ||                             ||
||                          ||                               ||                             ||
||                          ||                               ||                             ||




chown -R 0:0 lynis
chown 0:0 ./include/functions




U

echo -e "\t<<+}========================================={+>>"
echo -e "\t\t\t{+} Read File Permissions"
echo -e "\t<<+}========================================={+>>"
echo "\t"_______________________________"
echo -e "\t\tuser: 400  | chmod u+r"
echo -e "\t\tgroup: 40  | chmod g+r"
echo -e "\t\tothers: 4  | chmod o+r"



echo -e "\t\tuser: 200  | chmod u+w
group: 20  | chmod g+w
others: 2  | chmod o+w


________________________________
|200| |user  |   |$ chmod u+w |
|-20| |group |   |$ chmod g+w |
|--2| |others|   |$ chmod o+w |
________________________________


echo -e "\t<<+}========================================={+>>"
echo -e "\t\t\t{+} Execution File Permissions"
echo -e "\t<<+}========================================={+>>"

________________________________

echo -e "\t\t Perm  Owner       Command Execution
echo -e "\t\t |400| |user  |   |$ chmod u+x |"
echo -e "\t\t |-40| |group |   |$ chmod g+x |
echo -e "\t\t |--4| |others|   |$ chmod o+x |


echo -e "\t\t Perm     Owner   Command Execution
echo -e "\t\t |user  | |400|   |$ chmod u+x |"
echo -e "\t\t |group | |-40|   |$ chmod g+x |"
echo -e "\t\t |others| |--4|   |$ chmod o+x |"

echo -e "\t\t Perm     Owner   Command Execution
echo -e "\t\t |$ chmod u+x |   |user  | |400|"
echo -e "\t\t |$ chmod g+x |   |group | |-40|"
echo -e "\t\t |$ chmod o+x |   |others| |--4|"

echo -e "\t\tCommand Execution   Perm    _Owner__
echo -e "\t\t |$ chmod u+x |     |400|   |user  |"
echo -e "\t\t |$ chmod g+x |     |-40|   |group |"
echo -e "\t\t |$ chmod o+x |     |--4|   |others|"



________________________________

user:   |100| chmod u+x
group:  |-10| chmod g+x
others: |--1| chmod o+x
SetUID (SUID):	4000  | chmod u+s 
SetGID (SGID):	2000  | chmod g+s 
Sticky: 		1000  | chmod +t 





                     ______________
                      | |  |  |  |
                      |A|  |  |  |
				      |T|  |  |  |
                      |T|O |G |O |	
                      |R|w |r |t |
                      |I|n |o |h |
                      |B|e |u |e |
                      |U|r |p |r |
                      |T|  |  |  |
                      |E|  |  |  |
______________________| |  |  |  |___________________________
|$ chmod 0000 |______| ---------- ||$ chmod ugo-a
|$ chmod 0111 |______| ---x--x--x ||$ chmod a=x
|$ chmod 0400 |______| -r-------- ||$ chmod u=r 
|$ chmod 0444 |______| -r--r--r-- ||$ chmod a=r
|$ chmod 0500 |______| -r-x------ ||$ chmod u=rx 
|$ chmod 0550 |______| -r-xr-x--- ||$ chmod ug=rx
|$ chmod 0600 |______| -rw------- ||$ chmod u=rw
|$ chmod 0620 |______| -rw--w---- ||$ chmod ug=w,u+r
|$ chmod 0640 |______| -rw-r----- ||$ chmod ug=r,u+w
|$ chmod 0644 |______| -rw-r--r-- ||$ chmod a=r,u+w			
|$ chmod 0655 |______| -rw-r-xr-x ||$ chmod a=r,ug+x,u+w
|$ chmod 0660 |______| -rw-rw---- ||$ chmod ug=rw
|$ chmod 0700 |______| -rwx------ ||$ chmod u+rwx,go-rwx
|$ chmod 0710 |______| -rwx--x--- ||$ chmod u=rwx,g=x 
|$ chmod 0720 |______| -rwx-w---- ||$ chmod u=rwx,g=w
|$ chmod 0740 |______| -rwxr----- ||$ chmod u=rwx,g=r
|$ chmod 0744 |______| -rwxr--r-- ||$ chmod a=r,u+wx
|$ chmod 0755 |______| -rwxr-xr-x ||$ chmod a=rx,u+w
|$ chmod 0775 |______| -rwxrwxr-x ||$ chmod a=rwx,o-w
|$ chmod 0776 |______| -rwxrwxrw- ||$ chmod a=rwx,o-x
|$ chmod 0777 |______| -rwxrwxrwx ||$ chmod a=rwx
|$ chmod 2755 |______| -rwxr-sr-x ||$ chmod a=r,uo+x,g+s,u+w
|$ chmod 2775 |______| -rwxrwsr-x ||$ chmod a=r,uo+x,g+s,ug+w
|$ chmod 4420 |______| -r-S-w---- ||$ chmod u=r,u+S,g+w
|$ chmod 4655 |______| -rwsr-xr-x ||$ chmod a=r,go+x,u+sw
|$ chmod 4755 |______| -rwSr-xr-x ||$ chmod a=r,go+x,u+w,g+S
======================| |  |  |  |===========================================
                      |A|  |  |  |
                      |T|  |  |  |
                      |T|O |G |O |	
                      |R|w |r |t |
                      |I|n |o |h |
                      |B|e |u |e |
                      |U|r |p |r |
                      |T|  |  |  |
                      |E|  |  |  |
                      |_|__|__|__|



chmod a-w		r-xr-xr-x |


Owner types
✦ u = The user who owns it
✦ g = Other users in the file’s group
✦ o = Other users not in the file’s group
✦ a = All users

Permission actions
✦ + = Selected permissions are added to the existing permissions of each file
✦ - = Selected permissions are removed from the existing permissions of each file
✦ = = Selected permissions are assigned as the only permissions of each file

Permission types
✦ r = Read
✦ w = Write
✦ x = Execute for files or access for directories
✦ X = Execute only if the file is a directory or already has execute permission for

some user
✦ s = Sets user or group ID on execution
✦ t = Saves program text on swap device
✦ u = The permissions that the user who owns the file currently has for the file
✦ g = The permissions that other users in the file’s group have for the file
✦ o = The permissions that other users, not in the file’s group, have for the file
✦ a = All users





#####################################################
	Sample umask values and their effects
#####################################################
 Umask 	 Created files 		   Chmod  Created directories
#####################################################

||$ chmod -v 0777 ||	(rwxrwxrwx)	 ||$ chmod -v 
||$ chmod -v 0775 ||	(rwxrwxr-x)  ||$ chmod -v a=rx,ug+w
||$ chmod -v 0755 ||	(rwxr-xr-x)	 ||$ chmod -v u=rwx,g=r,a=x
||$ chmod -v 0750 ||	(rwxr-x---)  ||$ chmod -v u=rwx,g=x
0741 (rwxr----x)
||$ chmod -v 0700 ||	(rwx------)  ||$ chmod -v go+rwx


||$ chmod -v 0777 ||	(rwxrwxrwx)	 ||$ chmod -v 
||$ chmod -v 0775 ||	(rwxrwxr-x)  ||$ chmod -v 
||$ chmod -v 0755 ||	(rwxr-xr-x)	 ||$ chmod -v 
||$ chmod -v 0750 ||	(rwxr-x---)  ||$ chmod -v 
||$ chmod -v 0700 ||$ chmod -v go-rwx	  ||  (rwx------)


| chmod 0700 |______| -rwx------ |  chmod go-rwx	rwx------ |
|$ chmod -v 0500 |	(r-x------)	|


| 000 |	0666 | (rw-rw-rw-) 	  

| 002 |	0664 | (rw-rw-r--) 	  
| 022 |	0644 | (rw-r--r--) 	  
| 027 |	0640 | (rw-r-----) 	  
| 077 |	0600 | (rw-------) 	  
| 277 |	0400 | (r--------) 	  


| 000 |	0666 | (rw-rw-rw-) 	  | 0777 |	(rwxrwxrwx)	|
| 002 |	0664 | (rw-rw-r--) 	  | 0775 |	(rwxrwxr-x)	|
| 022 |	0644 | (rw-r--r--) 	  | 0755 |	(rwxr-xr-x)	|
| 027 |	0640 | (rw-r-----) 	  | 0750 |	(rwxr-x---)	|
| 077 |	0600 | (rw-------) 	  | 0700 |	(rwx------)	|
| 277 |	0400 | (r--------) 	  | 0500 |	(r-x------)	|

#####################################################



  =======================================================
//	Mode 		   	Number Description					\\
===========================================================
||__________||___________________________________||_____
||	0400 	|| Allows the owner to read			 ||
||__________||___________________________________||_____
||	0200 	|| Allows the owner to writ			 ||
||__________||___________________________________||_____
||	0100 	|| Allows owner X & search in dir 	 ||
||__________||___________________________________||_____
||	0040 	|| Allows group members to read		 ||
||__________||___________________________________||_____
||	0020 	|| Allows group members to write	 ||
||__________||___________________________________||_____
||	0010 	|| Allows group mem can X & search   ||
||			||  >> through dir					 ||
||__________||___________________________________||_____
||	0004 	|| Allows anyone / world to read	 ||
||__________||___________________________________||_____
||	0002 	|| Allows anyone / world to write	 ||
||__________||___________________________________||_____
||	0001 	|| Allows Anyone to X & search in dir||
||__________||___________________________________||_____
||	1000 	|| Sets the sticky bit				 ||
||__________||___________________________________||_____
||	2000 	|| Sets the setgid bit				 ||
||__________||___________________________________||_____
||	4000 	|| Sets the setuid bit				 ||
==========================================================

