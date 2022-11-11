============================================================================
#Volatility command line tool is also included
#Volatility Workbench is a graphical user interface (GUI) for the Volatility tool.
https://www.osforensics.com/tools/volatility-workbench.html 
============================================================================
volatility -f cridex.vmem imageinfo #get more information about the memory dump

#have the computer OS from which this memory dump comes fr1om (Win7SP1x64)
#The imageinfo plugin will scan the image and suggest a number of likely profiles
$ docker run -v /tmp:/tmp ubuntu/volatility:latest -f /tmp/OtterCTF.vmem imageinfo                              
Volatility Foundation Volatility Framework 2.6.1
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64_24000, Win2008R2SP1x64_23418, Win2008R2SP1x64, Win7SP1x64_24000, Win7SP1x64_23418
                     AS Layer1 : WindowsAMD64PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (/tmp/OtterCTF.vmem)
                      PAE type : No PAE
                           DTB : 0x187000L
                          KDBG : 0xf80002c430a0L
          Number of Processors : 2
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0xfffff80002c44d00L
                KPCR for CPU 1 : 0xfffff880009ef000L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2018-08-04 19:34:22 UTC+0000
     Image local date and time : 2018-08-04 22:34:22 +0300

volatility -f cridex.vmem --profile=WinXPSP2x86 pslist #see what were the running processes using the pslist plugin

#identify whether an unknown process is running or was running at an unusualtime
#identify the presence of any rogue processes and view any high-level running processes
volatility -f cridex.vmem --profile=WinXPSP2x86 pslist -P 

volatility -f cridex.vmem --profile=WinXPSP2x86 psscan #detailed list of processes found in the memory dump

volatility -f cridex.vmem --profile=WinXPSP2x86 pstree #display the processes and their parent processes,shows any unknown or abnormal processes

#list processes that are trying to hide themselves while running on the computer
#discovering any hidden processes in the plugin present in the memory dump
volatility -f cridex.vmem --profile=WinXPSP2x86 psxview 


volatility -f cridex.vmem --profile=WinXPSP2x86 connscan #scanner for TCP connections
volatility -f cridex.vmem --profile=WinXPSP2x86 sockets
volatility -f cridex.vmem --profile=WinXPSP2x86 netscan #details about the local and remote IP and also about the local and remote port
volatility -f cridex.vmem --profile=WinXPSP2x86 consoles  #extracts command history by scanning for _CONSOLE_INFORMATION
volatility -f cridex.vmem --profile=WinXPSP2x86 cmdscan  #extracts command history by scanning for _COMMAND_HISTORY
volatility -f cridex.vmem --profile=WinXPSP2x86 cmdline # display process command-line arguments

#find FILE_OBJECTs present in the physical memory,open files even if there is a hidden rootkit present in the files
volatility -f ram.mem --profile=Win7SP1x64 filescan 

volatility -f ram.mem --profile=Win7SP1x64 dumpregistry --dump-dir /root/ramdump/ #dump a registry hive into a disk location      
volatility -f ram.mem --profile=Win7SP1x64 moddump --dump-dir /root/ramdump/ #extract a kernel driver to a file

#dump the executable processes in a single location
#If there is malware it intentionally forges size fields in the PE header for the memory dumping tool to fail
volatility -f ram.mem --profile=Win7SP1x64 procdump --dump-dir /root/ramdump/

volatility -f ram.mem --profile=Win7SP1x64 memdump --dump-dir /root/ramdump/ #dump the memory-resident pages of a process into a separate file

volatility -f ram.mem --profile=Win7SP1x64 iehistory #recovers the fragments of Internet Explorer history by finding index.dat cache file

#.exe for user mode services and a driver name for services that run from kernel mode
#see the services are registered
volatility -f ram.mem --profile=Win7SP1x64 svcscan

# detect the DLLs which are used by a process by consulting the first of the three DLL lists stored in the PEB
#which tracks the order in which each DLL is loaded
# malware sometimes modifies that list to hide the presence of a DLL.
volatility -f ram.mem --profile=Win7SP1x64 dlllist -p 116,788
volatility -f ram.mem --profile=Win7SP1x64 dlldump –dump-dir #dump the DLLs from the memory space of the processes into another location

#display the open handles that are present in a process
#applies to files, registry keys, events, desktops, threads, and all other types of objects
volatility -f ram.mem --profile=Win7SP1x64 handles 

#view the SIDs stands for Security Identifiers that are associated with a process
#identifying processes that have maliciously escalated privileges and which processes belong to specific users
#identify if any malicious process has taken any privilege escalation
volatility -f ram.mem --profile=Win7SP1x64 getsids -p 464 

volatility -f ram.mem --profile=Win7SP1x64 timeliner #locate the artifacts according to the timeline

#locate kernel memory and its related objects
#all the previously unloaded drivers and also those drivers that have been hidden or have been unlinked by rootkits
volatility -f ram.mem --profile=Win7SP1x64 modscan 

volatility -f ram.mem --profile=Win7SP1x64 filescan #

#dump the NTLM hashes from the SYSTEM and SAM registry hives
#crack with John the Ripper or Hashcat
vol.py -f OtterCTF.vmem --profile="Win7SP1x64" hashdump #extract and decrypt cached domain credentials stored in the registry

#gives out information like the default password, the RDP public key
#extracting the plaintext password from the LSA secrets in  the registry
vol.py -f OtterCTF.vmem --profile="Win7SP1x64" lsadump   

vol.py --plugins=/tmp/volatility-plugins/ --info #plugins list

#finds and analyses the profiles based on the Kernel debugger data block,provides the correct profile related to the raw image
vol.py -f memory.dmp kdbgscan --dtb=0x185000 --profile=Win7SP1x86
vol.py -f memory.dmp kdbgscan

vol.py -f memory.dmp psscan --profile=Win7SP1x86_23418

#convert vmem to dmp file
vmss2core.exe -W virtual_machine_name.vmss virtual_machine_name.vmem
$ python vol.py imageinfo -f …/memory.dmp
$ python vol.py hivelist -f …/memory.dmp --profile=Win2008R2SP1x64
$ python vol.py hashdump -f …/memory.dmp --profile=Win2008R2SP1x64
python vol.py --info

#retrieve user's passwords from a Windows memory dump
volatility imageinfo -f test.elf 

# locate the virtual addresses present in the registry hives in memory, and their entire paths to hive on the disk
volatility -f test.elf hivelist --profile=Win2008R2SP1x64_23418 #The hostname is stored in the SYSTEM registry hive


============================================================================
vol.py -f memory_dump.img linux_cpuinfo
vol.py -f memory_dump.img linux_pslist
vol.py -f memory_dump.img linux_pstree
vol.py -f memory_dump.img linux_netstat
vol.py -f memory_dump.img linux_ifconfig
vol.py -f memory_dump.img linux_list_raw
vol.py -f memory_dump.img linux_bash
============================================================================
#using Mimikatz to get cleartext password from offline memory dump

C:\temp\procdump.exe -accepteula  -ma lsass.exe lsass.dmp
#For 32 bits
C:\temp\procdump.exe -accepteula -64 -ma lsass.exe  lsass.dmp  
#For 64 bits

volatility — plugins=/usr/share/volatility/plugins — profile=Win7SP0x86 -f halomar.dmp mimikatz
volatility — plugins=/usr/share/volatility/plugins — profile=Win7SP0x86 -f halomar.dmp hashdump #ntlm hash
============================================================================
