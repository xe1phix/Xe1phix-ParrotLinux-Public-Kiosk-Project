#!/bin/bash
##########################
## 
##########################








direct-attached storage (DAS)
network-attached storage (NAS)
radio frequency identification (RFID) chip
electromagnetic interference (EMI)
high-definition multimedia interface (HDMI)

synchronous dynamic RAM (SDRAM)
Peripheral Component Interface (PCI)
Read-Only Memory (ROM)
power-on self test (POST)
single data rate (SDR)
Universal Serial Bus (USB)
Video Graphics Adapter (VGA)
Electrically Erasable Programmable ROM
(EEPROM)
Digital Visual Interface (DVI)
double data rate (DDR)
dual inline memory module (DIMM)





Ternary content addressable memory (TCAM) is a specialized ASIC widely used in network search
engines. Most of the existing multi-match packet classification engines are based on TCAMs in
which each input performs a parallel search over all entries in one clock cycle, and only the first
matching index is output


SVMs (support vector machines) create hyper-plane delimitations based on distances between
points, creating maximum segments of classification [43]. The SVM finds the optimal separating
plane between members and non-members of a class in a feature space. The margin, as indicated
in Figure 14.12, represents the level to which the hyper-plane has managed to separate the classes,
which should be maximal. However, SVM is a purely binary system and will only identify the divi-
sions between two groups. It requires a small data sample for training and is not sensitive to the
dimension of data. This approach has been shown to be effective for intrusion detection although it
is more resource intensive and requires more training time.





ACPI (Advanced Configuration Power Interface)



Procedure Linkage Table (PLT)
runtime link editor (rtld)
Executable and Linkable Format (ELF)
Global Offset Table (GOT) 
return address (RET)
saved frame pointer (SFP)


Core Root of Trust for Measurement (CRTM)





three types of USB host controllers:
• Open Host Controller Interface (OHCI)
• Universal Host Controller Interface (UHCI)
• Enhanced Host Controller Interface (EHCI)

NMI (nonmaskable interrupt)
LOC (local timer interrupt)
TLB  (TLB flush interrupt),
RES (rescheduling interrupt)
CAL (remote function call interrupt)



The Advanced Forensic Format (AFF)
Human Interface Device (HID)
Input devices (mice, keyboards, etc.)

fchown() changes the ownership of the file referred to by the open file descriptor fd.
EACCES Search permission is denied on a component of the path prefix.

getpwnam

lsdev,

modinfo is run using modules compiled for a multiprocessing (SMP) kernel

modinfo -d 
modinfo -p 
modinfo -a 


grep /msdos.o: /lib/modules/2.2.5-15smp/modules.dep

Attempt to load all available network modules:
# modprobe -at net
Example 5

modprobe -l		# List all modules available for use:


modprobe -lt net | grep 3c			# List all modules in the net directory for 3Com network interfaces:



When you turn on a computer, the firmware
performs a power-on self-test (POST), initializes hardware to a known operational state,
loads the boot loader from the boot device (typically the first hard disk), and passes control
to the boot loader, which in turn loads the OS.


The motherboard’s firmware resides in 
Electronically Erasable Programmable Read-Only Memory (EEPROM), aka flash memory




Extensible Firmware Interface (EFI)
Basic Input/Output System (BIOS)
Industry Standard Architecture (ISA)
Peripheral Component Interconnect (PCI) bus 
Accelerated Graphics Port (AGP) driver
Direct Rendering Manager (DRM) 
Advanced Configuration and Power Interface (ACPI) 
Advanced Power Management (APM)
Micro Channel Architecture (MCA) bus
The Extended Industry Standard Architecture (EISA) bus 
Peripheral
Component Interconnect (PCI)
Executable and Linkable Format (ELF)
IDE (Integrated Drive Electronics)
cyclic redundancy check (CRC) algorithms
Small Computer Systems Interface (SCSI)
Modified Frequency Modulation (MFM)

serial port and parallel ports are character devices.

SCSI stands for Small Computer
Systems Interface — a type of interface through which you can connect multi-
ple devices (such as hard drives and scanners) to the PC.


Block devices (such as disk drives) transfer data in chunks (as opposed to
keyboards, which transfer data one character at a time). 

Modified Frequency Modulation (MFM) - which is the way data
was encoded on older hard drives. These hard drives can work over an
IDE interface.

ATA stands for AT Attachment and refers to the PC-AT style interface
that connects hard drives and CD-ROM drives to the PC’s motherboard.


frame buffer is an abstraction for the graphics hardware so that the kernel
and other software can produce graphical output without having to rely on
the low-level details (such as hardware registers) of a video card.


I2C (Inter-Integrated Circuit) 
 is a protocol
Philips has developed for communication between integrated circuit chips
over a pair of wires at rates between 10 and 100 kHz. System Management
Bus (SMBus) is a subset of the I2C protocol. Many modern motherboards
have an SMBus meant for connecting devices such as EEPROM (electrically
erasable programmable read only memory) and chips for hardware monitor-
ing. Linux supports the I2C and SMBus protocols.



An interrupt request (IRQ), or interrupt, is a signal sent to the CPU instructing it to
suspend its current activity and to handle some external event such as keyboard input. 



IRQ 	Typical use 				Notes
0 		System timer Reserved for internal use.
1 			Keyboard Reserved for keyboard use only.

2 			Cascade for IRQs 			8–15 The original x86 IRQ-handling circuit can manage
                        			 just 8 IRQs; 2 are tied together to handle 16 IRQs,
                      				  but IRQ 2 must be used to handle IRQs 8–15.
3 			Second RS-232 serial 		May also be shared by a fourth RS-232 serial port.
  									port ( COM2: in Windows) 
4 		First RS-232 serial port 	May also be shared by a third RS-232 serial port.
 		 ( COM1: in Windows) 

5	  Sound card or second 
		parallel port ( LPT2: in Windows) 
5			 Sound card or second 
6 			Floppy disk controller 
7 			First parallel port 
8 			Real-time clock 
9 			Open interrupt 
10 			Open interrupt 
11			Open interrupt 
12 			PS/2 mouse 
13 			Math coprocessor 	Reserved for internal use.
  parallel port ( LPT2: in in Windows) 
  Windows) 
14 Primary ATA controller The controller for ATA devices such as hard drives;
                         traditionally /dev/hda and /dev/hdb under Linux.1
15 Secondary ATA The controller for more ATA devices; traditionally
   controller /dev/hdc and /dev/hdd under Linux.1

2 Cascade for IRQs 8–15 




Each level of cache (L1, L2, and so on) is relatively
slower and larger than its predecessor. In most systems, these caches are built into the
processor and each of its cores.



echo "########################################################################################"
						echo -e "\t\tShared Library Linkers"
echo "########################################################################################"
echo "________________________________________________________________________________________"
echo -e "\t>> /lib/ld.so   					{+}  a.out dynamic linker/loader"
echo "________________________________________________________________________________________"
echo -e "\t>> /lib/ld-linux.so.*  			{+} ELF dynamic linker/loader"
echo "________________________________________________________________________________________"
echo -e "\t>> /etc/ld.so.preload 	 		{+} File containing a whitespace separated list ##"
echo "								   ###	### of ELF shared libraries to be loaded before ##"
echo "								  ###  ###	the program. libraries and an ordered list  ##"
echo "								 ###  ###	of candidate libraries.	  ####################"
echo "								###  #####################################################"
echo "							  ############################################################"
echo "________________________________________________________________________________________"
echo -e "\t>> /etc/ld.so.nohwcap  			{+} When this file is present the dynamic linker "
echo "										///	will load the non-optimized version of a library"
echo "									   /// even if the CPU supports the optimized version."
echo "________________________________________________________________________________________"
echo -e "\t>> lib*.so*     					{+} shared libraries"
echo "________________________________________________________________________________________"
echo -e "\t>> lib*.so.version       		{+}  shared libraries"
echo "________________________________________________________________________________________"
echo -e "\t>> /etc/ld.so.conf   			{+}  File containing a list of newline  separated "
echo "				 							 directories in which to search through the libraries."
echo "________________________________________________________________________________________"
echo -e "\t>> /etc/ld.so.cache      	{+} File containing an ordered list of libraries "
echo "										|| found in the directories specified in /etc/ld.so.conf."
echo " 						  				|| This file is not in human readable format,and "
echo "										|| is not intended to be edited."
echo "########################################################################################"






Memory Management Unit (MMU) The MMU is the hardware unit that translates the address that the processor
requests to its corresponding address in main memory. 
the translation lookaside buffer (TLB), for the MMU transla-
tion table. Prior to each memory access, the TLB is consulted before asking the MMU to
perform a costly address translation operation.

The address space refers
to a range of valid addresses used to identify the data stored within a finite allocation
of memory.
The single continuous address space that is
exposed to a running program is referred to as a linear address space. 


physical address space to refer to the
addresses that the processor requests for accessing physical memory. These addresses
are obtained by translating the linear addresses to physical ones


Software running on an IA-32 processor can have a linear address space
and a physical address space up to 4GB. but you can expand the size of
physical memory to 64GB using the IA-32 Physical Address Extension (PAE) feature.



The IA-32 architecture defines a small amount of extremely fast memory, called registers,
which the CPU uses for temporary storage during processing. Each processor core con-
tains eight 32-bit general-purpose registers

The EIP register, also referred to as the program counter, contains the linear address
of the next instruction that executes. 


CR0 contains flags that control the operating mode of the processor, including a flag that
enables paging. 
CR1 is reserved and should not be accessed. 
CR2 contains the linear address that caused a page fault. 
CR3 contains the physical address of the initial structure
used for address translation. It is updated during context switches when a new task is
scheduled. CR4 is used to enable architectural extensions, including PAE.




IA-32 processors implement two memory management mechanisms: segmentation and
paging. Segmentation divides the 32-bit linear address space into multiple variable-length
segments. All IA-32 memory references are addressed using a 16-bit segment selector,
which identifies a particular segment descriptor, and a 32-bit offset into the specified
segment

A segment descriptor is a memory-resident data structure that defines the loca-
tion, size, type, and permissions for a given segment. Each processor core contains two
special registers, GDTR and LDTR, which point to tables of segment descriptors, called
the Global Descriptor Table (GDT) and the Local Descriptor Table, respectively. The segmen-
tation registers CS (for code), SS (for stack), and DS, ES, FS, and GS (each for data) should
always contain valid segment selectors.

Paging provides the ability to virtualize the linear address space. It creates an execution
environment in which a large linear address space is simulated with a modest amount
of physical memory and disk storage.

Each 32-bit linear address space is broken up into
fixed-length sections, called pages, which can be mapped into physical memory in an
arbitrary order. When a program attempts to access a linear address, this mapping uses
memory-resident page directories and page tables to translate the linear address into a physi-
cal address

To compute the page directory entry (PDE) address, you combine bits 31:12 from the
CR3 register with bits 31:22 from the virtual address. You then locate the page table entry
(PTE) by combining bits 31:12 from the PDE with bits 21:12 of the virtual address. Finally,
you can obtain the physical address (PA) by combining bits 31:12 of the PTE with bits 11:0
of the virtual address.








ASCII strings
use 1 byte per character, and Unicode uses 2 bytes per character.





The following are the most com-
mon and interesting sections in a PE file:
.text		The .text section contains the instructions that the CPU exe-
			cutes. All other sections store data and supporting information. Gener-
			ally, this is the only section that can execute, and it should be the only
			section that includes code.

.rdata		The .rdata section typically contains the import and export infor-
			mation, which is the same information available from both Dependency
			Walker and PEview. This section can also store other read-only data used
			by the program. Sometimes a file will contain an .idata and .edata section,
			which store the import and export information 

.data		The .data section contains the program’s global data, which is
			accessible from anywhere in the program. Local data is not stored in
			this section, or anywhere else in the PE file. 

.rsrc		The .rsrc section includes the resources used by the executable
			that are not considered part of the executable, such as icons, images,
			menus, and strings. Strings can be stored either in the .rsrc section or
			in the main program, but they are often stored in the .rsrc section for
			multilanguage support.


Sections of a PE File for a Windows Executable
Executable Description
.text 		Contains the executable code
.rdata 		Holds read-only data that is globally accessible within the program
.data 		Stores global data accessed throughout the program
.idata 		Sometimes present and stores the import function information; if this section is
      		not present, the import function information is stored in the .rdata section
.edata 		Sometimes present and stores the export function information; if this section is not
     		present, the export function information is stored in the .rdata section
.pdata 		Present only in 64-bit executables and stores exception-handling information
.rsrc 		Stores resources needed by the executable
.reloc 		Contains information for relocation of library files









The system_call( ) function implements the system call handler. It starts by saving the
system call number and all the CPU registers that may be used by the exception handler on
the stack, except for eflags, cs, eip, ss, and esp, which have already been saved
automatically by the control unit also loads the Segment
Selector of the kernel data segment in ds and es:



All information needed by the filesystem to handle a file is included in a data structure called
an inode. Each file has its own inode, which the filesystem uses to identify the file.


This system call creates an "open file" object and returns an identifier called file descriptor .
An open file object contains:
•
•
Some file-handling data structures, like a pointer to the kernel buffer memory area
where file data will be copied; an offset field that denotes the current position in the
file from which the next operation will take place (the so-called file pointer); and so
on.
Some pointers to kernel functions that the process is enabled to invoke. The set of
permitted functions depends on the value of the flag parameter.


A file descriptor represents an interaction between a process and an opened file, while
an open file object contains data related to that interaction. The same open file object
may be identified by several file descriptors.


the read( ) and write( ) system calls always refer
to the position of the current file pointer. In order to modify the value, a program must
explicitly invoke the lseek( ) system call. When a file is opened, the kernel sets the file
pointer to the position of the first byte in the file (offset 0)


The read( ) system call requires the following parameters:
nread = read(fd, buf, count);
which have the following meaning:
fd: 		Indicates the file descriptor of the opened file
buf: 		Specifies the address of the buffer in the processs address space to which the data will be transferred
count: 		Denotes the number of bytes to be read

system calls set up the group of parameters that identifies the
process request and then executes the hardware-dependent CPU instruction to switch from
User Mode to Kernel Mode.

the mmap( ) system call, which allows part of a file or the memory
residing on a device to be mapped into a part of a process address space.



Every time a Segment Selector is loaded in a segmentation register, the
corresponding Segment Descriptor is loaded from memory into the matching
nonprogrammable CPU register.

Examines the TI field of the Segment Selector, in order to determine which Descriptor
Table stores the Segment Descriptor. This field indicates that the Descriptor is either
in the GDT (in which case the segmentation unit gets the base linear address of the
GDT from the gdtr register) or in the active LDT (in which case the segmentation
unit gets the base linear address of that LDT from the ldtr register).

segmentation can assign a different linear address space to each process while
paging can map the same linear address space into different physical address spaces.

A Task State Segment (TSS) segment for each process. The descriptors of these
segments are stored in the GDT.











The ELF header is located at the very beginning (offset 0) of a file.

e_ident: Holds the file identification information. 
e_type: Tells you the file type
e_entry: Holds the program entry point
e_phoff, e_phentsize, and e_phnum: Hold the file offset, entry size, and number of
program header entries.
 e_shoff, e_shentsize, and e_shnum: Hold the file offset, entry size, and number of
section header entries.
e_shstrndx: Stores the index within the section header table of the strings that map
to section names.




•	section headers include name, type, address, offset, and size for each section.
•	program headers map the file and its sections into memory at runtime.
•	Shared libraries (.so shared object) are reusable pieces of code that can be dynamically loaded into an appli-
cation
•	The global offset table (GOT) stores the runtime address of symbols that cannot be com-
puted at link time.
•	The procedure linkage table (PLT) supports calling functions within shared libraries.
•	The application programming interfaces (APIs) that the Linux kernel provides in order to
have unified data structures throughout the kernel.




Common ELF Sections
Section Name Description
.text Contains the application’s executable code
.data Contains the read/write data (variables)
.rdata Contains read-only data
.bss Contains variables that are initialized to zero
.got Contains the global offset table


Common Section Types
Section Type Description
PROGBITS Sections whose contents from disk will be loaded into memory upon execution.
NOBITS Sections that do not have data in the file, but have regions allocated in memory. The
      .bss is typically a NOBITS section because all its memory is initialized to zero upon
     execution (and there is no need to store zeroes within the file).
STRTAB Holds a string table of the application.
DYNAMIC Indicates that this is a dynamically linked application and holds the dynamic
       information.
HASH Contains the hash table of the application’s symbols.



As an executable is loaded into its address space, the shared libraries that it needs
must also be loaded in order to satisfy the dependencies (such as function calls or global
variables). ELF files specify which shared libraries they need within the dynamic infor-
mation section
readelf -d /bin/bash | grep NEEDED


linux-gate is a virtual shared object that is loaded into every Linux
process by the kernel and is not an actual file on disk.

ld-linux is the loader library and
is stored within the INTERP header

The global offset table (GOT) stores the runtime address of symbols that cannot be com-
puted at link time. These symbols are often stored within shared libraries that can be
loaded anywhere within the process’ address space. 
Analyzing GOT entries in memory dumps allows you to determine the
addresses of symbols within a process
This analysis often explains how malicious code altered the runtime state.

strcpy and memcpy can overwrite arbitrary memory
within the address space
Within include/linux/list.h of the Linux kernel source code are type-generic implemen-
tations of doubly linked lists and hash tables.







RELRO is a generic exploit mitigation technique to harden the
data sections of an ELF

Partial RELRO

gcc -Wl,-z,relro

The ELF sections are reordered so that the ELF internal data
sections (.got, .dtors, etc.) precede the program’s data sections
 (.data and .bss)

Non-PLT GOT is read-only.

PLT-dependent GOT is still writeable.


Full RELRO


gcc -Wl,-z,relro,-z,now
The entire GOT is (re)mapped as read-only.



Both Partial and Full RELRO reorder the ELF internal data sec-
tions to protect them from being overwritten in the event of a buffer
overflow in the program’s data sections (.data and .bss), but only Full
RELRO mitigates the popular technique of modifying a GOT entry to
get control over the program execution flow


Memory is divided into pages. Typically, a process, a thread, or the
kernel cannot read from or write to a memory location on the zero
page

GOT overwrite, works by manipulating an entry in the so-called Global
Offset Table (GOT) of an Executable and Linkable Format (ELF)1 object to
gain control over the instruction pointer.


The GOT is located in an ELF-internal data section called .got.
Its purpose is to redirect position-independent address calculations
to an absolute location, so it stores the absolute location of function-
call symbols used in dynamically linked code. When a program calls a
library function for the first time, the runtime link editor (rtld) locates
the appropriate symbol and relocates it to the GOT. Every new call to
that function passes the control directly to that location, so rtld isn’t
called for that function anymore.


Input/output controls (IOCTLs) are used
for communication between user-mode applica-
tions and the kernel.



the fundamental
STREAMS unit is called a Stream, which is a data transfer path between
a process in user space and the kernel. All kernel-level input and out-
put under STREAMS are based on STREAMS messages, which usually
contain the following elements: a data buffer, a data block, and a mes-
sage block.



The data buffer is the location in memory where the actual
data of the message is stored. The data block (struct datab) describes
the data buffer. The message block (struct msgb) describes the data
block and how the data is used.



The structure elements b_rptr and b_wptr specify the current
read and write pointers in the data buffer pointed to by b_datap


When using the STREAMS model, the IOCTL input data is refer-
enced by the b_rptr element of the msgb structure, or its typedef mblk_t.
Another important component of the STREAMS model is the so-called
linked message blocks. As described in the STREAMS Programming Guide,
“[a] complex message can consist of several linked message blocks. If
buffer size is limited or if processing expands the message, multiple
message blocks are formed in the message”


sed the ::msgbuf debugger command to display the message
buffer, including all console messages up to the kernel panic:


the kernel and the user space of a process share the
same zero page

Each user-mode address space is unique to a particular process, while
the kernel address space is shared across all processes. Mapping the
NULL page in one process only causes it to be mapped in that pro-
cess’s address space only.






##########################################################################
			System Management Interrupt (SMI) handlers:
##########################################################################





System Management Interrupt (SMI) handlers
Sherri
Sparks and Shawn Embleton at Black Hat USA 2008 [smm_rkt]
CPU SMRAM caching design [smm_cache]

The first instruction fetched by CPU after reset is located at 0xFFFFFFF0
address and is mapped to BIOS firmware ROM

BIOS boot block code copies the rest of system BIOS code
from ROM into DRAM. This process is known as "BIOS shadowing". Shadowed
system BIOS code and data segments reside in lower DRAM regions below 1MB.
Main system BIOS code is located in memory ranges 0xE0000 - 0xEFFFF or
0xF0000 - 0xFFFFF.

This run-time firmware
consists of System Management Interrupt (SMI) handlers that execute in
System Management Mode (SMM) of a CPU.
BIOS firmware includes not only boot-time code but also firmware that will
be executing at run-time "in parallel" to the Operating System but in its
own "orthogonal" SMRAM memory reserved from the OS.

In response
to SMI it executes special SMI handler located in System Management RAM
(SMRAM) region reserved by the BIOS from Operating System for various SMI
handlers. SMRAM is consisting of several regions contiguous in physical
memory: compatibility segment (CSEG) fixed to addresses 0xA0000 - 0xBFFFF
below 1MB or top segment (TSEG) that can reside anywhere in the physical
memory.

If CPU accesses CSEG while not in SMM mode (regular protected mode code),
memory controller forwards the access to video memory instead of DRAM.
Similarly, non-SMM access to TSEG memory is not allowed by the hardware.
Consequently, access to SMRAM regions is allowed only while processor is
executing code in SMM mode. At boot time, system BIOS firmware initializes
SMRAM, decompresses SMI handlers stored in BIOS ROM and copies them to
SMRAM. BIOS firmware then should "lock" SMRAM to enable its protection

Upon receiving SMI CPU starts fetching SMI handler instructions from SMRAM
in big real mode with predefined CPU state. Shortly after that, SMI code
in modern systems initializes and loads Global Descriptor Table (GDT) and
transitions CPU to protected mode without paging. SMI handlers can access
4GB of physical memory. Operating System execution is suspended for the
entire time SMI handler is executing till it resumes to protected mode and
restarts OS execution from the point it was interrupted by SMI.

Default treatment of SMI and SMM code by the processor that supports
virtual machine extensions (for example, Intel VMX) is to leave virtual
machine mode upon receiving SMI for the entire time SMI handler is
executing [intel_man]. Nothing can cause CPU to exit to virtual machine
root (host) mode when in SMM, meaning that Virtual Machine Monitor (VMM)
does not control/virtualize SMI handlers.

the SMM represents an isolated and "privileged"
environment, and Once malicious code is
injected into SMRAM, no OS kernel or VMM based anti-virus software can
protect the system nor can they remove it from SMRAM.

SMI handlers is a
part of BIOS system firmware and can be disassembled similarly to any BIOS code.
almost no motherboards use digitally signed non-EFI BIOS firmware.
There are two easy ways to dump SMI handlers on a system:

1. Use any vulnerability to directly access SMRAM from protected mode and
   dump all contents of SMRAM region used by the BIOS (TSEG, High SMRAM or
   legacy SMRAM region at 0xA0000-0xBFFFF). For instance, if BIOS doesn't
   lock SMRAM by setting D_LCK bit then SMRAM can be dumped after
   modifying SMRAMC PCI configuration register as explained in [smm] and
   [phrack_smm].

2. There's another, probably simpler, way to disassemble SMI handlers, that
   doesn't require access to SMRAM at run-time. 

   2.1. Dump BIOS firmware binary from BIOS ROM using Flash programmer or
   simply download the latest BIOS binary from vendor's web site ;)
   AMIBIOS BIOS Module Manipulation Utility, MMTool.exe, to
   extract the Main BIOS module
   Open downloaded .ROM file in MMTool,
   choose to extract "Single Link Arch BIOS" module (ID=1Bh), check "In
   uncompressed form" option and save it. This is uncompressed Main BIOS
   module containing SMI handlers.
   
      Check out a resource on modifying AMI BIOS on The Rebels Heaven forum
   [ami_mod].
   using HIEW or IDA Pro
   
   
   Each entry in the array starts with signature
"$SMIxx" where last two characters 'xx' identify specific SMI handler.	
Both tables have the last structure with '$DEF' signature which describes
default SMI handler invoked when none of other handlers claimed ownership
of current SMI. It does nothing more than simply clearing all SMI statuses.

From the above tables we can try to reconstruct contents of each table
entry:

_smi_handler STRUCT
  signature		BYTE	'$SMI',?,?
  some_flags		WORD	0
  some_ptr0		DWORD	?
  some_ptr1		DWORD	?
  some_ptr2		DWORD	?
  handle_smi_ptr	DWORD	?
_smi_handler ENDS

Each SMI handler entry in SMI dispatch table starts with signature '$SMI'
followed by 2 characters specific to SMI handler. Only entry for the
default SMI handler starts with '$DEF' signature.

Each _smi_handler entry contains several pointers to SMI handler functions.
The most important pointer occupies last 4 bytes, handle_smi_ptr. It points
to the main handling function of the corresponding SMI handler.


Disassembling "main" SMI dispatching function


A special SMI dispatch routine (let's name it "dispatch_smi") iterates
through each SMI handler entry in the table and invokes its handle_smi_ptr.
If none of the registered SMI handlers claimed ownership of the current SMI
it invokes handle_smi_ptr routine of $DEF handler.

Replacing default SMI handler ($DEF) may be possible if injected payload
is designed to handle an SMI that isn't supported by the current BIOS.



SMI dispatch table


Here's a hint how to find where BIOS firmware sets D_LCK bit. BIOS
   firmware is most likely using legacy I/O access to PCI configuration
   registers using 0xCF8/0xCFC ports. To access SMRAMC register BIOS
   should first write value 0x8000009C to 0xCF8 address port and then a
   needed value (typically, 0x1A to lock SMRAM) to 0xCFC data port.



detailed information on reversing Award and AMI BIOS:
Pinczakko [bios_disasm]









Movies;
	Cybergedden
	ask me anything




purranoid



why dont i shove a broom up my ass and sweap the floor while im at it


liberty and justice for most




In cell lines transfected with human catecholamine transporters, amphetamine tripled the
expression of the early intermediate gene c-fos, which is thought to play an important role in
neural plasticity




Beyond the characterization of generally safe treatment protocols, it is important to identify
protective factors. As noted above, a genotype that codes for lower density of dopamine D2
receptors (compared to a parallel functional polymorphism), protects against amphetamine-
induced psychosis 198. Treatment with either lithium or valproate reportedly protect against
dextroamphetamine-induced alterations of brain choline concentration in patients with bipolar
disorder 









(execute_kernexec_retaddr)
(execute_kernexec_fptr)
PLUGIN_FINISH_TYPE callback: sets TYPE_READONLY
pax_track_stack
Static Single Assignment (SSA)
GCC plugins
Kernel stack information leak reduction (STACKLEAK)
Read-only function pointers (CONSTIFY)
KERNEXEC/amd64 helper plugin
Integer (size) overflows (SIZE_OVERFLOW)
Latent Entropy Extraction (LATENT_ENTROPY)
free_pages_prepare
check_object_size

SLAB_USERCOPY flag are let
through
cifs_request, cifs_small_rq, jfs_ip, kvm_vcpu,
names_cache, task_xstate
All kmalloc-* slabs (for now)

Limited stack buffer checking (object_is_on_stack)
Current function frame under CONFIG_FRAME_POINTER
Current kernel stack without CONFIG_FRAME_POINTER

switch_mm: calls __clone_user_pgds and
__shadow_user_pgds
clone: sets up the normal userland pgd entries in cpu_pgd[N]
shadow: sets up the shadow userland mapping in cpu_pgd[N]

swapper_pg_dir (init_level4_pgt on amd64) is kept as
master pgd for the kernel
cpu_pgd[NR_CPUS][PTRS_PER_PGD] array
Invariant:
cr3 on cpuN must always point to cpu_pgd[N]


kernel data segment (__KERNEL_DS) prevents
userland access
http://forums.grsecurity.net/viewtopic.php?f=7&t=3046

CONFIG_DEBUG_SET_MODULE_RONX)
http://kernelbof.blogspot.com/2009/04/kernel-memory-corruptions-are-not-just.html

ioremap problem: too easy access to physical memory
No access allowed above 1MB
No more sensitive data in the first 1MB

BIOS/ACPI (ioremap)
Does not prevent userland code execution per se
KERNEXEC gcc p


kmaps: tool for auditing a page table hierarchy
More details than CONFIG_X86_PTDUMP
	
	
	


Makes some important kernel data read-only (IDT, GDT,
some page tables, CONSTIFY, __read_only, etc)




have __KERNEL_CS cover only kernel code
base: __PAGE_OFFSET+__LOAD_PHYSICAL_ADDR
limit: 4GB during init, _etext after free_initmem

CONFIG_X86_PTDUMP
vsyscall, BIOS/ACPI (ioremap)
CR4.SMEP
CONFIG_DEBUG_SET_MODULE_RONX)



Non-executable Kernel pages (KERNEXEC)
Userland/kernel separation (UDEREF)
Userland/kernel copying
(USERCOPY/STACKLEAK/SANITIZE)
Reference counter overflows (REFCOUNT)
NX bit
SMEP
backtrace, ftrace,
kprobes, lockdep, perf




PaX - gcc plugins:
Structure Constification (CONSTIFY)
Latent Entropy Extraction (LATENT_ENTROPY)
Kernel Stack Leak Reduction (STACKLEAK/STRUCTLEAK)
Static Single Assignment (SSA) based representation

http://forums.grsecurity.net/viewtopic.php?f=7&t=3043
CONSTIFY:		# find all non-constifiable types/variables
REFCOUNT:		# find all non-refcount atomic_t/atomic64_t uses
SIZE_OVERFLOW:	# walk use-def chains across function calls, eliminate the hash table
STACKLEAK:		# find all local variables whose address sinks into copy*user
USERCOPY:		# find all kmalloc-* slab allocations that sink into copy*user

devrandom			# Programs to test /dev/*random.
malloc				# A program to test and benchmark malloc().
netfibs				# Programs to test multi-FIB network stacks.
posixshm			# A program to test POSIX shared memory.
testfloat			# Programs to test floating-point implementations
RTL pass			# removes unneeded pax_track_stack calls
pax_check_alloca
pax_track_stack
checkpatch.pl
checkpatch.pl: 		# no modification, source code analysis (pre-AST)
sparse: 			# no modification, only analysis
coccinelle: 		# modification by generating source patches doesn’t scale, harder to maintain non-executable pages





http://www.cse.iitb.ac.in/grc/


First set of optimization/transformation passes runs on
GIMPLE (, )
Data structures: cgraph_node, function, basic_block,
gimple, tree

GCC IR #2: RTL
GIMPLE is lowered to RTL (pre-SSA gcc had only this)
Second set of optimization passes runs on RTL
(-fdump-rtl-all)
Data structures: rtx, tree


gcc-4.8.1 -O2 -fdump-tree-all -fdump-ipa-all
-fdump-rtl-all -fdump-passes
-fdump-tree-ssa-raw
-fdump-tree-ssa
-fdump-ipa-all
-fdump-tree-all

checkpatch.pl


PLUGIN_ATTRIBUTES callback: registers do_const and
no_const attributes
Linux code patched by hand
Could be automated (static analysis, LTO)
PLUGIN_FINISH_TYPE callback: sets TYPE_READONLY and
C_TYPE_FIELDS_READONLY on eligible structure types
Only function pointer members, recursively
do_const is set, no_const is not set



per-cpu pgd concept
Idea:		# instead of a single per-process pgd have one per-cpu
Allows local (per-cpu) changes to the process memory map
swapper_pg_dir (init_level4_pgt on amd64) is kept as
master pgd for the kernel
cpu_pgd[NR_CPUS][PTRS_PER_PGD] array
Invariant:
cr3 on cpuN must always point to cpu_pgd[N] Reduces number of userland pgd entries (256 vs. 8 on amd64), reduces ASLR (5 bits less)


switch_mm: calls 
__clone_user_pgds		# sets up the normal userland pgd entries in cpu_pgd[N]
__shadow_user_pgds		# sets up the shadow userland mapping in cpu_pgd[N]








KERNEXEC/amd64 helper plugin

CVE-2013-0914 (sa_restorer leak between userland processes)
CVE-2013-2141 (do_tkill kernel stack leak)
CVE-2013-2141

SIZE_OVERFLOW 2012
When a walk stops, stmt duplication begins
New variable is created with signed_size_overflow_type
DImode or TImode (signed)

PLUGIN_ATTRIBUTES
SImode/DImode vs. DImode/TImode
kmalloc(count * sizeof...)

handle_function_arg
handle_function
size_overflow
PLUGIN_PASS_MANAGER_SETUP:
PLUGIN_FINISH_TYPE

PLUGIN_START_UNIT callback:




gcc-plugin-compat.h

C_TYPE_FIELDS_READONLY

Some boilerplate code: plugin_is_GPL_compatible,
plugin_info, plugin_init
Pass registration: register_callback,
register_pass_info, simple_ipa_opt_pass,
ipa_opt_pass_d, gimple_opt_pass, rtl_opt_pass
Callbacks: PLUGIN_INFO, PLUGIN_START_UNIT,
PLUGIN_PASS_MANAGER_SETUP, PLUGIN_ATTRIBUTES,
PLUGIN_FINISH_TYPE, PLUGIN_FINISH_DECL
opt_pass: type, name, gate, execute, pass number,
properties, todo flags


thread_info



##########################################################################
##########################################################################










{+} The arithmetic logic unit (ALU) component does the actual pro-
cessing. It receives data and instructions and delivers a result.








Physically, a CPU is a very small and thin sheet of semiconductor material
(usually silicon) with a complex array of tiny transistors and buses stamped
into it with a die. Semiconductor material is used for CPUs because it does
not affect the flow of electricity one way or another: The semiconductor
neither conducts nor impedes the electrical flow

{+} ROM-BIOS: A motherboard has an EEPROM chip that contains
the low-level startup instructions for the hardware.

{+} Caches: The caches in a CPU are a type of static RAM (SRAM).



{+} dual inline memory module (DIMM) A
small rectangular circuit board that holds DRAM,
fitting into a memory slot on a motherboard.­

{+} synchronous dynamic RAM (SDRAM)
DRAM that operates at the speed of the
system clock.

{+} single data rate SDRAM (SDR SDRAM)
SDRAM that performs one action per clock tick.

{+} double data rate SDRAM (DDR SDRAM)
SDRAM that performs two actions per clock tick.

{+} chipset The controller chip on a circuit board. 

{+} form factor The size and shape of a circuit 
board, such as a motherboard. 

{+} expansion slot A slot in the motherboard into
which an expansion card (a small circuit board)
can be installed.

{+} expansion card A small circuit board that fits
into a slot on the motherboard to add functionality.


Peripheral Component Interface (PCI)
A motherboard slot that accepts PCI expansion
boards. PCI is considered a legacy interface
(mostly obsolete).
PCI Express (PCIe) A new and updated 
version of the PCI motherboard slot. Different 
numbers of channels are used in different sized 
PCIe slots, such as 16, 4, or 1. 

Digital Visual Interface (DVI) A digital port
for connecting a monitor to a PC.
Video Graphics Adapter An analog port for
connecting a monitor to a PC.


Universal Serial Bus (USB) A general-purpose
port for connecting external devices to a PC.
IEEE 1394A A connector used to connect
certain types of devices to a computer that require
high-speed connection, such as some external
hard drives and video cameras. A competitor to
USB. Also called FireWire.


PS/2 A connector used to connect some older 
keyboards and mice to a computer. PS stands for 
Personal System. This connector was first intro- 
duced with the IBM PS/2 computer in 1987. 

parallel port A port used to connect some older 
printers to a computer. It is sometimes called an 
LPT port, which stands for Line Printer. 
	







**** MEMORY LAYOUT

The traditional memory map for the kernel loader, used for Image or
zImage kernels, typically looks like:

	|			 |
0A0000	+------------------------+
	|  Reserved for BIOS	 |	Do not use.  Reserved for BIOS EBDA.
09A000	+------------------------+
	|  Command line		 |
	|  Stack/heap		 |	For use by the kernel real-mode code.
098000	+------------------------+	
	|  Kernel setup		 |	The kernel real-mode code.
090200	+------------------------+
	|  Kernel boot sector	 |	The kernel legacy boot sector.
090000	+------------------------+
	|  Protected-mode kernel |	The bulk of the kernel image.
010000	+------------------------+
	|  Boot loader		 |	<- Boot sector entry point 0000:7C00
001000	+------------------------+
	|  Reserved for MBR/BIOS |
000800	+------------------------+
	|  Typically used by MBR |
000600	+------------------------+ 
	|  BIOS use only	 |
000000	+------------------------+






When using bzImage, the protected-mode kernel was relocated to
0x100000 ("high memory"), and the kernel real-mode block (boot sector,
setup, and stack/heap) was made relocatable to any address between
0x10000 and end of low memory












For a modern bzImage kernel with boot protocol version >= 2.02, a
memory layout like the following is suggested:

	~                        ~
        |  Protected-mode kernel |
100000  +------------------------+
	|  I/O memory hole	 |
0A0000	+------------------------+
	|  Reserved for BIOS	 |	Leave as much as possible unused
	~                        ~
	|  Command line		 |	(Can also be below the X+10000 mark)
X+10000	+------------------------+
	|  Stack/heap		 |	For use by the kernel real-mode code.
X+08000	+------------------------+	
	|  Kernel setup		 |	The kernel real-mode code.
	|  Kernel boot sector	 |	The kernel legacy boot sector.
X       +------------------------+
	|  Boot loader		 |	<- Boot sector entry point 0000:7C00
001000	+------------------------+
	|  Reserved for MBR/BIOS |
000800	+------------------------+
	|  Typically used by MBR |
000600	+------------------------+ 
	|  BIOS use only	 |
000000	+------------------------+

... where the address X is as low as the design of the boot loader
permits.







**** THE REAL-MODE KERNEL HEADER

In the following text, and anywhere in the kernel boot sequence, "a
sector" refers to 512 bytes.  It is independent of the actual sector
size of the underlying medium.

The first step in loading a Linux kernel should be to load the
real-mode code (boot sector and setup code) and then examine the
following header at offset 0x01f1.  The real-mode code can total up to
32K, although the boot loader may choose to load only the first two
sectors (1K) and then examine the bootup sector size.

The header looks like:

Offset	Proto	Name		Meaning
/Size

01F1/1	ALL(1	setup_sects	The size of the setup in sectors
01F2/2	ALL	root_flags	If set, the root is mounted readonly
01F4/4	2.04+(2	syssize		The size of the 32-bit code in 16-byte paras
01F8/2	ALL	ram_size	DO NOT USE - for bootsect.S use only
01FA/2	ALL	vid_mode	Video mode control
01FC/2	ALL	root_dev	Default root device number
01FE/2	ALL	boot_flag	0xAA55 magic number
0200/2	2.00+	jump		Jump instruction
0202/4	2.00+	header		Magic signature "HdrS"
0206/2	2.00+	version		Boot protocol version supported
0208/4	2.00+	realmode_swtch	Boot loader hook (see below)
020C/2	2.00+	start_sys_seg	The load-low segment (0x1000) (obsolete)
020E/2	2.00+	kernel_version	Pointer to kernel version string
0210/1	2.00+	type_of_loader	Boot loader identifier
0211/1	2.00+	loadflags	Boot protocol option flags
0212/2	2.00+	setup_move_size	Move to high memory size (used with hooks)
0214/4	2.00+	code32_start	Boot loader hook (see below)
0218/4	2.00+	ramdisk_image	initrd load address (set by boot loader)
021C/4	2.00+	ramdisk_size	initrd size (set by boot loader)
0220/4	2.00+	bootsect_kludge	DO NOT USE - for bootsect.S use only
0224/2	2.01+	heap_end_ptr	Free memory after setup end
0226/1	2.02+(3 ext_loader_ver	Extended boot loader version
0227/1	2.02+(3	ext_loader_type	Extended boot loader ID
0228/4	2.02+	cmd_line_ptr	32-bit pointer to the kernel command line
022C/4	2.03+	ramdisk_max	Highest legal initrd address
0230/4	2.05+	kernel_alignment Physical addr alignment required for kernel
0234/1	2.05+	relocatable_kernel Whether kernel is relocatable or not
0235/1	2.10+	min_alignment	Minimum alignment, as a power of two
0236/2	2.12+	xloadflags	Boot protocol option flags
0238/4	2.06+	cmdline_size	Maximum size of the kernel command line
023C/4	2.07+	hardware_subarch Hardware subarchitecture
0240/8	2.07+	hardware_subarch_data Subarchitecture-specific data
0248/4	2.08+	payload_offset	Offset of kernel payload
024C/4	2.08+	payload_length	Length of kernel payload
0250/8	2.09+	setup_data	64-bit physical pointer to linked list
				of struct setup_data
0258/8	2.10+	pref_address	Preferred loading address
0260/4	2.10+	init_size	Linear memory required during initialization
0264/4	2.11+	handover_offset	Offset of handover entry point







Assigned boot loader ids (hexadecimal):

	0  LILO			(0x00 reserved for pre-2.00 bootloader)
	1  Loadlin
	2  bootsect-loader	(0x20, all other values reserved)
	3  Syslinux
	4  Etherboot/gPXE/iPXE
	5  ELILO
	7  GRUB
	8  U-Boot
	9  Xen
	A  Gujin
	B  Qemu
	C  Arcturus Networks uCbootloader
	D  kexec-tools
	E  Extended		(see ext_loader_type)
	F  Special		(0xFF = undefined)
       10  Reserved
       11  Minimal Linux Bootloader <http://sebastian-plotz.blogspot.de>
       12  OVMF UEFI virtualization stack









The kernel is started by jumping to the kernel entry point, which is
located at *segment* offset 0x20 from the start of the real mode
kernel. 



ACPI tables have different types and purposes:
– the Root System Description Table (RSDT) contains a set of pointers to
the other tables. The address of the RSDT is provided by the Root System
Description Pointer (RSDP), which must be stored in the Extended BIOS
Data Area (EBDA), or in the BIOS read-only memory space. The OSPM
will only locate the RSDP by searching for a particular magic number (the
RSDP signature) that the RSDP is required to begin with;


The Linux kernel also allows the user to define an alternate DSDT file, differ-
ent from the one specified by the BIOS. This function is quite convenient as it
allows the DSDT to be modified, e.g. for debug purposes.
The easiest way to force the kernel to use a custom DSDT is through the use
of an “initial RAM disk” (initrd). An initrd is usually used by the bootloader of
a Linux system to load kernel modules that are required to access the root file
system (SATA or IDE drivers, file system-related modules for instance)


But the initrd can also be used to provide
a custom DSDT to the kernel. For the kernel to use a custom DSDT, all we have
to do is create an initrd file with the following command1 and provide the initrd
to the bootloader.
mkinitrd --dsdt=dsdt.aml initrd.img 2.6.17

It is also possible to copy the system DSDT and change the definition of ACPI
registers. If we map kernel structures such as system calls to ACPI registers, or
define new ACPI registers, compiling the modified DSDT does not cause any
warning. It is then possible to update the initrd of the system in order for the
modified DSDT to be used by the system after the next reboot. The following
code describes how to define such new ACPI registers. 



The first OperationRe-
gion() command defines an ACPI register called LIN corresponding to a byte-
wide PCI configuration register. The second OperationRegion command defines
a system memory 12-byte wide ACPI register called SAC composed of three
4-byte registers defined through the following Field() command called SAC1,
SAC2 and SAC3.


/* PCI configuration register : */
/* Bus 0 Dev 0 Fun 0 Offset 0x62 is mapped to LIN */
Name(_ADR, 0x00000000)
OperationRegion(LIN, PCI_Config, 0x62, 0x01)
Field(LIN, ByteAcc, Nolock, Preserve) { INF,8 }
/* System Memory at address 0x00175c96 */
/* (Setuid() syscall) is mapped to SAC */
OperationRegion (SAC, SystemMemory, 0x00175c96, 0x000c)
Field (SAC, AnyAcc, NoLock, Preserve)
{ SAC1,32, SAC2,32, SAC3,32 }




Actually, the OSPM has no particular way to determine whether ACPI
tables are genuine or not. Also, the OSPM has no means to properly identify
what the ACPI registers are. As ACPI does not provide any ACPI register
identification scheme, the OSPM cannot ensure that the methods defined in the
DSDT actually manipulate only ACPI registers, so the OSPM can merely trust
those methods.

platform- specific information (for instance the location of ACPI registers) is
pushed in ACPI tables for the operating system to configure the platform without
an in-depth understanding of the semantics of the chipset or devices registers. In
other words, ACPI would be useless if the OSPM knew enough of the platform
details to identify the ACPI registers.


The chipset is
able to know the location and the purpose of most ACPI registers, but it does
not know when the OSPM is running on the CPU, nor can it distinguish ACPI-
related access to the registers from non-ACPI-related accesses. From the chipset
perspective, a userspace code attempting to modify a register is not different
from the OSPM, so there is no way for the chipset to enforce that the OSPM
be the only component to access ACPI-related registers and that OSPM cannot
access non-ACPI-related registers


the chipset is already
used as a policy enforcement point to restrict access to security-critical memory
areas such as the SMRAM [3], so using the chipset to make the platform more
secure would not really be that innovative.



– it is impossible to detect a bug in the DSDT that would incorrectly define an
ACPI register (remember that disassembling the DSDT and reassembling it
on some computers reveals AML errors);
– it is impossible to detect live modifications of the DSDT image the OSPM
is using.
SMI handler is a
component running in the CPU System Management Mode [3] and that is vir-
tually inaccessible from operating systems. 

Another possibility for the rootkit is
modify one of the methods of the DSDT to make sure that each time this
method is launched by the OSPM, functions of the rootkit get executed.

On Linux-operated laptops, the STA (Status Request) function of the BAT1
device is used by the OSPM to check the status of the main battery, so it is
supposed to be executed quite frequently (experiments have shown that it is
invoked around once every 10 seconds).
The _PSR (Power Source) function of the ADP1 device is called when the power
adapter is unplugged or plugged in. This function is used by the system to
determine what the current power sources are. The attacker can use the newly
created INF ACPI to keep track of the number of times the _PSR function has
been executed in a row without the BAT1._STA function being called. This can
be achieved by means of the following modifications. The BAT1._STA function is
modified to ensure that each time BAT1._STA is executed, the INF ACPI register
is set to 1. This can be done by using the Store() ASL command.
it is possible to modify other functions4 in the same way as BAT1._STA to make
sure that the INF ACPI register is set to 1 as often as possible.

it seems AMD has an equivalent of Intel ME also,
just disguised as Platform Security Processor (PSP)


SYSRET attack



Core Root of Trust for Measurement (CRTM)
For the BIOS-enforced (Static) Trusted Boot to make sense, the CRTM would
have to be stored in some immutable ROM-like memory. In fact this is exactly
what the TCG spec has required for years


The Core Root of Trust for Measurement (CRTM) MUST be an
immutable portion of the Host Platform’s initialization
code that executes upon a Host Platform Reset
This way, even if the attacker somehow managed to reflash the BIOS code, the
(original) trusted CRTM code would still run first and measure the (modified)
code in the flash, and send this hash to the TPM, before the malicious code
could forge the measurements


































	7 deadly fuckups
	CIA Tradecraft
	Dont fuck it up





https://sites.google.com/site/mydebiansourceslist/
https://code.google.com/p/pentest-bookmarks/wiki/BookmarksList



https://hak5.org/
http://cultdeadcow.com/


#######################
## Professional Infosec Training:
#######################

http://www.openculture.com/freeonlinecourses
http://www.codecademy.com/
https://www.coursera.org/courses




http://www.howtogeek.com
http://www.thegeekstuff.com
http://www.cyberciti.biz/


http://www.irongeek.com/
http://www.ehacking.net/

http://www.question-defense.com/http://cultdeadcow.com/
http://www.social-engineer.org/

http://www.backtrack-linux.org/wiki/index.php/Main_Page




http://www.reuters.com
https://firstlook.org/theintercept
https://threatpost.com
linuxtoday.com
http://arstechnica.com/arstechnica/index
http://www.securityfocus.com
http://gizmodo.com/
http://lifehacker.com/
https://thehackernews.com/
http://packetstormsecurity.com/
https://www.schneier.com
http://www.dailydot.com
http://krebsonsecurity.com
theguardian.com
https://www.trustwave.com
http://www.spiegel.de/international/index.rss




http://packetstormsecurity.com/Crackers/wordlists/
http://wiki.skullsecurity.org/Passwords
http://www.nirsoft.net/articles/saved_password_location.html
http://www.skullsecurity.org/wiki/index.php/Passwords
http://www.skullsecurity.org/wiki/index.php/Main_Page



I2P

http://theanondog.i2p/cgi-bin/feed.py
http://i2p-projekt.i2p/en/feed/blog/atom
http://plugins.i2p/news/index.rss




http://cultdeadcow.com/

http://www.stoned-vienna.com/


References and links
http://software.intel.com/en-us/articles/architecture-guide-intel-active-management-technology/
http://software.intel.com/sites/manageability/AMT_Implementation_and_Reference_Guide/
http://theinvisiblethings.blogspot.com/2009/08/vegas-toys-part-i-ring-3-tools.html
http://download.intel.com/technology/itj/2008/v12i4/paper[1-10].pdf
http://web.it.kth.se/~maguire/DEGREE-PROJECT-REPORTS/100402-Vassilios_Ververis-with-cover.pdf
http://www.thefengs.com/wuchang/work/courses/cs592/cs592_spring2007/
http://www.stewin.org/papers/dimvap15-stewin.pdf
http://www.stewin.org/techreports/pstewin_spring2011.pdf
http://www.stewin.org/slides/pstewin-SPRING6-EvaluatingRing-3Rootkits.pdf
http://marcansoft.com/blog/2009/06/enabling-intel-vt-on-the-aspire-8930g/
http://flashrom.org/trac/flashrom/browser/trunk/Documentation/mysteries_intel.txt
http://review.coreboot.org/gitweb?p=coreboot.git;a=blob;f=src/southbridge/intel/bd82x6x/me.c
http://download.intel.com/technology/product/DCMI/DCMI-HI_1_0.pdf
www.blackhat.com/presentations/bh-federal-06/BH-Fed-06-Heasman.pdf
http://www.acpi.info/spec.htm









