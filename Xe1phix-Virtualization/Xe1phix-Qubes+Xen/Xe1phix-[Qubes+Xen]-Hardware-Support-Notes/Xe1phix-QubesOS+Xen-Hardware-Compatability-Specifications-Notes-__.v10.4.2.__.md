



            ----------
             ${IOMMU} 
            ----------
  ---------------------------------
   $['IO Memory Management Unit'] 
  ---------------------------------
          support from 
         CPU/BIOS/chipset 
          is needed for:
  ------------------------------
    $['Xen IO Virtualization'] 
  ------------------------------

          ------------
            ${IOMMU} 
          ------------
  makes it possible to dedicate 
     PCI device securely to
       A Xen VM by using
    ------------------------
     $['Xen PCI passthru']
    ------------------------


           _____________
          | ${'SR-IOV'} |
 -------------------------------------
 |-['Single Root IO Virtualization']-|
 -------------------------------------
     can be used together with:

      -----------------------
       ${IOMMU PCI passthru} 
      -----------------------
                + 
         ----------------
          ${PCI Express}
         ----------------
              With 
           -----------
            ${SR-IOV}
           ----------- 
          capabilities 






For example: 

          Intel 82599 
    10 Gigabit Ethernet NIC
          supports 64
   ---------------------------
     Virtual Functions (VFs) 
   ---------------------------


      which means the NIC 
 can be configured to show up 
as 64 different PCI devices (PCI IDs)


       so you can use 
     Xen PCI passthru to
 passthrough each VF to some
          Xen VM 

      and give the VM 
       direct access 
    to the PCI-e device. 


    -----------
     ${SR-IOV}
    -----------
 provides excellent 
   IO performance 
and very low overhead.








        ---------
        ${SR-IOV} 
        ---------
needs to be supported and 
  enabled by the system:
      ------------
       ${chipset}
            +
         ${BIOS} 
            +
        ${PCI-e} 
      -------------
      device itself. 





Virtual Functions (VFs)




run "xl info" in dom0 and check from the 'xen_caps' line if Xen is able to run hvm guests.


Also Xen hypervisor boot messages in "xl dmesg" show if hardware virtualization (HVM) is enabled or disabled. 


xl dmesg | grep -i hvm





output for an Intel system where HVM is supported by the CPU:


(XEN) HVM: VMX enabled



output for an Intel system where HVM is supported by the CPU but it's disabled in the system BIOS:


(XEN) VMX disabled by Feature Control MSR.




xl dmesg | grep -i hvm


output for an AMD system where HVM is supported:


(XEN) HVM: SVM enabled





check Xen dmesg by running "xl dmesg" to verify if HAP is supported on your CPU:

(XEN) HVM: Hardware Assisted Paging detected and enabled.

Newer Xen versions (4.1.3+, 4.2.x+) will have info like this:

(XEN) HVM: Hardware Assisted Paging (HAP) detected
(XEN) HVM: HAP page sizes: 4kB, 2MB

HAP support is provided by the following features on CPUs:

    Intel EPT (Extended Page Tables).
    AMD NPT (Nested Page Tables, sometimes also called as AMD RVI - Rapid Virtualization Indexing).













${PV} (ParaVirtualized) VMs 
         on any 
    ${PAE-capable x86} 
           or 
      $['x86_64 CPU']
  (both Intel and AMD CPUs)


          if you run Xen as
          ---------------
            ${PV} domUs
          ---------------
               Then:
 ------------------------------------
  $['CPU Virtualization Extensions']
 ------------------------------------
      are NOT required or used.



            Xen requires 
 ------------------------------------
  $['CPU Virtualization Extensions']
 ------------------------------------
           In order to run 
            ------------
             ${Xen HVM}
            ------------
     --------------------------
       $['Fully Virtualized'] 
     --------------------------
                VMs


the system BIOS needs to support, 
and enable the 

CPU Virtualization Extensions.

  $['CPU Virtualization Extensions'] 
            are called:

 ${Intel VT-x}
      or 
   ${AMD-V}


 [?] they are required for running Xen HVM guests.


          ${HAP}


$['Hardware Assisted Paging']


can be optionally used 
to boost the performance of 


$['Xen memory management'] 

          for 

       ${HVM} VMs 

          The 
       -----------
         ${HAP} 
       -----------
        feature

 is an additional feature of the CPU, 
and it's not present on older CPUs. 



    ${Intel HAP}
    
      is called 
      
    ${Intel EPT} 
    
$['Extended Page Tables]

             and 
        -------------
         ${AMD HAP}
        -------------
        
         is called:
         
        -------------
         ${AMD NPT} 
        -------------
  --------------------------
   $['Nested Page Tables']
  --------------------------
  
      --------------
        ${AMD NPT}
      --------------
      
  is sometimes referred as:

      --------------
        ${AMD RVI} 
      --------------
-------------------------------------
 $['Rapid Virtualization Indexing']
-------------------------------------










    $['Opteron]' 
  (2nd generation) 
        and 
 $(third-generation) 
 
 
  $(Phenom) 
     and 
 $(Phenom II) 
  processors


The 
 $(APU Fusion)
   processors 
    support 
   $[AMD-V]
 

all modern 

$['Zen-based AMD]' 
   processors 
    support 
   $[AMD-V]



AMD Opteron CPUs beginning with the 

Family 0x10 Barcelona line, 
and 
Phenom II 
CPUs 
support a 
second generation hardware virtualization technology called 

Rapid Virtualization Indexing 

(formerly known as 

Nested Page Tables

during its development
later adopted by Intel as 

Extended Page Tables (EPT)



$['I/O MMU virtualization [AMD-Vi]

$['input/output memory management unit (IOMMU) 

allows guest virtual machines to 
directly use peripheral devices, 
such as Ethernet, 
accelerated graphics cards, 
and hard-drive controllers, 

      through 
        DMA 
        and 
interrupt remapping.


$[AMD's I/O Virtualization Technology] 
           $[AMD-Vi] 

 originally called 
    $[IOMMU]


 In addition to the 
    CPU support, 
        both 

$[motherboard chipset]
         and 
system firmware (BIOS or UEFI) 
need to fully support the 

$['IOMMU I/O virtualization]' 
      functionality 
    for it to be usable. 




Unfortunately many motherboards ship with broken BIOSes 
(for example incorrect ACPI DMAR, DRHD or RMRR tables) 





add iommu=1 
   flag 
    or 
   vtd=1 
(in older versions)


Check if IOMMU (Intel VT-d or AMD IOMMU) is enabled in the system BIOS. 
Some BIOSes call this feature "IO virtualization" or "Directed IO".

https://xenbits.xen.org/docs/unstable/misc/xen-command-line.html






Even when the chipset supports IOMMU, the bios must have a ACPI IVRS table to enable the use of it! 

So actual support depends on the motherboard manufacturer. 




Motherboards with a BIOS supporting the IOMMU(as reported by users):

    ASUS Crosshair IV (reported working by Jens Krehbiel-GrÃ¤ther)
    ASUS Crosshair V Formula (reported working by Pavel Matěja)
    ASUS F2A85-V PRO
    ASUS M4A89TD Pro/USB3 (reported working by Jens Krehbiel-GrÃ¤ther)
    Asrock 890FX Deluxe3 (reported working by Jens Krehbiel-GrÃ¤ther)
    Biostar TA890FXE (from bios version 89FAD629.BST reported working by Joop Boonen, Konrad Rzeszutek Wilk)
    Gigabyte GA-970A-UD3 (Bios F7)
    Asrock released bios updates supporting IOMMU for all motherboards with A55 or A75 chipset (see discussion)

Motherboards with a beta-bios available from tech-support that supports the IOMMU:

    Gigabyte GA-890FXA-UD5
    Gigabyte GA-890FXA-UD7
    MSI 890FXA-GD70 (from beta-bios 1.75 reported working by Sander Eikelenboom)


AMD server (opteron) chipsets with IOMMU support

    AMD SR5690 / SR5670 (Tyan S8212)






Xen VGA Passthrough with AMD Radeon HD 6450

Hardware Configuration:

    Processor: Intel Core i5-4430 CPU @ 3.00GHz (Quad Core)
    Motherboard: Asrock B85M Pro4 LGA 1150 Motherboard
    Memory: 32 GB DDR3-1600
    PCI-E x16 Display Card: Sapphire AMD Radeon HD 6450 1 GB DDR3
    VT-x: Enabled in UEFI BIOS
    VT-d: Enabled in UEFI BIOS











   Only the 
      PCI 
       or 
   PCI Express 
devices supporting 

$[Function Level Reset] (FLR) 

can be virtualized this way, 
as it is required for reassigning 
various device functions 
between virtual machines.


check if your PCI devices have FLR function,

If you see output with "FLReset-" then your PCI device don't support FLR function. If output have "FLReset+" then it does. 




lspci -vv
lspci -vv | egrep -i --colour flreset







VT-d Pass-Through is a technique to give a domU exclusive access to a PCI function using the IOMMU provided by VT-d. It is primarily targeted at HVM (fully virtualised) guests because PV (paravirtualized) pass-through does not require VT-d (altough it may be utilized too) 



 
The CPU flag for AMD-V is 
$[svm]
 
This may be checked in Linux via 
/proc/cpuinfo
 

grep --color vmx /proc/cpuinfo

egrep -o '(vmx|svm)' /proc/cpuinfo | sort | uniq

egrep '^flags|lm' /proc/cpuinfo  --color






  [ lm ]  Flag      ## 64 bit CPU support
vmx – Intel VT-x, virtualization support
svm – AMD SVM,virtualization support

 aes       hardware AES/AES-NI advanced encryption support




egrep -wo 'vmx|ept|vpid|npt|tpr_shadow|flexpriority|vnmi|lm|aes' /proc/cpuinfo


egrep -wo 'vmx|lm|aes' /proc/cpuinfo 



Intel CPU Virtualization Support (cpu flags)


  [ vnmi ]  Flag            ## Intel Virtual NMI - helps with selected interrupt events in guests.
  [  ]  Flag            ## 
  [  ]  Flag            ## 
  [  ]  Flag            ## 

  [ ept ]  Flag            ## 
  [ vpid ]  Flag            ## 
  
  [ tpr_shadow ]  Flag              ## Intel feature that reduces calls into the hypervisor when accessing the Task Priority Register, 
  [ flexpriority ]  Flag            ## which helps when running certain types of SMP guests.
  
  [  ]  Flag            ## 
  [  ]  Flag            ## 






  [+] AMD CPU Virtualization Support (CPU Flags)


  [  ]  Flag            ## 
  [  ]  Flag            ## 
  [  ]  Flag            ## 
  [  ]  Flag            ## 
  [  ]  Flag            ## 
  [  ]  Flag            ## 
  [  ]  Flag            ## 
  [  ]  Flag            ## 
  [  ]  Flag            ## 
  [  ]  Flag            ## 
  [  ]  Flag            ## 
  [  ]  Flag            ## 


    npt – AMD Nested Page Tables, similar to Intel EPT.
    lbrv – AMD LBR Virtualization support.
    svm_lock – AMD SVM locking MSR.
    nrip_save – AMD SVM next_rip save.
    tsc_scale – AMD TSC scaling support.
    vmcb_clean – AMD VMCB clean bits support.
    flushbyasid – AMD flush-by-ASID support.
    decodeassists – AMD Decode Assists support.
    pausefilter – AMD filtered pause intercept.
    pfthreshold – AMD pause filter threshold.





   ##-=======================================================================-##
   ##  [+] check Intel VT support - provides full hardware virtualization
   ##-=======================================================================-##


   ## ----------------------------------------------- ##
   ##   [?] If the output has the vmx flags, 
   ##       then your Intel CPU is capable of 
   ##       running hardware virtualization.
   ## ----------------------------------------------- ##


   ##-================================================-##
   ##  [+] check AMD V CPU virtualization extensions
   ##-================================================-##




## Finding Intel virtualization, encryption and 64 bit cpu
| sed -e 's/aes/Hardware encryption=Yes (&)/g' \
-e 's/lm/64 bit cpu=Yes (&)/g' -e 's/vmx/Intel hardware virtualization=Yes (&)/g'




VT-d Enabled Systems

AMD FX-8120 / FX-8150



VT-d 


AMD desktop chipsets with IOMMU support

AMD 890FX chipset supports IOMMU. 

[!] Other 890 chipsets don't have IOMMU support!

AMD 990FX, 990X and 970 chipsets support IOMMU.











https://xenproject.org/
https://wiki.debian.org/Xen
https://www.qubes-os.org/
https://www.whonix.org/wiki/Qubes
https://www.qubes-os.org/doc/

https://www.qubes-os.org/doc/system-requirements/
https://wiki.xen.org/wiki/Xen_Common_Problems#What_are_the_names_of_different_hardware_features_related_to_virtualization_and_Xen.3F
https://en.wikipedia.org/wiki/List_of_IOMMU-supporting_hardware
https://www.qubes-os.org/hcl/



https://puri.sm/
https://puri.sm/librem-13/

https://www.qubes-os.org/news/2016/07/21/new-hw-certification-for-q4/
https://www.qubes-os.org/doc/certified-hardware/
https://www.qubes-os.org/doc/hardware-testing/
https://www.qubes-os.org/doc/certified-laptops/
https://www.qubes-os.org/news/2015/12/09/purism-partnership/
https://www.qubes-os.org/doc/certified-hardware/#qubes-certified-laptop-insurgo-privacybeast-x230
https://insurgo.ca/produit/qubesos-certified-privacybeast_x230-reasonably-secured-laptop/
https://www.qubes-os.org/news/2019/07/18/insurgo-privacybeast-qubes-certification/
https://en.wikipedia.org/wiki/List_of_IOMMU-supporting_hardware




https://en.wikipedia.org/wiki/Hardware-assisted_virtualization

https://en.wikipedia.org/wiki/CPUID#EAX.3D1:_Processor_Info_and_Feature_Bits
https://en.wikipedia.org/wiki/Second_Level_Address_Translation
https://en.wikipedia.org/wiki/Second_Level_Address_Translation#Rapid_Virtualization_Indexing
https://en.wikipedia.org/wiki/Second_Level_Address_Translation#Extended_Page_Tables

https://en.wikipedia.org/wiki/Second_Level_Address_Translation#RVI
https://en.wikipedia.org/wiki/X86_virtualization#AMD_virtualization_.28AMD-V.29
https://en.wikipedia.org/wiki/X86_virtualization#Intel_virtualization_(VT-x)
https://en.wikipedia.org/wiki/X86_virtualization#Chipset
https://en.wikipedia.org/wiki/Message_Signaled_Interrupts
https://en.wikipedia.org/wiki/Paravirtualization




https://wiki.xen.org/wiki/VTd_HowTo
https://www.cyberciti.biz/faq/linux-xen-vmware-kvm-intel-vt-amd-v-support/
https://wiki.xen.org/wiki/Xen_PCI_Passthrough#How_can_I_check_if_PCI_device_supports_FLR_.28Function_Level_Reset.29_.3F
https://xenbits.xen.org/docs/unstable/misc/xen-command-line.html
https://wiki.xen.org/wiki/Xen_Common_Problems#What_are_the_names_of_different_hardware_features_related_to_virtualization_and_Xen.3F
http://www.linux-kvm.org/page/How_to_assign_devices_with_VT-d_in_KVM
http://opensecuritytraining.info/AdvancedX86-VTX.html


https://github.com/QubesOS
https://blog.torproject.org/tor-heart-qubes-os
https://www.whonix.org/wiki/Qubes












