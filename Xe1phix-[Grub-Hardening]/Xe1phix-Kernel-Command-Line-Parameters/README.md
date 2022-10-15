# Xe1phix - Kernel Commandline Parameters
<br>
<p align="center">
  <a href="https://gitlab.com/xe1phix/ParrotLinux-Public-Kiosk-Project/tree/master/Xe1phix-Grub-Hardening/Xe1phix-Kernel-Command-Line-Parameters">
    <img src="https://img.shields.io/badge/Xe1phix-Kernel_Commandline_Parameters-darkred?style=flat&logo=gitlab" alt="Xe1phix Kernel Parameter Hardening">
  </a>
</p>
<br>

<details>
<summary>Table of content</summary>

## Table of content
   * [Xe1phix - Kernel Commandline Parameters](#xe1phix-kernel-commandline-parameters)
      * [Commonly Used Commandline Parameters](#commonly-used-commandline-parameters)
         * [Commonly Used Commandline Parameters - Image](#common-parameters-image)
      * [Systemd + Module Based Kernel Parameters](#systemd+module-based-parameters)
         * [Systemd + Module Based Kernel Parameters - Image](#systemd+module-based-parameters-image)
</details>

# Commonly Used Commandline Parameters
- FStab Mount Options
- LUKS Encrypted Persistence Parameters
- User|Group Quotas
- Security Modes
    - AppArmor Security
    - SELinux Security
    - Tomoyo Security
- KALSR
- NoAutoLogin
- Username
- Debug
- NoEFI
- NoRock
- NoJuliet
- 
![Kernel Self Protection Project - Recommended Kernel Hardening Settings](https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project/Recommended_Settings#kernel_command_line_options)
- pti=on          - Kernel Page Table Isolation
- slub_debug=ZF   - SLUB redzoning and sanity checking
- slub_debug=P    - slub/slab allocator free poisoning
- page_poison=1   - Enable buddy allocator free poisoning
- iommu.strict=1  - Force IOMMU TLB invalidation
- slab_nomerge    - Disable slab merging (makes many heap overflow attacks more difficult)
- init_on_alloc=1 - (Wipe slab and page allocations)
- randomize_kstack_offset=on - (Randomize kernel stack offset on syscall entry)
- 

![Commonly Used Commandline Parameters - Image](https://gitlab.com/xe1phix/ParrotLinux-Public-Kiosk-Project/raw/master/Xe1phix-Grub-Hardening/Xe1phix-Kernel-Command-Line-Parameters/Xe1phix-Kernel-Parameter-Notes-Digitally-Converted/KernelParameters4.jpg)
<br>


# Systemd + Module Based Kernel Parameters
![Xe1phix - Kernel Commandline Parameters](https://gitlab.com/xe1phix/ParrotLinux-Public-Kiosk-Project/raw/master/Xe1phix-Grub-Hardening/Xe1phix-Kernel-Command-Line-Parameters/Xe1phix-Kernel-Parameter-Notes-Digitally-Converted/KernelParameters2-v2.jpg)

