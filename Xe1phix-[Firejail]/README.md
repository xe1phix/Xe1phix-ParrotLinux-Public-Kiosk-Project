___
#  [+] Xe1phix - Firejail Wiki
___

![Firejail Banner](https://gitlab.com/xe1phix/LinuxIcons/raw/master/InfoSec/firejail-logo.png)
___

<p align="center">
  <a href="https://telegram.me/xe1phix">
    <img src="https://img.shields.io/badge/Telegram-%40Xe1phix-blue?style=flat&logo=telegram" alt="Telegram @Xe1phix">
  </a>
  <a href="https://gitlab.com/xe1phix/Gnupg/blob/master/Xe1phix-WireGnuPG.txt">
    <img src="https://img.shields.io/badge/Wire-%40Xe1phix-critical?style=flat&logo=tails" alt="Xe1phix's Wire Messenger GnuPG Key">
  </a>
  <a href="https://gitlab.com/xe1phix/Gnupg/blob/master/Xe1phix-InfoSecContact-v4.2.txt">
    <img src="https://img.shields.io/badge/%40Xe1phix-InfoSec_Contact-blue?style=flat&logo=tor" alt="Xe1phix InfoSec-Contact">
  </a>
  <a href="https://secdsm.slack.com">
    <img src="https://img.shields.io/badge/Slack-%40Xe1phix-blueviolet?style=flat&logo=slack" alt="SecDSM Slack @Xe1phix">
  </a>
  <a href="https://twitter.com/xe1phix">
    <img src="https://img.shields.io/twitter/url/https/xe1phix?label=%40Xe1phix&logo=twitter&style=flat" alt="Twitter @Xe1phix">
  </a>
  <a href="https://gitlab.com/xe1phix/Gnupg/blob/master/Xe1phix.asc">
    <img src="https://img.shields.io/badge/Xe1phix's-GnuPG%20Key-red?style=flat&logo=gnu" alt="Xe1phix's GnuPG Key">
  </a>
  <a href="mailto:xe1phix@protonmail.ch">
    <img src="https://img.shields.io/badge/Xe1phix-%40protonmail.ch-blue?style=plastic&logo=gnu" alt="ProtonMail - Xe1phix">
  </a>
  <a href="https://gitlab.com/xe1phix/Gnupg/blob/master/Xe1phix_protonmail.ch.asc">
    <img src="https://img.shields.io/badge/Xe1phix-%40protonmail.ch-blue?style=plastic&logo=gnu" alt="Xe1phix - ProtonMail Public Key">
  </a>
</p>

___

<p align="center">
  <a href="https://repology.org/project/firejail/versions">
    <img src="https://repology.org/badge/latest-versions/firejail.svg" alt="latest packaged version(s)">
  </a>
  <a href="https://repology.org/project/firejail/versions">
    <img src="https://repology.org/badge/version-for-repo/debian_stable/firejail.svg" alt="Debian Stable package">
  </a>
  <a href="https://repology.org/project/firejail/versions">
    <img src="https://repology.org/badge/version-for-repo/parrot/firejail.svg" alt="Parrot package">
  </a>
  <a href="https://repology.org/project/firejail/versions">
   <img src="https://repology.org/badge/version-for-repo/kali_rolling/firejail.svg" alt="Kali Linux Rolling package">
  </a>
  <a href="https://repology.org/project/firejail/versions">
    <img src="https://repology.org/badge/tiny-repos/firejail.svg" alt="Packaging status">
  </a>
</p>


## Table of Contents:

- [Firejail Features](https://gitlab.com/xe1phix/ParrotLinux-Public-Kiosk-Project/-/blob/master/Xe1phix-%5BFirejail%5D/README.md#firejail-features)
- [Xe1phix Youtube Tutorial Videos](https://gitlab.com/xe1phix/ContainerizationFirejail/edit/master/README.md#xe1phix-youtube-tutorial-videos)
- [Xe1phix Archive.org Tutorial Videos](https://gitlab.com/xe1phix/ContainerizationFirejail/edit/master/README.md#xe1phix-archiveorg-tutorial-videos)
- [Xe1phix Bitchute Tutorial Videos](https://gitlab.com/xe1phix/ContainerizationFirejail/edit/master/README.md#xe1phix-bitchute-tutorial-videos)
- [Firejail - Enable AppArmor](https://gitlab.com/xe1phix/ContainerizationFirejail/edit/master/README.md#Firejail-Enable-AppArmor)
- [Firejail Syntax Options](https://gitlab.com/xe1phix/ContainerizationFirejail/edit/master/README.md#firejail-syntax-options)
- [Firejail - Firetools - Firejail-UI](https://gitlab.com/xe1phix/ContainerizationFirejail/edit/master/README.md#firejail-firetools-firejail-ui)
- [Firejail - Firejail-UI - Capabilities](https://gitlab.com/xe1phix/ContainerizationFirejail/edit/master/README.md#firejail-firejail-ui-capabilities)
- [Firejail Resources](https://gitlab.com/xe1phix/ContainerizationFirejail/edit/master/README.md#firejail-resources)

___

## Firejail Features:

- [Seccomp-BPF (Restrict System Call)](https://firejail.wordpress.com/documentation-2/seccomp-guide/)
- [AppArmor Confinement](https://firejail.wordpress.com/documentation-2/basic-usage/#apparmor)
- [User Namespaces (CLONE_NEWUSER)](https://lwn.net/Articles/528078/)
- [Mount namespaces (CLONE_NEWNS)](https://www.ibm.com/developerworks/linux/library/l-mount-namespaces/index.html)
- [Chroot Containers](https://firejail.wordpress.com/documentation-2/basic-usage/#chroot)
- [PID Namespaces (CLONE_NEWPID)](https://lwn.net/Articles/259217/)
- [OverlayFS](https://firejail.wordpress.com/documentation-2/basic-usage/#overlayfs)
- [Linux rlimits (Resource Allocation)](https://firejail.wordpress.com/features-3/#resurces)
- [Grsecurity Support](https://firejail.wordpress.com/documentation-2/grsecurity-notes/)
- [CGroupV2 (Linux Control Groups)](https://www.kernel.org/doc/Documentation/admin-guide/cgroup-v2.rst)
- [Berkeley Packet Filter (BPF) Support)](https://www.kernel.org/doc/Documentation/bpf/btf.rst)
- [Extended Berkeley Packet Filter (eBPF) Support]()
- [NoGroup](https://lwn.net/Articles/532593/)
- [NoNewPrivs](https://www.kernel.org/doc/Documentation/filesystems/proc.txt)
- [NoRoot (User Namespace Mounts)](https://lwn.net/Articles/532593/)
- [IPC Namespaces (CLONE_NEWIP) - isolate certain interprocess communication (IPC) resources](https://lwn.net/Articles/187274/)
- [Filesystem Containers](https://lwn.net/Articles/690679/)
- [Linux Capabilities (POSIX 1003.1e)](https://firejail.wordpress.com/documentation-2/linux-capabilities-guide/)
- [Whitelist Linux Capabilities (POSIX 1003.1e)](https://firejail.wordpress.com/documentation-2/building-whitelisted-profiles/)
- [Blacklist Linux Capabilities (POSIX 1003.1e)](https://firejail.wordpress.com/documentation-2/linux-capabilities-guide/)
- [Audit Linux Capabilities (POSIX 1003.1e)](https://firejail.wordpress.com/documentation-2/linux-capabilities-guide/)
- [Network Namespaces (CLONE_NEWNET)](https://lwn.net/Articles/219794/)
- [Protocol Filtering (unix, inet and inet6)](https://firejail.wordpress.com/features-3/#security)
- [UTS Namespaces (CLONE_NEWUTS)](https://lwn.net/Articles/179345/)
- [Overlayfs Filesystems](https://wiki.archlinux.org/index.php/Overlay_filesystem)
- [Private Mounting](https://firejail.wordpress.com/documentation-2/basic-usage/#private)
- [Bind Mounts](https://www.kernel.org/doc/Documentation/filesystems/sharedsubtree.txt)
- [TmpFS Mounting (Temporary Filesystem)](https://wiki.archlinux.org/index.php/Tmpfs)
- [Read-Only | File(s) & Directories](https://firejail.wordpress.com/features-3/#filesystem)
- [Read-Write | File(s) & Directories](https://firejail.wordpress.com/features-3/#filesystem)
- [NoExec (No Execution)](https://firejail.wordpress.com/features-3/#filesystem)
- [Blacklist | File(s) & Directories](https://firejail.wordpress.com/features-3/#filesystem)
- [Whitelist | File(s) & Directories](https://firejail.wordpress.com/features-3/#filesystem)
- [Blacklist External Devices](https://firejail.wordpress.com/features-3/#filesystem)
- Anonymous Machine-ID - Spoof unique machine-id number in /etc/machine-id
- Blacklist 3D
- [Blacklist /dev/](https://lwn.net/Articles/531114/)
- [Blacklist /mnt/](https://lwn.net/Articles/531114/)
- [Blacklist /media/](https://lwn.net/Articles/531114/)
- [Read-Only Bind Mounts](https://lwn.net/Articles/281157/)
- [X11 Sandboxing](https://firejail.wordpress.com/documentation-2/x11-guide/)
- [Xpra Support](https://firejail.wordpress.com/documentation-2/x11-guide/)
- [Xephyr Server Support](https://firejail.wordpress.com/documentation-2/x11-guide/)
- [Network Interface Support: | macvlan, Bridged Interfaces, VLANs](https://firejail.wordpress.com/documentation-2/basic-usage/#networking)
- [TUN Network Driver Support (Ethernet Virtual Network Interface)](https://firejail.wordpress.com/documentation-2/basic-usage/#networking)
- [TAP Network Driver Support (Wireless Virtual Network Interface)](https://firejail.wordpress.com/documentation-2/basic-usage/#networking)
- [Trustworthy DNS (Enforced)](https://firejail.wordpress.com/documentation-2/basic-usage/#networking)
- [Netfilter (IPTables) Packet Filtering/Firewall](https://firejail.wordpress.com/documentation-2/basic-usage/#routed)
- [Bridged Network Interfaces](https://firejail.wordpress.com/documentation-2/basic-usage/#routed)
- [VLAN Network Interfaces]() 
- [NoNet (Isolate Network Interface In Its Own Namespace)](https://firejail.wordpress.com/documentation-2/basic-usage/#networking)
- [EncFS and SSHFS](https://firejail.wordpress.com/documentation-2/basic-usage/#encfs)
- [Traffic Shaping](https://firejail.wordpress.com/documentation-2/basic-usage/#bandwidth)
- Sandbox Auditing
- System Call Tracing
- DNS Auditing
- Debug Firejail Profiles
- Audit Firejail Profiles
- Whitelist Auditing
- Blacklist Auditing
- Network Protocol Auditing
- Network Protocol Debugging
- [AppImage Support](https://firejail.wordpress.com/documentation-2/appimage-support/)
- [Firejail Sandbox Configuration Wizard](https://firejail.wordpress.com/features-3/man-firejail-ui/)
- [Firetools - Graphical user interface](https://firejail.wordpress.com/features-3/man-firetools/)





## Xe1phix Youtube Tutorial Videos:
- [Xe1phix's Firejail Playlist](https://www.youtube.com/playlist?list=PLsvJPgaCwszZv3b2XBe-NekHQH0gFZp46)
- [Firejail - Using Firetools GUI - On ParrotSec Linux](https://www.youtube.com/watch?v=6oMoAftZtZY)
- [Hardening Firefox Using User.js And Firejail - On Parrot Linux](https://www.youtube.com/watch?v=RKBQeMVF3GU)
- [Compiling Firejail From Source + Enable Apparmor Support - Using Parrot Linux](https://www.youtube.com/watch?v=v0rQUUjQJNQ)
- [Start TorBrowser In A Sandbox Using Firejail Configuration](https://www.youtube.com/watch?v=293D-Cu3KuM)
- [Start Telegram In A Firejailed Sandbox Using Parrot Linux](https://www.youtube.com/watch?v=5f3nYoXr6Qc&t=81s)
- [Starting Telegram In A Sandbox With Firetools Using Parrot Linux](https://www.youtube.com/watch?v=v0rQUUjQJNQ)
- [Start TorBrowser In A Sandbox Using Firejail Configuration Wizard](https://www.youtube.com/watch?v=293D-Cu3KuM)



## Xe1phix Archive.org Tutorial Videos:
- [Telegram Messenger - Using Mullvad OpenVPN SOCKS5 Prox](https://archive.org/details/UsingMullvadOpenVPNSOCKS5ProxyWithTelegram)
- [Firefox In A Firejail Sandbox + Mullvad With An OpenVPN Connection](https://archive.org/details/Firefox-With-FirejailMullvad-OpenVPN-Connection)
- [Start TorBrowser In A Sandbox Using Firejail Configuration Wizard](https://archive.org/details/StartTorBrowserInASandboxUsingFirejailConfigurationWizard)
- [Starting Telegram In A Sandbox With Firetools Using Parrot Linux](https://archive.org/details/StartingTelegramInASandboxWithFiretools)
- [Start Telegram In A Firejailed Sandbox in Parrot Linux](https://archive.org/details/StartTelegramInAFirejailedSandbox)
- [Compiling Firejail From Source + Enable Apparmor Support](https://archive.org/details/CompileFirejailFromSourceApparmor)
- [Firejail Configuration Wizard - Setup Firefox Inside Restricted Environment](https://archive.org/details/FirejailConfigurationWizardSetupFirefoxEsrInsideRestrictedEnvironment)
- [Hardening Firefox Internals - Using User.js + Strict Sandboxing With Firejail - Seccomp-bpf, Namespaces, Cap Filters, AppArmor](https://archive.org/details/ParrotSecHardenedFirefoxEsruser.jsAdvancedProcessRestrictionIsolationFirejail)
- [ParrotSec - Firejail - Using Firetools GUI](https://archive.org/details/Xe1phixFirejailUsingFiretoolsGUI)



## Xe1phix Bitchute Tutorial Videos:
- [Firefox In A Firejailed Sandbox + Mullvad With An OpenVPN Connection Using Parrot Linux](https://www.bitchute.com/video/NR7RWcjq2HE9/)
- [Start TorBrowser In A Sandbox Using Firejail Configuration Wizard](https://www.bitchute.com/video/293D-Cu3KuM/)
- [Starting Telegram In A Sandbox With Firetools Using Parrot Linux](https://www.bitchute.com/video/DFnHcUqIaP0M/)
- [Start Telegram In A Firejailed Sandbox in Parrot Linux](https://www.bitchute.com/video/weO7s31UtjwP/)
- [Firejail Configuration Wizard - Setup Firefox-esr - Inside Restricted Environment](https://www.bitchute.com/video/OHOnTovUDz3U/)
- [Compiling Firejail From Source + Enable Apparmor Support - Using Parrot Linux](https://www.bitchute.com/video/YobUm2sWEyYD/)
- [ParrotSec - Firejail - Using Firetools GUI](https://www.bitchute.com/video/6HlMyx3Rzbqc/)



## Firejail - Firejail CLI - Version:
![Firejail - Firejail CLI - Version](https://gitlab.com/xe1phix/ParrotSecWiki/-/raw/InfoSecTalk/Xe1phix-InfoSec-Talk-Materials/Secure-Linux-Networking-v2-%5BCornCon-2021%5D/Secure-Linux-Networking-v2-%5BScreenshots%5D/%5BFirejail%5D-Screenshots/%5BFirejail-Compilation%5D-Screenshots/Firejail-Version-0.9.67.png?inline=false)


## Firejail-Enable-AppArmor:
![Firejail-Enable-AppArmor](https://gitlab.com/xe1phix/ParrotSecWiki/-/raw/InfoSecTalk/Xe1phix-InfoSec-Talk-Materials/Secure-Linux-Networking-v2-%5BCornCon-2021%5D/Secure-Linux-Networking-v2-%5BScreenshots%5D/%5BFirejail%5D-Screenshots/%5BFirejail-Compilation%5D-Screenshots/Firejail-Enable-AppArmor.png?inline=false)


## Firejail Syntax Options:
![Firejail - Firejail Syntax](https://gitlab.com/xe1phix/xe1phix-linuxwiki/raw/master/Firejail/Firejail-Wiki-Screenshots/Firejail-Syntax/Firejail-Syntax.png)


## Firejail - Firetools - Firejail-UI:
![Firejail - Firetools - Firejail-UI](https://gitlab.com/xe1phix/xe1phix-linuxwiki/raw/master/Firejail/Firejail-Wiki-Screenshots/Firejail-Firetools-Firejail-UI/Firejail-Firemgr-Firefox.png)


## Firejail - Firejail-UI - Capabilities:
![Firejail - Firejail-UI - Capabilities](https://gitlab.com/xe1phix/xe1phix-linuxwiki/raw/master/Firejail/Firejail-Wiki-Screenshots/Firejail-Firetools-Firejail-UI/Firejail-Firemgr-Capabilities.png)


## Firejail - Firejail Wizard - Custom DNS Servers: 
![Firejail - Firejail Wizard - Custom DNS Servers](https://gitlab.com/xe1phix/xe1phix-linuxwiki/-/raw/master/Firejail/Firejail-Wiki-Screenshots/Firejail-Configuration-Wizard/Firejail-Wizard-Step-1.png)


## Firejail - Firejail Wizard - View DNS Servers:
![Firejail - Firejail Wizard - View DNS Servers](https://gitlab.com/xe1phix/ParrotSecWiki/-/raw/InfoSecTalk/Xe1phix-InfoSec-Talk-Materials/Secure-Linux-Networking-v2-%5BCornCon-2021%5D/Secure-Linux-Networking-v2-%5BScreenshots%5D/%5BFirejail%5D-Screenshots/firemon-DNS.png?inline=false)

## Firejail - Firejail CLI - AppArmor - Print:
![Firejail - Firejail-UI - Capabilities](https://gitlab.com/xe1phix/ParrotSecWiki/-/raw/InfoSecTalk/Xe1phix-InfoSec-Talk-Materials/Secure-Linux-Networking-v2-%5BCornCon-2021%5D/Secure-Linux-Networking-v2-%5BScreenshots%5D/%5BFirejail%5D-Screenshots/%5BFirejail-AppArmor%5D-Screenshots/firejail-print-apparmor.png?inline=false)



## Firejail Resources:
- [Firejail Github](https://github.com/netblue30/firejail)
- [Firetools Github](https://github.com/netblue30/firetools)
- [Firejail GnuPG Key](https://firejail.wordpress.com/download-2/#Checksums)
- [Firejail Blog](https://firejail.wordpress.com)
- [Firejail ArchWiki](https://wiki.archlinux.org/index.php/Firejail)
- [Seccomp Filtering - Kernel.org Documentation](https://www.kernel.org/doc/Documentation/prctl/seccomp_filter.txt)
- [Namespaces - Kernel.org Documentation](https://www.kernel.org/doc/Documentation/admin-guide/namespaces/compatibility-list.rst)
- [OverlayFS - Kernel.org Documentation](https://www.kernel.org/doc/Documentation/filesystems/overlayfs.txt)
