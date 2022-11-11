# Ubuntu 18.04
sudo apt install linux-tools-$(uname -r) linux-tools-generic -y
$ perf --version
perf version 4.18.12

# stat: runs a command and gathers performance counter statistics from it, command -> tree -a
sudo perf stat tree -a

# top: generates and displays a performance counter profile in real time
sudo perf top
sudo perf top --sort comm,dso

# record: runs a command and gathers a performance counter profile from it. 
# The gathered data is saved into perf.data without displaying anything.
sudo perf record -e faults tree -a
sudo perf record tree -a

# list all pre-defined events
perf list
# Listing sched tracepoints:
perf list 'sched:*'

# read the performance record
perf report -i perf.data

sudo perf stat -B dd if=/dev/zero of=/dev/null count=1000000
sudo perf record dd if=/dev/zero of=/dev/null count=1000000
perf report -i perf.data

perf top -z
sudo perf top -z -e cpu-clock
sudo perf top -z -e task-clock
strace -o /tmp/strace-file -s 512 \
dd if=/dev/zero of=/tmp/file bs=1024k count=5

# measure one or more events per run
sudo perf stat -e cpu-clock,faults ping -c 3 www.google.com

run the same test workload multiple times
sudo perf stat -r 4  ping -c 3 www.google.com
  
sudo perf record -e cpu-cycles -c 100000 ping -c 3 www.google.com

sudo  perf record -g ping -c 3 www.google.com
sudo perf report -g none

# measure one or more events per run
sudo perf stat -e cpu-clock,faults ping -c 3 www.google.com

run the same test workload multiple times
sudo perf stat -r 4  ping -c 3 www.google.com
  
sudo perf record -e cpu-cycles -c 100000 ping -c 3 www.google.com

sudo  perf record -g ping -c 3 www.google.com
sudo perf report -g none

# troubleshoot the command -> cp test1 perf.data > /dev/null 2>&1, test1 does not exist
$ ls
perf.data  test

$ cp test1 perf.data
cp: cannot stat 'test1': No such file or directory

collect statistics on make and its children
$ sudo perf stat -- make hello
$ sudo perf stat make hello
$ sudo perf stat -d make hello
record data on the make command and its children
$ sudo perf record -- make hello
all the specified events become members of a single group with the first event as a group leader
$ sudo perf record -e '{cycles, faults}' -- make hello
Use perf report to output an analysis of perf.data
the following command produces a report of the executable that consumes the most time
The column on the left shows the relative frequency of the samples
This output shows that make spends most of this time in xsltproc and the pdfxmltex
$ sudo perf report --sort=comm
# Samples: 1083783860000
#
# Overhead          Command
# ........  ...............
#
    48.19%         xsltproc
    44.48%        pdfxmltex
     6.01%             make
     0.95%             perl
     0.17%       kernel-doc
     0.05%          xmllint
     0.05%              cc1
     0.03%               cp
     0.01%            xmlto
     0.01%               sh
     0.01%          docproc
     0.01%               ld
     0.01%              gcc
     0.00%               rm
     0.00%              sed
     0.00%   git-diff-files
     0.00%             bash
     0.00%   git-diff-index
list the functions executed by xsltproc
# perf report -n --comm=xsltproc

------------------------------------------------------------------------------------------
strace -o /tmp/strace-cp1 -s 512 \
cp test1 perf.data > /dev/null 2>&1

strace -c -o /tmp/strace-cp2 -s 512 \
cp test1 perf.data > /dev/null 2>&1


strace  -o /tmp/strace-stat -e trace=stat64 \
cp test1 perf.data > /dev/null 2>&1

strace -o /tmp/strace-file1 -s 512 \
tree -a

strace -c -o /tmp/strace-file2 -s 512 \
tree -a
------------------------------------------------------------------------------------------
$hostnamectl
   Static hostname: postgresql03
         Icon name: computer-vm
           Chassis: vm
        Machine ID: cfa0388701ff415dbceb1d083ec3fdfd
           Boot ID: a14b86f696e145b5bf668d93d81ddaa4
    Virtualization: kvm
  Operating System: CentOS Linux 7 (Core)
       CPE OS Name: cpe:/o:centos:centos:7
            Kernel: Linux 3.10.0-957.1.3.el7.x86_64
      Architecture: x86-64
$ uname -r
3.10.0-957.1.3.el7.x86_64
$ rpm -qa | grep kernel
kernel-3.10.0-957.12.2.el7.x86_64
kernel-tools-libs-3.10.0-957.12.2.el7.x86_64
kernel-tools-3.10.0-957.12.2.el7.x86_64
kernel-3.10.0-957.1.3.el7.x86_64

sudo rpm -ivh http://ftp.riken.jp/Linux/cern/centos/7.6.1810/updates/Debug/x86_64/kernel-debuginfo-common-$(uname -p)-$(uname -r).rpm
sudo rpm -ivh http://ftp.riken.jp/Linux/cern/centos/7.6.1810/updates/Debug/x86_64/kernel-debuginfo-$(uname -r).rpm
sudo yum install -y kernel-devel-$(uname -r)

$ rpm -qa | grep kernel-de*
kernel-debuginfo-3.10.0-957.1.3.el7.x86_64
kernel-debuginfo-common-x86_64-3.10.0-957.1.3.el7.x86_64
kernel-devel-3.10.0-957.1.3.el7.x86_64
$ sudo yum -y install systemtap systemtap-debuginfo -y
$ stap --version
Systemtap translator/driver (version 3.3/0.172, rpm 3.3-3.el7)
Copyright (C) 2005-2018 Red Hat, Inc. and others
This is free software; see the source for copying conditions.
tested kernel versions: 2.6.18 ... 4.18-rc0
enabled features: AVAHI BOOST_STRING_REF DYNINST BPF JAVA PYTHON2 LIBRPM LIBSQLITE3 LIBVIRT LIBXML2 NLS NSS READLINE

command simply instructs SystemTap to print read performed then exit properly once a virtual file system read is detected.
$ sudo stap -v -e 'probe vfs.read {printf("read performed\n"); exit()}'

Pass 5
indicate that SystemTap was able to successfully create the instrumentation to probe the kernel
run the instrumentation
detect the event being probed (in this case, a virtual file system read)
execute a valid handler (print text then close it with no errors)

instructs stap to run the script passed by echo to standard input
$ echo "probe timer.s(1) {exit()}" | sudo stap -v -

simple stap scrip
# cat hello-world.stp
#!/use/bin/env stap

probe begin
{
    printf ("hello world\n")
    exit ()
}

# stap -v hello-world.stp
# stap -v -p 4 hello-world.stp
Pass 1: parsed user script and 479 library scripts using 247868virt/49964res/3448shr/46396data kb, in 820usr/20sys/852real ms.
Pass 2: analyzed script: 1 probe, 1 function, 0 embeds, 0 globals using 249188virt/51544res/3748shr/47716data kb, in 10usr/0sys/13real ms.
/root/.systemtap/cache/b0/stap_b013d9850b952b9fa68246bba7df5605_1013.ko
Pass 3: using cached /root/.systemtap/cache/b0/stap_b013d9850b952b9fa68246bba7df5605_1013.c
Pass 4: using cached /root/.systemtap/cache/b0/stap_b013d9850b952b9fa68246bba7df5605_1013.ko
# ls -l /root/.systemtap/cache/b0/stap_b013d9850b952b9fa68246bba7df5605_1013.ko
# staprun /root/.systemtap/cache/b0/stap_b013d9850b952b9fa68246bba7df5605_1013.ko
hello world

help you understand if the process received a signal 15 (SIGTERM)
# cat getstatus.stp
#!/usr/bin/env stap

probe signal.send {
  time_ns = gettimeofday_ns();
  if (pid_name == @1) {
     if (sig_name == "SIGTERM") {
        printf("%ld: %s(pid: %d) received a %s signal sent by %s(%d)\n", time_ns, pid_name, sig_pid, sig_name, execname(), pid())
        exit()
     }
  }
}

# stap /tmp/getstatus.stp dhcpd


instructs SystemTap to probe all entries to the system call open; 
for each event, it prints the current execname() (a string with the executable name) 
and pid() (the current process ID number), followed by the word open
# cat variables-in-printf-statements.stp
probe syscall.open
{
  printf ("%s(%d) open\n", execname(), pid())
}
$ sudo stap variables-in-printf-statements.stp


The time (in microseconds) since the initial thread_indent() call for the thread (included in the string from thread_indent()). 
The process name (and its corresponding ID) that made the function call (included in the string from thread_indent()). 
An arrow signifying whether the call was an entry (<-) or an exit (->); the indentations help you match specific function call entries with their corresponding exits. 
The name of the function called by the process. 
# cat thread_indent.stp
probe kernel.function("*@net/socket.c") 
{
  printf ("%s -> %s\n", thread_indent(1), probefunc())
}
probe kernel.function("*@net/socket.c").return 
{
  printf ("%s <- %s\n", thread_indent(-1), probefunc())
}
$ sudo stap thread_indent.stp

----------------------------------------------------------------------------------------------------


$ hostnamectl
   Static hostname: control-machine
         Icon name: computer-vm
           Chassis: vm
        Machine ID: c3dbdd98481045bdbbbfecad34aa29e2
           Boot ID: 3b6ee7c136a54fb0b006dfe7efb7cc53
    Virtualization: oracle
  Operating System: Ubuntu 18.10
            Kernel: Linux 4.18.0-10-generic
      Architecture: x86-64
$ uname -r
4.18.0-10-generic
$ sudo apt-get install -y systemtap gcc -y
$ sudo apt-get install linux-headers-$(uname -r)
$ dpkg-query -s linux-headers-$(uname -r)



# get debug symbols for kernel X
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys C8CAB6595FDFF622

# additional repositories that contain the debuginfo packages
codename=$(lsb_release -c | awk  '{print $2}')
sudo tee /etc/apt/sources.list.d/ddebs.list << EOF
deb http://ddebs.ubuntu.com/ ${codename}      main restricted universe multiverse
deb http://ddebs.ubuntu.com/ ${codename}-security main restricted universe multiverse
deb http://ddebs.ubuntu.com/ ${codename}-updates  main restricted universe multiverse
deb http://ddebs.ubuntu.com/ ${codename}-proposed main restricted universe multiverse
EOF

sudo apt-get update
sudo apt-get install linux-image-$(uname -r)-dbgsym -y

$ sudo stap -e 'probe begin { printf("Hello, World!\n"); exit() }'
Hello, World!

sudo stap -l 'kernel.function("acpi_*")' | sort
sudo stap -l 'module("ohci1394").function("*")' | sort
stap -L 'module("thinkpad_acpi").function("brightness*")' | sort

# https://sourceware.org/systemtap/examples/
network/netfilter_summary.stp - System-Wide Count of Network Packets by IPs
------------------------------------------------------------------------------------------
$ hostnamectl
   Static hostname: postgresql03
         Icon name: computer-vm
           Chassis: vm
        Machine ID: cfa0388701ff415dbceb1d083ec3fdfd
           Boot ID: a14b86f696e145b5bf668d93d81ddaa4
    Virtualization: kvm
  Operating System: CentOS Linux 7 (Core)
       CPE OS Name: cpe:/o:centos:centos:7
            Kernel: Linux 3.10.0-957.1.3.el7.x86_64
      Architecture: x86-64
      
  $ sudo yum install valgrind -y
  $ valgrind --version
valgrind-3.13.0

$ valgrind --tool=memcheck ls

make -C makefile-test1/ hello
$ ./makefile-test1/hello

 Hello World!!!
 

$ sudo valgrind --tool=memcheck ./makefile-test1/hello
==22386== Memcheck, a memory error detector
==22386== Copyright (C) 2002-2017, and GNU GPL'd, by Julian Seward et al.
==22386== Using Valgrind-3.13.0 and LibVEX; rerun with -h for copyright info
==22386== Command: ./makefile-test1/hello
==22386==

 Hello World!!!
==22386==
==22386== HEAP SUMMARY:
==22386==     in use at exit: 0 bytes in 0 blocks
==22386==   total heap usage: 0 allocs, 0 frees, 0 bytes allocated
==22386==
==22386== All heap blocks were freed -- no leaks are possible
==22386==
==22386== For counts of detected and suppressed errors, rerun with: -v
==22386== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)

# a list of arguments for toolname
# https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/developer_guide/profiling#valgrind-tools


$ sudo valgrind --tool=cachegrind ./makefile-test1/hello
$ sudo valgrind --tool=massif ./makefile-test1/hello
$ sudo valgrind --tool=massif --log-file=hello.valgrind.output ./makefile-test1/hello
------------------------------------------------------------------------------------------
$ hostnamectl
   Static hostname: postgresql03
         Icon name: computer-vm
           Chassis: vm
        Machine ID: cfa0388701ff415dbceb1d083ec3fdfd
           Boot ID: a14b86f696e145b5bf668d93d81ddaa4
    Virtualization: kvm
  Operating System: CentOS Linux 7 (Core)
       CPE OS Name: cpe:/o:centos:centos:7
            Kernel: Linux 3.10.0-957.1.3.el7.x86_64
      Architecture: x86-64
      
$ sudo operf -l
Your kernel's Performance Events Subsystem does not support your processor type.
Please use the opcontrol command instead of operf.

$ sudo opcontrol --status
Daemon not running
Session-dir: /var/lib/oprofile
Separate options: none
vmlinux file:
Image filter: none
Call-graph depth: 0

$ sudo opcontrol --separate=kernel --vmlinux=/boot/vmlinuz-3.10.0-957.1.3.el7.x86_64
$ sudo opcontrol --start
The specified file /boot/vmlinuz-3.10.0-957.1.3.el7.x86_64 does not seem to be valid
Make sure you are using the non-compressed image file (e.g. vmlinux not vmlinuz)
------------------------------------------------------------------------------------------
# https://github.com/iovisor/bpftrace/blob/master/INSTALL.md 
# High-level tracing language for Linux eBPF 

$ hostnamectl
   Static hostname: bpftrace-machine
         Icon name: computer-vm
           Chassis: vm
        Machine ID: fa8a1edd06864f47ba4cad5d0f5ca134
           Boot ID: aad6228b799c4b4e84179c0b8ba23d73
    Virtualization: oracle
  Operating System: Fedora 29 (Twenty Nine)
       CPE OS Name: cpe:/o:fedoraproject:fedora:29
            Kernel: Linux 4.18.16-300.fc29.x86_64
      Architecture: x86-64

# mainline kernel branch:
curl -s https://repos.fedorapeople.org/repos/thl/kernel-vanilla.repo | sudo tee /etc/yum.repos.d/kernel-vanilla.repo
sudo dnf --enablerepo=kernel-vanilla-mainline update; sudo dnf config-manager --set-enabled kernel-vanilla-mainline
sudo dnf update; sudo reboot

$ hostnamectl
   Static hostname: bpftrace-machine
         Icon name: computer-vm
           Chassis: vm
        Machine ID: fa8a1edd06864f47ba4cad5d0f5ca134
           Boot ID: 5591872d8ff7420587763c80f0580f16
    Virtualization: oracle
  Operating System: Fedora 29 (Twenty Nine)
       CPE OS Name: cpe:/o:fedoraproject:fedora:29
            Kernel: Linux 5.2.0-0.rc2.git1.1.vanilla.knurd.1.fc29.x86_64
      Architecture: x86-64

      sudo dnf install -y bison flex cmake make git gcc-c++ elfutils-libelf-devel zlib-devel llvm-devel clang-devel bcc-devel systemtap-sdt-devel
      git clone https://github.com/iovisor/bpftrace;  cd bpftrace;  mkdir build; cd build; sudo cmake -DCMAKE_BUILD_TYPE=Release ..
      sudo make -j8
      sudo make install


------------------------------------------------------------------------------------------
