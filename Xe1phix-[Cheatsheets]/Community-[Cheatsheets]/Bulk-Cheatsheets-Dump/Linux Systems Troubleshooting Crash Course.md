# Linux Systems Troubleshooting Crash Course

This document is a guide to Linux systems troubleshooting, with a slant towards CoreOS Container Linux.

# Glossary

- **TCP**: Transmission Control Protocol, a network protocol for reliable, error-checked in-order data transmission
- **UDP**: User Datagram Protocol, a network protocol for unreliable low-latency data transmission
- **TLS**: Transport Layer Security, an encryption protocol layered over TCP. Successor to **SSL** (Secure Sockets Layer).
- **container**: A mechanism for isolating processes from the rest of the system and restricting the resources which processes can use.
- **cron**: Classically, a daemon that triggered other processes on defined repeating schedules. In modern systems, a generic term for any scheduled trigger. Named after the word _chronos_, which means time in Greek.
- **daemon**: A process that runs in the background. Pronouned "demon" or "daymon". Named after the Maxwell's Daemon thought experiment from physics.
- **flag**/**option**: A modifer passed to a command preceded by one or two dashes. Examples: `command -a -b`, `command -ab`, `command --help`
- **fork**: To create a clone.
- **kernel**: The core software of the operating system which directly manages the hardware.
- **manpage**: A command's documentation. Short for _manual page_. On most Linux systems you can access a manpage by running `man <command or topic>`. You can also google `man <topic>` to find them online.
- **process**: An instance of a running program.
- **shell**: A command line program which provides a scriptable interactive computing environment. The two most common shells are POSIX Shell (`sh`), a simple and older shell, and Bourne Again Shell (`bash`), which is relatively newer.
- **socket**: An endpoint that allows processes to communicate with each other. **Unix domain sockets** allow communication between processes on the same computer. **Network sockets** allow communication between processes on the same or different computers.
- **userspace**/**userland**: The part of the system which is not the kernel.

# Fundamentals

If you aren't familiar with the fundamentals of \*nix command lines, you should learn the following:

- How to run commands in a shell (e.g. Bash)
- Common commands (manpages are your friend!):
    - `cat`
    - `head`/`tail`
    - `ls`
    - `pwd`
    - `mkdir`
    - `cd`
    - `pushd`/`popd`
    - `touch`
    - `cp`
    - `mv`
    - `rm`
    - `grep`
    - `sed`
    - `jq`
    - `find`
    - `scp`/`rsync`
    - `tar`
    - `gzip`/`unzip`
    - `vi`/`vim` (`vimtutor` can help)
    - `make`
- The differences between short flags, long flags and arguments and how to use them to change the behavior of programs
- How to use pipes (`|`) to chain commands together
- How to use wildcards/globs (`*`) to select multiple files in a single command
- How to use basic regular expressions to pattern-match text
- Basic control structures: `if; then; elif; fi`, `for; do; done`, `while; do; done`, `until; do; done`
- How to write simple Bash scripts using variables
- How the shell environment works (environment variables, TTYs, `$PATH`, `export`)

Without these skills the rest of this document will be close to impossible to apply in practice!

# systemd

[systemd](https://freedesktop.org/wiki/Software/systemd) is the primary process on most modern Linux systems. It is the first process that starts after the kernel boot and sets up the rest of the system. You can interact with systemd using the command `systemctl`.

systemd is configured using *unit files*, each of which describe a piece of the system (such as a mounted drive/volume, a process, a cron timer...). There are a few places unit files are read from but the main one operators deal with is `/etc/systemd/system/`. Units have names like `foo.service` (defines a daemon) or `foo.timer` (defines a cron trigger).

## Common Commands

- `systemctl` (no arguments): Display all of the units and their statuses.
- `systemctl list-units`: Display units which are either currently active, are pending or have failed.
- `systemctl list-units --all`: Display all units.
- `systemctl list-timers`: Display timer units. Timer units are triggers for starting other units automatically on a repeating schedule.
- `sudo systemctl start <unit>`: Start the given unit, if it is not already active.
- `sudo systemctl enable <unit>`: Configure the given unit to start automatically whenever the system boots.
- `sudo systemctl disable <unit>`: Configure the given unit to NOT start automatically on boot.
- `sudo systemctl restart <unit>`: Stop the given unit if it is active, and then start it.
- `systemctl status <unit>`: Show the given unit's status.
- `systemctl cat <unit>`: Show the definition of a unit.
- `sudo systemctl daemon-reload`: If you edit a unit file, you need to run this command to load the change.
- `systemctl reboot`: Reboot the system.

## Further Reading

systemd has _excellent_ manpages.

- [systemd.unit](https://www.freedesktop.org/software/systemd/man/systemd.unit.html)
- [systemd.service](https://www.freedesktop.org/software/systemd/man/systemd.service.html)
- [systemd.timer](https://www.freedesktop.org/software/systemd/man/systemd.timer.html)
- [systemctl](https://www.freedesktop.org/software/systemd/man/systemctl.html#)

# System Journal (logs)

systemd sends the logs for both the kernel and all of the userspace processes it manages to the _system journal_. You can query the journal with `journalctl`.

You can type `journalctl`, which shows all of the logs from every process since the system last booted. You can run `journalctl -f` to follow the logs live, which often feels like that scene from _The Matrix_ where the guy is watching the lines of code flow down the screen.

To view the logs for a specific unit, run `journalctl -u <unit>`. You can combine the follow and unit options to follow the logs for a specific unit with `journalctl -fu <unit>`. This is a very handy command you can easily remember because you are saying "Eff You!" to whatever broken piece of software is currently ruining your life.

See the excellent [journalctl manpage](https://www.freedesktop.org/software/systemd/man/journalctl.html). There are many options to modify the output, filter on various parameters and show logs from previous boot cycles.

# Processes

Processes are running instances of software. Every process has a unique **PID** (Process ID). Processes do NOT have unique names! Processes can spawn other processes, which is referred to as a **parent process** spawning **child processes**. When a process creates a copy of itself, it is said to **fork**. The relationships between all processes on the system makes up the **process tree**.

## Querying Processes

`ps` (process snapshot) shows the processes currently running.

By default, `ps` only shows the processes running under your current shell, which is not very useful. To see every process running on the system, run `ps -e`.

By default, `ps` only shows the name of the process. To see the full command arguments, run `ps -f`

By default, `ps` displays a table. To see a hierarchical representation of the process tree, run `ps -H`

You can combine all of these commands with `ps -He` or `ps -Hef` to see a complete snapshot of the process tree.

If want to see a specific process only, run `ps -p <PID>`.

If you know the name of some processes and want to get their PIDs, you can use `pgrep` to search for them by name or other attributes.

## Signaling Processes

You can send *signals* to processes to trigger behaviors.

To send a process to a signal, run `kill -s <signal name> <PID>`

There are quite a few signals for historical purposes, but only four are commomly used by operators:

- `SIGINT` (Interupt): Signals that a program should be interupted. This is the signal sent when you hit Ctrl+c on a foreground process. Most programs stop immediately, but you can write a program to gracefully shut down or even ignore this signal instead.
- `SIGHUP` (Hang Up): Signals that a program should reload without stopping. Commonly used with load balancers and other processes designed to rarely restart. The name is a historical artifact from back int eh days of remote terminals and mainframes, and was later repurposed.
- `SIGTERM` (Terminate): Signals that a program should gracefully and promptly stop. Most programs stop quickly, but you can write a program to slowly shut down or even ignore this signal instead.
- `SIGKILL` (Kill): Forcefully and immediately halts a program. Cannot be ignored.

## Syscall Tracing

`strace` can be used to show the kernel syscalls a userspace process is making. When you have a bizzare issue that seems impossible to debug, `strace` is your guardian angel.

- `strace <command> <args>`: Run a program as a child process of strace.
- `strace -p <PID>`: Start tracing another process which is already running.
- `strace -c  [...]`: Produce a histogram of syscall metrics. Useful for performance profiling. See also `-C`, `-S`

See [strace.io](https://strace.io) for a quick cheatsheet.

# Networking

## Ping (Sucks)

You can send an ICMP Type 8 Echo packet (aka a ping):

`ping <address>`

This doesn't really tell you anything useful, though. Lots of systems will allow ICMP Type 8 traffic but block or have issues with other protocols. It's like checking if your favorite restaurant is open by checking if the road to their building is still there.

## Interfaces

`ip` is the userland interface for the kernel networking capabilities.

- `ip link`: Show layer 1 and 2 interfaces (MAC addresses)
- `ip neighbor`: Show ARP neighbors
- `ip address`: Show layer 1, 2 and 3 interfaces (IP addreses)
- `ip route`: Show routing table

Some people use `ifconfig`, `arp` and `route` for these. Those people are wrong.

## Socket Search

`ss` (socket search) queries the sockets on a system.

- `ss -ltnp`: Display listening TCP sockets by number and the processes bound to them.
- `ss -lunp`: Display listening UDP sockets by number and the processes bound to them.
- `ss -xp`: Display Unix Domain Sockets and the processes bound to them.

## Network Mapper

`nmap` is a security scanner that can be used to probe systems. It's the [l33t haxx0r warez you see in tons of Hollywood movies](https://nmap.org/movies). Sometimes people will use `telnet` for TCP probing, but telnet is for n00bs!

- `nmap -sTU <address>`: Scan all TCP and UDP port on an address. If security is doing their job, this _will_ be noticed!
- `nmap -sT -p <port> <address>`: Probe a specific TCP port.
- `nmap -sU -p <port> <address>`: Probe a specific UDP port.

If the probe hangs for a long time, there's probably a firewall dropping your packets. If it returns quickly with the state "closed" there's probably nothing listening.

Many networks will detect the port scans/probes and mask them. You can sometimes work around this by using `-Pn` to skip host discovery, which is a little stealthier.

- `nmap -Pn -p <port> <address>`: Stealth-probe a specific TCP port.

`nmap` is an amazing tool. It's also got spoofing/stealth/evasion/reconaissance/offensive capabilities... it just happens to be a nice troubleshooting tool on the side.

## Packet Analysis

Sometimes the best way to debug a _really_ weird problem is to record the network traffic (a _packet capture_) and inspect it in [Wireshark](https://www.wireshark.org).

You can take a packet cature using `tcpdump`:

```bash
# Capture all traffic through the etho0 interface and save it to a file
tcpdump -i etho0 -w /tmp/$(date +%s).pcap
```

You can then transfer the `.pcap` file to a laptop and open it in Wireshark to analyse the traffic. Note that encrypted traffic requires the encryption keys to view, and certain encryption algorithms (such as Perfect Forward Secrecy TLS ciphers) are not possible to decrypt even if you have the key.

Further reading:

- [tcpdump practical examples](https://danielmiessler.com/study/tcpdump)
- Wireshark documentation:
    - [Opening capture files](https://www.wireshark.org/docs/wsug_html/#ChIOOpenSection)
    - [Viewing captured packets](https://www.wireshark.org/docs/wsug_html/#ChWorkViewPacketsSection)
    - [Filtering displayed packets](https://wiki.wireshark.org/DisplayFilters)
    - [Following protocol streams](https://www.wireshark.org/docs/wsug_html/#ChAdvFollowStreamSection)
    - [TCP reassembly](https://www.wireshark.org/docs/wsug_html/#ChAdvReassemblyTcp)
    - [Statistical analysis](https://www.wireshark.org/docs/wsug_html/#ChStatIntroduction)

## DNS

`dig` is super useful for troubleshooting DNS.

```bash
# General form
dig @<resolver> <record>

dig @1.1.1.1 www.example.com
# Omit the resolver to use the system's configured resolvers
dig www.example.com
# Don't need the full output?
dig +short www.example.com
```

Advice about troubleshooting network problems:

> It's not DNS.
>
> There's no way it's DNS.
>
> It was DNS.

[This site explains how DNS works.](https://howdns.works)

## HTTP/S

`curl` can be used to troubleshoot HTTP/S connections.

```bash
# General form
curl -X <method> -i <url>

# GET request with response headers
curl -X GET -i https://www.example.com
# JSON payload
curl -X POST -H "Content-Type:application/json" --data '{"payload": "foobar"}' https://www.example.com
```

If it's available, [HTTPie](https://httpie.org) (`http`) is way better:

```bash
# General form
http <method> <address> <payload>

# GET request with response headers
http -h get https://www.example.com
# GET request following redirects
http -f get google.com
# JSON payload
http post https://www.example.com payload=foobar
# URL parameters
http get https://www.example.com param==foobar
```

# Filesystems

- `stat`: Display the status of a file. This has some useful output like ownership, permissions and modification timestamps.
- `lsof`: List open files. Since everything is a file in \*nix, this can also query sockets and all kinds of system resources
- `mount`: Show mounted filesystems
- `df -h`: Show disk usage by filesystem
- `df -i`: Show inode usage by filesystem
- `du -ch`: Show disk usage by file

# Docker Containers

Docker is a popular interface for sharing _images_ (portable filesystems and environments that include everything an application needs to run) and launching containers from those images.

- `docker login`: Authenticate to a Docker registry
- `docker pull <image>`: Download a Docker image from a registry
- `docker push <image>`: Upload a Docker image to a registry
- `docker images`: Show Docker images present on system
- `docker run -it <image>`: Launch a container in interactive mode
- `docker attach <container id>`: Attach interactively to a running container
- `docker run -it --rm alpine`: Launch a throwaway Alpine Linux container (handy for troubleshooting!)
- `docker ps`: Show running containers
- `docker ps -a`: Show all containers
- `docker stats`: Show resource utilization by container
- `docker logs <container id>`: Show logs from a container
- `docker stop <container id>`: Stop a container
- `docker kill <container id>`: Like `docker stop` but angrier
