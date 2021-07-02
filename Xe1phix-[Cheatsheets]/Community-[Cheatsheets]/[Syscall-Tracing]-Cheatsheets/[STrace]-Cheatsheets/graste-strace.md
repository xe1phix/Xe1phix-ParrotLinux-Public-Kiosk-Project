# File activity

```strace -e trace=file -fp PID``` (file) or ```strace -e trace=desc -fp PID``` (file descriptors)

Common calls:

- `access`
- `close` – close file handle
- `fchmod` – change file permissions
- `fchown` – change file ownership
- `fstat` – retrieve details
- `lseek` – move through file
- `open` – open file for reading/writing
- `read` – read a piece of data
- `statfs` – retrieve file system related details

# Network activity

```strace -o /tmp/strace.out -s 10000 -e trace=network -fp PID```

Common syscalls:

- `bind` – link the process to a network port
- `listen` – allow to receive incoming connections
- `socket` – open a local or network socket
- `setsockopt` – define options for an active socket

# Memory activity

```strace -e trace=memory -fp PID```

Common syscalls:

- `mmap`
- `munmap`
 
# `strace` cli options

- `-c` – current statistics about what time is spend where (combine with `-S` for sorting)
- `-f` – track process including forked child processes
- `-o somefile.out` – write output to a file
- `-p PID` – track a process by PID
- `-P /tmp` – track interaction with a path
- `-s 10000` – maximum string size to output (32 by default)
- `-T` – include syscall duration in output

Tracking via specific system call group:

- `-e trace=ipc` – communication between processes (IPC)
- `-e trace=memory` – memory syscalls
- `-e trace=network` – network syscalls
- `-e trace=process` – process calls (like fork, exec)
- `-e trace=signal` – process signal handling (like HUP, exit)
- `-e trace=file` – file related syscalls
- `-e trace=desc` – all file descriptor related system calls

Tracing multiple syscalls

Monitor opening/closing of files via ```strace -e open,close```
