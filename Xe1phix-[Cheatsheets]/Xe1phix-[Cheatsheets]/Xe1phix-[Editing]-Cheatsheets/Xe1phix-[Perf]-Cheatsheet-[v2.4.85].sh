#!/bin/sh

# Listing all currently known events:
perf list


# CPU counter statistics for the specified command:
perf stat command


# CPU counter statistics for the specified PID, until Ctrl-C:
perf stat -p PID


# Sample on-CPU functions for the specified command, at 99 Hertz:
perf record -F 99 command


# Trace all block device (disk I/O) requests with stack traces, until Ctrl-C:
perf record -e block:block_rq_insert -ag


# Add a tracepoint for the kernel tcp_sendmsg() function entry ("--add" is optional):
perf probe --add tcp_sendmsg


# Trace system calls by process, showing a summary refreshing every 2 seconds:
perf top -e raw_syscalls:sys_enter -ns comm


# Show perf.data with a column for sample count:
perf report -n
