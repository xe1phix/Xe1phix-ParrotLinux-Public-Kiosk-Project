

Show tcp_sendmsg() sizes bigger than 8192 bytes, per-event:

    bpftrace -e 'k:tcp_sendmsg /arg2 > 8192/ { printf("PID %d: %d bytes\n", pid, arg2); }'

Show a histogram of request size for each process (PID and comm):

    bpftrace -e 'k:tcp_sendmsg { @size[pid, comm] = hist(arg2); }'

Frequency count return values:

    bpftrace -e 'kr:tcp_sendmsg { @return[retval] = count(); }'

Show per-second statistics: event count, average size, and total bytes:

    bpftrace -e 'k:tcp_sendmsg { @size = stats(arg2); }
        interval:s:1 { print(@size); clear(@size); }'

Count calling stack traces:

    bpftrace -e 'k:tcp_sendmsg { @[kstack] = count(); }'

Count calling stack traces, three levels deep:

    bpftrace -e 'k:tcp_sendmsg { @[kstack(3)] = count(); }'

Show function latency as a histogram, in nanoseconds:

    bpftrace -e 'k:tcp_sendmsg { @ts[tid] = nsecs; }
        kr:tcp_sendmsg /@ts[tid]/ { @ns = hist(nsecs - @ts[tid]); delete(@ts[tid]); }'

This last example is saving a timestamp in one probe (keyed on thread ID) and retrieving it in another. This pattern can be used for custom latency measurements.


