#!/usr/bin/env python3
from bcc import BPF
from bcc.utils import printb
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
from time import strftime
import sys

# eBPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>

// Define constants and structures
#define AF_INET 2
#define AF_INET6 10
#define TASK_COMM_LEN 16

// Data structure to send to user space
struct data_t {
    u32 pid;
    u32 uid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u16 family;
    char task[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

// kprobe function
int trace_connect(struct pt_regs *ctx, struct sock *sk) {
    struct data_t data = {};
    u16 dport;
    u16 sport;
    u32 saddr;
    u32 daddr;
    u16 family;

    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family != AF_INET && family != AF_INET6) {
        return 0;
    }

    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    bpf_probe_read_kernel(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&sport, sizeof(sport), &sk->__sk_common.skc_num);

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    data.saddr = saddr;
    data.daddr = daddr;
    data.sport = sport;
    data.dport = ntohs(dport);  // Convert to host byte order
    data.family = family;
    bpf_get_current_comm(&data.task, sizeof(data.task));

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

# Load BPF program
b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect")
b.attach_kprobe(event="tcp_v6_connect", fn_name="trace_connect")

# Print header
print("%-9s %-7s %-16s %-15s %-5s %-15s %-5s %-7s" % ("TIME", "PID", "COMM", "SADDR", "SPORT", "DADDR", "DPORT", "FAMILY"))

def inet_ntoa(addr, family):
    if family == AF_INET:
        return inet_ntop(AF_INET, pack("I", addr))
    elif family == AF_INET6:
        return inet_ntop(AF_INET6, addr.to_bytes(16, 'big'))
    else:
        return "Unknown"

# Callback function to print events
def print_event(cpu, data, size):
    event = b["events"].event(data)
    family_str = "IPv4" if event.family == AF_INET else "IPv6" if event.family == AF_INET6 else "Unknown"
    print("%-9s %-7d %-16s %-15s %-5d %-15s %-5d %-7s" % (
        strftime("%H:%M:%S"), event.pid,
        event.task.decode('utf-8', 'replace'),
        inet_ntoa(event.saddr, event.family), event.sport,
        inet_ntoa(event.daddr, event.family), event.dport,
        family_str))

# Open perf buffer
b["events"].open_perf_buffer(print_event)

# Poll the perf buffer
try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nExiting...")
    sys.exit(0)
