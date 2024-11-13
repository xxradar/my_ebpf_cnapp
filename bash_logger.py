#!/usr/bin/env python3
from bcc import BPF
from time import strftime
from elftools.elf.elffile import ELFFile
import argparse

# Argument parser for specifying the location of libreadline.so
parser = argparse.ArgumentParser(
    description="Print entered bash commands from all running shells",
    formatter_class=argparse.RawDescriptionHelpFormatter
)
parser.add_argument("-s", "--shared", nargs="?", const="/lib/libreadline.so", type=str,
                    help="Specify the location of libreadline.so library. Default is /lib/libreadline.so")
args = parser.parse_args()

# Determine the library name
libreadline_path = args.shared if args.shared else "/bin/bash"

# Function to get the symbol for `readline` or `readline_internal_teardown`
def get_readline_symbol(filename):
    with open(filename, 'rb') as f:
        elf = ELFFile(f)
        symbol_table = elf.get_section_by_name(".dynsym")
        for symbol in symbol_table.iter_symbols():
            if symbol.name == "readline_internal_teardown":
                return "readline_internal_teardown"
    return "readline"

readline_sym = get_readline_symbol(libreadline_path)

# eBPF program to capture command-line inputs via readline
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct str_t {
    u32 pid;
    char str[80];
};

BPF_PERF_OUTPUT(events);

int printret(struct pt_regs *ctx) {
    struct str_t data = {};
    char comm[TASK_COMM_LEN] = {};

    if (!PT_REGS_RC(ctx))
        return 0;

    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_probe_read_user(&data.str, sizeof(data.str), (void *)PT_REGS_RC(ctx));

    // Capture only if the command is from a bash process
    bpf_get_current_comm(&comm, sizeof(comm));
    if (comm[0] == 'b' && comm[1] == 'a' && comm[2] == 's' && comm[3] == 'h' && comm[4] == 0) {
        events.perf_submit(ctx, &data, sizeof(data));
    }

    return 0;
}
"""

# Load and attach the eBPF program
b = BPF(text=bpf_text)
b.attach_uretprobe(name=libreadline_path, sym=readline_sym, fn_name="printret")

# Print header
print("%-9s %-7s %s" % ("TIME", "PID", "COMMAND"))

# Function to print events from the perf buffer
def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("%-9s %-7d %s" % (strftime("%H:%M:%S"), event.pid, event.str.decode('utf-8', 'replace')))

# Open the perf buffer and set the callback function
b["events"].open_perf_buffer(print_event)

# Poll the perf buffer to receive events
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\nExiting...")
        break
