#include "vmlinux.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ptrace.h>


struct event{
    __u32 pid;          // Process ID
    __u32 syscall_id;          // User ID
    __u64 timestamp;    // Timestamp of the event
    char comm[16]; // Name of the syscall
};


// Ring Buffer for events, like a conveyor belt but moves from kernel space to user space
struct {
    __uint(type,BPF_MAP_TYPE_RINGBUF); // BPF_MAP_TYPE_RINGBUF is like a special container for events
    __uint(max_entries, 256*1024); //   Maximum size of the ring buffer
} events SEC(".maps:"); // Marks this as a special storage area

// Process State Tracking
struct{
    __uint(type, BPF_MAP_TYPE_HASH); // BPF_MAP_TYPE_HASH is like a dictionary for quick lookups
    __uint(max_entries, 1024); // holds upto 1024 suspicious processes
    __type(key, __u32); // Key is the process ID
    __type(value, __u32); // Value is the flag (1=suspicious, 0=normal))
} suspicious_processes SEC(".maps");


// process_vm_writev  is for writing to a process's memory, and this installs a camera to watch it
SEC("tracepoint/syscalls/sys_enter_process_vm_writev");

int trace_process_injection(struct trace_event_raw_sys_enter *ctx){
    __u32 pid = bpf_get_current_pid_tgid() >> 32; // Get the process ID and  >>32 extracts the process part from a 64 bit value
    __u32 target_pid = ctx->args[0]; // The first argument is the target process ID, the process being written to

    // Check for cross process memory writes
    if (target_pid != pid){
        struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0); // Reserve space in the ring buffer for the event
        if (e){
            e->pid = pid;
            e->syscall_id = 310; // 310 is the syscall number for process_vm_writev
            e->timestamp = bpf_ktime_get_ns();
            bpf_get_current_comm(e->comm, sizeof(e->comm)); // Get the name of the current process
            bpf_ringbuf_submit(e,0); // Submit the event to the ring buffer

            // Mark process as suspicious
            __u32 flag = 1; // 1 means suspicious
            bpf_map_update_elem(&suspicious_processes, &pid, &flag, BPF_ANY); // Update the hash map with the process ID and flag, 
            //BPF_ANY means it will add or update the entry
        }
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_socket") // This is for socket creation, like setting up a phone line, adds a camera to watch it
int trace_socket(struct trace_event_raw_sys_enter *ctx){
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0); // Reserve space in the ring buffer for the event
    if (e){
        e->pid = pid;
        e->syscall_id = 41; // 41 is the syscall number for socket
        e->timestamp = bpf_ktime_get_ns();
        bpf_get_curr_comm(e->comm , sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

char LICENSE[] SEC("LICENSE") = "GPL"; // License for the BPF program, like a permission slip for using it
