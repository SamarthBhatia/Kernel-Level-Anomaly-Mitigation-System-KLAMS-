#include <uapi/linux/ptrace.h> // For BPF programs
#include <linux/sched.h> // For task_struct
#include <linux/fs.h>  // For file operations

struct event_t{
    u32 pid;    // Process ID
    u32 syscall_id; // Syscall ID
    u64 timestamp; // Timestamp of the event
    char comm[TASK_COMM_LEN]; // Name of the process
};

BPF_RINGBUF_OUTPUT(events, 8); // Ring buffer for events
//Creates a ring buffer named events:
//Acts like a shared mailbox between kernel and user-space
//8 = Size in memory pages (8 * 4096 bytes = 32KB)
//Stores detected events for user-space programs to read

BPF_HASH(suspicious_processes, u32, u32, 1024); // Hash map for suspicious processes
// Creates a key-value store (hash table):
//Name: suspicious_processes
//Key: u32 (Process ID)
//Value: u32 (Flag - 1 means suspicious)
//1024 = Max 1024 entries
//Used to flag processes doing cross-process writes


// Tracepoint for process_vm_writev syscall
TRACEPOINT_PROBE(syscalls, sys_enter_process_vm_writev){  //This syscall lets a process write to another process's memory
    u32 pid = bpf_get_current_pid_tgid() >> 32; //Get the current process ID
    u32 target_pid = args->pid; //Get the target process ID from syscall arguments

    if (target_pid != pid){
        struct event_t event = {}; // Initialize event structure
        event.pid = pid; // Set the current process ID
        event.syscall_id = 310; // Syscall number for process_vm_writev
        event.timestamp = bpf_ktime_get_ns();
        bpf_get_current_comm(&event.comm, sizeof(event.comm)); // Get the name of the current process

        events.ringbuf_output(&event, sizeof(event), 0); // Output event to ring buffer

        u32 flag = 1; // Mark as suspicious
        suspicious_processes.update(&pid, &flag); // Update the hash map with the process ID and flag
    }
    return 0;
}

// Tracepoint for socket syscall
TRACEPOINT_PROBE(syscalls, sys_enter_socket){
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct event_t event = {};
    event.pid = pid;
    event.syscall_id = 41; // Syscall number for socket
    event.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&event.comm, sizeof(event.comm)); 

    events.ringbuf_output(&event, sizeof(event), 0); 
    return 0;
}