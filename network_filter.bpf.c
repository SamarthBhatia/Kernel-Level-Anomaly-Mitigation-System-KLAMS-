#include "vmlinux.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>


// Shared map with user space
struct {
    __uint(type, BPF_MAP_TYPE_HASH); 
    __uint(max_entries, 1024);
    __type(key, __u32); 
    __type(value, __u32); 
} blocked_pids SEC(".maps");

SEC("socket") // Intercept socket creation


int socket_filter(struct __sk_buff *skb){  //struct __sk_buff *skb: Represents a network packet
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    __u32 *blocked = bpf_map_lookup_elem(&blocked_pids, &pid); // Check if the process ID is in the blocked list
    if (blocked && *blocked){ // If the process is blocked 
        bpf_printk("Dropping packet from blocked PID %d", pid);
        return 0; 
    }
    return -1; // Allow the packet to pass through
}

char LICENSE[] SEC("license") = "GPL";