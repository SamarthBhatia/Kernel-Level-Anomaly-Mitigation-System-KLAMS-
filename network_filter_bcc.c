#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/bpf.h>


BPF_HASH(blocked_pids, u32, u32, 1024); // Hash map to store blocked PIDs

// Socket filter to block network traffic from suspicious processes
int socket_filter(struct __sk_buff *skb){
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u32 *blocked = blocked_pids.lookup(&pid); // Check if the PID is in the blocked list
    if (blocked && *blocked){
        bpf_trace_printk("Dropping packet from blocked PID %d\\n", pid);
        return 0;
    }
    return -1; // Allow the packet to pass through
}

// Cgroup egress filter for broader network filtering, This attaches to cgroups (control groups) - like a firewall at a neighborhood exit:
int cgroup_skb_egress(struct __sk_buff *skb){
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u32 *blocked = blocked_pids.lookup(&pid);

    if (blocked && *blocked){
        bpf_trace_printk("Blocked egress traffic from PID %d\\n", pid);
        return 0;
    }
    return 1;
}

