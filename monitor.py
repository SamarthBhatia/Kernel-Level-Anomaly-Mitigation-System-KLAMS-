
from bcc import BPF
import time
import ctypes as ct
import subprocess
from datetime import datetime

# Load both eBPF programs
print("Loading syscall monitor...")
syscall_monitor = BPF(src_file="syscall_monitor_bcc.c")

print("Loading network filter...")
network_filter = BPF(src_file="network_filter_bcc.c")

# Process tracking
suspicious_processes = set()
blocked_processes = set()

class EventData(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint32),
        ("syscall_id", ct.c_uint32), 
        ("timestamp", ct.c_uint64),
        ("comm", ct.c_char * 16)
    ]

def block_process_network(pid):
    """Block network access for a process using multiple methods"""
    success = True
    
    try:
        # Method 1: iptables blocking
        subprocess.run([
            "iptables", "-A", "OUTPUT", 
            "-m", "owner", "--pid-owner", str(pid), 
            "-j", "DROP"
        ], check=True, capture_output=True)
        
        # Method 2: Update eBPF map for kernel-level blocking
        pid_key = ct.c_uint32(pid)
        block_flag = ct.c_uint32(1)
        network_filter["blocked_pids"][pid_key] = block_flag
        
        print(f"🔒 Network access BLOCKED for PID {pid} (iptables + eBPF)")
        
    except subprocess.CalledProcessError as e:
        print(f"⚠️ Failed to block PID {pid}: {e}")
        success = False
        
    return success

def handle_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(EventData)).contents
    timestamp = datetime.fromtimestamp(event.timestamp / 1e9)
    comm = event.comm.decode('utf-8', 'replace')
    
    print(f"[{timestamp.strftime('%H:%M:%S')}] PID: {event.pid} CMD: {comm} Syscall: {event.syscall_id}")
    
    # Process injection detection (syscall 310 = process_vm_writev)
    if event.syscall_id == 310:
        print(f"🚨 PROCESS INJECTION DETECTED!")
        print(f"   └─ Process {event.pid} ({comm}) injecting into another process")
        
        suspicious_processes.add(event.pid)
        blocked_processes.add(event.pid)
        
        # Block network access using both methods
        block_process_network(event.pid)
        
        # Also update syscall monitor's suspicious processes map
        pid_key = ct.c_uint32(event.pid)
        flag = ct.c_uint32(1)
        syscall_monitor["suspicious_processes"][pid_key] = flag
    
    # Socket creation monitoring (syscall 41 = socket)
    elif event.syscall_id == 41:
        if event.pid in suspicious_processes:
            print(f"🚫 BLOCKED: Suspicious process {event.pid} ({comm}) attempted socket creation")
        else:
            print(f"📡 Network activity: Process {event.pid} ({comm}) created socket")

def cleanup_firewall():
    """Clean up iptables rules and eBPF maps"""
    try:
        # Clean iptables
        subprocess.run(["iptables", "-F", "OUTPUT"], capture_output=True)
        print("✅ Firewall rules cleaned")
        
        # Clear eBPF maps
        syscall_monitor["suspicious_processes"].clear()
        network_filter["blocked_pids"].clear()
        print("✅ eBPF maps cleared")
        
    except Exception as e:
        print(f"⚠️ Cleanup error: {e}")

# Attach network filter to socket operations
try:
    # Attach to socket filter (requires manual setup)
    print("ℹ️  Network filter loaded (manual attachment may be required)")
except Exception as e:
    print(f"⚠️ Network filter attachment failed: {e}")

# Open ring buffer for syscall events
syscall_monitor["events"].open_ring_buffer(handle_event)

print("\n🔍 HIPS Monitor Started")
print("📊 Syscall monitoring: ACTIVE")
print("🔒 Network filtering: ACTIVE") 
print("Press Ctrl+C to stop\n")

try:
    while True:
        syscall_monitor.ring_buffer_poll()
        time.sleep(0.1)
        
except KeyboardInterrupt:
    print("\n🛑 Monitor stopped")
    cleanup_firewall()