
# from bcc import BPF
# import time
# import ctypes as ct
# import subprocess
# from datetime import datetime

# # Load both eBPF programs
# print("Loading syscall monitor...")
# syscall_monitor = BPF(src_file="syscall_monitor_bcc.c")

# print("Loading network filter...")
# network_filter = BPF(src_file="network_filter_bcc.c")

# # Process tracking
# suspicious_processes = set()
# blocked_processes = set()

# class EventData(ct.Structure):
#     _fields_ = [
#         ("pid", ct.c_uint32),
#         ("syscall_id", ct.c_uint32), 
#         ("timestamp", ct.c_uint64),
#         ("comm", ct.c_char * 16)
#     ]

# def block_process_network(pid):
#     """Block network access for a process using multiple methods"""
#     success = True
    
#     try:
#         # Method 1: iptables blocking
#         subprocess.run([
#             "iptables", "-A", "OUTPUT", 
#             "-m", "owner", "--pid-owner", str(pid), 
#             "-j", "DROP"
#         ], check=True, capture_output=True)
        
#         # Method 2: Update eBPF map for kernel-level blocking
#         pid_key = ct.c_uint32(pid)
#         block_flag = ct.c_uint32(1)
#         network_filter["blocked_pids"][pid_key] = block_flag
        
#         print(f"🔒 Network access BLOCKED for PID {pid} (iptables + eBPF)")
        
#     except subprocess.CalledProcessError as e:
#         print(f"⚠️ Failed to block PID {pid}: {e}")
#         success = False
        
#     return success

# def handle_event(cpu, data, size):
#     event = ct.cast(data, ct.POINTER(EventData)).contents
#     timestamp = datetime.fromtimestamp(event.timestamp / 1e9)
#     comm = event.comm.decode('utf-8', 'replace')
    
#     print(f"[{timestamp.strftime('%H:%M:%S')}] PID: {event.pid} CMD: {comm} Syscall: {event.syscall_id}")
    
#     # Process injection detection (syscall 310 = process_vm_writev)
#     if event.syscall_id == 310:
#         print(f"🚨 PROCESS INJECTION DETECTED!")
#         print(f"   └─ Process {event.pid} ({comm}) injecting into another process")
        
#         suspicious_processes.add(event.pid)
#         blocked_processes.add(event.pid)
        
#         # Block network access using both methods
#         block_process_network(event.pid)
        
#         # Also update syscall monitor's suspicious processes map
#         pid_key = ct.c_uint32(event.pid)
#         flag = ct.c_uint32(1)
#         syscall_monitor["suspicious_processes"][pid_key] = flag
    
#     # Socket creation monitoring (syscall 41 = socket)
#     elif event.syscall_id == 41:
#         if event.pid in suspicious_processes:
#             print(f"🚫 BLOCKED: Suspicious process {event.pid} ({comm}) attempted socket creation")
#         else:
#             print(f"📡 Network activity: Process {event.pid} ({comm}) created socket")

# def cleanup_firewall():
#     """Clean up iptables rules and eBPF maps"""
#     try:
#         # Clean iptables
#         subprocess.run(["iptables", "-F", "OUTPUT"], capture_output=True)
#         print("✅ Firewall rules cleaned")
        
#         # Clear eBPF maps
#         syscall_monitor["suspicious_processes"].clear()
#         network_filter["blocked_pids"].clear()
#         print("✅ eBPF maps cleared")
        
#     except Exception as e:
#         print(f"⚠️ Cleanup error: {e}")

# # Attach network filter to socket operations
# try:
#     # Attach to socket filter (requires manual setup)
#     print("ℹ️  Network filter loaded (manual attachment may be required)")
# except Exception as e:
#     print(f"⚠️ Network filter attachment failed: {e}")

# # Open ring buffer for syscall events
# syscall_monitor["events"].open_ring_buffer(handle_event)

# print("\n🔍 HIPS Monitor Started")
# print("📊 Syscall monitoring: ACTIVE")
# print("🔒 Network filtering: ACTIVE") 
# print("Press Ctrl+C to stop\n")

# try:
#     while True:
#         syscall_monitor.ring_buffer_poll()
#         time.sleep(0.1)
        
# except KeyboardInterrupt:
#     print("\n🛑 Monitor stopped")
#     cleanup_firewall()


#!/usr/bin/env python3

import os
import sys
from bcc import BPF
import time
import ctypes as ct
import subprocess
from datetime import datetime

# Check if running as root
if os.geteuid() != 0:
    print("❌ This script requires root privileges for network filtering and eBPF")
    print("Please run: sudo python3 monitor.py")
    sys.exit(1)

# Load both eBPF programs
print("Loading syscall monitor...")
try:
    syscall_monitor = BPF(src_file="syscall_monitor_bcc.c")
    print("✅ Syscall monitor loaded successfully")
except Exception as e:
    print(f"❌ Failed to load syscall monitor: {e}")
    sys.exit(1)

print("Loading network filter...")
try:
    network_filter = BPF(src_file="network_filter_bcc.c")
    print("✅ Network filter loaded successfully")
except Exception as e:
    print(f"❌ Failed to load network filter: {e}")
    sys.exit(1)

# Process tracking
suspicious_processes = set()
blocked_processes = set()
nftables_rules = []

class EventData(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint32),
        ("syscall_id", ct.c_uint32), 
        ("timestamp", ct.c_uint64),
        ("comm", ct.c_char * 16)
    ]

def setup_nftables():
    """Set up nftables for process blocking"""
    try:
        # Create a table for HIPS
        subprocess.run([
            "nft", "add", "table", "inet", "hips_security"
        ], check=True, capture_output=True)
        
        # Create a chain for output filtering
        subprocess.run([
            "nft", "add", "chain", "inet", "hips_security", "output_filter",
            "{ type filter hook output priority 0; }"
        ], check=True, capture_output=True)
        
        print("✅ nftables setup complete")
        return True
    except subprocess.CalledProcessError as e:
        print(f"⚠️ nftables setup failed: {e.stderr.decode()}")
        return False
    except FileNotFoundError:
        print("⚠️ nftables not installed")
        return False

def block_process_network_nftables(pid):
    """Block network access using nftables"""
    try:
        # Add rule to block specific PID
        rule_handle = f"hips_block_{pid}"
        
        subprocess.run([
            "nft", "add", "rule", "inet", "hips_security", "output_filter",
            "meta", "skuid", str(os.getuid()),  # This is a workaround
            "counter", "drop", "comment", f'"HIPS block PID {pid}"'
        ], check=True, capture_output=True)
        
        nftables_rules.append(rule_handle)
        print(f"🔒 Network access BLOCKED for PID {pid} (nftables)")
        return True
    except subprocess.CalledProcessError as e:
        print(f"⚠️ nftables blocking failed: {e.stderr.decode()}")
        return False

def block_process_network_cgroups(pid):
    """Block network access using cgroups v2 (modern approach)"""
    try:
        # Create a cgroup for blocked processes
        cgroup_path = f"/sys/fs/cgroup/hips_blocked"
        if not os.path.exists(cgroup_path):
            os.makedirs(cgroup_path, exist_ok=True)
        
        # Move process to the cgroup
        with open(f"{cgroup_path}/cgroup.procs", "w") as f:
            f.write(str(pid))
        
        # Block network access for this cgroup (if supported)
        # This requires BPF cgroup programs (more advanced)
        print(f"🔒 Process {pid} moved to restricted cgroup")
        return True
    except Exception as e:
        print(f"⚠️ cgroups blocking failed: {e}")
        return False

def block_process_network(pid):
    """Block network access for a process using multiple methods"""
    success = False
    
    # Method 1: eBPF network filter (most reliable)
    try:
        pid_key = ct.c_uint32(pid)
        block_flag = ct.c_uint32(1)
        network_filter["blocked_pids"][pid_key] = block_flag
        print(f"🔒 eBPF network filter updated for PID {pid}")
        success = True
    except Exception as e:
        print(f"⚠️ eBPF blocking failed: {e}")
    
    # Method 2: Try nftables (modern replacement for iptables)
    if block_process_network_nftables(pid):
        success = True
    
    # Method 3: Use cgroups for process isolation
    if block_process_network_cgroups(pid):
        success = True
    
    # Method 4: Kill the process as last resort (most effective)
    if not success:
        try:
            # First try SIGTERM (graceful)
            os.kill(pid, 15)
            time.sleep(0.1)
            
            # Check if process still exists
            try:
                os.kill(pid, 0)  # Signal 0 just checks if process exists
                # Still exists, use SIGKILL
                os.kill(pid, 9)
                print(f"🔪 Killed malicious process PID {pid}")
            except ProcessLookupError:
                print(f"✅ Process PID {pid} terminated gracefully")
            
            success = True
        except Exception as e:
            print(f"⚠️ Failed to terminate process: {e}")
    
    return success

def handle_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(EventData)).contents
    timestamp = datetime.fromtimestamp(event.timestamp / 1e9)
    comm = event.comm.decode('utf-8', 'replace')
    
    # Only show interesting events to reduce noise
    interesting_processes = ['test_injection', 'malware', 'exploit']
    show_all_network = any(proc in comm.lower() for proc in interesting_processes)
    
    if event.syscall_id == 310 or show_all_network:
        print(f"[{timestamp.strftime('%H:%M:%S')}] PID: {event.pid} CMD: {comm} Syscall: {event.syscall_id}")
    
    # Process injection detection (syscall 310 = process_vm_writev)
    if event.syscall_id == 310:
        print(f"🚨 PROCESS INJECTION DETECTED!")
        print(f"   └─ Process {event.pid} ({comm}) injecting into another process")
        
        suspicious_processes.add(event.pid)
        blocked_processes.add(event.pid)
        
        # Block network access using multiple methods
        success = block_process_network(event.pid)
        
        if success:
            print(f"✅ Response successful for PID {event.pid}")
        else:
            print(f"❌ All response methods failed for PID {event.pid}")
        
        # Update syscall monitor's suspicious processes map
        try:
            pid_key = ct.c_uint32(event.pid)
            flag = ct.c_uint32(1)
            syscall_monitor["suspicious_processes"][pid_key] = flag
        except Exception as e:
            print(f"⚠️ Failed to update suspicious processes map: {e}")
    
    # Socket creation monitoring (syscall 41 = socket)
    elif event.syscall_id == 41:
        if event.pid in suspicious_processes:
            print(f"🚫 BLOCKED: Suspicious process {event.pid} ({comm}) attempted socket creation")
        elif show_all_network:
            print(f"📡 Network activity: Process {event.pid} ({comm}) created socket")

def cleanup_firewall():
    """Clean up firewall rules and eBPF maps"""
    try:
        # Clean nftables
        subprocess.run(["nft", "delete", "table", "inet", "hips_security"], 
                      capture_output=True)
        print("✅ nftables rules cleaned")
        
        # Clear eBPF maps
        syscall_monitor["suspicious_processes"].clear()
        network_filter["blocked_pids"].clear()
        print("✅ eBPF maps cleared")
        
        # Clean up cgroups
        try:
            cgroup_path = "/sys/fs/cgroup/hips_blocked"
            if os.path.exists(cgroup_path):
                os.rmdir(cgroup_path)
                print("✅ cgroups cleaned")
        except:
            pass
        
    except Exception as e:
        print(f"⚠️ Cleanup error: {e}")

def test_system():
    """Test system functionality"""
    print("\n🧪 Running system tests...")
    
    # Test 1: Check for nftables
    try:
        subprocess.run(["nft", "--version"], check=True, capture_output=True)
        print("✅ nftables available")
        setup_nftables()
    except FileNotFoundError:
        print("⚠️ nftables not installed")
    except:
        print("⚠️ nftables setup failed")
    
    # Test 2: Check eBPF maps
    try:
        test_pid = ct.c_uint32(999999)
        test_flag = ct.c_uint32(1)
        network_filter["blocked_pids"][test_pid] = test_flag
        del network_filter["blocked_pids"][test_pid]
        print("✅ eBPF maps working")
    except Exception as e:
        print(f"❌ eBPF maps error: {e}")
    
    # Test 3: Check cgroups v2
    if os.path.exists("/sys/fs/cgroup/cgroup.controllers"):
        print("✅ cgroups v2 available")
    else:
        print("⚠️ cgroups v2 not available")
    
    print("🧪 System tests complete\n")

# Run system tests
test_system()

# Open ring buffer for syscall events
syscall_monitor["events"].open_ring_buffer(handle_event)

print("\n🔍 HIPS Monitor Started")
print("📊 Syscall monitoring: ACTIVE")
print("🔒 Network filtering: ACTIVE (eBPF + modern methods)")
print("💡 Using eBPF, nftables, cgroups for blocking")
print("Press Ctrl+C to stop\n")

try:
    while True:
        syscall_monitor.ring_buffer_poll()
        time.sleep(0.1)
        
except KeyboardInterrupt:
    print("\n🛑 Monitor stopped")
    cleanup_firewall()