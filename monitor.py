#!/usr/bin/env python3
from bcc import BPF
import time
from datetime import datetime

b = BPF(src_file="syscall_monitor.bpf.c") # Load the BPF program from the C source file

# Now Process Tracking
suspicious_processes = set()  # Set to keep track of suspicious processes
process_activities = {} # Dictionary to keep track of process activities

def handle_event(cpu, data, size): # Callback function to handle events
    event = b["events"].event(data) # Get the event from the BPF map
    timestamp = datetime.fromtimestamp(event.timestamp / 1e9) # Convert timestamp to a human-readable format

    print(f"[{timestamp}] PID: {event.pid} CMD: {event.comm.decode()} " f"Syscall ID: {event.syscall_id} ") # Print the event details

    # Detect process injection pattern
    if event.syscall_id == 310:
        print(f" Injection detected: Process {event.pid} ({event.comm.decode()}) Injecting into another process")  # This is a common pattern for process injection
        suspicious_processes.add(event.pid); # Add the process to the suspicious processes set

        # Block network process using iptables
        import subprocess  
        subprocess.run(["sudo" ,"iptables", "-A", "OUTPUT", "-m", "owner", "--pid-owner", str(event.pid), "-j", "DROP"])# Block the process from making network connections
        print(f"Block network access for PID {event.pid}")

    #Monitor network activity for suspicious processes
    elif event.syscall_id == 41: # socket
        if event.pid in suspicious_processes:
            print(f" Blocked: Suspicious Process {event.pid} attempted network access")


b["events"].open_ring_buffer(handle_event) # Open a ring buffer to receive events

print("Monitor Started - Press Ctrl+C to stop")
print("Monitoring for process injection and network activity...\n")

try:
    while True:
        b_ring_buffer_poll() # Poll the ring buffer for events
        time.sleep(1) # Sleep for a while to avoid busy waiting
except KeyboardInterrupt:
    print("\nMonitor stopped")
