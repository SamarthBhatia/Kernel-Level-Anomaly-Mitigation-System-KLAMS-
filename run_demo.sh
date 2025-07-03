#!/bin/bash

echo "🚀 Starting HIPS Proof of Concept Demo"
echo "======================================"

# Check required files
required_files=("syscall_monitor_bcc.c" "network_filter_bcc.c" "monitor.py" "demo_dashboard.py" "test_injection.c")
for file in "${required_files[@]}"; do
    if [[ ! -f "$file" ]]; then
        echo "❌ Missing required file: $file"
        exit 1
    fi
done

# Compile test programs
echo "Compiling test programs..."
gcc -o test_injection test_injection.c
if [[ $? -ne 0 ]]; then
    echo "❌ Failed to compile test_injection.c"
    exit 1
fi

# Note: eBPF programs are compiled on-the-fly by BCC
echo "✅ eBPF programs will be compiled by BCC at runtime"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "❌ This demo requires root privileges for eBPF and iptables"
   echo "Please run: sudo ./run_demo.sh"
   exit 1
fi

# Check if BCC is installed
echo "Checking BCC installation..."
python3 -c "from bcc import BPF; print('✅ BCC is installed')" 2>/dev/null || {
    echo "❌ BCC not found. Installing..."
    apt update
    apt install -y python3-bpfcc bpfcc-tools linux-headers-$(uname -r)
    
    # Verify installation
    python3 -c "from bcc import BPF; print('✅ BCC installed successfully')" || {
        echo "❌ BCC installation failed"
        exit 1
    }
}

# Clean existing iptables rules
echo "Cleaning firewall rules..."
iptables -F OUTPUT 2>/dev/null || true
iptables -F INPUT 2>/dev/null || true

# Start the demo components
echo "🎬 Starting demo dashboard..."
python3 demo_dashboard.py &
DASHBOARD_PID=$!

# Give dashboard time to start
sleep 2

echo "🔍 Starting HIPS monitor..."
python3 monitor.py &
MONITOR_PID=$!

# Check if processes started successfully
sleep 2
if ! kill -0 $DASHBOARD_PID 2>/dev/null; then
    echo "❌ Dashboard failed to start"
    exit 1
fi

if ! kill -0 $MONITOR_PID 2>/dev/null; then
    echo "❌ Monitor failed to start"
    kill $DASHBOARD_PID 2>/dev/null
    exit 1
fi

echo ""
echo "✅ Demo is ready!"
echo "📊 Dashboard: GUI window should open"
echo "🔍 Monitor: Running in background"
echo "🔒 Network filtering: Active"
echo ""
echo "Demo Steps:"
echo "1. Click 'Start Monitor' in the dashboard"
echo "2. Click 'Simulate Attack' to trigger detection"
echo "3. Click 'Test Network' to verify blocking"
echo "4. Watch the monitor output for real-time detection"
echo ""
echo "Files being used:"
echo "  - syscall_monitor_bcc.c (eBPF syscall monitoring)"
echo "  - network_filter_bcc.c (eBPF network filtering)"  
echo "  - monitor.py (Main monitoring logic)"
echo "  - demo_dashboard.py (GUI interface)"
echo "  - test_injection (Attack simulation)"
echo ""
echo "Press Ctrl+C to stop the demo"

# Wait for interrupt
trap 'echo -e "\n🛑 Stopping demo..."; kill $DASHBOARD_PID $MONITOR_PID 2>/dev/null; iptables -F OUTPUT 2>/dev/null; iptables -F INPUT 2>/dev/null; echo "✅ Demo stopped"; exit 0' INT
wait