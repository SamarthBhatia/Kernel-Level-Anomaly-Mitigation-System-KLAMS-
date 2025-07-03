#!/bin/bash

echo "🚀 Starting HIPS Proof of Concept Demo"
echo "======================================"

# Compile test programs
echo "Compiling test programs..."
gcc -o test_injection test_injection.c

# Compile eBPF programs
echo "Compiling eBPF programs..."
clang -O2 -target bpf -c syscall_monitor.bpf.c -o syscall_monitor.o

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "❌ This demo requires root privileges for eBPF and iptables"
   echo "Please run: sudo ./run_demo.sh"
   exit 1
fi

# Clean existing iptables rules
echo "Cleaning firewall rules..."
iptables -F OUTPUT 2>/dev/null || true

# Start the demo
echo "🎬 Starting demo dashboard..."
python3 demo_dashboard.py &
DASHBOARD_PID=$!

echo "🔍 Starting eBPF monitor..."
python3 monitor.py &
MONITOR_PID=$!

echo ""
echo "✅ Demo is ready!"
echo "📊 Dashboard: GUI window should open"
echo "🔍 Monitor: Running in background"
echo ""
echo "Demo Steps:"
echo "1. Click 'Start Monitor' in the dashboard"
echo "2. Click 'Simulate Attack' to trigger detection"
echo "3. Click 'Test Network' to verify blocking"
echo ""
echo "Press Ctrl+C to stop the demo"

# Wait for interrupt
trap 'echo "🛑 Stopping demo..."; kill $DASHBOARD_PID $MONITOR_PID 2>/dev/null; iptables -F OUTPUT 2>/dev/null; exit 0' INT
wait