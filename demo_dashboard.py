#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import subprocess
import time
from datetime import datetime

class HIPSDemo:
    def __init__(self, root):
        self.root = root
        self.root.title("HIPS Proof of Concept - Live Demo")
        self.root.geometry("800x600")
        
        # Status tracking
        self.monitor_running = False
        self.detected_attacks = 0
        self.blocked_connections = 0
        
        self.setup_ui()
        
    def setup_ui(self):
        # Title
        title = tk.Label(self.root, text="Behavioral Firewall - Live Demo", 
                        font=("Arial", 16, "bold"))
        title.pack(pady=10)
        
        # Status frame
        status_frame = ttk.Frame(self.root)
        status_frame.pack(fill="x", padx=10, pady=5)
        
        self.status_label = tk.Label(status_frame, text="Status: Stopped", 
                                   font=("Arial", 12))
        self.status_label.pack(side="left")
        
        # Statistics frame
        stats_frame = ttk.LabelFrame(self.root, text="Statistics")
        stats_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(stats_frame, text="Attacks Detected:").grid(row=0, column=0, sticky="w")
        self.attacks_label = tk.Label(stats_frame, text="0", font=("Arial", 12, "bold"))
        self.attacks_label.grid(row=0, column=1, sticky="w")
        
        tk.Label(stats_frame, text="Connections Blocked:").grid(row=1, column=0, sticky="w")
        self.blocked_label = tk.Label(stats_frame, text="0", font=("Arial", 12, "bold"))
        self.blocked_label.grid(row=1, column=1, sticky="w")
        
        # Control buttons
        control_frame = ttk.Frame(self.root)
        control_frame.pack(fill="x", padx=10, pady=5)
        
        self.start_btn = ttk.Button(control_frame, text="Start Monitor", 
                                   command=self.start_monitor)
        self.start_btn.pack(side="left", padx=5)
        
        self.stop_btn = ttk.Button(control_frame, text="Stop Monitor", 
                                  command=self.stop_monitor, state="disabled")
        self.stop_btn.pack(side="left", padx=5)
        
        self.attack_btn = ttk.Button(control_frame, text="Simulate Attack", 
                                    command=self.simulate_attack)
        self.attack_btn.pack(side="left", padx=5)
        
        self.test_btn = ttk.Button(control_frame, text="Test Network", 
                                  command=self.test_network)
        self.test_btn.pack(side="left", padx=5)
        
        # Log display
        log_frame = ttk.LabelFrame(self.root, text="Real-time Activity Log")
        log_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=20)
        self.log_text.pack(fill="both", expand=True, padx=5, pady=5)
        
    def log_message(self, message, color="black"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        full_message = f"[{timestamp}] {message}\n"
        
        self.log_text.config(state="normal")
        self.log_text.insert("end", full_message)
        self.log_text.see("end")
        self.log_text.config(state="disabled")
        
    def start_monitor(self):
        self.monitor_running = True
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.status_label.config(text="Status: Monitoring Active", fg="green")
        
        self.log_message("🔍 HIPS Monitor Started", "green")
        self.log_message("Monitoring system calls and network activity...")
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self.run_monitor)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
    def stop_monitor(self):
        self.monitor_running = False
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.status_label.config(text="Status: Stopped", fg="red")
        
        self.log_message("🛑 HIPS Monitor Stopped", "red")
        
    def simulate_attack(self):
        self.log_message("🎯 Launching simulated process injection attack...", "orange")
        
        # Run attack simulation
        threading.Thread(target=self.run_attack_simulation).start()
        
    def run_attack_simulation(self):
        try:
            result = subprocess.run(["./test_injection"], capture_output=True, text=True)
            self.log_message("Attack simulation completed")
        except Exception as e:
            self.log_message(f"Attack simulation error: {e}", "red")
            
    def test_network(self):
        self.log_message("🌐 Testing network connectivity...")
        
        def run_test():
            try:
                result = subprocess.run(["curl", "-s", "--connect-timeout", "5", 
                                       "http://gmail.com"], 
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    self.log_message("✅ Network test successful - connection allowed")
                else:
                    self.log_message("❌ Network test failed - connection blocked")
            except Exception as e:
                self.log_message(f"Network test error: {e}")
                
        threading.Thread(target=run_test).start()
        
    def run_monitor(self):
        # Simulate monitoring (in real implementation, this would run the eBPF monitor)
        while self.monitor_running:
            time.sleep(1)
            
            # Simulate detection events (replace with real eBPF integration)
            if hasattr(self, '_attack_detected'):
                self.detected_attacks += 1
                self.blocked_connections += 1
                self.attacks_label.config(text=str(self.detected_attacks))
                self.blocked_label.config(text=str(self.blocked_connections))
                self.log_message("🚨 PROCESS INJECTION DETECTED!", "red")
                self.log_message("🔒 Network access blocked for malicious process", "red")
                delattr(self, '_attack_detected')

if __name__ == "__main__":
    root = tk.Tk()
    app = HIPSDemo(root)
    root.mainloop()