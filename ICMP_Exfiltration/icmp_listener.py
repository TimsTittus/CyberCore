#!/usr/bin/env python3
from scapy.all import sniff, ICMP, Raw

def process_packet(pkt):
    if pkt.haslayer(ICMP):
        icmp = pkt[ICMP]

        # Only care about Echo Request / Reply (type 8 / 0)
        if pkt.haslayer(Raw):
            payload = pkt[Raw].load.decode(errors="ignore")

            print("\n[ICMP Packet Detected]")
            print(f"Type: {icmp.type} Code: {icmp.code}")
            print(f"Source: {pkt[0][1].src}")
            print(f"Destination: {pkt[0][1].dst}")
            print(f"Payload: {payload}")
            print("-" * 50)

print("[*] ICMP Listener Started... (Ctrl+C to stop)")
sniff(filter="icmp", prn=process_packet, store=False)