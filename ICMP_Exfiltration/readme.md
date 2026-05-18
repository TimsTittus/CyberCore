## ICMP Exfiltration

Follow these steps to set up and observe ICMP-based exfiltration and its listener.

1. Create an ICMP payload script (example name):

```bash
nano icmp_lab_exfil.py
```

2. Create an ICMP listener script (example name):

```bash
nano icmp_listener.py
```

3. Start the sniffer FIRST. Then run the exfiltration script.

4. Run the payload:

```bash
sudo python3 icmp_lab_exfil.py
```

5. Monitor traffic with Wireshark, tcpdump, or similar and analyze ICMP Echo Request / Reply packets.

6. How to view the payloads

Option 1 — Wireshark

- Use the display filter: `icmp`
- Inspect a packet, expand "Internet Control Message Protocol" → "Data" to see the payload bytes.

Option 2 — Scapy sniffer

- Run your `icmp_listener.py` to capture packets and inspect payloads using Scapy.

Notes
- Running raw ICMP sockets or sniffers may require root privileges.
- Ensure you have authorization to run network capture/exfiltration tests on the network you use.