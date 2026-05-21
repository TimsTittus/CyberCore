# MAC Flooding Attack (CAM Table Overflow) using Scapy

## Overview
**MAC Flooding** (also known as **CAM Table Overflow**) is a Layer 2 attack where the attacker floods a network switch with thousands of Ethernet frames containing random fake source MAC addresses.

When the switch’s Content Addressable Memory (CAM) table becomes full, it enters **fail-open mode** and starts behaving like a hub — flooding all unicast traffic to every port. This allows the attacker to sniff traffic that would normally be filtered by the switch.

---

## What is the Attacker's Gain?

- **Main Objective**: Turn the switch into a hub to **sniff all network traffic** on the same VLAN.
- Capture sensitive data (usernames, passwords, sessions, files) from other devices.
- Perform advanced reconnaissance and man-in-the-middle attacks more effectively.
- Break network segmentation at Layer 2.

---

## Requirements
- Python 3 + Scapy
- Root/Sudo privileges
- Direct connection to the target switch port
- Authorized lab or testing environment only

---

## How to Use (Step by Step)

1. **Save the code** as `mac_flood.py`

2. **Make it executable**:
   ```bash
   chmod +x mac_flood.py
   ```

3. **Run the script**:
   ```bash
   sudo python3 mac_flood.py
   ```

4. **Follow the on-screen prompts**:
   - Enter network interface (eth0, enp0s3, wlan0, etc.)
   - Choose Continuous mode or fixed packet count
   - Enable/disable payload (recommended for realism)

---

## Verifying Success

### Best Verification Method
1. Start the MAC flood script.
2. From another machine on the same switch, generate traffic (ping, web browsing, file transfer).
3. In Wireshark, apply this filter:
   ```wireshark
   eth.dst != ff:ff:ff:ff:ff:ff && eth.dst != your_own_mac_address
   ```
   **Result:** If you see unicast traffic destined to other devices, the attack is successful.

### Additional Success Indicators
- **Statistics → Conversations → Ethernet**: Thousands of unique MAC addresses.
- Huge spike in broadcast packets (`eth.dst == ff:ff:ff:ff:ff:ff`).
- Sudden appearance of IP/TCP/HTTP traffic not belonging to the attacker.
- Switch CAM table shows maximum entries (`show mac address-table` on Cisco).

---

## Wireshark Useful Filters
- **Flood traffic only**: `eth.dst == ff:ff:ff:ff:ff:ff`
- **Victim traffic**: `eth.dst != ff:ff:ff:ff:ff:ff && eth.dst != your_mac`
- **Real user protocols**: `tcp` or `http` or `ftp` or `telnet`

---

## ⚠️ Legal Notice
Use this tool only in authorized security labs, CTFs, or with explicit written permission. Unauthorized use on production networks is illegal.

*Guide prepared for educational and authorized testing purposes.*