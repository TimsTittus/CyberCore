# IPv4 Fragmentation Attack Tool (Scapy)

## Overview
**IPv4 Fragmentation Attacks** exploit how network devices and firewalls handle fragmented IP packets. 

By sending specially crafted fragmented packets (normal, overlapping, tiny, or incomplete), an attacker can:
- Bypass firewall/IDS rules
- Exhaust kernel memory (reassembly queues)
- Trigger bugs in IP stack reassembly (Teardrop-style attacks)
- Cause Denial of Service (DoS)

---

## Attacker's Gain

- **Firewall / IDS Evasion** — Fragments can bypass signature-based detection.
- **Denial of Service** — Overlapping fragments or incomplete chains can crash or slow down the target.
- **Resource Exhaustion** — Force the target to allocate large amounts of memory for reassembly.
- **Stability Testing** — Discover vulnerabilities in OS/network stack handling of fragmented packets.

---

## Requirements
- Python 3 + Scapy
- Root/Sudo privileges
- Target reachable on the network
- **Authorized lab or test environment only**

---

## How to Use (Step by Step)

1. **Save the code** as `ipv4_fragment.py`

2. **Make it executable**:
   ```bash
   chmod +x ipv4_fragment.py
   ```

3. **Run the script**:
   ```bash
   sudo python3 ipv4_fragment.py
   ```

4. **Follow the on-screen prompts**:
   - Enter Target IP (e.g. 192.168.0.107)
   - Choose Attack Mode (1–5)
   - Set Packets per second (recommended: 500–2000)
   - Set Duration (0 = unlimited, stop with Ctrl+C)

---

## Recommended Attack Modes

| Mode | Name | Purpose | Strength |
| :--- | :--- | :--- | :--- |
| 1 | High-Rate Fragment Flood | Bandwidth & CPU stress | Medium |
| 2 | Tiny Fragments | Best for evasion | High |
| 3 | Teardrop (Overlapping) | Classic reassembly attack | High |
| 4 | Incomplete Fragment Storm | Reassembly buffer exhaustion | High |
| 5 | Random Mixed Attack | Chaotic / unpredictable | Medium |

---

## Verifying Success

### In Wireshark (on attacker machine):
- **All fragments**: `ip.dst == <target_ip> && (ip.flags.mf == 1 || ip.frag_offset > 0)`
- **Teardrop / Overlapping**: Look for same `ip.id` with overlapping offsets
- **Target response**: Monitor if the target stops responding to normal pings

### On Target Machine:
- High CPU usage
- Slow network performance
- **Kernel logs**: `dmesg | grep -i frag`
- System instability or crash (on vulnerable systems)

---

## Wireshark Useful Filters
- **General fragments**: `ip.flags.mf == 1 || ip.frag_offset > 0`
- **Specific target**: `ip.dst == 192.168.0.107 && ip.proto == 1`
- **Fragment ID tracking**: `ip.id == 0x1234` (replace with actual ID)

---

## ⚠️ Legal & Safety Warning
This is a real attack tool. Use only in isolated lab environments or authorized security assessments with explicit permission. Unauthorized use on production networks is illegal and may cause system crashes.

*Guide prepared for educational and authorized penetration testing purposes.*