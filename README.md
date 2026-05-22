# CyberCore

Welcome to the **CyberCore** repository. This project serves as a comprehensive collection of cybersecurity scripts, simulations, and tools carefully crafted for authorized penetration testing, vulnerability assessment, and educational research.

These tools demonstrate various capabilities, ranging from network scanning elements to aggressive denial-of-service simulations, to better understand and defend against both network-level and endpoint-based attacks.

---

## 🛡️ Attack & Simulation Tools 

The tools are categorized by their attack vector (Network vs. Endpoint) and sorted loosely from **Low Severity** (reconnaissance) to **Critical Severity** (Denial of Service, system impairment, or exfiltration).

### 🌐 Network-Based Attacks
These tools target network architecture, protocols, and layer 2/layer 3 configurations.

| Tool / Attack | Description | Severity |
| :--- | :--- | :--- |
| [**Network Scanner**](./Network_Scanner/) | Performs basic reconnaissance and network host discovery. | Low |
| [**Web Vulnerability Scanner**](./Web_Vuln_Scanner/) | Scans web applications for common framework and structural vulnerabilities. | Medium |
| [**Beaconing**](./Beaconing/) | Simulates C2 network beaconing to test detection systems. | Medium |
| [**IPv4 Fragmentation**](./IPv4_Fragmentation/) | Attacks exploiting network stack limitations (e.g., Teardrop, fragment overlaps). | High |
| [**MAC Flooding**](./Mac_Flooding/) | Overflows standard switch CAM tables to force fail-open (hub configuration). | High |
| [**ICMP Exfiltration**](./ICMP_Exfiltration/) | Sneaks payload exfiltration data over restricted networks using ICMP. | Critical |
| [**Advanced ICMP Tunneling**](./Advanced_ICMP_Tunneling/) | Complex covert C2 proxying strictly utilizing ICMP tunneling. | Critical |

### 🖥️ Endpoint-Based Attacks
These tools target local machine resources, kernel stability, or explicit software configurations on targeted endpoints.

| Tool / Attack | Description | Severity |
| :--- | :--- | :--- |
| [**Credential Harvesting**](./Credential_Harvesting/) | Covert bash/python scripts to steal SSH keys, tokens, and standard user directories. | High |
| [**Disk Filler**](./Disk_Filler/) | Simplified DoS focusing on burning partition space quickly via `dd`. | High |
| [**Disk Space Exhaustion**](./DiskSpace_Exhaustion/) | Advanced structured payload generation filling crucial `/tmp` and `/var` directories. | High |
| [**Memory Exhaustion**](./Memory_Exhaustion/) | Rapid background process generation to overwhelm OS scaling and memory (RAM). | Critical |
| [**Kernel Stress**](./Kernel_Stress/) | Severe I/O Wait pressure simulation specifically manipulating cache and load. | Critical |
| [**Fork Bomb**](./Fork_Bomb/) | Exponential process replication targeting the core process table, causing immediate freezes. | Critical |

---

## ⚠️ Legal & Ethical Notice
This repository is explicitly crafted for **Authorized Security Engineers, Blue Teams, and Penetration Testers ONLY**. Be advised:
* Do **NOT** execute anything herein against production environments or unapproved networks.
* These components possess the capacity to completely break systems and disrupt real-time network flows.
* **The author(s) assume zero liability** regarding damages, system downtimes, or illegal utilizations of these tools.

*Use responsibly in heavily segmented and specifically authorized virtual lab environments.*
