Network Scanner
Overview
Network Scanner is a Python-based tool designed for discovering and analyzing devices on a local network. It uses ARP requests to identify active devices and gathers detailed information such as IP addresses, MAC addresses, vendor details, hostnames, operating system estimates, and open ports. The results are displayed in a structured format and saved to a JSON file for further analysis.
Features

Automatic Network Detection: Identifies the default network interface and determines the network range.
Device Discovery: Uses ARP requests to find active devices on the specified network.
Comprehensive Device Profiling: Collects details including:
IP and MAC addresses
Vendor information
Hostname resolution
Ping responsiveness
Operating system estimation based on TTL
Common port scanning (FTP, SSH, Telnet, HTTP, HTTPS, SMB, RDP)


Output Storage: Saves scan results to a JSON file (network_scan.json).
Error Handling: Provides informative error messages for network issues, permissions, or interruptions.

Requirements

Python 3.x
Dependencies:
scapy: For network packet manipulation and scanning.
netifaces: For network interface and IP address information.
ipaddress: For handling IP network ranges.


Root Privileges: The script requires root access (sudo) to perform network operations.
Operating System: Compatible with Linux and other systems supporting the required libraries.

Installation

Clone or download the repository to your local machine.
Install the required Python packages:pip install scapy netifaces


Ensure you have root privileges to run the script.

Usage

Save the script as network_scanner.py.
Run the script with root privileges:sudo python3 network_scanner.py


The script will:
Detect the default network interface and network range.
Perform an ARP scan to discover active devices.
Analyze each device for detailed information.
Display the results in the terminal.
Save the results to network_scan.json.



Output

Terminal Output: Detailed device information including IP, MAC, vendor, hostname, OS guess, ping response, and open ports.
JSON File: A structured JSON file (network_scan.json) containing the scan results.

Notes

The script defaults to the 192.168.18.0/24 network range if automatic detection fails.
Ensure the network range is correct for your environment to avoid scanning issues.
Some devices may block ARP requests, leading to incomplete results.
Port scanning is limited to common ports (21, 22, 23, 80, 443, 445, 3389) with a short timeout for efficiency.

Limitations

Requires root privileges for raw socket operations.
OS detection is based on TTL values and may not be precise.
Port scanning is limited to predefined common ports.
Network issues or firewalls may prevent accurate device discovery.

License
This project is licensed under the MIT License. See the LICENSE file for details.
Disclaimer
Use this tool responsibly and only on networks where you have explicit permission to scan. Unauthorized network scanning may violate laws or network policies.