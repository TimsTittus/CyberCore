import scapy.all as scapy
import socket
import sys
import os
import netifaces
from ipaddress import ip_network
from datetime import datetime
import json

def get_default_interface():
    """Gets the default network interface"""
    try:
        gws = netifaces.gateways()
        return gws['default'][netifaces.AF_INET][1]
    except Exception as e:
        print(f"Interface detection warning: {e}")
        return None

def get_network_range():
    """Automatically detects the network range"""
    try:
        iface = get_default_interface()
        if not iface:
            raise ValueError("No default interface found")
            
        iface_details = netifaces.ifaddresses(iface)
        ip_info = iface_details[netifaces.AF_INET][0]
        network = ip_network(f"{ip_info['addr']}/{ip_info['netmask']}", strict=False)
        return str(network)
    except Exception as e:
        print(f"Network detection warning: {e}")
        return "192.168.18.0/24"  # Default to your network

def get_device_details(ip, mac):
    """Gets comprehensive details for a single device"""
    details = {
        "IP Address": ip,
        "MAC Address": mac,
        "Vendor": "Unknown",
        "Open Ports": {},
        "OS Guess": "Unknown",
        "Hostname": "Unknown",
        "Ping Response": "No"
    }
    
    # Get MAC vendor
    try:
        details["Vendor"] = scapy.getmacbyip(ip) or "Unknown"
    except:
        pass
    
    # Get hostname
    try:
        details["Hostname"] = socket.gethostbyaddr(ip)[0]
    except:
        pass
    
    # Check ping response
    try:
        ping = scapy.sr1(scapy.IP(dst=ip)/scapy.ICMP(), timeout=2, verbose=0)
        details["Ping Response"] = "Yes" if ping else "No"
    except:
        pass
    
    # OS detection via TTL
    try:
        if ping:
            ttl = ping[scapy.IP].ttl
            if ttl <= 64:
                details["OS Guess"] = "Linux/Unix"
            elif ttl <= 128:
                details["OS Guess"] = "Windows"
    except:
        pass
    
    # Port scanning
    common_ports = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        80: "HTTP",
        443: "HTTPS",
        445: "SMB",
        3389: "RDP"
    }
    
    for port, service in common_ports.items():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((ip, port)) == 0:
                    details["Open Ports"][port] = service
        except:
            continue
    
    return details

def scan_network(ip_range):
    """Scans the network and returns detailed device info"""
    print(f"\nScanning {ip_range}...")
    try:
        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        
        answered, unanswered = scapy.srp(
            arp_request_broadcast,
            timeout=2,
            verbose=0,
            inter=0.1,
            retry=1
        )
        
        devices = []
        for sent, received in answered:
            ip = received.psrc
            mac = received.hwsrc
            print(f"\nAnalyzing {ip}...")
            devices.append(get_device_details(ip, mac))
        
        return devices
    except Exception as e:
        print(f"Scanning error: {e}")
        return []

def display_device_details(device):
    """Displays device information in a detailed format"""
    print("\n" + "="*60)
    print(f"Device Details - {device['IP Address']}")
    print("="*60)
    
    print(f"\n🔹 Basic Information:")
    print(f"  • MAC Address: {device['MAC Address']}")
    print(f"  • Vendor: {device['Vendor']}")
    print(f"  • Hostname: {device['Hostname']}")
    print(f"  • Responds to Ping: {device['Ping Response']}")
    print(f"  • Likely OS: {device['OS Guess']}")
    
    if device["Open Ports"]:
        print("\nOpen Ports:")
        for port, service in device["Open Ports"].items():
            print(f"  • Port {port}: {service}")
    else:
        print("\nNo open ports found")
    
    print("\n" + "-"*60)

def main():
    print(f"\nAdvanced Network Scanner - {datetime.now()}")
    
    # Check requirements
    if os.geteuid() != 0:
        print("\nPlease run as root (sudo)")
        sys.exit(1)
    
    # Detect network
    ip_range = get_network_range()
    print(f"\nNetwork: {ip_range}")
    
    # Scan network
    devices = scan_network(ip_range)
    
    if not devices:
        print("\nNo devices found. Possible reasons:")
        print("  - Wrong network range")
        print("  - Devices blocking ARP requests")
        print("  - Network interface issue")
        sys.exit(1)
    
    # Display results
    print(f"\nFound {len(devices)} active devices:")
    for device in devices:
        display_device_details(device)
    
    # Save results
    with open("network_scan.json", "w") as f:
        json.dump(devices, f, indent=2)
    print("\nResults saved to network_scan.json")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan stopped by user")
    except Exception as e:
        print(f"\nError: {e}")