#!/usr/bin/env python3
"""
Exposed Services Check
Checks if any OT devices are exposing services unnecessarily
"""

import os
import sys
import socket
import time
import concurrent.futures
import subprocess
import json
from collections import defaultdict

def check_exposed_services():
    """Check for unnecessarily exposed services on OT devices"""
    print("Checking for unnecessarily exposed services on OT devices...")
    
    # Create output directory
    output_dir = "/home/kali/ot_discovery/security_analysis"
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "exposed_services.txt")
    
    # Get list of discovered hosts
    hosts_file = "/home/kali/ot_discovery/live_hosts.txt"
    if not os.path.exists(hosts_file):
        print(f"Error: {hosts_file} not found. Please run network enumeration first.")
        return
    
    with open(hosts_file, 'r') as f:
        hosts = [line.strip() for line in f.readlines()]
    
    if not hosts:
        print("No hosts found to check. Please run network enumeration first.")
        return
    
    # Define service categories
    service_categories = {
        "administrative": [22, 23, 3389, 5900],  # SSH, Telnet, RDP, VNC
        "web": [80, 443, 8080, 8443],  # HTTP, HTTPS, alt HTTP/HTTPS
        "file_transfer": [20, 21, 69, 989, 990],  # FTP, TFTP, SFTP
        "database": [1433, 1521, 3306, 5432],  # MSSQL, Oracle, MySQL, PostgreSQL
        "industrial": [102, 502, 20000, 44818, 1911, 2222, 47808, 1962, 789, 9600]  # OT protocols
    }
    
    # Flatten service categories for scanning
    all_ports = []
    for category, ports in service_categories.items():
        all_ports.extend(ports)
    
    # Scan hosts for open ports
    results = scan_hosts(hosts, all_ports)
    
    # Analyze results
    report = generate_report(results, service_categories)
    
    # Save report to file
    with open(output_file, 'w') as f:
        f.write(report)
    
    print(f"Exposed services check completed. Results saved to {output_file}")
    print(report)

def scan_hosts(hosts, ports):
    """Scan hosts for open ports"""
    print(f"Scanning {len(hosts)} hosts for {len(ports)} potentially exposed services...")
    
    results = defaultdict(list)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_host_port = {}
        
        # Submit scanning tasks
        for host in hosts:
            for port in ports:
                future = executor.submit(check_port, host, port)
                future_to_host_port[future] = (host, port)
        
        # Process results as they complete
        for i, future in enumerate(concurrent.futures.as_completed(future_to_host_port)):
            if i % 50 == 0:
                print(f"Processed {i}/{len(future_to_host_port)} port checks...")
                
            host, port = future_to_host_port[future]
            try:
                is_open = future.result()
                if is_open:
                    service_name = get_service_name(port)
                    results[host].append((port, service_name))
            except Exception as e:
                print(f"Error checking {host}:{port} - {e}")
    
    return results

def check_port(host, port):
    """Check if a port is open on a host"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((host, port))
    sock.close()
    return result == 0  # Return True if port is open

def get_service_name(port):
    """Get the service name for a port"""
    common_services = {
        20: "FTP Data",
        21: "FTP Control",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        69: "TFTP",
        80: "HTTP",
        102: "Siemens S7comm",
        110: "POP3",
        123: "NTP",
        143: "IMAP",
        161: "SNMP",
        443: "HTTPS",
        502: "Modbus TCP",
        1433: "MS SQL",
        1521: "Oracle DB",
        1911: "Niagara Fox",
        2222: "EtherNet/IP Implicit",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        8080: "HTTP Alternate",
        8443: "HTTPS Alternate",
        9600: "OMRON FINS",
        20000: "DNP3",
        44818: "EtherNet/IP",
        47808: "BACnet"
    }
    
    return common_services.get(port, f"Unknown ({port})")

def generate_report(results, service_categories):
    """Generate a report on exposed services"""
    report = "===== EXPOSED SERVICES ANALYSIS =====\n\n"
    
    # Count exposed services by category
    category_counts = defaultdict(int)
    host_category_services = defaultdict(lambda: defaultdict(list))
    
    for host, services in results.items():
        for port, service_name in services:
            # Find which category this port belongs to
            for category, category_ports in service_categories.items():
                if port in category_ports:
                    category_counts[category] += 1
                    host_category_services[host][category].append((port, service_name))
                    break
    
    # Report summary
    report += "Exposed Services Summary:\n"
    total_exposed = sum(category_counts.values())
    report += f"Found {total_exposed} exposed services across {len(results)} hosts\n\n"
    
    for category, count in category_counts.items():
        report += f"{category.title()} Services: {count}\n"
    
    report += "\n"
    
    # Report by host
    report += "Detailed Findings by Host:\n"
    for host, categories in sorted(host_category_services.items()):
        report += f"\nHost {host}:\n"
        
        # List services by category
        for category, services in categories.items():
            report += f"  {category.title()} Services:\n"
            
            for port, service_name in services:
                # Determine security recommendation
                if category == "administrative":
                    security_level = "HIGH RISK"
                    recommendation = "Administrative services should be restricted to management networks"
                elif category == "web" and port in (80, 8080):
                    security_level = "MEDIUM RISK"
                    recommendation = "Unencrypted web services should be replaced with HTTPS"
                elif category == "file_transfer" and port in (20, 21, 69):
                    security_level = "HIGH RISK"
                    recommendation = "Unencrypted file transfer protocols should be replaced with secure alternatives"
                elif category == "industrial":
                    security_level = "INFORMATIONAL"
                    recommendation = "Industrial protocol required for operation, restrict access with firewall"
                else:
                    security_level = "LOW RISK"
                    recommendation = "Service should be reviewed for necessity"
                
                report += f"    [WARNING] Port {port} ({service_name}): {security_level} - {recommendation}\n"
    
    # Overall recommendations
    report += """
\nSecurity Recommendations:
1. Administrative Services (SSH, Telnet, RDP, VNC)
   - Restrict to dedicated management networks
   - Implement jump servers for access
   - Replace Telnet with SSH where possible
   - Enable strong authentication

2. Web Services (HTTP, HTTPS)
   - Replace HTTP with HTTPS where possible
   - Implement proper certificate management
   - Consider removing web interfaces from critical control systems

3. File Transfer Services (FTP, TFTP)
   - Replace with secure alternatives (SFTP, SCP)
   - Restrict to only necessary file transfer paths
   - Implement read-only access where possible

4. Database Services
   - Should not be exposed in OT environments
   - Restrict to application servers only

5. Industrial Services
   - Restrict with firewall rules to authorized hosts only
   - Implement deep packet inspection where possible
   - Monitor for unauthorized commands

General Recommendations:
- Implement network segmentation to isolate critical systems
- Use host-based firewalls to restrict services
- Disabled unused services/ports on all devices
- Implement least privilege principle for all services
"""
    
    return report

if __name__ == "__main__":
    check_exposed_services()
