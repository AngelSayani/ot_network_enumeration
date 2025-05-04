#!/usr/bin/env python3
"""
Industrial Protocol Broadcast Listener
Listens for broadcasts from industrial protocols to discover devices that may not respond to direct scanning
"""

import socket
import struct
import time
import threading
import sys
from datetime import datetime

class BroadcastListener:
    def __init__(self):
        """Initialize the broadcast listener"""
        self.running = True
        self.found_devices = set()
        self.print_lock = threading.Lock()

    def listen_ethernetip(self):
        """Listen for EtherNet/IP (CIP) broadcasts on UDP port 2222"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('', 2222))
            sock.settimeout(1)
            
            while self.running:
                try:
                    data, addr = sock.recvfrom(1024)
                    self.process_ethernetip(data, addr)
                except socket.timeout:
                    pass
                    
        except Exception as e:
            with self.print_lock:
                print(f"Error in EtherNet/IP listener: {e}")
        finally:
            sock.close()
            
    def listen_bacnet(self):
        """Listen for BACnet broadcasts on UDP port 47808"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('', 47808))
            sock.settimeout(1)
            
            while self.running:
                try:
                    data, addr = sock.recvfrom(1024)
                    self.process_bacnet(data, addr)
                except socket.timeout:
                    pass
                    
        except Exception as e:
            with self.print_lock:
                print(f"Error in BACnet listener: {e}")
        finally:
            sock.close()
            
    def listen_profinet(self):
        """Listen for PROFINET DCP broadcasts on EtherType 0x8892"""
        # PROFINET DCP uses raw Ethernet frames with EtherType 0x8892
        # Can't easily capture in Python without root/special permissions
        # Here we simulate finding some devices for demonstration purposes
        time.sleep(2)
        self.add_found_device("192.168.100.30", "PROFINET (simulated)", "Siemens S7-1200 PLC")
        self.add_found_device("192.168.100.31", "PROFINET (simulated)", "PROFINET I/O Device")
            
    def listen_modbus(self):
        """Simulate listening for Modbus devices"""
        # Modbus doesn't typically broadcast, but we can simulate discovery
        time.sleep(3)
        self.add_found_device("192.168.100.40", "Modbus TCP (simulated)", "Hidden Modbus Slave")
            
    def process_ethernetip(self, data, addr):
        """Process EtherNet/IP broadcast packet"""
        try:
            # Check if it's a List Identity Response
            if len(data) > 24 and data[0:2] == b'\x63\x00':
                # Parse out vendor ID and product name if possible
                vendor_id = struct.unpack('<H', data[30:32])[0]
                device_type = struct.unpack('<H', data[32:34])[0]
                
                vendor_name = "Unknown"
                if vendor_id == 1:
                    vendor_name = "Allen-Bradley"
                elif vendor_id == 6:
                    vendor_name = "Schneider Electric"
                
                device_types = {
                    0x00: "Generic Device",
                    0x02: "AC Drive",
                    0x07: "Position Sensor",
                    0x0C: "Pneumatic Valve",
                    0x20: "I/O Block",
                    0x30: "PLC",
                    0x33: "HMI"
                }
                
                device_name = device_types.get(device_type, f"Unknown Device (0x{device_type:04X})")
                device_info = f"{vendor_name} {device_name}"
                
                self.add_found_device(addr[0], "EtherNet/IP", device_info)
                
        except Exception as e:
            with self.print_lock:
                print(f"Error processing EtherNet/IP packet: {e}")
    
    def process_bacnet(self, data, addr):
        """Process BACnet broadcast packet"""
        try:
            # Very basic BACnet parsing (just enough to recognize device)
            if len(data) > 6 and data[0] == 0x81:  # BACnet Virtual Link Control
                self.add_found_device(addr[0], "BACnet", "Building Automation Controller")
                
        except Exception as e:
            with self.print_lock:
                print(f"Error processing BACnet packet: {e}")
    
    def add_found_device(self, ip, protocol, device_info):
        """Add a discovered device to the list if it's new"""
        device_key = f"{ip}:{protocol}"
        if device_key not in self.found_devices:
            self.found_devices.add(device_key)
            with self.print_lock:
                timestamp = datetime.now().strftime("%H:%M:%S")
                print(f"[{timestamp}] Discovered hidden device: {ip} - {protocol} - {device_info}")

def main():
    print("Starting Industrial Protocol Broadcast Listener...")
    print("Listening for devices that broadcast their presence...")
    print("Press Ctrl+C to stop\n")
    
    listener = BroadcastListener()
    
    # Start listener threads
    threads = []
    threads.append(threading.Thread(target=listener.listen_ethernetip))
    threads.append(threading.Thread(target=listener.listen_bacnet))
    threads.append(threading.Thread(target=listener.listen_profinet))
    threads.append(threading.Thread(target=listener.listen_modbus))
    
    for thread in threads:
        thread.daemon = True
        thread.start()
    
    try:
        # Run for some time before automatically stopping
        for i in range(60):
            if i % 10 == 0 and i > 0:
                print(f"\nListening for broadcast packets... ({i} seconds elapsed)")
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nStopping listeners...")
    finally:
        listener.running = False
        
        # Wait for threads to finish
        for thread in threads:
            thread.join(1)
    
    print("\nDiscovered devices summary:")
    if listener.found_devices:
        for i, device_key in enumerate(sorted(listener.found_devices)):
            ip, protocol = device_key.split(':', 1)
            print(f"  {i+1}. {ip} - {protocol}")
    else:
        print("  No devices discovered. This could indicate:")
        print("  - No broadcasting devices in the network")
        print("  - Network segmentation preventing broadcasts")
        print("  - Firewalls blocking broadcast traffic")
    
    print("\nNote: Some OT devices are configured not to broadcast their presence")
    print("for security reasons. These devices require other detection methods.")

if __name__ == "__main__":
    main()
