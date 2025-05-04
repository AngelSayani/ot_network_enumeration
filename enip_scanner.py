#!/usr/bin/env python3
"""
EtherNet/IP Scanner
Queries an EtherNet/IP device (Allen-Bradley/Rockwell) for identification information
"""

import sys
import socket
import struct
import time

# EtherNet/IP command codes
COMMAND_LIST_IDENTITY = 0x63
COMMAND_LIST_INTERFACES = 0x64
COMMAND_LIST_SERVICES = 0x04

# Encapsulation header format
# 2 bytes: Command
# 2 bytes: Length
# 4 bytes: Session handle
# 4 bytes: Status
# 8 bytes: Sender context
# 4 bytes: Options
EIP_HEADER = struct.Struct('<HHIIQH')

def decode_device_type(dtype):
    """Decode the device type code"""
    device_types = {
        0x00: "Generic Device",
        0x02: "AC Drive",
        0x03: "Motor Overload",
        0x04: "Limit Switch",
        0x05: "Inductive Proximity Switch",
        0x06: "Photoelectric Sensor",
        0x07: "Position Sensor",
        0x09: "DC Drive",
        0x0C: "Pneumatic Valve",
        0x0E: "Hydraulic Valve",
        0x10: "Process Control Valve",
        0x13: "Residual Gas Analyzer",
        0x15: "Generic Sensor",
        0x1E: "Pneumatic Positioner",
        0x1F: "Hydraulic Positioner",
        0x20: "I/O Block",
        0x23: "Position Controller/Monitor",
        0x24: "DC Power Generator",
        0x25: "AC Power Generator",
        0x26: "DC Power Monitor",
        0x27: "AC Power Monitor",
        0x28: "Frequency Monitor",
        0x29: "Phase Monitor",
        0x2A: "Vacuum Pump",
        0x2B: "Water Pump",
        0x2C: "Wind Turbine Generator",
        0x2D: "Solar Panel",
        0x30: "Programmable Logic Controller",
        0x32: "Motion Controller",
        0x33: "Human-Machine Interface",
        0x35: "Mass Flow Controller",
        0x37: "Safety Discrete I/O Device",
        0x38: "Safety Analog I/O Device",
        0x39: "Safety Drive Controller"
    }
    
    return device_types.get(dtype, f"Unknown Device Type (0x{dtype:02X})")

def decode_vendor(vendor_id):
    """Decode the vendor ID"""
    vendors = {
        1: "Allen-Bradley / Rockwell Automation",
        2: "Schneider Electric",
        3: "Eaton Electrical",
        4: "Siemens",
        5: "Honeywell",
        6: "General Electric",
        7: "Omron",
        8: "Bosch Rexroth",
        9: "Mitsubishi Electric",
        10: "Parker Hannifin",
        11: "ABB",
        13: "Emerson",
        15: "Yaskawa"
    }
    
    return vendors.get(vendor_id, f"Unknown Vendor (ID: {vendor_id})")

def decode_status(status):
    """Decode the device status word"""
    status_map = {
        0: "Unknown Status",
        1: "Self-testing",
        2: "Standby",
        3: "Operational",
        4: "Recoverable Fault",
        5: "Major Fault - Unrecoverable",
        6: "Maintenance Required",
        7: "Maintenance in Progress"
    }
    
    status_code = status & 0x0F  # Bottom 4 bits are status code
    configured = (status & 0x10) != 0  # Bit 4 is configured
    owned = (status & 0x20) != 0  # Bit 5 is owned
    
    result = status_map.get(status_code, f"Unknown Status ({status_code})")
    if configured:
        result += " | Configured"
    else:
        result += " | Not Configured"
        
    if owned:
        result += " | Owned (in use)"
    else:
        result += " | Not Owned (available)"
        
    return result

def scan_enip_device(ip_address):
    """Scan an EtherNet/IP device for identification information"""
    print(f"Scanning EtherNet/IP device at {ip_address}...")
    
    # Create socket for EtherNet/IP communication
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    
    try:
        # Connect to the EtherNet/IP port
        sock.connect((ip_address, 44818))
        
        # Create List Identity request
        header = EIP_HEADER.pack(
            COMMAND_LIST_IDENTITY,  # Command
            0,                      # Length
            0,                      # Session handle
            0,                      # Status
            0,                      # Sender context
            0                       # Options
        )
        
        # Send the request
        sock.send(header)
        
        # Receive the response
        response = sock.recv(1024)
        
        # Unpack the header
        command, length, session, status, context, options = EIP_HEADER.unpack_from(response)
        
        # If we got a valid response
        if command == COMMAND_LIST_IDENTITY and length > 0:
            # Skip the header to get to the data
            data = response[24:]
            
            # Parse the identity response
            # Format:
            # 2 bytes: Item count (should be 1)
            # 2 bytes: Item type code (should be 0x000C for Identity)
            # 2 bytes: Item length
            # Then the identity object:
            #   2 bytes: Protocol version
            #   2 bytes: Socket address size (should be 16)
            #   16 bytes: Socket address (sin_family, sin_port, sin_addr, sin_zero)
            #   2 bytes: Vendor ID
            #   2 bytes: Device Type
            #   2 bytes: Product Code
            #   1 byte: Revision major
            #   1 byte: Revision minor
            #   2 bytes: Status
            #   4 bytes: Serial number
            #   1 byte: Product name length
            #   n bytes: Product name
            
            item_count = struct.unpack('<H', data[0:2])[0]
            item_type = struct.unpack('<H', data[2:4])[0]
            item_length = struct.unpack('<H', data[4:6])[0]
            
            if item_type == 0x000C:  # Identity item
                identity_data = data[6:]
                
                protocol_version = struct.unpack('<H', identity_data[0:2])[0]
                socket_addr_size = struct.unpack('<H', identity_data[2:4])[0]
                
                # Skip socket address
                offset = 4 + socket_addr_size
                
                vendor_id = struct.unpack('<H', identity_data[offset:offset+2])[0]
                device_type = struct.unpack('<H', identity_data[offset+2:offset+4])[0]
                product_code = struct.unpack('<H', identity_data[offset+4:offset+6])[0]
                revision_major = identity_data[offset+6]
                revision_minor = identity_data[offset+7]
                status = struct.unpack('<H', identity_data[offset+8:offset+10])[0]
                serial_number = struct.unpack('<I', identity_data[offset+10:offset+14])[0]
                
                product_name_len = identity_data[offset+14]
                product_name = identity_data[offset+15:offset+15+product_name_len].decode('ascii', errors='replace')
                
                print("\n===== DEVICE IDENTIFICATION =====")
                print(f"Vendor: {decode_vendor(vendor_id)}")
                print(f"Device Type: {decode_device_type(device_type)}")
                print(f"Product Code: {product_code}")
                print(f"Revision: {revision_major}.{revision_minor}")
                print(f"Serial Number: {serial_number}")
                print(f"Product Name: {product_name}")
                print(f"Status: {decode_status(status)}")
                print("\n===== DEVICE FUNCTION (INFERRED) =====")
                
                # Infer device function based on device type
                if device_type == 0x30:  # PLC
                    if "CompactLogix" in product_name:
                        print("This is a CompactLogix PLC, typically used for small to medium automation tasks.")
                    elif "ControlLogix" in product_name:
                        print("This is a ControlLogix PLC, typically used for large, complex automation systems.")
                    elif "MicroLogix" in product_name:
                        print("This is a MicroLogix PLC, typically used for small automation tasks.")
                    else:
                        print("This is a Programmable Logic Controller (PLC), the central controller in the automation system.")
                        
                elif device_type == 0x33:  # HMI
                    print("This is a Human-Machine Interface (HMI), used by operators to monitor and control the process.")
                    
                elif device_type == 0x32:  # Motion Controller
                    print("This is a Motion Controller, responsible for precise control of motors and movement.")
                    
                elif device_type == 0x02 or device_type == 0x09:  # AC/DC Drive
                    print("This is a Variable Frequency Drive (VFD), controlling motor speed in the process.")
                    
                elif device_type == 0x37 or device_type == 0x38 or device_type == 0x39:  # Safety device
                    print("This is a Safety Device, responsible for emergency shutdown or safety monitoring.")
                    
                elif device_type == 0x20:  # I/O Block
                    print("This is an I/O Block, providing sensor inputs and control outputs to the PLC.")
                    
                else:
                    print(f"This device functions as a {decode_device_type(device_type)}.")
                    
            else:
                print(f"Unexpected item type: {item_type}")
        else:
            print(f"Invalid response command: {command}")
    
    except socket.timeout:
        print(f"Connection to {ip_address} timed out")
    except ConnectionRefusedError:
        print(f"Connection to {ip_address} refused")
    except Exception as e:
        print(f"Error scanning device: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 enip_scanner.py <ip_address>")
        sys.exit(1)
        
    ip_address = sys.argv[1]
    scan_enip_device(ip_address)
