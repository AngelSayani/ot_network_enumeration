#!/usr/bin/env python3
"""
Modbus Device ID Scanner
Queries a Modbus TCP device for identification information
"""

import sys
from pymodbus.client.sync import ModbusTcpClient
from pymodbus.constants import DeviceInformation
from pymodbus.exceptions import ModbusException
from pymodbus.mei_message import ReadDeviceInformationRequest

def read_device_identification(ip_address):
    """Read the device identification information from a Modbus TCP device"""
    print(f"Querying Modbus device at {ip_address} for identification information...")
    
    client = ModbusTcpClient(ip_address, port=502)
    
    try:
        client.connect()
        
        # Read identification information categories
        info_categories = {
            "VendorName": DeviceInformation.VendorName,
            "ProductCode": DeviceInformation.ProductCode, 
            "RevisionId": DeviceInformation.RevisionId,
            "VendorUrl": DeviceInformation.VendorUrl,
            "ProductName": DeviceInformation.ProductName,
            "ModelName": DeviceInformation.ModelName,
            "UserApplicationName": DeviceInformation.UserApplicationName
        }
        
        print("\n===== DEVICE IDENTIFICATION =====")
        
        for name, category in info_categories.items():
            try:
                # Try to read each category of identification info
                request = ReadDeviceInformationRequest(unit=1, read_code=4, object_id=category)
                response = client.execute(request)
                
                if hasattr(response, 'information') and category in response.information:
                    value = response.information[category].decode('utf-8', errors='replace')
                    print(f"{name}: {value}")
                
            except Exception as e:
                # Some categories might not be supported by all devices
                pass
                
        # Read some device-specific holding registers that might contain identification info
        # Registers 0-10 often have device configuration information
        response = client.read_holding_registers(0, 10, unit=1)
        if not response.isError():
            print("\n===== CONFIGURATION REGISTERS =====")
            print(f"Registers[0-9]: {response.registers}")
            
            # Interpret some common register meanings
            if len(response.registers) >= 5:
                print("\n===== DEVICE FUNCTION (INFERRED) =====")
                if response.registers[0] > 0 and response.registers[1] > 0:
                    print("This appears to be a PLC controlling an industrial process.")
                    
                    # Analyze register patterns
                    if 100 <= response.registers[0] <= 500 and response.registers[1] < 100:
                        print("Likely function: Temperature controller for heating process")
                    elif response.registers[0] < 100 and 1000 <= response.registers[2] <= 3000:
                        print("Likely function: Motor drive controller")
                    elif 1000 <= response.registers[0] <= 5000:
                        print("Likely function: Pressure or flow controller")
                    else:
                        print("Likely function: General purpose controller")
                
    except ModbusException as e:
        print(f"Modbus error: {e}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        client.close()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 modbus_device_id.py <ip_address>")
        sys.exit(1)
        
    ip_address = sys.argv[1]
    read_device_identification(ip_address)
