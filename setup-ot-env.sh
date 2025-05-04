#!/bin/bash
# Setup script for OT environment simulation

echo "Setting up OT environment simulation..."

# Create directory for services
mkdir -p /opt/ot-simulation

# Create Python script for Modbus Server simulation
cat > /opt/ot-simulation/modbus_server.py << 'EOF'
#!/usr/bin/env python3
"""
Modbus TCP Server Simulation
Simulates a Modbus TCP server for OT environment testing
"""

import socket
import threading
import struct
import time
import random
import logging
import sys
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("ModbusServer")

class ModbusServer:
    def __init__(self, host='0.0.0.0', port=502, device_id=1, device_type="PLC"):
        self.host = host
        self.port = port
        self.device_id = device_id
        self.device_type = device_type
        self.server_socket = None
        self.running = False
        self.clients = []
        
        # Modbus registers
        self.coils = [False] * 1000  # 0xxxx - Coils (Digital Outputs)
        self.discrete_inputs = [False] * 1000  # 1xxxx - Discrete Inputs (Digital Inputs)
        self.holding_registers = [0] * 1000  # 4xxxx - Holding Registers (Analog Outputs)
        self.input_registers = [0] * 1000  # 3xxxx - Input Registers (Analog Inputs)
        
        # Set some initial values based on device type
        if device_type == "PLC":
            self.setup_plc_values()
        elif device_type == "HMI":
            self.setup_hmi_values()
        elif device_type == "RTU":
            self.setup_rtu_values()
        elif device_type == "VFD":
            self.setup_vfd_values()
    
    def setup_plc_values(self):
        """Set up values for a PLC simulation"""
        # Set product identity information in holding registers
        # These are often in a standard format, here using a simplified version
        # Registers 0-9 reserved for identity
        self.holding_registers[0] = 1  # Vendor code (1 = Simulated)
        self.holding_registers[1] = 101  # Product code (101 = PLC)
        self.holding_registers[2] = 10  # Firmware version major
        self.holding_registers[3] = 5  # Firmware version minor
        
        # Process values in input registers
        # Simulating a temperature process
        self.input_registers[0] = 175  # Process temperature (175 degrees)
        self.input_registers[1] = 180  # Setpoint temperature
        self.input_registers[2] = 1  # Control mode (1 = Auto)
        
        # Control outputs in coils
        self.coils[0] = True  # Heater output
        self.coils[1] = False  # Cooling output
        self.coils[2] = True  # Process running
        
        # Inputs in discrete inputs
        self.discrete_inputs[0] = True  # High temperature limit switch
        self.discrete_inputs[1] = False  # Low temperature limit switch
    
    def setup_hmi_values(self):
        """Set up values for an HMI simulation"""
        # Identity information
        self.holding_registers[0] = 1  # Vendor code
        self.holding_registers[1] = 201  # Product code (201 = HMI)
        
        # HMI status information
        self.input_registers[0] = 1  # Screen ID
        self.input_registers[1] = 0  # Alarm count
    
    def setup_rtu_values(self):
        """Set up values for a Remote Terminal Unit simulation"""
        # Identity information
        self.holding_registers[0] = 1  # Vendor code
        self.holding_registers[1] = 301  # Product code (301 = RTU)
        
        # RTU status and I/O
        for i in range(10):  # Simulate 10 digital inputs
            self.discrete_inputs[i] = random.choice([True, False])
        
        for i in range(5):  # Simulate 5 analog inputs
            self.input_registers[i] = random.randint(100, 900)  # Random values
    
    def setup_vfd_values(self):
        """Set up values for a Variable Frequency Drive simulation"""
        # Identity information
        self.holding_registers[0] = 1  # Vendor code
        self.holding_registers[1] = 401  # Product code (401 = VFD)
        
        # VFD parameters
        self.holding_registers[10] = 6000  # Speed setpoint (0.1 Hz, so 6000 = 600.0 Hz)
        self.input_registers[0] = 5950  # Actual speed
        self.input_registers[1] = 250  # Motor current (0.1 A, so 250 = 25.0 A)
        self.input_registers[2] = 4800  # DC bus voltage (0.1 V, so 4800 = 480.0 V)
        
        # VFD status
        self.coils[0] = True  # Running
        self.coils[1] = False  # Fault
        self.coils[2] = True  # Ready
    
    def update_process_values(self):
        """Update simulated process values"""
        while self.running:
            # Update based on device type
            if self.device_type == "PLC":
                # Simulate temperature fluctuating around setpoint
                setpoint = self.holding_registers[1]  # Get setpoint
                current_temp = self.input_registers[0]  # Get current temperature
                
                # Adjust temperature based on heater/cooler state
                if self.coils[0]:  # Heater on
                    new_temp = current_temp + random.randint(0, 3)
                elif self.coils[1]:  # Cooler on
                    new_temp = current_temp - random.randint(0, 3)
                else:
                    # Natural cooling
                    new_temp = current_temp - random.randint(0, 1)
                
                # Apply some randomness
                new_temp += random.randint(-1, 1)
                
                # Update temperature
                self.input_registers[0] = max(0, min(500, new_temp))  # Clamp to 0-500
                
                # Control logic: turn heater on/off based on setpoint
                if new_temp < setpoint - 5:
                    self.coils[0] = True  # Turn heater on
                    self.coils[1] = False  # Turn cooler off
                elif new_temp > setpoint + 5:
                    self.coils[0] = False  # Turn heater off
                    self.coils[1] = True  # Turn cooler on
            
            elif self.device_type == "VFD":
                # Simulate VFD approaching setpoint speed
                setpoint = self.holding_registers[10]  # Speed setpoint
                actual_speed = self.input_registers[0]  # Actual speed
                
                # Adjust actual speed to approach setpoint
                if actual_speed < setpoint:
                    self.input_registers[0] = min(setpoint, actual_speed + random.randint(5, 15))
                elif actual_speed > setpoint:
                    self.input_registers[0] = max(setpoint, actual_speed - random.randint(5, 15))
                else:
                    self.input_registers[0] = setpoint + random.randint(-5, 5)
                
                # Simulate motor current based on speed
                self.input_registers[1] = 100 + int(self.input_registers[0] * 0.03)
            
            # Introduce occasional changes to discrete inputs for all devices
            for i in range(10):
                if random.random() < 0.05:  # 5% chance of change
                    self.discrete_inputs[i] = not self.discrete_inputs[i]
            
            time.sleep(1)  # Update once per second
    
    def start(self):
        """Start the Modbus server"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        
        self.running = True
        
        # Start process value update thread
        update_thread = threading.Thread(target=self.update_process_values)
        update_thread.daemon = True
        update_thread.start()
        
        logger.info(f"Modbus server started on {self.host}:{self.port} as {self.device_type}")
        
        try:
            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    logger.info(f"Client connected from {address}")
                    
                    client_thread = threading.Thread(target=self.handle_client, args=(client_socket, address))
                    client_thread.daemon = True
                    client_thread.start()
                    
                    self.clients.append((client_socket, address))
                except Exception as e:
                    logger.error(f"Error accepting connection: {e}")
        except KeyboardInterrupt:
            logger.info("Server shutting down")
        finally:
            self.stop()
    
    def stop(self):
        """Stop the Modbus server"""
        self.running = False
        
        # Close all client connections
        for client_socket, _ in self.clients:
            try:
                client_socket.close()
            except:
                pass
        
        # Close server socket
        if self.server_socket:
            self.server_socket.close()
        
        logger.info("Modbus server stopped")
    
    def handle_client(self, client_socket, address):
        """Handle a client connection"""
        try:
            while self.running:
                # Receive the MBAP header (7 bytes)
                mbap_header = client_socket.recv(7)
                if not mbap_header or len(mbap_header) < 7:
                    break
                
                # Parse MBAP header
                (transaction_id, protocol_id, length, unit_id) = struct.unpack(">HHHB", mbap_header)
                
                # Receive the function code and data
                data = client_socket.recv(length - 1)
                if not data:
                    break
                
                function_code = data[0]
                
                # Process the request
                response = self.process_request(function_code, data[1:], unit_id)
                
                # Build MBAP header for response
                response_header = struct.pack(">HHHB", transaction_id, protocol_id, len(response) + 1, unit_id)
                
                # Send response
                client_socket.send(response_header + response)
                
        except Exception as e:
            logger.error(f"Error handling client {address}: {e}")
        finally:
            client_socket.close()
            if (client_socket, address) in self.clients:
                self.clients.remove((client_socket, address))
            logger.info(f"Client disconnected from {address}")
    
    def process_request(self, function_code, data, unit_id):
        """Process a Modbus request and generate a response"""
        logger.debug(f"Processing request: function_code={function_code}, data={data.hex()}")
        
        try:
            # Read Coils (0x01)
            if function_code == 0x01:
                return self.read_coils(data)
            
            # Read Discrete Inputs (0x02)
            elif function_code == 0x02:
                return self.read_discrete_inputs(data)
            
            # Read Holding Registers (0x03)
            elif function_code == 0x03:
                return self.read_holding_registers(data)
            
            # Read Input Registers (0x04)
            elif function_code == 0x04:
                return self.read_input_registers(data)
            
            # Write Single Coil (0x05)
            elif function_code == 0x05:
                return self.write_single_coil(data)
            
            # Write Single Register (0x06)
            elif function_code == 0x06:
                return self.write_single_register(data)
            
            # Write Multiple Coils (0x0F)
            elif function_code == 0x0F:
                return self.write_multiple_coils(data)
            
            # Write Multiple Registers (0x10)
            elif function_code == 0x10:
                return self.write_multiple_registers(data)
            
            # Read Device Identification (0x2B, 0x0E)
            elif function_code == 0x2B and len(data) >= 2 and data[0] == 0x0E:
                return self.read_device_identification(data)
            
            # Unknown or unsupported function code
            else:
                return bytes([function_code | 0x80, 0x01])  # Exception code 0x01 (Illegal Function)
                
        except Exception as e:
            logger.error(f"Error processing request: {e}")
            return bytes([function_code | 0x80, 0x04])  # Exception code 0x04 (Server Failure)
    
    def read_coils(self, data):
        """Process Read Coils (0x01) request"""
        start_address = (data[0] << 8) | data[1]
        quantity = (data[2] << 8) | data[3]
        
        # Validate request
        if quantity < 1 or quantity > 2000 or start_address + quantity > len(self.coils):
            return bytes([0x01 | 0x80, 0x02])  # Exception code 0x02 (Illegal Data Address)
        
        # Prepare response
        byte_count = (quantity + 7) // 8
        response = bytes([0x01, byte_count])
        
        # Pack coils into bytes
        result_bytes = bytearray(byte_count)
        for i in range(quantity):
            if self.coils[start_address + i]:
                result_bytes[i // 8] |= (1 << (i % 8))
        
        return response + bytes(result_bytes)
    
    def read_discrete_inputs(self, data):
        """Process Read Discrete Inputs (0x02) request"""
        start_address = (data[0] << 8) | data[1]
        quantity = (data[2] << 8) | data[3]
        
        # Validate request
        if quantity < 1 or quantity > 2000 or start_address + quantity > len(self.discrete_inputs):
            return bytes([0x02 | 0x80, 0x02])  # Exception code 0x02 (Illegal Data Address)
        
        # Prepare response
        byte_count = (quantity + 7) // 8
        response = bytes([0x02, byte_count])
        
        # Pack discrete inputs into bytes
        result_bytes = bytearray(byte_count)
        for i in range(quantity):
            if self.discrete_inputs[start_address + i]:
                result_bytes[i // 8] |= (1 << (i % 8))
        
        return response + bytes(result_bytes)
    
    def read_holding_registers(self, data):
        """Process Read Holding Registers (0x03) request"""
        start_address = (data[0] << 8) | data[1]
        quantity = (data[2] << 8) | data[3]
        
        # Validate request
        if quantity < 1 or quantity > 125 or start_address + quantity > len(self.holding_registers):
            return bytes([0x03 | 0x80, 0x02])  # Exception code 0x02 (Illegal Data Address)
        
        # Prepare response
        byte_count = quantity * 2
        response = bytes([0x03, byte_count])
        
        # Pack registers into bytes
        result_bytes = bytearray(byte_count)
        for i in range(quantity):
            result_bytes[i*2] = (self.holding_registers[start_address + i] >> 8) & 0xFF
            result_bytes[i*2+1] = self.holding_registers[start_address + i] & 0xFF
        
        return response + bytes(result_bytes)
    
    def read_input_registers(self, data):
        """Process Read Input Registers (0x04) request"""
        start_address = (data[0] << 8) | data[1]
        quantity = (data[2] << 8) | data[3]
        
        # Validate request
        if quantity < 1 or quantity > 125 or start_address + quantity > len(self.input_registers):
            return bytes([0x04 | 0x80, 0x02])  # Exception code 0x02 (Illegal Data Address)
        
        # Prepare response
        byte_count = quantity * 2
        response = bytes([0x04, byte_count])
        
        # Pack registers into bytes
        result_bytes = bytearray(byte_count)
        for i in range(quantity):
            result_bytes[i*2] = (self.input_registers[start_address + i] >> 8) & 0xFF
            result_bytes[i*2+1] = self.input_registers[start_address + i] & 0xFF
        
        return response + bytes(result_bytes)
    
    def write_single_coil(self, data):
        """Process Write Single Coil (0x05) request"""
        address = (data[0] << 8) | data[1]
        value = (data[2] << 8) | data[3]
        
        # Validate request
        if address >= len(self.coils):
            return bytes([0x05 | 0x80, 0x02])  # Exception code 0x02 (Illegal Data Address)
        
        # Set coil value (0x0000 = OFF, 0xFF00 = ON)
        self.coils[address] = (value == 0xFF00)
        
        # Return echo of the request
        return bytes([0x05]) + data
    
    def write_single_register(self, data):
        """Process Write Single Register (0x06) request"""
        address = (data[0] << 8) | data[1]
        value = (data[2] << 8) | data[3]
        
        # Validate request
        if address >= len(self.holding_registers):
            return bytes([0x06 | 0x80, 0x02])  # Exception code 0x02 (Illegal Data Address)
        
        # Set register value
        self.holding_registers[address] = value
        
        # Return echo of the request
        return bytes([0x06]) + data
    
    def write_multiple_coils(self, data):
        """Process Write Multiple Coils (0x0F) request"""
        start_address = (data[0] << 8) | data[1]
        quantity = (data[2] << 8) | data[3]
        byte_count = data[4]
        
        # Validate request
        if quantity < 1 or quantity > 1968 or start_address + quantity > len(self.coils):
            return bytes([0x0F | 0x80, 0x02])  # Exception code 0x02 (Illegal Data Address)
        
        # Update coil values
        for i in range(quantity):
            byte_index = i // 8
            bit_index = i % 8
            
            if byte_index < byte_count:
                self.coils[start_address + i] = (data[5 + byte_index] & (1 << bit_index)) != 0
        
        # Prepare response
        response = bytes([0x0F, data[0], data[1], data[2], data[3]])
        
        return response
    
    def write_multiple_registers(self, data):
        """Process Write Multiple Registers (0x10) request"""
        start_address = (data[0] << 8) | data[1]
        quantity = (data[2] << 8) | data[3]
        byte_count = data[4]
        
        # Validate request
        if quantity < 1 or quantity > 123 or start_address + quantity > len(self.holding_registers) or byte_count != quantity * 2:
            return bytes([0x10 | 0x80, 0x02])  # Exception code 0x02 (Illegal Data Address)
        
        # Update register values
        for i in range(quantity):
            self.holding_registers[start_address + i] = (data[5 + i*2] << 8) | data[5 + i*2 + 1]
        
        # Prepare response
        response = bytes([0x10, data[0], data[1], data[2], data[3]])
        
        return response
    
    def read_device_identification(self, data):
        """Process Read Device Identification (0x2B, 0x0E) request"""
        # Simplified MEI response
        mei_type = data[0]  # Should be 0x0E for Device ID
        read_device_id_code = data[1]
        object_id = data[2] if len(data) > 2 else 0
        
        # Only support basic device identification
        if mei_type == 0x0E and read_device_id_code in (0x01, 0x04):
            # Prepare response
            response = bytes([0x2B, 0x0E, read_device_id_code, 0x01])  # Conformity level 0x01
            
            # Device information
            objects = {
                0x00: f"Simulated {self.device_type}".encode(),
                0x01: f"Model {100 + self.device_id}".encode(),
                0x02: f"v1.0.{self.device_id}".encode(),
                0x03: f"Simulated OT Device".encode(),
                0x04: f"http://localhost/device/{self.device_id}".encode(),
                0x05: f"SIM-{self.device_type}-{self.device_id:03d}".encode(),
                0x06: f"Operational Technology Simulation".encode()
            }
            
            # Filter objects based on read_device_id_code
            if read_device_id_code == 0x01:  # Basic
                objects = {k: v for k, v in objects.items() if k <= 0x02}
            elif read_device_id_code == 0x04:  # Individual access
                objects = {k: v for k, v in objects.items() if k == object_id}
            
            # Build response
            response += bytes([len(objects)])  # Object count
            
            # More follows
            response += bytes([0x00])  # Last object
            
            # Add objects
            for obj_id, value in objects.items():
                response += bytes([obj_id, len(value)]) + value
            
            return response
        
        else:
            return bytes([0x2B | 0x80, 0x01])  # Exception code 0x01 (Illegal Function)

def main():
    """Main function to start the Modbus server"""
    # Parse command line arguments
    import argparse
    
    parser = argparse.ArgumentParser(description="Modbus TCP Server Simulation")
    parser.add_argument("-a", "--address", default="0.0.0.0", help="Interface address to bind to")
    parser.add_argument("-p", "--port", type=int, default=502, help="TCP port to bind to")
    parser.add_argument("-d", "--device-id", type=int, default=1, help="Modbus device ID")
    parser.add_argument("-t", "--device-type", default="PLC", 
                        choices=["PLC", "HMI", "RTU", "VFD"], 
                        help="Device type to simulate")
    
    args = parser.parse_args()
    
    # Create and start server
    server = ModbusServer(
        host=args.address,
        port=args.port,
        device_id=args.device_id,
        device_type=args.device_type
    )
    
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()
    except Exception as e:
        logger.error(f"Error starting server: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
EOF

# Make server executable
chmod +x /opt/ot-simulation/modbus_server.py

# Create systemd service files for multiple Modbus devices
cat > /etc/systemd/system/modbus-plc.service << 'EOF'
[Unit]
Description=Modbus PLC Simulation
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/ot-simulation/modbus_server.py -p 502 -d 1 -t PLC
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/modbus-hmi.service << 'EOF'
[Unit]
Description=Modbus HMI Simulation
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/ot-simulation/modbus_server.py -p 503 -d 2 -t HMI
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/modbus-rtu.service << 'EOF'
[Unit]
Description=Modbus RTU Simulation
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/ot-simulation/modbus_server.py -p 504 -d 3 -t RTU
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/modbus-vfd.service << 'EOF'
[Unit]
Description=Modbus VFD Simulation
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/ot-simulation/modbus_server.py -p 505 -d 4 -t VFD
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Create script to check service status
cat > /home/kali/lab_files/check-services.sh << 'EOF'
#!/bin/bash
echo "Checking status of OT services..."

# Enable services
systemctl enable modbus-plc.service
systemctl enable modbus-hmi.service
systemctl enable modbus-rtu.service
systemctl enable modbus-vfd.service

# Start services
systemctl start modbus-plc.service
systemctl start modbus-hmi.service
systemctl start modbus-rtu.service
systemctl start modbus-vfd.service

# Check status
echo "PLC Service:"
systemctl status modbus-plc.service --no-pager

echo "HMI Service:"
systemctl status modbus-hmi.service --no-pager

echo "RTU Service:"
systemctl status modbus-rtu.service --no-pager

echo "VFD Service:"
systemctl status modbus-vfd.service --no-pager

echo "OT services setup complete."
EOF

chmod +x /home/kali/lab_files/check-services.sh

# Configure network forwarding and iptables to redirect ports to different services
cat > /home/kali/lab_files/setup-network.sh << 'EOF'
#!/bin/bash
echo "Setting up network for OT simulation..."

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Create virtual IP addresses for different devices
ip addr add 192.168.100.50/24 dev eth0 label eth0:plc
ip addr add 192.168.100.51/24 dev eth0 label eth0:hmi
ip addr add 192.168.100.52/24 dev eth0 label eth0:rtu
ip addr add 192.168.100.53/24 dev eth0 label eth0:vfd

# Set up port forwarding
iptables -t nat -A PREROUTING -p tcp -d 192.168.100.50 --dport 502 -j REDIRECT --to-port 502
iptables -t nat -A PREROUTING -p tcp -d 192.168.100.51 --dport 502 -j REDIRECT --to-port 503
iptables -t nat -A PREROUTING -p tcp -d 192.168.100.52 --dport 502 -j REDIRECT --to-port 504
iptables -t nat -A PREROUTING -p tcp -d 192.168.100.53 --dport 502 -j REDIRECT --to-port 505

echo "Network setup complete."
EOF

chmod +x /home/kali/lab_files/setup-network.sh

# Run the network setup
/home/kali/lab_files/setup-network.sh

# Start the services
systemctl daemon-reload
systemctl enable modbus-plc.service
systemctl enable modbus-hmi.service
systemctl enable modbus-rtu.service
systemctl enable modbus-vfd.service
systemctl start modbus-plc.service
systemctl start modbus-hmi.service
systemctl start modbus-rtu.service
systemctl start modbus-vfd.service

echo "OT environment setup complete!"
