#!/usr/bin/env python3
"""
Modbus Process Analyzer
Repeatedly reads process values from a Modbus device and analyzes patterns
to determine what industrial process it likely controls
"""

import sys
import time
import statistics
from pymodbus.client.sync import ModbusTcpClient
from pymodbus.exceptions import ModbusException

def analyze_process_values(ip_address, samples=20, delay=1):
    """Read process values from a Modbus device and analyze patterns"""
    print(f"Analyzing process values from Modbus device at {ip_address}...")
    print(f"Collecting {samples} samples with {delay} second delay...")
    
    client = ModbusTcpClient(ip_address, port=502)
    
    try:
        client.connect()
        
        # Arrays to store collected data
        holding_registers = []
        input_registers = []
        discrete_inputs = []
        coils = []
        
        # Collect data samples
        for i in range(samples):
            sys.stdout.write(f"\rCollecting sample {i+1}/{samples}...")
            sys.stdout.flush()
            
            # Read holding registers (function code 3)
            try:
                response = client.read_holding_registers(0, 20, unit=1)
                if not response.isError():
                    holding_registers.append(response.registers)
            except Exception:
                pass
            
            # Read input registers (function code 4)
            try:
                response = client.read_input_registers(0, 20, unit=1)
                if not response.isError():
                    input_registers.append(response.registers)
            except Exception:
                pass
            
            # Read discrete inputs (function code 2)
            try:
                response = client.read_discrete_inputs(0, 20, unit=1)
                if not response.isError():
                    discrete_inputs.append(response.bits)
            except Exception:
                pass
            
            # Read coils (function code 1)
            try:
                response = client.read_coils(0, 20, unit=1)
                if not response.isError():
                    coils.append(response.bits)
            except Exception:
                pass
            
            time.sleep(delay)
        
        print("\nAnalysis complete!")
        
        # Analyze collected data
        print("\n===== PROCESS ANALYSIS =====")
        
        # Analyze holding registers (usually process setpoints)
        if holding_registers:
            print("\nHolding Registers Analysis (Process Setpoints):")
            analyze_register_patterns(holding_registers)
        
        # Analyze input registers (usually process values)
        if input_registers:
            print("\nInput Registers Analysis (Process Values):")
            analyze_register_patterns(input_registers)
        
        # Analyze discrete inputs (usually digital sensor inputs)
        if discrete_inputs:
            print("\nDiscrete Inputs Analysis (Digital Sensors):")
            analyze_boolean_patterns(discrete_inputs)
        
        # Analyze coils (usually digital outputs/controls)
        if coils:
            print("\nCoils Analysis (Digital Outputs/Controls):")
            analyze_boolean_patterns(coils)
        
        # Infer process type based on patterns
        print("\n===== PROCESS TYPE INFERENCE =====")
        infer_process_type(holding_registers, input_registers, discrete_inputs, coils)
        
    except ModbusException as e:
        print(f"Modbus error: {e}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        client.close()

def analyze_register_patterns(register_samples):
    """Analyze patterns in register values"""
    if not register_samples:
        return
    
    # Transpose data for per-register analysis
    registers_by_address = list(zip(*register_samples))
    
    for addr, values in enumerate(registers_by_address):
        if not values:
            continue
        
        # Check if values are changing
        if len(set(values)) == 1:
            print(f"  Register {addr}: Static value {values[0]} (configured parameter or unused)")
            continue
        
        # Calculate statistics
        min_val = min(values)
        max_val = max(values)
        avg_val = sum(values) / len(values)
        
        # Identify patterns
        increasing = all(values[i] <= values[i+1] for i in range(len(values)-1))
        decreasing = all(values[i] >= values[i+1] for i in range(len(values)-1))
        fluctuating = not increasing and not decreasing
        
        # Analyze value range
        range_pct = ((max_val - min_val) / max(max_val, 1)) * 100
        
        print(f"  Register {addr}: Values range from {min_val} to {max_val} (avg: {avg_val:.2f})")
        
        # Describe the pattern
        if increasing:
            print(f"    Pattern: Steadily increasing (ramp up)")
        elif decreasing:
            print(f"    Pattern: Steadily decreasing (ramp down)")
        elif range_pct < 5:
            print(f"    Pattern: Small fluctuations (around setpoint)")
        elif range_pct > 50:
            print(f"    Pattern: Large swings (on/off cycling)")
        else:
            print(f"    Pattern: Normal process variations")
        
        # Typical value ranges for various process types
        if 0 <= min_val <= max_val <= 100:
            print(f"    Likely represents: Percentage value (valve position, motor speed)")
        elif 15 <= min_val <= 30 and 15 <= max_val <= 30:
            print(f"    Likely represents: Ambient temperature (Celsius)")
        elif 100 <= min_val <= 200 and 100 <= max_val <= 200:
            print(f"    Likely represents: Process temperature (Celsius)")
        elif 1000 <= min_val <= 2000 and 1000 <= max_val <= 2000:
            print(f"    Likely represents: Pressure (PSI or kPa)")
        elif 0 <= min_val <= 10 and 0 <= max_val <= 10:
            print(f"    Likely represents: Flow rate or level")

def analyze_boolean_patterns(boolean_samples):
    """Analyze patterns in boolean values"""
    if not boolean_samples:
        return
    
    # Transpose data for per-bit analysis
    bits_by_address = list(zip(*boolean_samples))
    
    for addr, values in enumerate(bits_by_address):
        if not values:
            continue
        
        # Check if values are changing
        if len(set(values)) == 1:
            status = "ON" if values[0] else "OFF"
            print(f"  Bit {addr}: Static {status} (configured parameter or unused)")
            continue
        
        # Count transitions
        transitions = sum(1 for i in range(len(values)-1) if values[i] != values[i+1])
        
        # Calculate percentage of time ON
        pct_on = (sum(1 for v in values if v) / len(values)) * 100
        
        print(f"  Bit {addr}: ON {pct_on:.1f}% of the time, {transitions} transitions")
        
        # Describe the pattern
        if transitions == 1:
            print(f"    Pattern: Single state change")
        elif transitions > len(values) * 0.4:
            print(f"    Pattern: Rapidly cycling (sensor feedback or alarm)")
        elif pct_on > 90:
            print(f"    Pattern: Mostly ON with occasional OFF")
        elif pct_on < 10:
            print(f"    Pattern: Mostly OFF with occasional ON")
        else:
            print(f"    Pattern: Normal ON/OFF cycling")

def infer_process_type(holding_registers, input_registers, discrete_inputs, coils):
    """Infer the type of industrial process based on observed patterns"""
    process_indicators = {
        "temperature_control": 0,
        "motor_control": 0,
        "valve_control": 0,
        "level_control": 0,
        "pressure_control": 0,
        "flow_control": 0,
        "safety_system": 0
    }
    
    # Check for temperature control indicators
    if holding_registers and input_registers:
        # Simplistic detection: look for values between 15-250 in registers
        for samples in [holding_registers, input_registers]:
            for sample in samples:
                for value in sample:
                    if 15 <= value <= 30:  # Ambient temperature range
                        process_indicators["temperature_control"] += 1
                    elif 100 <= value <= 250:  # Process temperature range
                        process_indicators["temperature_control"] += 2
    
    # Check for motor control indicators
    if holding_registers and input_registers:
        # Motors often use percentage values for speed
        for samples in [holding_registers, input_registers]:
            for sample in samples:
                if any(0 <= value <= 100 for value in sample):
                    process_indicators["motor_control"] += 1
    
    # Check for valve control indicators
    if coils:
        # Valves often use coils for open/close control
        process_indicators["valve_control"] += len(coils[0]) // 2
    
    # Check for level control indicators
    if input_registers:
        # Level sensors often provide values in a fixed range
        for sample in input_registers:
            if any(0 <= value <= 100 for value in sample):
                process_indicators["level_control"] += 1
    
    # Check for pressure control indicators
    if input_registers:
        # Pressure values are often in the hundreds or thousands
        for sample in input_registers:
            if any(100 <= value <= 5000 for value in sample):
                process_indicators["pressure_control"] += 1
    
    # Check for flow control indicators
    if input_registers:
        # Flow values often change more rapidly than other measurements
        registers_by_address = list(zip(*input_registers))
        for values in registers_by_address:
            if len(set(values)) > len(values) // 2:
                process_indicators["flow_control"] += 1
    
    # Check for safety system indicators
    if discrete_inputs and coils:
        # Safety systems often have many discrete I/O points
        if len(discrete_inputs[0]) > 10 or len(coils[0]) > 10:
            process_indicators["safety_system"] += 1
    
    # Find the most likely process types
    sorted_indicators = sorted(process_indicators.items(), key=lambda x: x[1], reverse=True)
    
    print("Based on the observed data patterns, this device likely controls:")
    
    if sorted_indicators[0][1] == 0:
        print("  Unable to determine process type from available data")
        return
    
    # Print top process types
    for process, score in sorted_indicators:
        if score > 0 and score >= sorted_indicators[0][1] / 2:
            if process == "temperature_control":
                print("  A TEMPERATURE CONTROL process (heating/cooling system)")
                print("  - This could be a furnace, oven, refrigeration, or HVAC system")
                print("  - Critical for maintaining process conditions and product quality")
            
            elif process == "motor_control":
                print("  A MOTOR CONTROL process (conveyor, pump, fan)")
                print("  - This could be controlling conveyors, mixers, or material handling")
                print("  - Critical for material movement and processing")
            
            elif process == "valve_control":
                print("  A VALVE CONTROL process (fluid flow regulation)")
                print("  - This could be controlling product flow, mixing, or batching")
                print("  - Critical for process recipe compliance and quality control")
            
            elif process == "level_control":
                print("  A LEVEL CONTROL process (tank, hopper)")
                print("  - This could be monitoring storage levels or feeding material")
                print("  - Critical for preventing overflow/underflow conditions")
            
            elif process == "pressure_control":
                print("  A PRESSURE CONTROL process (vessel, pipeline)")
                print("  - This could be regulating pressure in vessels or distribution systems")
                print("  - Critical for process safety and product quality")
            
            elif process == "flow_control":
                print("  A FLOW CONTROL process (pipeline, distribution)")
                print("  - This could be managing fluid or gas flow rates")
                print("  - Critical for process timing and throughput")
            
            elif process == "safety_system":
                print("  A SAFETY SYSTEM (emergency shutdown, permissive)")
                print("  - This appears to be monitoring safety conditions")
                print("  - Critical for personnel and equipment protection")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 modbus_process_analyzer.py <ip_address>")
        sys.exit(1)
        
    ip_address = sys.argv[1]
    analyze_process_values(ip_address)
