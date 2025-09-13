#!/usr/bin/env python3
"""
Simple Port Discovery Service

Analyzes PCAP traffic patterns to find the most active ports.
Simple and effective - no complex logic, just traffic analysis.

Author: Fabio Bilotto (Amdocs)
"""

import subprocess
from typing import List, Tuple, Dict
from pathlib import Path
from collections import Counter


class DiameterPortConstants:
    """Simple telecom port mappings for description purposes only."""
    
    PORT_MAPPINGS = {
        3868: "Base Diameter (S6a MME-HSS)",
        3869: "Base Diameter (S6d SGSN-HSS)", 
        3009: "Gx (PCRF-PCEF Policy Control)",
        31012: "Gx (PCRF-PCEF Alternative)",
        3019: "Gy (PCEF-OCS Credit Control)",
        31117: "Gy (PCEF-OCS Alternative)",
        3029: "Rx (AF-PCRF Media Plane)",
        3039: "Sy (PCRF-OCS Spending Limits)",
    }


class DiameterPortDiscovery:
    """
    Simple traffic pattern analysis to find the most active ports.
    No complex logic - just count which ports have the most traffic.
    """
    
    def __init__(self, pcap_filepath: str, sctp: bool = False):
        """Initialize with PCAP file path."""
        self.pcap_filepath = pcap_filepath
        self.sctp = sctp
        self.filename = Path(pcap_filepath).name
        
        if not Path(pcap_filepath).exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_filepath}")
    
    def discover_ports(self) -> Tuple[List[int], float, float]:
        """
        Simple approach: analyze all traffic and find most active ports.
        
        Returns:
            Tuple of (most_active_ports, start_timestamp, end_timestamp)
        """
        print(f"📊 Analyzing traffic patterns in {self.filename}...")
        
        protocol = "sctp" if self.sctp else "tcp"
        
        # Get all traffic with timestamps, src ports, and dst ports
        command = (f'tshark -r "{self.pcap_filepath}" -T fields '
                  f'-e frame.time_epoch -e {protocol}.srcport -e {protocol}.dstport')
        
        try:
            output = subprocess.check_output(command, shell=True, 
                                          stderr=subprocess.STDOUT).decode()
            
            if not output.strip():
                print("❌ No TCP/SCTP traffic found in PCAP")
                return [], 0.0, 0.0
                
            # Parse the output
            port_counter = Counter()
            timestamps = []
            
            for line in output.strip().split('\n'):
                if not line.strip():
                    continue
                    
                parts = line.split('\t')
                if len(parts) >= 3:
                    try:
                        timestamp = float(parts[0])
                        src_port = parts[1]
                        dst_port = parts[2]
                        
                        timestamps.append(timestamp)
                        
                        # Count both src and dst ports
                        if src_port and src_port.isdigit():
                            port_counter[int(src_port)] += 1
                        if dst_port and dst_port.isdigit():
                            port_counter[int(dst_port)] += 1
                            
                    except ValueError:
                        continue
            
            if not port_counter:
                print("❌ No valid ports found in traffic")
                return [], 0.0, 0.0
            
            # Get the most active ports (top 5)
            most_active = [port for port, count in port_counter.most_common(5)]
            
            # Get time range
            start_time = min(timestamps) if timestamps else 0.0
            end_time = max(timestamps) if timestamps else 0.0
            
            print(f"✅ Most active ports: {most_active}")
            for port in most_active[:3]:  # Show top 3
                count = port_counter[port]
                print(f"   📡 Port {port}: {count} packets")
            
            return most_active, start_time, end_time
            
        except subprocess.CalledProcessError as e:
            print(f"⚠️  Error analyzing traffic: {e}")
            return [], 0.0, 0.0
    
    def get_port_descriptions(self, ports: List[int]) -> Dict[int, str]:
        """Get descriptions for ports."""
        descriptions = {}
        for port in ports:
            if port in DiameterPortConstants.PORT_MAPPINGS:
                descriptions[port] = DiameterPortConstants.PORT_MAPPINGS[port]
            else:
                descriptions[port] = f"Port {port} (Most Active)"
        return descriptions
