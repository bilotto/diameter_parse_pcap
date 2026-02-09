import subprocess
import re
from typing import List, Optional, Tuple
from .port_discovery import DiameterPortDiscovery


def auto_discover_ports(pcap_filepath: str, sctp: bool = False, filename: str = None) -> Tuple[List[int], Optional[float], Optional[float]]:
    """
    Auto-discover ports from PCAP file using traffic pattern analysis.
    
    Args:
        pcap_filepath: Path to the PCAP file
        sctp: Whether to use SCTP protocol (default: False for TCP)
        filename: Optional filename for display purposes
        
    Returns:
        Tuple of (discovered_ports, start_timestamp, end_timestamp)
        Returns empty list and None timestamps if discovery fails
    """
    if filename is None:
        import os
        filename = os.path.basename(pcap_filepath)
    
    print(f"🤖 No ports specified for {filename}, analyzing traffic patterns...")
    try:
        discovery_service = DiameterPortDiscovery(pcap_filepath, sctp)
        discovered_ports, start_time, end_time = discovery_service.discover_ports()
        
        if discovered_ports:
            # Set timestamps from discovery
            if start_time and end_time:
                duration = end_time - start_time
                print(f"⏱️  PCAP duration: {duration:.1f} seconds")
            
            # Show discovered ports with descriptions
            descriptions = discovery_service.get_port_descriptions(discovered_ports)
            for port, desc in descriptions.items():
                print(f"   📡 Port {port}: {desc}")
            
            return discovered_ports, start_time, end_time
        else:
            print("❌ No active ports found in PCAP")
            return [], None, None
            
    except Exception as e:
        print(f"⚠️  Traffic analysis failed: {e}")
        return [], None, None


def get_timestamps_and_packet_count(pcap) -> None:
    """
    Extract timestamps and count diameter packets (not messages) from PCAP.
    Updates the pcap object's start_timestamp, end_timestamp, n_diameter_packets, and cut_short attributes.
    
    NOTE: This counts PACKETS containing diameter data, not individual diameter messages.
    Some packets may contain multiple diameter messages (duplicate_layers), so the actual
    message count during processing may be higher than n_diameter_packets.
    
    Args:
        pcap: Pcap object with filepath, ports, filter, sctp attributes
    """
    command = f"tshark -r {pcap.filepath} {pcap.get_ports()} -Y \"{pcap.filter}\" -T fields -e frame.time_epoch"
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT).decode().strip().split('\n')
        if not output:
            return
    except subprocess.CalledProcessError as e:
        error_output = e.output.decode() if isinstance(e.output, bytes) else str(e.output)
        if "appears to have been cut short" in error_output:
            print(f"File {pcap.filepath} appears to have been cut short. Skipping...")
            pcap.cut_short = True
            output = error_output.strip().split('\n')
        else:
            # print(f"Error getting timestamps from {pcap.filepath}: {e}")
            # Don't try to process output if tshark failed - return early
            return
    
    if not output:
        # print(f"No valid timestamps found in {pcap.filepath}")
        return
    
    pkt_timestamps = []
    for i in output:
        if re.match(r'^\d+\.\d+$', i):
            pkt_timestamps.append(float(i))
    
    if not pkt_timestamps:
        # print(f"No valid timestamps found in {pcap.filepath}")
        return

    # Set the values directly on the pcap object
    pcap.start_timestamp = pkt_timestamps[0]
    pcap.end_timestamp = pkt_timestamps[-1]
    pcap.n_diameter_packets = len(pkt_timestamps)


def get_md5sum(pcap_filepath: str) -> str:
    command = f"md5sum {pcap_filepath}"
    output = subprocess.check_output(command, shell=True).decode().strip()
    md5sum = output.split()[0]
    return md5sum
