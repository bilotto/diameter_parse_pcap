import os
import subprocess
from datetime import datetime
from typing import List, Optional, Tuple, Set, Dict
from dataclasses import dataclass, field
# from .diameter_message import DiameterMessagePcap
# from diameter.message import Message
import json

# Import the focused port discovery service
# from .port_discovery import DiameterPortConstants
from .pcap_operations import get_timestamps_and_packet_count, get_md5sum

from diameter_telecom.message import DiameterMessage

@dataclass
class Pcap:
    filepath: str
    ports: List[int] = field(default_factory=list)
    sctp: bool = False
    filter: str = 'diameter'
    start_timestamp: Optional[float] = field(default=None, repr=True)
    end_timestamp: Optional[float] = field(default=None, repr=True)
    n_diameter_packets: int = 0  # NOTE: This is the count of PACKETS, not individual diameter messages
    n_diameter_messages: int = 0
    pid_file: Optional[str] = field(default=None, repr=False)
    cut_short: bool = field(default=False, repr=False)
    _auto_discovered_ports: Optional[List[int]] = field(default=None, init=False, repr=False)
    _pyshark_obj: Optional[object] = field(default=None, init=False, repr=False)
    diameter_packets: Dict[Tuple[float, int], List[DiameterMessage]] = field(default_factory=dict)
    md5sum: Optional[str] = field(default=None, repr=True)
    mtime: Optional[str] = field(default=None, repr=True)

    def __setattr__(self, name, value):
        # Remove automatic date setting since start_date and end_date are now read-only properties
        super().__setattr__(name, value)
    
    def __post_init__(self):
        """
        Post-initialization processing - validates file exists.
        """
        # Validate file exists
        if not os.path.exists(self.filepath):
            raise FileNotFoundError(f"PCAP file not found: {self.filepath}")
                
    @property
    def is_ports_auto_discovered(self) -> bool:
        """Check if ports were automatically discovered vs. manually specified."""
        return self._auto_discovered_ports is not None

    # @property
    # def pyshark_obj(self):
    #     if self._pyshark_obj is None:
    #         self._pyshark_obj = create_pyshark_object(self)
    #     return self._pyshark_obj

    def __eq__(self, value):
        if isinstance(value, Pcap):
            return self.filepath == value.filepath
        elif isinstance(value, str):
            return self.filepath == value
        return False
    
    def __hash__(self):
        return hash(self.filepath)
    
    def to_dict(self):
        pcap_dict = dict()
        pcap_dict['filepath'] = self.filepath
        if self.ports:
            pcap_dict['ports'] = self.ports
        if self.start_timestamp:
            pcap_dict['start_timestamp'] = self.start_timestamp
        if self.end_timestamp:
            pcap_dict['end_timestamp'] = self.end_timestamp
        if self.n_diameter_packets is not None:
            pcap_dict['n_diameter_packets'] = self.n_diameter_packets
        if self.cut_short:
            pcap_dict['cut_short'] = self.cut_short
        if self.filter:
            pcap_dict['filter'] = self.filter
        if self.md5sum:
            pcap_dict['md5sum'] = self.md5sum
        if self.mtime:
            pcap_dict['mtime'] = self.mtime
        return pcap_dict

    @property
    def filename(self):
        return os.path.basename(self.filepath)
    
    @property
    def filename_no_extension(self):
        return os.path.splitext(self.filename)[0]
    
    @property
    def dirname(self):
        return os.path.dirname(self.filepath)
    
    @property
    def start_date(self) -> Optional[datetime]:
        """Get start date computed from start_timestamp."""
        if self.start_timestamp:
            return datetime.fromtimestamp(float(self.start_timestamp))
        return None
    
    @property
    def end_date(self) -> Optional[datetime]:
        """Get end date computed from end_timestamp."""
        if self.end_timestamp:
            return datetime.fromtimestamp(float(self.end_timestamp))
        return None

    @property
    def decode_as(self):
        decode_as = {}
        for port in self.ports:
            if not self.sctp:
                decode_as[f"tcp.port=={port}"] = 'diameter'
            else:
                decode_as[f"sctp.port=={port}"] = 'diameter'
        return decode_as
    
    def get_ports(self):
        command = ""
        for port in self.ports:
            if not self.sctp:
                command += f"-d tcp.port=={port},diameter "
            else:
                command += f"-d sctp.port=={port},diameter "
        return command
    
    def get_port_fields(self):
        """
        Get the correct tshark field names for port extraction.
        Returns protocol-specific port field names.
        """
        if not self.sctp:
            return "tcp.srcport,tcp.dstport"
        else:
            return "sctp.srcport,sctp.dstport"
    
    def get_port_filter_fields(self):
        """
        Get port field names for filtering (matches both src and dst).
        """
        if not self.sctp:
            return "tcp.port"
        else:
            return "sctp.port"

    def dump_packets(self, filter, output_file):
        command = f"tshark -r {self.filepath} {self.get_ports()} -Y \"{filter}\" -w {output_file}"
        subprocess.run(command, shell=True)

    def tcpdump_command(self, interface="any"):
        return f"sudo tcpdump -i {interface} port {','.join(map(str, self.ports))} -w {self.filepath} &"

    def get_timestamps(self):
        """
        Extract timestamps and count diameter packets (not messages).
        
        NOTE: This counts PACKETS containing diameter data, not individual diameter messages.
        Some packets may contain multiple diameter messages (duplicate_layers), so the actual
        message count during processing may be higher than n_diameter_packets.
        """
        get_timestamps_and_packet_count(self)
    
    # def get_timestamps_with_ports(self):
    #     """
    #     Extract timestamps along with source and destination ports from PCAP.
    #     Returns list of tuples: (timestamp, src_port, dst_port)
        
    #     This method uses the correct tshark field names for port extraction.
    #     """
    #     print(f"Getting timestamps and ports from {self.filepath} with filter '{self.filter}'")
    #     port_fields = self.get_port_fields()
    #     command = f"tshark -r {self.filepath} {self.get_ports()} -Y \"{self.filter}\" -T fields -e frame.time_epoch -e {port_fields.replace(',', ' -e ')}"
        
    #     try:
    #         output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT).decode().strip().split('\n')
    #         if not output:
    #             return []
    #     except subprocess.CalledProcessError as e:
    #         if "appears to have been cut short" in e.output.decode():
    #             print(f"File {self.filepath} appears to have been cut short. Attempting to process partial data...")
    #             output = e.output.decode().strip().split('\n')
    #         else:
    #             print(f"Error getting timestamps and ports from {self.filepath}: {e}")
    #             return []
                
    #     results = []
    #     for line in output:
    #         if line.strip():
    #             parts = line.split('\t')
    #             if len(parts) >= 3:
    #                 try:
    #                     timestamp = float(parts[0])
    #                     src_port = int(parts[1]) if parts[1] else None
    #                     dst_port = int(parts[2]) if parts[2] else None
    #                     results.append((timestamp, src_port, dst_port))
    #                 except (ValueError, IndexError):
    #                     continue
        
    #     return results
    
    def to_json(self) -> dict:
        """Convert Pcap object to JSON-serializable dictionary."""
        return {
            'filepath': self.filepath,
            'start_timestamp': self.start_timestamp,
            'end_timestamp': self.end_timestamp,
            'n_diameter_packets': self.n_diameter_packets,
            'ports': self.ports,
            'mtime': self.mtime,
            'md5sum': self.md5sum,
        }

    def get_md5sum(self):
        self.md5sum = get_md5sum(self.filepath)

    def add_diameter_message(self, frame_number: int, diameter_message: DiameterMessage):
        frame_number = int(frame_number)
        if not self.diameter_packets.get(frame_number):
            self.diameter_packets[frame_number] = []
        self.diameter_packets[frame_number].append(diameter_message)
        self.n_diameter_messages += 1

    # def get_diameter_messages_from_pkt(self, pkt) -> List[DiameterMessagePcap]:
    #     pkt_diameter_messages = []
    #     if isinstance(pkt.diameter_raw.value, list):
    #         payload_hex = pkt.diameter_raw.value[0]
    #     else:
    #         payload_hex = pkt.diameter_raw.value
    #     diameter_message = DiameterMessagePcap(payload_hex)
    #     diameter_message.timestamp = pkt.frame_info.time_epoch
    #     diameter_message.pkt_number = pkt.number
    #     pkt_diameter_messages.append(diameter_message)
    #     if pkt.diameter_raw.duplicate_layers:
    #         for i in pkt.diameter_raw.duplicate_layers:
    #             payload_hex = i.value
    #             if isinstance(payload_hex, list):
    #                 print("payload_hex is list")
    #             if not isinstance(payload_hex, str):
    #                 continue
    #             diameter_bytes = bytes.fromhex(i.value)
    #             diameter_message = DiameterMessagePcap(Message.from_bytes(diameter_bytes))
    #             diameter_message.timestamp = pkt.frame_info.time_epoch
    #             diameter_message.pkt_number = pkt.number
    #             pkt_diameter_messages.append(diameter_message)

    #     return pkt_diameter_messages

    # def get_diameter_messages_from_pcap(self) -> List[DiameterMessagePcap]:
    #     pcap_diameter_messages = []
    #     try:
    #         for pkt in self.pyshark_obj:
    #             pkt_timestamp = pkt.frame_info.time_epoch
    #             pkt_number = pkt.number
    #             pkt_diameter_messages = self.get_diameter_messages_from_pkt(pkt)
    #             if not pkt_diameter_messages:
    #                 print(f"No Diameter messages found in packet {pkt_number}")
    #             for diameter_message in pkt_diameter_messages:
    #                 if not isinstance(diameter_message, DiameterMessagePcap):
    #                     continue
    #                 diameter_message.pcap_filepath = self.filepath
    #                 pcap_diameter_messages.append(diameter_message)
    #     except pyshark.capture.capture.TSharkCrashException as e:
    #         if "appears to have been cut short" in str(e):
    #             print(f"File {self.filepath} appears to have been cut short. Processing available packets...")
    #             self.cut_short = True
    #         else:
    #             raise e

    #     return pcap_diameter_messages

# import pyshark

# def create_pyshark_object(pcap_file: Pcap):
#     return pyshark.FileCapture(pcap_file.filepath, decode_as=pcap_file.decode_as, display_filter=pcap_file.filter, include_raw=True, use_json=True, debug=False)


