import os
import subprocess
import re
from typing import List, Optional, Dict, Any, Pattern
from datetime import datetime
from .pcap import Pcap
from .diameter_messages import DiameterMessages
from .functions import get_diameter_messages_from_pkt
import pyshark


class PcapGroup:
    """
    A class to manage a group of PCAP files in a directory with regex name filtering.
    
    This class provides functionality to:
    - Find PCAP files in a directory using regex patterns
    - Sort PCAPs by timestamp
    - Process multiple PCAPs with consistent configuration
    - Extract and manage diameter messages from all PCAPs
    """
    
    def __init__(self, 
                 directory: str,
                 name_pattern: Optional[str] = None,
                 ports: List[int] = None,
                 filter_str: str = "diameter",
                 sctp: bool = False,
                 recursive: bool = True):
        """
        Initialize a PcapGroup.
        
        Args:
            directory: Directory path to search for PCAP files
            name_pattern: Regex pattern to match PCAP filenames (optional)
            ports: List of ports to decode as diameter (default: [31012, 31117])
            filter_str: Wireshark filter string (default: "diameter")
            sctp: Whether to use SCTP decoding (default: False)
            recursive: Whether to search recursively in subdirectories (default: True)
        """
        self.directory = directory
        self.name_pattern = name_pattern
        self.ports = ports or [31012, 31117]
        self.filter_str = filter_str
        self.sctp = sctp
        self.recursive = recursive
        
        self._pcaps: List[Pcap] = []
        self._compiled_pattern: Optional[Pattern] = None
        self._diameter_messages = DiameterMessages()
        
        # Compile regex pattern if provided
        if self.name_pattern:
            try:
                self._compiled_pattern = re.compile(self.name_pattern)
            except re.error as e:
                raise ValueError(f"Invalid regex pattern '{self.name_pattern}': {e}")
    
    def find_pcap_files(self) -> List[str]:
        """
        Find PCAP files in the directory matching the name pattern.
        
        Returns:
            List of file paths to PCAP files
        """
        if not os.path.exists(self.directory):
            raise FileNotFoundError(f"Directory not found: {self.directory}")
        
        # Build find command
        if self.recursive:
            command = f"find {self.directory} -type f -name '*.pcap*'"
        else:
            command = f"find {self.directory} -maxdepth 1 -type f -name '*.pcap*'"
        
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"Warning: find command failed: {result.stderr}")
                return []
            
            output = result.stdout.strip().split('\n')
            pcap_files = [f for f in output if f.strip()]
            
            # Filter by regex pattern if provided
            if self._compiled_pattern:
                pcap_files = [f for f in pcap_files if self._compiled_pattern.search(os.path.basename(f))]
            
            return pcap_files
            
        except Exception as e:
            print(f"Error finding PCAP files: {e}")
            return []
    
    def load_pcaps(self) -> None:
        """
        Load and initialize all PCAP objects from the directory.
        """
        pcap_files = self.find_pcap_files()
        print(f"Found {len(pcap_files)} PCAP files in {self.directory}")
        
        self._pcaps = []
        for filepath in pcap_files:
            try:
                pcap_obj = Pcap(
                    filepath=filepath,
                    ports=self.ports,
                    filter=self.filter_str,
                    sctp=self.sctp
                )
                pcap_obj.get_timestamps()
                self._pcaps.append(pcap_obj)
                print(f"Loaded: {pcap_obj.filename} ({pcap_obj.n_diameter_messages} messages)")
            except Exception as e:
                print(f"Error loading {filepath}: {e}")
                continue
        
        # Sort by start timestamp
        self._pcaps = sorted(self._pcaps, key=lambda x: x.start_timestamp or 0)
        print(f"Successfully loaded {len(self._pcaps)} PCAP files")
    
    def process_all_pcaps(self, session_manager=None) -> DiameterMessages:
        """
        Process all loaded PCAPs and extract diameter messages.
        
        Args:
            session_manager: Optional SessionManager to process messages
            
        Returns:
            DiameterMessages object containing all extracted messages
        """
        if not self._pcaps:
            print("No PCAPs loaded. Call load_pcaps() first.")
            return self._diameter_messages
        
        print(f"Processing {len(self._pcaps)} PCAP files...")
        
        for pcap in self._pcaps:
            print(f"Processing: {pcap.filename}")
            try:
                pyshark_obj = pyshark.FileCapture(
                    pcap.filepath,
                    decode_as=pcap.decode_as,
                    display_filter=pcap.filter,
                    include_raw=True,
                    use_json=True,
                    debug=False
                )
                
                for pkt in pyshark_obj:
                    diameter_messages = get_diameter_messages_from_pkt(pkt)
                    for dm in diameter_messages:
                        dm.pcap_filepath = pcap.filepath
                        self._diameter_messages.add_message(dm)
                        
                        # Process with session manager if provided
                        if session_manager:
                            session_manager.process_diameter_message(dm)
                            
            except Exception as e:
                print(f"Error processing {pcap.filename}: {e}")
                continue
        
        print(f"Extracted {len(self._diameter_messages.messages)} diameter messages total")
        return self._diameter_messages
    
    def get_pcaps_by_time_range(self, start_time: datetime, end_time: datetime) -> List[Pcap]:
        """
        Get PCAPs that overlap with the specified time range.
        
        Args:
            start_time: Start of time range
            end_time: End of time range
            
        Returns:
            List of PCAPs that overlap with the time range
        """
        start_timestamp = start_time.timestamp()
        end_timestamp = end_time.timestamp()
        
        overlapping_pcaps = []
        for pcap in self._pcaps:
            if (pcap.start_timestamp and pcap.end_timestamp and
                not (pcap.end_timestamp < start_timestamp or pcap.start_timestamp > end_timestamp)):
                overlapping_pcaps.append(pcap)
        
        return overlapping_pcaps
    
    def get_pcaps_by_name_pattern(self, pattern: str) -> List[Pcap]:
        """
        Get PCAPs whose filenames match the given regex pattern.
        
        Args:
            pattern: Regex pattern to match against filenames
            
        Returns:
            List of matching PCAPs
        """
        try:
            compiled_pattern = re.compile(pattern)
        except re.error as e:
            raise ValueError(f"Invalid regex pattern '{pattern}': {e}")
        
        matching_pcaps = []
        for pcap in self._pcaps:
            if compiled_pattern.search(pcap.filename):
                matching_pcaps.append(pcap)
        
        return matching_pcaps
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get a summary of the PCAP group.
        
        Returns:
            Dictionary containing summary information
        """
        if not self._pcaps:
            return {
                "directory": self.directory,
                "name_pattern": self.name_pattern,
                "total_pcaps": 0,
                "total_messages": 0,
                "time_range": None
            }
        
        total_messages = sum(pcap.n_diameter_messages for pcap in self._pcaps)
        
        # Calculate time range
        start_times = [pcap.start_timestamp for pcap in self._pcaps if pcap.start_timestamp]
        end_times = [pcap.end_timestamp for pcap in self._pcaps if pcap.end_timestamp]
        
        time_range = None
        if start_times and end_times:
            earliest_start = min(start_times)
            latest_end = max(end_times)
            time_range = {
                "start": datetime.fromtimestamp(earliest_start).isoformat(),
                "end": datetime.fromtimestamp(latest_end).isoformat(),
                "duration_seconds": latest_end - earliest_start
            }
        
        return {
            "directory": self.directory,
            "name_pattern": self.name_pattern,
            "total_pcaps": len(self._pcaps),
            "total_messages": total_messages,
            "time_range": time_range,
            "ports": self.ports,
            "filter": self.filter_str
        }
    
    @property
    def pcaps(self) -> List[Pcap]:
        """Get the list of loaded PCAP objects."""
        return self._pcaps.copy()
    
    @property
    def diameter_messages(self) -> DiameterMessages:
        """Get the DiameterMessages object containing all extracted messages."""
        return self._diameter_messages
    
    def __len__(self) -> int:
        """Return the number of loaded PCAPs."""
        return len(self._pcaps)
    
    def __repr__(self) -> str:
        """String representation of the PcapGroup."""
        return (f"PcapGroup(directory='{self.directory}', "
                f"pattern='{self.name_pattern}', "
                f"pcaps={len(self._pcaps)}, "
                f"messages={len(self._diameter_messages.messages)})")
    
    def __iter__(self):
        """Allow iteration over PCAP objects."""
        return iter(self._pcaps)
