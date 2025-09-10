import os
import re
import glob
from typing import List, Optional, Dict, Any, Pattern, Callable
from datetime import datetime
from dataclasses import dataclass, field
from .pcap import Pcap
from .functions import get_diameter_messages_from_pkt
import pyshark
from diameter_telecom.diameter.session_manager import SessionManager


@dataclass
class PcapGroup:
    """
    A class to manage a group of PCAP files in a directory with regex name filtering.
    
    This class provides functionality to:
    - Find PCAP files in a directory using regex patterns
    - Sort PCAPs by timestamp
    - Process multiple PCAPs with consistent configuration
    - Extract and manage diameter messages from all PCAPs
    """
    directory: str
    name_pattern: str
    ports: List[int] = field(default_factory=lambda: [31012, 31117])
    filter_str: str = "diameter"
    sctp: bool = False
    recursive: bool = False
    _pcaps: List[Pcap] = field(default_factory=list, init=False, repr=False)
    _processed_messages: List[Any] = field(default_factory=list, init=False, repr=False)
    _session_manager: SessionManager = field(default_factory=SessionManager, init=False, repr=False)
    
    def __post_init__(self):
        """Validate the regex pattern and find PCAP files after dataclass initialization."""
        try:
            re.compile(self.name_pattern)
        except re.error as e:
            raise ValueError(f"Invalid regex pattern '{self.name_pattern}': {e}")
        
        # Automatically find PCAP files on instantiation
        self._find_and_load_pcaps()

    def set_session_manager(self, session_manager: SessionManager):
        self._session_manager = session_manager
    
    def find_pcap_files(self) -> List[str]:
        """
        Find PCAP files in the directory matching the name pattern using Python methods.
        
        Returns:
            List of file paths to PCAP files
        """
        if not os.path.exists(self.directory):
            raise FileNotFoundError(f"Directory not found: {self.directory}")
        
        # Use glob to find PCAP files
        if self.recursive:
            # Recursive search
            search_pattern = os.path.join(self.directory, "**", "*.pcap*")
            pcap_files = glob.glob(search_pattern, recursive=True)
        else:
            # Non-recursive search
            search_pattern = os.path.join(self.directory, "*.pcap*")
            pcap_files = glob.glob(search_pattern)

        print(pcap_files)
        
        # Filter by regex pattern
        matching_files = []
        compiled_pattern = re.compile(self.name_pattern)
        for filepath in pcap_files:
            filename = os.path.basename(filepath)
            if compiled_pattern.search(filename):
                matching_files.append(filepath)
        
        return matching_files
    
    def _find_and_load_pcaps(self) -> None:
        """
        Internal method to find and load PCAP files automatically.
        This is called during __post_init__.
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
                if pcap_obj.n_diameter_messages == 0:
                    continue
                self._pcaps.append(pcap_obj)
                print(f"Loaded: {pcap_obj.filename} ({pcap_obj.n_diameter_messages} messages)")
            except Exception as e:
                print(f"Error loading {filepath}: {e}")
                continue
        
        # Sort by start timestamp
        self._pcaps = sorted(self._pcaps, key=lambda x: x.start_timestamp or 0)
        print(f"Successfully loaded {len(self._pcaps)} PCAP files")
    
    def load_pcaps(self) -> None:
        """
        Reload PCAP objects from the directory.
        This method can be called to refresh the PCAP list.
        """
        self._find_and_load_pcaps()
    
    def process_single_pcap(self, pcap: Pcap, message_handler: Optional[Callable] = None) -> List[Any]:
        """
        Process a single PCAP file and extract diameter messages.
        
        Args:
            pcap: Pcap object to process
            message_handler: Optional callable to handle each diameter message.
                           Should accept a diameter message as argument.
                           If None, messages are stored in internal list.
            
        Returns:
            List of processed diameter messages from this PCAP
        """
        pcap_messages = []
        
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
                    
                    # Handle message with provided handler or store in list
                    if self._session_manager:
                        self._session_manager.process_diameter_message(dm)
                    else:
                        pcap_messages.append(dm)
                        
        except Exception as e:
            print(f"Error processing {pcap.filename}: {e}")
        
        return pcap_messages
    
    def process_all_pcaps(self):
        if not self._pcaps:
            print("No PCAPs found matching the pattern.")
            return
        
        print(f"Processing {len(self._pcaps)} PCAP files...")
        
        for pcap in self._pcaps:
            if not pcap.n_diameter_messages:
                continue

            print(f"Processing: {pcap.filename}")
            self.process_single_pcap(pcap)
        
    
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
            "processed_messages": len(self._processed_messages),
            "time_range": time_range,
            "ports": self.ports,
            "filter": self.filter_str
        }
    
    @property
    def pcaps(self) -> List[Pcap]:
        """Get the list of loaded PCAP objects."""
        return self._pcaps.copy()
    
    @property
    def processed_messages(self) -> List[Any]:
        """Get the list of processed diameter messages."""
        return self._processed_messages.copy()
    
    def __len__(self) -> int:
        """Return the number of loaded PCAPs."""
        return len(self._pcaps)
    
    
    def __iter__(self):
        """Allow iteration over PCAP objects."""
        return iter(self._pcaps)
