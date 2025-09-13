import os
import re
import glob
import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Dict, Any, Pattern, Callable
from datetime import datetime
from dataclasses import dataclass, field
from .pcap import Pcap
# from .functions import get_diameter_messages_from_pkt
# import pyshark
from diameter_telecom.diameter.session_manager import SessionManager
from .pyshark import get_diameter_messages_from_pkt, create_pyshark_object

@dataclass
class PcapGroup:
    """
    A class to manage a group of PCAP files in a directory with regex name filtering.
    
    This class provides functionality to:
    - Find PCAP files in a directory using regex patterns
    - Sort PCAPs by timestamp
    - Process multiple PCAPs with consistent configuration (in parallel)
    - Extract and manage diameter messages from all PCAPs
    """
    directory: str
    name_pattern: str
    ports: List[int] = field(default_factory=lambda: [])
    filter: str = "diameter && diameter.cmd.code != 257 && diameter.cmd.code != 280"
    sctp: bool = False
    recursive: bool = False
    max_workers: Optional[int] = None
    _pcaps: List[Pcap] = field(default_factory=list, init=False, repr=True)
    _processed_messages: List[Any] = field(default_factory=list, init=False, repr=False)
    session_manager: SessionManager = field(default_factory=SessionManager, init=False, repr=False)
    
    def __post_init__(self):
        """Validate the regex pattern, set defaults, and find PCAP files after dataclass initialization."""
        # Set up logger
        self.logger = logging.getLogger(f"{self.__class__.__module__}.{self.__class__.__name__}")
        
        # Set default max_workers based on CPU count if not provided
        if self.max_workers is None:
            self.max_workers = min(32, (os.cpu_count() or 1) + 4)
            
        try:
            re.compile(self.name_pattern)
        except re.error as e:
            raise ValueError(f"Invalid regex pattern '{self.name_pattern}': {e}")
        
        # Simple cache logic: if cache exists, load it; otherwise process and save
        cache_file = os.path.join(self.directory, ".pcap_metadata_cache.json")
        if os.path.exists(cache_file):
            self._load_cache(cache_file)
        else:
            self._find_and_load_pcaps()
            self._save_cache(cache_file)

    def set_session_manager(self, session_manager: SessionManager):
        self.session_manager = session_manager
    
    def _load_cache(self, cache_file: str) -> None:
        """Load PCAP objects from cache file."""
        try:
            with open(cache_file, 'r') as f:
                pcap_data_list = json.load(f)
            
            self._pcaps = []
            for pcap_data in pcap_data_list:
                pcap_obj = Pcap(
                    filepath=pcap_data['filepath'],
                    ports=pcap_data.get('ports', self.ports),
                    filter=self.filter,
                    sctp=self.sctp
                )
                # Set cached attributes
                pcap_obj.start_timestamp = pcap_data.get('start_timestamp')
                pcap_obj.end_timestamp = pcap_data.get('end_timestamp') 
                pcap_obj.n_diameter_messages = pcap_data.get('n_diameter_messages', 0)
                
                if pcap_obj.n_diameter_messages > 0:
                    self._pcaps.append(pcap_obj)
            
            self._pcaps = sorted(self._pcaps, key=lambda x: x.start_timestamp or 0)
            self.logger.info(f"Loaded {len(self._pcaps)} PCAP objects from cache")
            
        except Exception as e:
            self.logger.error(f"Failed to load cache: {e}")
            self._find_and_load_pcaps()
            self._save_cache(cache_file)
    
    def _save_cache(self, cache_file: str) -> None:
        """Save PCAP objects to cache file."""
        try:
            cache_data = [pcap.to_json() for pcap in self._pcaps]
            with open(cache_file, 'w') as f:
                json.dump(cache_data, f, indent=2)
            self.logger.info(f"Saved {len(cache_data)} PCAP objects to cache")
        except Exception as e:
            self.logger.error(f"Failed to save cache: {e}")
    
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

        self.logger.debug(f"Found PCAP files: {pcap_files}")
        
        # Filter by regex pattern
        matching_files = []
        compiled_pattern = re.compile(self.name_pattern)
        for filepath in pcap_files:
            filename = os.path.basename(filepath)
            if compiled_pattern.search(filename):
                matching_files.append(filepath)
        
        return matching_files
    
    def _load_single_pcap(self, filepath: str) -> Optional[Pcap]:
        """
        Thread-safe method to load a single PCAP file.
        
        Args:
            filepath: Path to the PCAP file to load
            
        Returns:
            Pcap object if loaded successfully, None otherwise
        """
        try:
            pcap_obj = Pcap(
                filepath=filepath,
                ports=self.ports,
                filter=self.filter,
                sctp=self.sctp
            )
            pcap_obj.get_timestamps()
            if pcap_obj.n_diameter_messages == 0:
                self.logger.debug(f"Skipping {os.path.basename(filepath)}: no diameter messages")
                return None
            self.logger.debug(f"Loaded: {pcap_obj.filename} ({pcap_obj.n_diameter_messages} messages)")
            return pcap_obj
        except Exception as e:
            self.logger.error(f"Error loading {os.path.basename(filepath)}: {e}")
            return None

    def _find_and_load_pcaps(self) -> None:
        """
        Internal method to find and load PCAP files in parallel.
        This is called during __post_init__.
        """
        pcap_files = self.find_pcap_files()
        self.logger.info(f"Found {len(pcap_files)} PCAP files in {self.directory}")
        
        self._pcaps = []
        
        # Load PCAPs in parallel using ThreadPoolExecutor
        self.logger.info(f"Loading PCAPs with {self.max_workers} workers...")
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_filepath = {executor.submit(self._load_single_pcap, filepath): filepath 
                                for filepath in pcap_files}
            
            # Collect results as they complete
            for future in as_completed(future_to_filepath):
                filepath = future_to_filepath[future]
                try:
                    pcap_obj = future.result()
                    if pcap_obj is not None:
                        self._pcaps.append(pcap_obj)
                except Exception as e:
                    self.logger.error(f"Unexpected error processing {os.path.basename(filepath)}: {e}")
        
        # Sort by start timestamp
        self._pcaps = sorted(self._pcaps, key=lambda x: x.start_timestamp or 0)
        self.logger.info(f"Successfully loaded {len(self._pcaps)} PCAP files")
    
    def load_pcaps(self) -> None:
        """Reload PCAP objects from the directory."""
        cache_file = os.path.join(self.directory, ".pcap_metadata_cache.json")
        if os.path.exists(cache_file):
            self._load_cache(cache_file)
        else:
            self._find_and_load_pcaps()
            self._save_cache(cache_file)
    
    def process_single_pcap(self, pcap: Pcap) -> List[Any]:
        """
        Process a single PCAP file and extract diameter messages.
        
        Args:
            pcap: Pcap object to process
            
        Returns:
            List of processed diameter messages from this PCAP
        """
        pcap_messages = []
        
        try:
            pyshark_obj = create_pyshark_object(pcap)
            
            for pkt in pyshark_obj:
                diameter_messages = get_diameter_messages_from_pkt(pkt)
                for dm in diameter_messages:
                    dm.pcap_filepath = pcap.filepath
                    
                    # Handle message with provided handler or store in list
                    if self.session_manager:
                        self.session_manager.process_diameter_message(dm)
                    else:
                        pcap_messages.append(dm)
                        
        except Exception as e:
            self.logger.error(f"Error processing {pcap.filename}: {e}")
        
        return pcap_messages
    
    def process_all_pcaps(self):
        if not self._pcaps:
            self.logger.warning("No PCAPs found matching the pattern.")
            return
        
        self.logger.info(f"Processing {len(self._pcaps)} PCAP files...")
        
        for pcap in self._pcaps:
            if not pcap.n_diameter_messages:
                continue

            self.logger.info(f"Processing: {pcap.filename}")
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
    
    # def get_pcaps_by_name_pattern(self, pattern: str) -> List[Pcap]:
    #     """
    #     Get PCAPs whose filenames match the given regex pattern.
        
    #     Args:
    #         pattern: Regex pattern to match against filenames
            
    #     Returns:
    #         List of matching PCAPs
    #     """
    #     try:
    #         compiled_pattern = re.compile(pattern)
    #     except re.error as e:
    #         raise ValueError(f"Invalid regex pattern '{pattern}': {e}")
        
    #     matching_pcaps = []
    #     for pcap in self._pcaps:
    #         if compiled_pattern.search(pcap.filename):
    #             matching_pcaps.append(pcap)
        
    #     return matching_pcaps
    
    # def get_summary(self) -> Dict[str, Any]:
    #     """
    #     Get a summary of the PCAP group.
        
    #     Returns:
    #         Dictionary containing summary information
    #     """
    #     if not self._pcaps:
    #         return {
    #             "directory": self.directory,
    #             "name_pattern": self.name_pattern,
    #             "total_pcaps": 0,
    #             "total_messages": 0,
    #             "time_range": None
    #         }
        
    #     total_messages = sum(pcap.n_diameter_messages for pcap in self._pcaps)
        
    #     # Calculate time range
    #     start_times = [pcap.start_timestamp for pcap in self._pcaps if pcap.start_timestamp]
    #     end_times = [pcap.end_timestamp for pcap in self._pcaps if pcap.end_timestamp]
        
    #     time_range = None
    #     if start_times and end_times:
    #         earliest_start = min(start_times)
    #         latest_end = max(end_times)
    #         time_range = {
    #             "start": datetime.fromtimestamp(earliest_start).isoformat(),
    #             "end": datetime.fromtimestamp(latest_end).isoformat(),
    #             "duration_seconds": latest_end - earliest_start
    #         }
        
    #     return {
    #         "directory": self.directory,
    #         "name_pattern": self.name_pattern,
    #         "total_pcaps": len(self._pcaps),
    #         "total_messages": total_messages,
    #         "processed_messages": len(self._processed_messages),
    #         "time_range": time_range,
    #         "ports": self.ports,
    #         "filter": self.filter
    #     }
    
    @property
    def pcaps(self) -> List[Pcap]:
        """Get the list of loaded PCAP objects."""
        return self._pcaps.copy()
    
    # @property
    # def processed_messages(self) -> List[Any]:
    #     """Get the list of processed diameter messages."""
    #     return self._processed_messages.copy()
    
    def __len__(self) -> int:
        """Return the number of loaded PCAPs."""
        return len(self._pcaps)
    
    
    def __iter__(self):
        """Allow iteration over PCAP objects."""
        return iter(self._pcaps)
