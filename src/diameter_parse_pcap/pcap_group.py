import os
import re
import glob
import json
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Dict, Any, Pattern, Callable
from datetime import datetime
from dataclasses import dataclass, field
from .pcap import Pcap
# from .functions import get_diameter_messages_from_pkt
# import pyshark
from diameter_telecom import SessionManager
from diameter_telecom.csv_file import CsvFile, CSV_COLUMNS
from .pyshark import get_diameter_messages_from_pkt, create_pyshark_object
import subprocess


fields = ["frame.time_epoch", ]

def get_pcap_info(pcap: Pcap):
    command = f"tshark -r {pcap.filepath} {pcap.get_ports()} -Y \"{pcap.filter}\" -T fields -e frame.time_epoch"
    print(command)
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT).decode().strip().split('\n')
        if not output:
            return
    except subprocess.CalledProcessError as e:
        if "appears to have been cut short" in e.output.decode():
            print(f"File {pcap.filepath} appears to have been cut short. Skipping...")
            pcap.cut_short = True
            # Attempt to process the output if available
            output = e.output.decode().strip().split('\n')
        else:
            print(f"Error getting timestamps from {pcap.filepath}: {e}")
            output = e.output.decode().strip().split('\n')
    if not output:
        print(f"No valid timestamps found in {pcap.filepath}")
        return
    pkt_timestamps = []
    for i in output:
        if re.match(r'^\d+\.\d+$', i):
            pkt_timestamps.append(float(i))
    if not pkt_timestamps:
        print(f"No valid timestamps found in {pcap.filepath}")
        return
    pcap.start_timestamp = pkt_timestamps[0]
    pcap.end_timestamp = pkt_timestamps[-1]
    pcap.n_diameter_packets = len(pkt_timestamps)  # Count of diameter packets (not individual messages)


@dataclass
class PcapGroup:
    directory: str
    name_pattern: str = ".*\\.pcap"
    ports: List[int] = field(default_factory=lambda: [])
    filter: str = "diameter && diameter.cmd.code != 257 && diameter.cmd.code != 280"
    sctp: bool = False
    recursive: bool = False
    max_workers: Optional[int] = None
    csv_file: Optional[CsvFile] = None
    _pcaps: List[Pcap] = field(default_factory=list, init=False, repr=True)
    session_manager: SessionManager = field(default_factory=SessionManager, init=False, repr=False)
    clear_cache: bool = False
    
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

        self.session_manager.clear_sessions_after_termination = False
        
        # Pass CSV file to session manager if provided
        if self.csv_file:
            self.logger.info(f"📝 Configuring CSV logging: {self.csv_file.filename}")
            self.session_manager.csv_file = self.csv_file
        
        # Clear cache if requested
        cache_file = os.path.join(self.directory, ".pcap_metadata_cache.json")
        if self.clear_cache:
            self.logger.info(f"🧹 Clearing cache: {cache_file}")
            os.remove(cache_file)
            self.logger.info(f"✅ Cache cleared successfully: {cache_file}")
        
        # Simple cache logic: if cache exists, load it; otherwise process and save
        if os.path.exists(cache_file):
            self.logger.info(f"💾 Loading PCAP metadata from cache: {cache_file}")
            self._load_cache(cache_file)
        else:
            self.logger.info(f"🔍 No cache found, processing PCAP files...")
            self._find_and_load_pcaps()
            self._save_cache(cache_file)

    def set_session_manager(self, session_manager: SessionManager):
        session_manager.clear_sessions_after_termination = False
        self.session_manager = session_manager
    
    def _load_cache(self, cache_file: str) -> None:
        """Load PCAP objects from cache file."""
        try:
            with open(cache_file, 'r') as f:
                pcap_data_list = json.load(f)
            
            self.logger.info(f"📊 Loading {len(pcap_data_list)} PCAP entries from cache...")
            
            self._pcaps = []
            loaded_count = 0
            total_messages = 0
            
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
                pcap_obj.n_diameter_packets = pcap_data.get('n_diameter_packets', 0)
                
                if pcap_obj.n_diameter_packets > 0:
                    self._pcaps.append(pcap_obj)
                    loaded_count += 1
                    total_messages += pcap_obj.n_diameter_packets
                    self.logger.debug(f"✅ Cached: {pcap_obj.filename} ({pcap_obj.n_diameter_packets} packets)")
            
            self._pcaps = sorted(self._pcaps, key=lambda x: x.start_timestamp or 0)
            self.logger.info(f"🎯 Cache loaded successfully:")
            self.logger.info(f"   📁 PCAP files: {loaded_count}")
            self.logger.info(f"   📊 Total messages: {total_messages:,}")
            
        except Exception as e:
            self.logger.error(f"❌ Failed to load cache: {e}")
            self.logger.info(f"🔄 Falling back to PCAP file processing...")
            self._find_and_load_pcaps()
            self._save_cache(cache_file)
    
    def _save_cache(self, cache_file: str) -> None:
        """Save PCAP objects to cache file."""
        try:
            if not self._pcaps:
                self.logger.warning("⚠️  No PCAP objects to save to cache")
                return
                
            self.logger.info(f"💾 Saving {len(self._pcaps)} PCAP objects to cache...")
            cache_data = [pcap.to_json() for pcap in self._pcaps]
            with open(cache_file, 'w') as f:
                json.dump(cache_data, f, indent=2)
            
            cache_size = os.path.getsize(cache_file)
            self.logger.info(f"✅ Cache saved successfully:")
            self.logger.info(f"   📄 File: {cache_file}")
            self.logger.info(f"   📁 PCAP entries: {len(cache_data)}")
            self.logger.info(f"   💽 Size: {cache_size} bytes")
        except Exception as e:
            self.logger.error(f"❌ Failed to save cache: {e}")
    
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
        # Set thread name for better logging visibility during loading
        original_thread_name = threading.current_thread().name
        filename = os.path.basename(filepath)
        threading.current_thread().name = f"Load-{filename}"
        
        try:
            pcap_obj = Pcap(
                filepath=filepath,
                ports=self.ports,
                filter=self.filter,
                sctp=self.sctp
            )
            
            thread_name = threading.current_thread().name
            # pcap_obj.get_timestamps()
            if pcap_obj.n_diameter_packets == 0:
                self.logger.error(f"[{thread_name}] Skipping {filename}: no diameter messages")
                return None
            self.logger.info(f"[{thread_name}] Loaded: {filename} ({pcap_obj.n_diameter_packets:,} messages)")
            return pcap_obj
        except Exception as e:
            thread_name = threading.current_thread().name
            self.logger.error(f"[{thread_name}] Error loading {filename}: {e}")
            return None
        finally:
            # Restore original thread name
            threading.current_thread().name = original_thread_name

    def _find_and_load_pcaps(self) -> None:
        """
        Internal method to find and load PCAP files in parallel.
        This is called during __post_init__.
        """
        pcap_files = self.find_pcap_files()
        self.logger.info(f"🔍 Found {len(pcap_files)} PCAP files in {self.directory}")
        
        if not pcap_files:
            self.logger.warning("⚠️  No PCAP files found matching the pattern")
            return
        
        self._pcaps = []
        
        # Load PCAPs in parallel using ThreadPoolExecutor
        self.logger.info(f"⚡ Loading PCAPs with {self.max_workers} workers...")
        loaded_count = 0
        failed_count = 0
        total_messages = 0
        
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
                        loaded_count += 1
                        total_messages += pcap_obj.n_diameter_packets
                    else:
                        failed_count += 1
                except Exception as e:
                    failed_count += 1
                    self.logger.error(f"❌ Unexpected error processing {os.path.basename(filepath)}: {e}")
        
        # Sort by start timestamp
        self._pcaps = sorted(self._pcaps, key=lambda x: x.start_timestamp or 0)
        
        # Final loading summary
        self.logger.info(f"🎯 PCAP loading complete:")
        self.logger.info(f"   ✅ Successfully loaded: {loaded_count} files")
        if failed_count > 0:
            self.logger.warning(f"   ❌ Failed/Skipped: {failed_count} files")
        self.logger.info(f"   📊 Total messages: {total_messages:,}")
        
        if loaded_count == 0:
            self.logger.warning("⚠️  No valid PCAP files with diameter messages found")
    
    def load_pcaps(self) -> None:
        """Reload PCAP objects from the directory."""
        cache_file = os.path.join(self.directory, ".pcap_metadata_cache.json")
        if os.path.exists(cache_file):
            self._load_cache(cache_file)
        else:
            self._find_and_load_pcaps()
            self._save_cache(cache_file)
    
    def process_single_pcap(self, pcap: Pcap) -> None:
        """
        Process a single PCAP file and extract diameter messages.
        
        All messages are processed through the session manager.
        
        Args:
            pcap: Pcap object to process
        """
        # Set thread name to PCAP filename for better logging visibility
        original_thread_name = threading.current_thread().name
        threading.current_thread().name = pcap.filename
        
        processed_count = 0
        packets_processed = 0
        
        try:
            # Use estimated count for progress reporting
            estimated_messages = pcap.n_diameter_packets
            
            # Calculate adaptive progress interval based on estimated count
            if estimated_messages < 1000:
                progress_interval = 100
            elif estimated_messages < 10000:
                progress_interval = 500
            else:
                progress_interval = 1000
            
            # Also consider 10% intervals, but cap at reasonable values
            ten_percent = max(100, estimated_messages // 10)
            progress_interval = min(progress_interval, ten_percent)
            
            thread_name = threading.current_thread().name
            self.logger.info(f"🔄 [{thread_name}] Starting processing: {pcap.filename} (~{estimated_messages:,} messages estimated)")
            pyshark_obj = create_pyshark_object(pcap)
            
            for pkt in pyshark_obj:
                packets_processed += 1
                diameter_messages = get_diameter_messages_from_pkt(pkt)
                
                for dm in diameter_messages:
                    dm.pcap_filepath = pcap.filepath
                    self.session_manager.process_diameter_message(dm)
                    processed_count += 1
                    
                    # Log progress at adaptive intervals
                    if processed_count % progress_interval == 0:
                        if processed_count <= estimated_messages:
                            progress_pct = (processed_count / estimated_messages) * 100
                            self.logger.info(f"  📊 [{thread_name}] Progress: {processed_count:,}/{estimated_messages:,} messages ({progress_pct:.1f}%) | {packets_processed:,} packets")
                        else:
                            # We exceeded the estimate, show without percentage
                            self.logger.info(f"  📊 [{thread_name}] Progress: {processed_count:,} messages (>{estimated_messages:,} estimated) | {packets_processed:,} packets")
            
            # Final report with actual vs estimated
            if processed_count == estimated_messages:
                self.logger.info(f"✅ [{thread_name}] Completed: {pcap.filename} - {processed_count:,} messages processed (exact match)")
            elif processed_count > estimated_messages:
                excess_pct = ((processed_count - estimated_messages) / estimated_messages) * 100
                self.logger.info(f"✅ [{thread_name}] Completed: {pcap.filename} - {processed_count:,} messages processed (+{excess_pct:.1f}% more than estimated)")
            else:
                deficit_pct = ((estimated_messages - processed_count) / estimated_messages) * 100
                self.logger.info(f"✅ [{thread_name}] Completed: {pcap.filename} - {processed_count:,} messages processed (-{deficit_pct:.1f}% less than estimated)")
                        
        except Exception as e:
            thread_name = threading.current_thread().name
            self.logger.error(f"❌ [{thread_name}] Error processing {pcap.filename}: {e}")
        finally:
            # Restore original thread name
            threading.current_thread().name = original_thread_name
    
    def process_all_pcaps(self,start_time: datetime = None, end_time: datetime = None):
        """
        Process all PCAP files in parallel using ThreadPoolExecutor.
        
        When session_manager is available, messages are processed through it.
        The session_manager is thread-safe and supports concurrent processing.
        """
        if not self._pcaps:
            self.logger.warning("⚠️  No PCAPs found matching the pattern.")
            return
        
        # Filter PCAPs with diameter messages
        pcaps_to_process = [pcap for pcap in self.pcaps if pcap.n_diameter_packets > 0 and (start_time is None or pcap.start_date >= start_time) and (end_time is None or pcap.end_date <= end_time)]
        
        if not pcaps_to_process:
            self.logger.warning("⚠️  No PCAPs with diameter messages found.")
            return
        
        # Calculate processing statistics
        total_messages = sum(pcap.n_diameter_packets for pcap in pcaps_to_process)
        csv_status = "enabled" if self.session_manager.csv_file else "disabled"
        
        self.logger.info(f"🚀 Starting parallel PCAP processing:")
        self.logger.info(f"   📁 Files to process: {len(pcaps_to_process)}")
        self.logger.info(f"   📊 Total messages: {total_messages:,}")
        self.logger.info(f"   🧵 Worker threads: {self.max_workers}")
        self.logger.info(f"   📝 CSV export: {csv_status}")
        if self.session_manager.csv_file:
            self.logger.info(f"   📄 CSV file: {self.session_manager.csv_file.filename}")
        
        # Process PCAPs in parallel
        completed_files = 0
        failed_files = 0
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all processing tasks
            future_to_pcap = {executor.submit(self.process_single_pcap, pcap): pcap 
                            for pcap in pcaps_to_process}
            
            # Wait for all tasks to complete
            for future in as_completed(future_to_pcap):
                pcap = future_to_pcap[future]
                try:
                    future.result()  # Just wait for completion, no return value
                    completed_files += 1
                    progress_pct = (completed_files / len(pcaps_to_process)) * 100
                    self.logger.info(f"✅ [{completed_files}/{len(pcaps_to_process)}] ({progress_pct:.1f}%) Completed: {pcap.filename}")
                except Exception as e:
                    failed_files += 1
                    total_done = completed_files + failed_files
                    progress_pct = (total_done / len(pcaps_to_process)) * 100
                    self.logger.error(f"❌ [{total_done}/{len(pcaps_to_process)}] ({progress_pct:.1f}%) Failed: {pcap.filename} - {e}")
        
        # Final statistics
        self.logger.info(f"🎉 Parallel processing complete!")
        self.logger.info(f"   ✅ Successfully processed: {completed_files} files")
        if failed_files > 0:
            self.logger.warning(f"   ❌ Failed files: {failed_files}")
        
        # Session manager statistics
        total_sessions = self.session_manager.sessions.n_sessions
        self.logger.info(f"   📈 Session statistics:")
        self.logger.info(f"      🔗 Total sessions: {total_sessions}")
        self.logger.info(f"      👥 Total subscribers: {len(self.session_manager.subscribers.subscribers)}")
        self.logger.info(f"      📨 Total messages: {len(self.session_manager.messages):,}")
        
        # CSV statistics
        if self.session_manager.csv_file:
            self.logger.info(f"   📊 CSV export:")
            self.logger.info(f"      📝 Records written: {self.session_manager.csv_file.n_records:,}")
            self.logger.info(f"      📄 File: {self.session_manager.csv_file.filename}")
    
    def get_pcaps_by_time_range(self, start_time: datetime, end_time: datetime) -> List[Pcap]:
        """
        Get PCAPs that overlap with the specified time range.
        
        Args:
            start_time: Start of time range (datetime object)
            end_time: End of time range (datetime object)
            
        Returns:
            List of PCAPs that overlap with the time range
        """
        if start_time >= end_time:
            raise ValueError("start_time must be before end_time")
            
        start_timestamp = start_time.timestamp()
        end_timestamp = end_time.timestamp()
        
        overlapping_pcaps = []
        for pcap in self._pcaps:
            if (pcap.start_timestamp and pcap.end_timestamp and
                not (pcap.end_timestamp < start_timestamp or pcap.start_timestamp > end_timestamp)):
                overlapping_pcaps.append(pcap)
        
        return overlapping_pcaps
    
    def get_pcaps_by_date(self, target_date: datetime) -> List[Pcap]:
        """
        Get PCAPs that contain traffic on a specific date.
        
        Args:
            target_date: Target date (datetime object)
            
        Returns:
            List of PCAPs that contain traffic on the target date
        """
        # Create time range for the entire day
        start_of_day = target_date.replace(hour=0, minute=0, second=0, microsecond=0)
        end_of_day = target_date.replace(hour=23, minute=59, second=59, microsecond=999999)
        
        return self.get_pcaps_by_time_range(start_of_day, end_of_day)
    
    def get_pcaps_by_hour_range(self, start_hour: int, end_hour: int, target_date: datetime = None) -> List[Pcap]:
        """
        Get PCAPs that contain traffic within a specific hour range.
        
        Args:
            start_hour: Start hour (0-23)
            end_hour: End hour (0-23)
            target_date: Target date (defaults to today)
            
        Returns:
            List of PCAPs that contain traffic within the hour range
        """
        if not (0 <= start_hour <= 23 and 0 <= end_hour <= 23):
            raise ValueError("Hours must be between 0 and 23")
            
        if start_hour > end_hour:
            raise ValueError("start_hour must be <= end_hour")
            
        if target_date is None:
            target_date = datetime.now()
            
        start_time = target_date.replace(hour=start_hour, minute=0, second=0, microsecond=0)
        end_time = target_date.replace(hour=end_hour, minute=59, second=59, microsecond=999999)
        
        return self.get_pcaps_by_time_range(start_time, end_time)
    
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
        
        total_messages = sum(pcap.n_diameter_packets for pcap in self._pcaps)
        
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
            "filter": self.filter
        }
    
    @property
    def pcaps(self) -> List[Pcap]:
        # Return the list of pcap objects sorted by start, end timestamp
        return sorted(self._pcaps, key=lambda x: (x.start_timestamp, x.end_timestamp))
    
    
    def __len__(self) -> int:
        """Return the number of loaded PCAPs."""
        return len(self._pcaps)
    
    
    def __iter__(self):
        """Allow iteration over PCAP objects."""
        return iter(self._pcaps)

    def to_json(self) -> str:
        # Return all pcaps json
        return [pcap.to_json() for pcap in self.pcaps]