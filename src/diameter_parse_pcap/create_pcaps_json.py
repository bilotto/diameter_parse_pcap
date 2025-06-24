# from diameter_parse_pcap import *
from .pcap import Pcap
from .functions import read_pcap_json, create_from_dict
import subprocess
from typing import *
from concurrent.futures import ThreadPoolExecutor
import os
import json

from threading import Lock
from typing import List

progress_counter = 0
progress_lock = Lock()

def save_progress(pcaps_list: List[Pcap], filepath: str):
    """Save current progress to JSON file"""
    try:
        with open(filepath, "w") as f:
            json.dump([pcap.to_dict() for pcap in pcaps_list], f, indent=4)
        print(f"Progress saved to {filepath}")
    except Exception as e:
        print(f"Error saving progress: {e}")


def process_pcap(pcap_obj: Pcap):
    if pcap_obj.start_timestamp and pcap_obj.end_timestamp:
        print(f"Already processed {pcap_obj.filename} with timestamps {pcap_obj.start_timestamp} and {pcap_obj.end_timestamp}")
        return
    print(f"Processing {pcap_obj.filename}")
    pcap_obj.get_timestamps()


def run_pcap_processing(pcaps: List[Pcap], pcaps_json_filepath: str) -> None:
    def process_pcap_with_progress(index: int, total: int, pcap_obj: Pcap):
        global progress_counter
        try:
            with progress_lock:
                progress_counter += 1
                print(f"[{progress_counter}/{total}] Processing {pcap_obj.filename}")
            process_pcap(pcap_obj)
            
            # Save progress every 10 processed files
            if progress_counter % 10 == 0:
                save_progress(pcaps, pcaps_json_filepath)
        except Exception as e:
            print(f"Error processing {pcap_obj.filename}: {e}")
            # Save progress even if there's an error
            save_progress(pcaps, pcaps_json_filepath)
            raise
    # Main processing function that uses ThreadPoolExecutor to process pcaps concurrently
    try:
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = [
                executor.submit(process_pcap_with_progress, idx + 1, len(pcaps), p)
                for idx, p in enumerate(pcaps)
            ]
            
            # Wait for all futures to complete
            for future in futures:
                future.result()  # This will raise any exceptions that occurred

        # Sort pcaps, handling None values by putting them at the end
        pcaps.sort(key=lambda x: float('inf') if x.start_timestamp is None else x.start_timestamp)
        
        # Final save after successful completion
        save_progress(pcaps, pcaps_json_filepath)
        
    except Exception as e:
        print(f"Error during processing: {e}")
        # Save progress in case of error
        save_progress(pcaps, pcaps_json_filepath)
        raise

def create_json(pcaps_dir: str, ports: List[int] = [], pcaps_json_filepath: str = None) -> None:
    if not pcaps_json_filepath:
        pcaps_json_filepath = os.path.join(pcaps_dir, "pcaps.json")
    pcaps: List[Pcap] = []
    if not os.path.exists(pcaps_dir):
        raise FileNotFoundError(f"Directory not found: {pcaps_dir}")
    if os.path.exists(pcaps_json_filepath):
        for i in read_pcap_json(pcaps_json_filepath):
            pcaps.append(create_from_dict(i))

    print(f"Reading pcap files from {pcaps_dir}...")
    command = f"find {pcaps_dir} -type f -name '*.pcap*' | grep -v json"
    print(f"Running command: {command}")
    # Run command
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    # Get the output
    output = result.stdout.strip().split('\n')

    print(f"There are {len(output)} pcap files in the directory")

    for i in output:
        pcap_obj = Pcap(i, ports=ports, filter="diameter && diameter.cmd.code != 257 && diameter.cmd.code != 280")
        if not pcap_obj in pcaps:
            print(f"Adding {pcap_obj.filename} to the list")
            pcaps.append(pcap_obj)

    run_pcap_processing(pcaps, pcaps_json_filepath)

def read_from_json(pcaps_json_filepath: str) -> List[Pcap]:
    all_pcaps: List[Pcap] = []
    for i in read_pcap_json(pcaps_json_filepath):
        all_pcaps.append(create_from_dict(i))
    # Sort pcaps by start_timestamp
    all_pcaps.sort(key=lambda x: float('inf') if x.start_timestamp is None else x.start_timestamp)
    return all_pcaps



# try:
#     with ThreadPoolExecutor(max_workers=30) as executor:
#         futures = [
#             executor.submit(process_pcap_with_progress, idx + 1, total_pcaps, p)
#             for idx, p in enumerate(pcaps)
#         ]
        
#         # Wait for all futures to complete
#         for future in futures:
#             future.result()  # This will raise any exceptions that occurred

#     # Sort pcaps, handling None values by putting them at the end
#     pcaps.sort(key=lambda x: float('inf') if x.start_timestamp is None else x.start_timestamp)
    
#     # Final save after successful completion
#     save_progress(pcaps, pcaps_json_filepath)
    
# except Exception as e:
#     print(f"Error during processing: {e}")
#     # Save progress in case of error
#     save_progress(pcaps, pcaps_json_filepath)
#     raise

