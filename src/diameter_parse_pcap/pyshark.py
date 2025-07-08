import pyshark
from .pcap import Pcap

def create_pyshark_object(pcap_file: Pcap):
    return pyshark.FileCapture(pcap_file.filepath, decode_as=pcap_file.decode_as, display_filter=pcap_file.filter, include_raw=True, use_json=True, debug=False)
