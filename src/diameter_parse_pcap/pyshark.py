import pyshark
import asyncio
import threading
# from diameter_telecom import DiameterMessage
from .diameter_message import DiameterMessagePcap
from diameter.message import Message
from .pcap import Pcap
from typing import List

def create_pyshark_object(pcap_file: Pcap):
    """Create pyshark object with proper event loop handling for threading"""
    # Ensure there's an event loop in the current thread
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        # No event loop in current thread - create one
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
    return pyshark.FileCapture(pcap_file.filepath, decode_as=pcap_file.decode_as, display_filter=pcap_file.filter, include_raw=True, use_json=True, debug=False)

# def get_diameter_messages_from_pkt(pkt) -> List[DiameterMessagePcap]:
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
#             # diameter_bytes = bytes.fromhex(i.value)
#             diameter_message = DiameterMessagePcap(payload_hex)
#             diameter_message.timestamp = pkt.frame_info.time_epoch
#             diameter_message.pkt_number = pkt.number
#             pkt_diameter_messages.append(diameter_message)

#     return pkt_diameter_messages

from diameter_telecom.message import DiameterMessage

def get_diameter_messages_from_pkt(pkt) -> List[DiameterMessage]:
    pkt_diameter_messages = []
    if isinstance(pkt.diameter_raw.value, list):
        payload_hex = pkt.diameter_raw.value[0]
    else:
        payload_hex = pkt.diameter_raw.value
    diameter_message = DiameterMessage(payload_hex)
    # diameter_message.timestamp = pkt.frame_info.time_epoch
    # diameter_message.pkt_number = pkt.number
    pkt_diameter_messages.append(diameter_message)
    if pkt.diameter_raw.duplicate_layers:
        for i in pkt.diameter_raw.duplicate_layers:
            payload_hex = i.value
            if isinstance(payload_hex, list):
                print("payload_hex is list")
            if not isinstance(payload_hex, str):
                continue
            # diameter_bytes = bytes.fromhex(i.value)
            diameter_message = DiameterMessage(payload_hex)
            # diameter_message.timestamp = pkt.frame_info.time_epoch
            # diameter_message.pkt_number = pkt.number
            pkt_diameter_messages.append(diameter_message)

    return pkt_diameter_messages

def get_diameter_messages_from_pcap(pcap: Pcap) -> List[DiameterMessagePcap]:
    pcap_diameter_messages = []
    for pkt in create_pyshark_object(pcap):
        pkt_timestamp = pkt.frame_info.time_epoch
        pkt_number = pkt.number
        pkt_diameter_messages = get_diameter_messages_from_pkt(pkt)
        if not pkt_diameter_messages:
            print(f"No Diameter messages found in packet {pkt_number}")
        for diameter_message in pkt_diameter_messages:
            if not isinstance(diameter_message, DiameterMessagePcap):
                continue
            diameter_message.pcap_filepath = pcap.filepath
            pcap_diameter_messages.append(diameter_message)

    return pcap_diameter_messages