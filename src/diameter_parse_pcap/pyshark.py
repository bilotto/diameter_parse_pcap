import pyshark
# from diameter_telecom import DiameterMessage
from .diameter_message import DiameterMessagePcap
from diameter.message import Message
from .pcap import Pcap
from typing import List

def create_pyshark_object(pcap_file: Pcap):
    return pyshark.FileCapture(pcap_file.filepath, decode_as=pcap_file.decode_as, display_filter=pcap_file.filter, include_raw=True, use_json=True, debug=False)

def get_diameter_messages_from_pkt(pkt) -> List[DiameterMessagePcap]:
    pkt_diameter_messages = []
    if isinstance(pkt.diameter_raw.value, list):
        payload_hex = pkt.diameter_raw.value[0]
    else:
        payload_hex = pkt.diameter_raw.value
    diameter_message = DiameterMessagePcap(payload_hex)
    diameter_message.timestamp = pkt.frame_info.time_epoch
    diameter_message.pkt_number = pkt.number
    pkt_diameter_messages.append(diameter_message)
    if pkt.diameter_raw.duplicate_layers:
        for i in pkt.diameter_raw.duplicate_layers:
            payload_hex = i.value
            if isinstance(payload_hex, list):
                print("payload_hex is list")
            if not isinstance(payload_hex, str):
                continue
            diameter_bytes = bytes.fromhex(i.value)
            diameter_message = DiameterMessagePcap(Message.from_bytes(diameter_bytes))
            diameter_message.timestamp = pkt.frame_info.time_epoch
            diameter_message.pkt_number = pkt.number
            pkt_diameter_messages.append(diameter_message)

    return pkt_diameter_messages

def get_diameter_messages_from_pcap(pcap: Pcap) -> List[DiameterMessagePcap]:
    pcap_diameter_messages = []
    for pkt in pcap.pyshark_obj:
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