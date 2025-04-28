from typing import *
import json

def read_pcap_json(file_path: str) -> List[Dict[str, Any]]:
    """
    Read a JSON file and return a list of dictionaries.
    :param file_path: Path to the JSON file.
    :return: List of dictionaries.
    """
    with open(file_path, 'r') as f:
        data = f.read()
    return json.loads(data)  # Safely parse JSON


from .pcap import Pcap

def create_from_dict(pcap_dict: dict) -> Pcap:
    pcap = Pcap(filepath=pcap_dict['filepath'])
    pcap.start_timestamp = pcap_dict.get('start_timestamp')
    pcap.end_timestamp = pcap_dict.get('end_timestamp')
    pcap.n_diameter_messages = pcap_dict.get('n_diameter_messages', 0)
    pcap.cut_short = pcap_dict.get('cut_short', False)
    pcap.filter = pcap_dict.get('filter', 'diameter && diameter.cmd.code != 257 && diameter.cmd.code != 280')
    return pcap

import pyshark

def create_pyshark_object(pcap_file: Pcap):
    return pyshark.FileCapture(pcap_file.filepath, decode_as=pcap_file.decode_as, display_filter=pcap_file.filter, include_raw=True, use_json=True, debug=False)


from diameter_telecom.diameter_message import DiameterMessage, Message

def get_diameter_messages_from_pkt(pkt) -> List[DiameterMessage]:
    pkt_diameter_messages = []
    if isinstance(pkt.diameter_raw.value, list):
        payload_hex = pkt.diameter_raw.value[0]
    else:
        payload_hex = pkt.diameter_raw.value
    diameter_message = DiameterMessage(payload_hex)
    pkt_diameter_messages.append(diameter_message)
    diameter_message.set_timestamp(pkt.frame_info.time_epoch)
    diameter_message.pkt_number = pkt.number
    if pkt.diameter_raw.duplicate_layers:
        for i in pkt.diameter_raw.duplicate_layers:
            payload_hex = i.value
            if isinstance(payload_hex, list):
                print("payload_hex is list")
            if not isinstance(payload_hex, str):
                continue
            diameter_bytes = bytes.fromhex(i.value)
            diameter_message = DiameterMessage(Message.from_bytes(diameter_bytes))
            diameter_message.set_timestamp(pkt.frame_info.time_epoch)
            diameter_message.set_pkt_number(pkt.number)
            pkt_diameter_messages.append(diameter_message)

    return pkt_diameter_messages

def get_diameter_messages_from_pcap(pcap: Pcap) -> List[DiameterMessage]:
    pcap_diameter_messages = []
    for pkt in pcap.pyshark_obj:
        pkt_timestamp = pkt.frame_info.time_epoch
        pkt_number = pkt.number
        pkt_diameter_messages = get_diameter_messages_from_pkt(pkt)
        if not pkt_diameter_messages:
            print(f"No Diameter messages found in packet {pkt_number}")
        for diameter_message in pkt_diameter_messages:
            if not isinstance(diameter_message, DiameterMessage):
                continue
            diameter_message.pcap_filepath = pcap.filepath
            pcap_diameter_messages.append(diameter_message)

    return pcap_diameter_messages