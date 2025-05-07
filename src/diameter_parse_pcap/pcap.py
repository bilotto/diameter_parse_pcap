import os
import subprocess
from datetime import datetime
import re
from typing import List
from diameter_telecom import DiameterMessage
from diameter.message import Message

class Pcap:

    def __init__(self, filepath, ports: list = [], sctp=False, filter='diameter'):
        self.filepath = filepath
        self.ports = ports
        self.sctp = sctp
        self.filter = filter
        self.start_timestamp = None
        self.end_timestamp = None
        self.n_diameter_messages = 0
        self.pid_file = None
        self.cut_short = False
        self._pyshark_obj = None

    @property
    def pyshark_obj(self):
        if self._pyshark_obj is None:
            self._pyshark_obj = create_pyshark_object(self)
        return self._pyshark_obj

    def __eq__(self, value):
        if isinstance(value, Pcap):
            return self.filepath == value.filepath
        elif isinstance(value, str):
            return self.filepath == value
        return False
    
    def __hash__(self):
        return hash(self.filepath)


    def __repr__(self):
        return f"Pcap(filepath={self.filepath}, start_date={self.start_date}, end_date={self.end_date}, n_diameter_messages={self.n_diameter_messages})"
    
    def to_dict(self):
        pcap_dict = dict()
        pcap_dict['filepath'] = self.filepath
        if self.start_timestamp:
            pcap_dict['start_timestamp'] = self.start_timestamp
        if self.end_timestamp:
            pcap_dict['end_timestamp'] = self.end_timestamp
        if self.n_diameter_messages:
            pcap_dict['n_diameter_messages'] = self.n_diameter_messages
        if self.cut_short:
            pcap_dict['cut_short'] = self.cut_short
        if self.filter:
            pcap_dict['filter'] = self.filter
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
    def start_date(self) -> datetime:
        if self.start_timestamp:
            return datetime.fromtimestamp(float(self.start_timestamp))
    
    @property
    def end_date(self) -> datetime:
        if self.end_timestamp:
            return datetime.fromtimestamp(float(self.end_timestamp))

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

    def dump_packets(self, filter, output_file):
        command = f"tshark -r {self.filepath} {self.get_ports()} -Y \"{filter}\" -w {output_file}"
        subprocess.run(command, shell=True)

    def tcpdump_command(self, interface="any"):
        return f"sudo tcpdump -i {interface} port {','.join(map(str, self.ports))} -w {self.filepath} &"

    def get_timestamps(self):
        command = f"tshark -r {self.filepath} -Y \"{self.filter}\" -T fields -e frame.time_epoch"
        try:
            output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT).decode().strip().split('\n')
            if not output:
                return
        except subprocess.CalledProcessError as e:
            if "appears to have been cut short" in e.output.decode():
                print(f"File {self.filepath} appears to have been cut short. Skipping...")
                self.cut_short = True
                # Attempt to process the output if available
                output = e.output.decode().strip().split('\n')
                if not output:
                    return
            else:
                raise e
        pkt_timestamps = []
        for i in output:
            if re.match(r'^\d+\.\d+$', i):
                pkt_timestamps.append(float(i))
        if not pkt_timestamps:
            print(f"No valid timestamps found in {self.filepath}")
            return
        self.start_timestamp = pkt_timestamps[0]
        self.end_timestamp = pkt_timestamps[-1]
        self.n_diameter_messages = len(pkt_timestamps)

    def get_md5sum(self, filepath):
        command = f"md5sum {filepath}"
        try:
            output = subprocess.check_output(command, shell=True).decode().strip()
            md5sum = output.split()[0]
            return md5sum
        except subprocess.CalledProcessError as e:
            print(f"Error calculating md5sum for {filepath}: {e}")
            return None

    def get_diameter_messages_from_pkt(self, pkt) -> List[DiameterMessage]:
        pkt_diameter_messages = []
        if isinstance(pkt.diameter_raw.value, list):
            payload_hex = pkt.diameter_raw.value[0]
        else:
            payload_hex = pkt.diameter_raw.value
        diameter_message = DiameterMessage(payload_hex)
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
                diameter_message = DiameterMessage(Message.from_bytes(diameter_bytes))
                diameter_message.timestamp = pkt.frame_info.time_epoch
                diameter_message.pkt_number = pkt.number
                pkt_diameter_messages.append(diameter_message)

        return pkt_diameter_messages

    def get_diameter_messages_from_pcap(self) -> List[DiameterMessage]:
        pcap_diameter_messages = []
        for pkt in self.pyshark_obj:
            pkt_timestamp = pkt.frame_info.time_epoch
            pkt_number = pkt.number
            pkt_diameter_messages = self.get_diameter_messages_from_pkt(pkt)
            if not pkt_diameter_messages:
                print(f"No Diameter messages found in packet {pkt_number}")
            for diameter_message in pkt_diameter_messages:
                if not isinstance(diameter_message, DiameterMessage):
                    continue
                diameter_message.pcap_filepath = self.filepath
                pcap_diameter_messages.append(diameter_message)

        return pcap_diameter_messages

import pyshark

def create_pyshark_object(pcap_file: Pcap):
    return pyshark.FileCapture(pcap_file.filepath, decode_as=pcap_file.decode_as, display_filter=pcap_file.filter, include_raw=True, use_json=True, debug=False)
