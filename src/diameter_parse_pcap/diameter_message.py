from diameter_telecom import DiameterMessage, Subscriber

class DiameterMessagePcap(DiameterMessage):
    pkt_number: int = None
    pcap_filepath: str = None
