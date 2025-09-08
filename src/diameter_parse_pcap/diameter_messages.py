from diameter_telecom import DiameterMessage, Subscriber
from diameter_telecom.diameter.constants import *
from diameter_telecom.diameter.parse_avp import parse_subscription_id

def parse_gx_diameter_message(dm: DiameterMessage) -> DiameterMessage:
    if dm.name == CCR_I:
        if dm.message.subscription_id:
            parsed_subscription_id = parse_subscription_id(dm.message.subscription_id)
            msisdn = parsed_subscription_id[0]
            imsi = parsed_subscription_id[1]
            dm.subscriber = Subscriber(msisdn=msisdn, imsi=imsi)
    return dm

def parse_sy_diameter_message(dm: DiameterMessage) -> DiameterMessage:
    return dm

def parse_rx_dm(dm: DiameterMessage) -> DiameterMessage:
    return dm

def parse_diameter_message(dm: DiameterMessage) -> DiameterMessage:
    if dm.app_id == APP_3GPP_GX:
        return parse_gx_diameter_message(dm)
    elif dm.app_id == APP_3GPP_SY:
        return parse_sy_diameter_message(dm)
    elif dm.app_id == APP_3GPP_RX:
        return parse_rx_dm(dm)
    else:
        return dm


class DiameterMessages:
    def __init__(self):
        self.messages = []

    def append(self, message: DiameterMessage):
        self.messages.append(message)

    def add_message(self, message: DiameterMessage):
        self.append(message)

    def get_messages(self):
        # return self.messages
        # Return sorted by timestamp
        return sorted(self.messages, key=lambda x: x.timestamp if x.timestamp else float('inf'))

