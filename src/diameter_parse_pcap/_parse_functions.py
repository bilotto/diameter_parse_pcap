from typing import *
from diameter.message.constants import *
import logging

logger = logging.getLogger(__name__)

import datetime
def convert_timestamp(ts, gmt_delta=0) -> str:
    return (datetime.datetime.fromtimestamp(float(ts)) + datetime.timedelta(hours=gmt_delta)).strftime('%Y-%m-%d %H:%M:%S')

# import socket
# def bytes_to_ip(ip_bytes):
#     try:
#         return socket.inet_ntoa(ip_bytes)
#     except:
#         logger.error(f"Error converting bytes to IP: {ip_bytes}")
#         return None

# from diameter.message.avp.grouped import SubscriptionId
# def parse_subscription_id(subscription_id: List[SubscriptionId]):
#     msisdn = None
#     imsi = None
#     sip_uri = None
#     nai = None
#     private = None
#     for i in subscription_id:
#         if i.subscription_id_type == E_SUBSCRIPTION_ID_TYPE_END_USER_E164:
#             msisdn = i.subscription_id_data
#         elif i.subscription_id_type == E_SUBSCRIPTION_ID_TYPE_END_USER_IMSI:
#             imsi = i.subscription_id_data
#         elif i.subscription_id_type == E_SUBSCRIPTION_ID_TYPE_END_USER_SIP_URI:
#             sip_uri = i.subscription_id_data
#         elif i.subscription_id_type == E_SUBSCRIPTION_ID_TYPE_END_USER_NAI:
#             nai = i.subscription_id_data
#         elif i.subscription_id_type == E_SUBSCRIPTION_ID_TYPE_END_USER_PRIVATE:
#             private = i.subscription_id_data
#     return (msisdn, imsi, sip_uri, nai, private)


# import ipaddress
# def decode_framed_ipv6(raw_bytes):
#     try:
#         reserved_byte = raw_bytes[0]
#         prefix_length = raw_bytes[1]
#         ipv6_prefix_bytes = raw_bytes[2:]
#         ipv6_prefix_bytes_padded = ipv6_prefix_bytes.ljust(16, b'\x00')
#         ipv6_address = ipaddress.IPv6Address(ipv6_prefix_bytes_padded)
#         return f"{ipv6_address}/{prefix_length}"
#     except:
#         logger.error(f"Error decoding framed IPv6: {raw_bytes}")
#         return None