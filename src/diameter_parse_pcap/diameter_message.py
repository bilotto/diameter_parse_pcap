from diameter_telecom import DiameterMessage, Subscriber

class DiameterMessagePcap(DiameterMessage):
    pkt_number: int = None
    pcap_filepath: str = None
    # framed_ip_address: str = None
    # framed_ipv6_prefix: str = None
    # sgsn_mcc_mnc: str = None
    # called_station_id: str = None
    # granted_service_unit: str = None
    # used_service_unit: str = None
    # rat_type: str = None

# class DiameterMessagePcap(DiameterMessage):
#     def __init__(self, obj):
#         super().__init__(obj)
#         # Initialize _attributes directly to avoid __setattr__ complications
#         self._attributes = {
#             'pkt_number': None,
#             'pcap_filepath': None,
#             'framed_ip_address': None,
#             'framed_ipv6_prefix': None,
#             'sgsn_mcc_mnc': None,
#             'called_station_id': None,
#             'granted_service_unit': None,
#             'used_service_unit': None,
#             'result_code': None,
#             'rat_type': None,
#         }

#     def __getattr__(self, name):
#         # Avoid recursion by using object.__getattribute__ directly
#         try:
#             attributes = object.__getattribute__(self, '_attributes')
#             if name in attributes and attributes[name] is not None:
#                 return attributes[name]
#         except AttributeError:
#             pass

#         # Fallback to message attributes
#         try:
#             message = object.__getattribute__(self, 'message')
#             if hasattr(message, name):
#                 return getattr(message, name)
#         except AttributeError:
#             pass

#         return None

#     def __setattr__(self, name, value):
#         # Handle core attributes directly
#         if name in ('message', '_attributes', 'timestamp', 'subscriber'):
#             object.__setattr__(self, name, value)
#         elif name == 'processing_time':
#             # Convert processing_time (ms) to processing_time_microseconds and set that instead
#             if value is not None:
#                 object.__setattr__(self, 'processing_time_microseconds', value * 1000.0)
#             else:
#                 object.__setattr__(self, 'processing_time_microseconds', None)
#         else:
#             # Safe access to _attributes with fallback
#             try:
#                 attributes = object.__getattribute__(self, '_attributes')
#                 attributes[name] = value
#             except AttributeError:
#                 # Fallback for early initialization - set directly
#                 object.__setattr__(self, name, value)

