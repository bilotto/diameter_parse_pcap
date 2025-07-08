from diameter_telecom import DiameterMessage, Subscriber

class DiameterMessagePcap(DiameterMessage):
    def __init__(self, obj):
        super().__init__(obj)
        super().__setattr__('_attributes', {
            'pkt_number': None,
            'pcap_filepath': None,
            'framed_ip_address': None,
            'framed_ipv6_prefix': None,
            'sgsn_mcc_mnc': None,
            'called_station_id': None,
            'granted_service_unit': None,
            'used_service_unit': None,
            'result_code': None,
            'rat_type': None,
        })

    def __getattr__(self, name):
        attributes = super().__getattribute__('_attributes')
        if name in attributes and attributes[name] is not None:
            return attributes[name]

        message = super().__getattribute__('message')
        if hasattr(message, name):
            return getattr(message, name)

        return None

    def __setattr__(self, name, value):
        if name in ('message', '_attributes', 'timestamp', 'subscriber'):
            super().__setattr__(name, value)
        else:
            attributes = super().__getattribute__('_attributes')
            attributes[name] = value
