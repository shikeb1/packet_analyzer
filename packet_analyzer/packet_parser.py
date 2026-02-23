from scapy.all import Ether, IP, IPv6, TCP, UDP, Raw
from .types import FiveTuple

def parse_packet(packet):
    """Extract five-tuple, payload, and other metadata from a scapy packet."""
    if not packet.haslayer(Ether):
        return None
    eth = packet[Ether]
    
    # IP layer
    ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
    if not ip_layer:
        return None
    
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    proto = ip_layer.proto if isinstance(ip_layer, IP) else ip_layer.nh  # IPv6 next header
    
    # Transport layer
    transport = packet.getlayer(TCP) or packet.getlayer(UDP)
    if not transport:
        return None
    
    src_port = transport.sport
    dst_port = transport.dport
    
    five_tuple = FiveTuple(src_ip, dst_ip, src_port, dst_port, proto)
    
    # Payload (application data)
    payload = bytes(transport.payload) if transport.payload else b''
    
    return {
        'five_tuple': five_tuple,
        'payload': payload,
        'timestamp': packet.time,
        'raw_packet': packet,   # keep for writing output
        'tcp_flags': transport.flags if isinstance(transport, TCP) else None,
    }