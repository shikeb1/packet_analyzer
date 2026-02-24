from scapy.layers.inet import IP
from scapy.packet import Packet


def apply_rules(packets, rule_data):
    forwarded = 0
    dropped = 0
    breakdown = {}

    rules = rule_data

    for pkt in packets:
        drop_packet = False

        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            for rule in rules:
                if rule["type"] == "ip":
                    if rule["value"] == src_ip or rule["value"] == dst_ip:
                        drop_packet = True

        # Fake app detection (demo logic)
        app_name = "UNKNOWN"
        if pkt.haslayer("TCP"):
            app_name = "TCP"
        elif pkt.haslayer("UDP"):
            app_name = "UDP"

        breakdown[app_name] = breakdown.get(app_name, 0) + 1

        if drop_packet:
            dropped += 1
        else:
            forwarded += 1

    return forwarded, dropped, breakdown