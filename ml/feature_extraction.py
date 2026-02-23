import numpy as np

def extract_flow_features(flow_packets):
    if not flow_packets:
        return None
    flow_packets.sort(key=lambda p: p['timestamp'])
    first = flow_packets[0]
    last = flow_packets[-1]
    duration = last['timestamp'] - first['timestamp']
    total_packets = len(flow_packets)
    total_bytes = sum(len(p['raw_packet']) for p in flow_packets)
    avg_pkt_size = total_bytes / total_packets if total_packets else 0
    iats = [flow_packets[i+1]['timestamp'] - flow_packets[i]['timestamp'] for i in range(len(flow_packets)-1)]
    iat_mean = np.mean(iats) if iats else 0
    iat_std = np.std(iats) if iats else 0
    syn_count = sum(1 for p in flow_packets if p.get('tcp_flags') and (p['tcp_flags'] & 0x02))
    fin_count = sum(1 for p in flow_packets if p.get('tcp_flags') and (p['tcp_flags'] & 0x01))
    payload_packets = sum(1 for p in flow_packets if len(p['payload']) > 0)
    features = [
        duration,
        total_packets,
        total_bytes,
        avg_pkt_size,
        iat_mean,
        iat_std,
        syn_count,
        fin_count,
        payload_packets,
    ]
    return np.array(features, dtype=np.float32)