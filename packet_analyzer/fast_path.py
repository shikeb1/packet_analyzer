import threading
from .types import AppType
from .sni_extractor import extract_sni_from_tls, extract_host_from_http

class FastPath(threading.Thread):
    def __init__(self, fp_id, input_queue, output_queue, rule_manager, stop_event):
        super().__init__()
        self.fp_id = fp_id
        self.input_queue = input_queue
        self.output_queue = output_queue
        self.rule_manager = rule_manager
        self.stop_event = stop_event
        self.flows = {}  # local flow table (no lock needed)
        self.packets_processed = 0
        self.dropped = 0

    def classify_flow(self, packet_data, flow):
        if flow.app_type != AppType.UNKNOWN:
            return
        payload = packet_data['payload']
        ft = packet_data['five_tuple']
        if ft.dst_port == 443 and len(payload) > 5:
            sni = extract_sni_from_tls(payload)
            if sni:
                flow.sni = sni
                flow.app_type = self.sni_to_app_type(sni)
        elif ft.dst_port == 80:
            host = extract_host_from_http(payload)
            if host:
                flow.sni = host
                flow.app_type = self.sni_to_app_type(host)

    def sni_to_app_type(self, sni):
        sni_lower = sni.lower()
        if 'youtube' in sni_lower:
            return AppType.YOUTUBE
        if 'facebook' in sni_lower:
            return AppType.FACEBOOK
        if 'google' in sni_lower:
            return AppType.GOOGLE
        return AppType.HTTPS if sni else AppType.UNKNOWN

    def run(self):
        while not self.stop_event.is_set():
            packet_data = self.input_queue.pop(timeout=0.1)
            if packet_data is None:
                continue
            ft = packet_data['five_tuple']
            if ft not in self.flows:
                # Use a simple object for flow
                self.flows[ft] = type('Flow', (), {'app_type': AppType.UNKNOWN, 'sni': None, 'blocked': False})()
            flow = self.flows[ft]
            self.classify_flow(packet_data, flow)
            if self.rule_manager.is_blocked(ft.src_ip, flow.app_type, flow.sni):
                flow.blocked = True
                self.dropped += 1
            else:
                self.output_queue.push(packet_data)
                self.packets_processed += 1