import threading
from scapy.all import rdpcap, wrpcap, PcapWriter
from .packet_parser import parse_packet
from .sni_extractor import extract_sni_from_tls, extract_host_from_http
from .types import AppType
from .rule_manager import RuleManager
from .connection_tracker import ConnectionTracker
from .thread_safe_queue import ThreadSafeQueue
from .load_balancer import LoadBalancer
from .fast_path import FastPath
import time

class DPIEngine:
    def __init__(self, input_file, output_file, rules=None, num_lbs=1, num_fps_per_lb=1):
        self.input_file = input_file
        self.output_file = output_file
        self.rules = rules if rules else RuleManager()
        self.num_lbs = num_lbs
        self.num_fps_per_lb = num_fps_per_lb
        self.total_fps = num_lbs * num_fps_per_lb
        self.stop_event = threading.Event()
        self.stats = {
            'total_packets': 0,
            'forwarded': 0,
            'dropped': 0,
            'flows': {},
            'app_counts': {},
        }

    def _sni_to_app_type(self, sni):
        sni_lower = sni.lower()
        if 'youtube' in sni_lower:
            return AppType.YOUTUBE
        if 'facebook' in sni_lower:
            return AppType.FACEBOOK
        if 'google' in sni_lower:
            return AppType.GOOGLE
        return AppType.HTTPS

    def run_simple(self):
        packets = rdpcap(self.input_file)
        tracker = ConnectionTracker()
        output_packets = []
        for pkt in packets:
            parsed = parse_packet(pkt)
            if not parsed:
                continue
            ft = parsed['five_tuple']
            flow = tracker.get_or_create_flow(ft)
            if ft.dst_port == 443 and len(parsed['payload']) > 5:
                sni = extract_sni_from_tls(parsed['payload'])
                if sni:
                    flow.sni = sni
                    flow.app_type = self._sni_to_app_type(sni)
            elif ft.dst_port == 80:
                host = extract_host_from_http(parsed['payload'])
                if host:
                    flow.sni = host
                    flow.app_type = self._sni_to_app_type(host)
            if self.rules.is_blocked(ft.src_ip, flow.app_type, flow.sni):
                flow.blocked = True
                self.stats['dropped'] += 1
            else:
                output_packets.append(pkt)
                self.stats['forwarded'] += 1
            self.stats['total_packets'] += 1
            app = flow.app_type.name
            self.stats['app_counts'][app] = self.stats['app_counts'].get(app, 0) + 1
        wrpcap(self.output_file, output_packets)
        self.stats['flows'] = len(tracker.flows)
        self._print_report()

    def _reader_task(self, output_queue):
        packets = rdpcap(self.input_file)
        for pkt in packets:
            parsed = parse_packet(pkt)
            if not parsed:
                continue
            parsed['raw_packet'] = pkt
            output_queue.push(parsed)
            self.stats['total_packets'] += 1
        output_queue.push(None)  # sentinel

    def _writer_task(self, input_queue):
        writer = PcapWriter(self.output_file, append=False, sync=True)
        while True:
            packet_data = input_queue.pop(timeout=0.1)
            if packet_data is None:
                if self.stop_event.is_set() and input_queue.size() == 0:
                    break
                continue
            writer.write(packet_data['raw_packet'])
            self.stats['forwarded'] += 1
        writer.close()

    def run_multi(self):
        reader_queue = ThreadSafeQueue(maxsize=10000)
        lb_queues = [ThreadSafeQueue(maxsize=10000) for _ in range(self.num_lbs)]
        fp_queues = [ThreadSafeQueue(maxsize=10000) for _ in range(self.total_fps)]
        output_queue = ThreadSafeQueue(maxsize=10000)

        reader_thread = threading.Thread(target=self._reader_task, args=(reader_queue,))
        reader_thread.start()

        lbs = []
        for i in range(self.num_lbs):
            start = i * self.num_fps_per_lb
            end = (i + 1) * self.num_fps_per_lb
            lb = LoadBalancer(i, reader_queue, fp_queues[start:end], self.stop_event)
            lbs.append(lb)
            lb.start()

        fps = []
        for i in range(self.total_fps):
            fp = FastPath(i, fp_queues[i], output_queue, self.rules, self.stop_event)
            fps.append(fp)
            fp.start()

        writer_thread = threading.Thread(target=self._writer_task, args=(output_queue,))
        writer_thread.start()

        reader_thread.join()
        time.sleep(1)
        self.stop_event.set()

        for lb in lbs:
            lb.join()
        for fp in fps:
            fp.join()
        writer_thread.join()

        total_processed = sum(fp.packets_processed for fp in fps)
        total_dropped = sum(fp.dropped for fp in fps)
        self.stats['forwarded'] = total_processed
        self.stats['dropped'] = total_dropped
        self._print_report()

    def _print_report(self):
        print("\n" + "="*60)
        print("DPI ENGINE REPORT")
        print("="*60)
        print(f"Total packets: {self.stats['total_packets']}")
        print(f"Forwarded:     {self.stats['forwarded']}")
        print(f"Dropped:       {self.stats['dropped']}")
        print(f"Unique flows:  {self.stats.get('flows', 0)}")
        print("\nApplication Breakdown:")
        for app, count in sorted(self.stats['app_counts'].items(), key=lambda x: -x[1]):
            print(f"  {app}: {count}")
        print("="*60)