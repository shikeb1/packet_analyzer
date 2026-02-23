import threading
import hashlib
from .thread_safe_queue import ThreadSafeQueue

class LoadBalancer(threading.Thread):
    def __init__(self, lb_id, input_queue, fast_path_queues, stop_event):
        super().__init__()
        self.lb_id = lb_id
        self.input_queue = input_queue
        self.fast_path_queues = fast_path_queues
        self.stop_event = stop_event
        self.packets_dispatched = 0

    def run(self):
        while not self.stop_event.is_set():
            packet_data = self.input_queue.pop(timeout=0.1)
            if packet_data is None:
                continue
            ft = packet_data['five_tuple']
            key = f"{ft.src_ip}:{ft.dst_ip}:{ft.src_port}:{ft.dst_port}:{ft.protocol}"
            hash_val = int(hashlib.md5(key.encode()).hexdigest(), 16)
            fp_idx = hash_val % len(self.fast_path_queues)
            self.fast_path_queues[fp_idx].push(packet_data)
            self.packets_dispatched += 1