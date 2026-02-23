import threading
from .types import Flow

class ConnectionTracker:
    def __init__(self):
        self.flows = {}
        self.lock = threading.Lock()

    def get_or_create_flow(self, five_tuple):
        with self.lock:
            if five_tuple not in self.flows:
                self.flows[five_tuple] = Flow(five_tuple)
            return self.flows[five_tuple]

    def get_all_flows(self):
        with self.lock:
            return list(self.flows.values())