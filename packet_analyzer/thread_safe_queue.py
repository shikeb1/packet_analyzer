from queue import Queue, Full, Empty

class ThreadSafeQueue:
    def __init__(self, maxsize=0):
        self.queue = Queue(maxsize=maxsize)

    def push(self, item, timeout=None):
        try:
            self.queue.put(item, block=True, timeout=timeout)
        except Full:
            pass

    def pop(self, timeout=None):
        try:
            return self.queue.get(block=True, timeout=timeout)
        except Empty:
            return None

    def size(self):
        return self.queue.qsize()