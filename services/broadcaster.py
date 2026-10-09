"""
services/broadcaster.py
=======================
Real-Time Event Broadcaster for DNSWatch (SSE & WebSocket bridge).

Provides high-throughput, low-latency publish-subscribe streaming from the
detection engine and packet sniffer to connected dashboard browsers.
Compatible with Render reverse proxies and Gunicorn threaded workers.
"""

import json
import time
import queue
import threading
from datetime import datetime


class RealtimeBroadcaster:
    def __init__(self):
        self._lock = threading.Lock()
        self._listeners = set()

    def subscribe(self, max_buffer=100):
        """Register a new client listener queue."""
        q = queue.Queue(maxsize=max_buffer)
        with self._lock:
            self._listeners.add(q)
        return q

    def unsubscribe(self, q):
        """Unregister a client listener queue."""
        with self._lock:
            self._listeners.discard(q)

    register = subscribe
    unregister = unsubscribe

    def broadcast(self, event_type, data):
        """Broadcast an event payload to all connected clients."""
        msg = f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
        with self._lock:
            dead_queues = []
            for q in self._listeners:
                try:
                    q.put_nowait(msg)
                except queue.Full:
                    # Drop oldest or mark stale
                    try:
                        q.get_nowait()
                        q.put_nowait(msg)
                    except Exception:
                        dead_queues.append(q)
            for dq in dead_queues:
                self._listeners.discard(dq)

    def event_generator(self, q, ping_interval=15):
        """Yields Server-Sent Events from the queue with keepalive pings for Render."""
        last_ping = time.time()
        while True:
            now = time.time()
            timeout = max(0.5, ping_interval - (now - last_ping))
            try:
                msg = q.get(timeout=timeout)
                yield msg
            except queue.Empty:
                pass

            if time.time() - last_ping >= ping_interval:
                # Render proxies close idle connections after 100s.
                # SSE comment ': keepalive' keeps the connection open.
                yield ": keepalive\n\n"
                last_ping = time.time()


broadcaster = RealtimeBroadcaster()
