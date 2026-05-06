import time
import threading
import psutil
import socket
import pydivert

class TokenBucket:
    def __init__(self, rate_bytes_per_sec: float, burst_bytes: int = None):
        self.rate = rate_bytes_per_sec
        self.burst = burst_bytes or int(rate_bytes_per_sec * 0.5)
        self.tokens = self.burst
        self.last_refill = time.monotonic()
        self.lock = threading.Lock()

    def consume(self, num_bytes: int) -> bool:
        with self.lock:
            now = time.monotonic()
            elapsed = now - self.last_refill
            self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
            self.last_refill = now
            
            if self.tokens >= num_bytes:
                self.tokens -= num_bytes
                return True
            return False

    def update_rate(self, new_rate_bytes_per_sec: float):
        with self.lock:
            self.rate = new_rate_bytes_per_sec
            self.burst = int(new_rate_bytes_per_sec * 0.5)


class ConnectionMapper:
    def __init__(self, refresh_interval: float = 5.0):
        self.cache = {}
        self.last_refresh = 0
        self.refresh_interval = refresh_interval
        self.lock = threading.Lock()
    
    def refresh(self):
        new_cache = {}
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.pid and conn.laddr:
                    port = conn.laddr.port
                    proto = 'tcp' if conn.type == socket.SOCK_STREAM else 'udp'
                    try:
                        exe = psutil.Process(conn.pid).name()
                        new_cache[(port, proto)] = exe
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
        except Exception:
            pass
        with self.lock:
            self.cache = new_cache
            self.last_refresh = time.monotonic()
    
    def lookup(self, local_port: int, proto: str) -> str:
        if time.monotonic() - self.last_refresh > self.refresh_interval:
            self.refresh()
        with self.lock:
            return self.cache.get((local_port, proto), "unknown")


class TrafficShaper:
    def __init__(self, priority: int = 1000):
        self.buckets = {}
        self.mapper = ConnectionMapper()
        self.running = False
        self.thread = None
        self.priority = priority
        self.global_bucket = None
    
    def set_limit(self, exe_name: str, rate_mbps: float):
        rate_bps = rate_mbps * 125000
        if exe_name in self.buckets:
            self.buckets[exe_name].update_rate(rate_bps)
        else:
            self.buckets[exe_name] = TokenBucket(rate_bps)
    
    def remove_limit(self, exe_name: str):
        self.buckets.pop(exe_name, None)
    
    def set_global_limit(self, rate_mbps: float):
        rate_bps = rate_mbps * 125000
        self.global_bucket = TokenBucket(rate_bps)
    
    def _capture_loop(self):
        w = pydivert.WinDivert("inbound and (tcp or udp)", priority=self.priority)
        w.open()
        
        try:
            while self.running:
                packet = w.recv()
                
                local_port = packet.dst_port
                proto = 'tcp' if packet.tcp else 'udp'
                
                exe_name = self.mapper.lookup(local_port, proto)
                
                bucket = self.buckets.get(exe_name)
                
                allowed = True
                if bucket:
                    allowed = bucket.consume(len(packet.raw))
                
                if allowed and self.global_bucket:
                    allowed = self.global_bucket.consume(len(packet.raw))
                
                if allowed:
                    w.send(packet)
                # If not allowed, we just drop the packet (no w.send)
        finally:
            w.close()
    
    def start(self):
        self.running = True
        self.mapper.refresh()
        self.thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.thread.start()
    
    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
